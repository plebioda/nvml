/*
 * Copyright (c) 2015, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * pmemrad_client.c -- XXX
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_errno.h>

#include <libpmem.h>

#include "pmemra.h"
#include "pmemrad.h"
#include "pmemrad_client.h"

struct pmemrad_client_lane {
	struct fi_info *fi;
	struct fid_ep *ep;
	struct pmemra_persist tx_persist;
	struct fid_mr *tx_mr;
	struct pmemra_persist rx_persist;
	struct fid_mr *rx_mr;
};

struct pmemrad_client {
	int sockfd;
	struct sockaddr_in sock_addr;
	struct pmemrad_pdb *pdb;
	pthread_t thread;
	int run;
	const struct pmemrad_pool *pool;
	uint64_t rkey;
	unsigned nlanes;
	struct sockaddr_in fabric_sock_addr;
	struct fi_info *fi;
	struct fid_fabric *fabric;
	struct fid_eq *eq;
	struct fid_cq *cq;
	struct fid_pep *pep;
	struct fid_domain *domain;
	struct fid_mr *mr;
	struct pmemrad_client_lane *lanes;
};

typedef int (*msg_handler_t)(struct pmemrad_client *prc,
	struct pmemra_msg_hdr *hdrp);

static int
pmemrad_client_send(struct pmemrad_client *prc,
	void *msg_buff, size_t msg_len)
{
	ASSERT(msg_len < UINT32_MAX);
	ssize_t ret;

	ret = write(prc->sockfd, msg_buff, msg_len);
	if (ret < 0) {
		log_err("!write");
		return -1;
	}

	if ((size_t)ret != msg_len) {
		log_err("write failed");
		return -1;
	}

	return 0;
}

static int
pmemrad_client_fabric_init(struct pmemrad_client *prc)
{
	struct fi_info *hints = fi_allocinfo();
	if (!hints) {
		log_err("cannot alloc fi_info for hints");
		return -1;
	}

	hints->addr_format = FI_SOCKADDR_IN;
	hints->ep_attr->type = FI_EP_MSG;
	hints->domain_attr->mr_mode = FI_MR_BASIC;
	hints->caps = FI_MSG | FI_RMA;
	hints->mode = FI_CONTEXT | FI_LOCAL_MR | FI_RX_CQ_DATA;

	int ret;
	ret = fi_getinfo(PMEMRA_FIVERSION, NULL, NULL, 0, hints,
			&prc->fi);
	if (ret) {
		log_err("cannot get fabric info");
		goto err_fi_getinfo;
	}

	ret = fi_fabric(prc->fi->fabric_attr, &prc->fabric, NULL);
	if (ret) {
		log_err("cannot get fabric");
		goto err_fi_fabric;
	}

	struct fi_eq_attr eq_attr = {
		.size = 0,
		.flags = 0,
		.wait_obj = FI_WAIT_UNSPEC,
		.signaling_vector = 0,
		.wait_set = NULL,
	};

	ret = fi_eq_open(prc->fabric, &eq_attr, &prc->eq, NULL);
	if (ret) {
		log_err("cannot open event queue");
		goto err_fi_eq_open;
	}

	size_t cq_size = prc->fi->tx_attr->size < prc->fi->rx_attr->size ?
		prc->fi->tx_attr->size : prc->fi->rx_attr->size;

	struct fi_cq_attr cq_attr = {
		.size = cq_size,
		.flags = 0,
		.format = FI_CQ_FORMAT_DATA,
		.wait_obj = FI_WAIT_UNSPEC,
		.signaling_vector = 0,
		.wait_cond = FI_CQ_COND_NONE,
		.wait_set = NULL,
	};

	log_info("cq size %lu", cq_attr.size);
	ret = fi_domain(prc->fabric, prc->fi, &prc->domain, NULL);
	if (ret) {
		log_err("cannot access domain");
		goto err_fi_domain;
	}

	ret = fi_cq_open(prc->domain, &cq_attr, &prc->cq, NULL);
	if (ret) {
		log_err("cannot open completion queue");
		goto err_fi_cq_open;
	}

	ret = fi_mr_reg(prc->domain, prc->pool->addr, prc->pool->size,
			FI_REMOTE_READ | FI_REMOTE_WRITE, 0, 0, 0,
			&prc->mr, NULL);
	if (ret) {
		log_err("memory registration failed");
		goto err_fi_mr_reg;
	}

	prc->rkey = fi_mr_key(prc->mr);

	ret = fi_passive_ep(prc->fabric, prc->fi, &prc->pep, NULL);
	if (ret) {
		log_err("cannot create passive endpoint");
		goto err_fi_passive_ep;
	}

	ret = fi_pep_bind(prc->pep, &prc->eq->fid, 0);
	if (ret) {
		log_err("cannot bind passive endpoint");
		goto err_fi_bind;
	}

	ret = fi_listen(prc->pep);
	if (ret) {
		log_err("listen failed");
		goto err_fi_listen;
	}

	size_t addrlen = sizeof (prc->fabric_sock_addr);
	ret = fi_getname(&prc->pep->fid, &prc->fabric_sock_addr,
			&addrlen);
	if (ret) {
		log_err("getname failed");
		goto err_fi_getname;
	}

	log_info("listening on %s:%d",
		inet_ntoa(prc->fabric_sock_addr.sin_addr),
		htons(prc->fabric_sock_addr.sin_port));

	fi_freeinfo(hints);
	return 0;
err_fi_getname:
err_fi_listen:
err_fi_passive_ep:
	fi_close(&prc->mr->fid);
err_fi_bind:
	fi_close(&prc->pep->fid);
err_fi_mr_reg:
	fi_close(&prc->cq->fid);
err_fi_cq_open:
	fi_close(&prc->domain->fid);
err_fi_domain:
	fi_close(&prc->eq->fid);
err_fi_eq_open:
	fi_close(&prc->fabric->fid);
err_fi_fabric:
	fi_freeinfo(prc->fi);
err_fi_getinfo:
	fi_freeinfo(hints);
	return ret;
}

static int
pmemrad_client_fabric_accept_ep(struct pmemrad_client *prc, size_t lane,
	struct fi_info *info)
{
	int ret;
	struct pmemrad_client_lane *lanep = &prc->lanes[lane];

	ret = fi_endpoint(prc->domain, info, &lanep->ep, NULL);
	if (ret) {
		log_err("cannot create endpoint");
		goto err_fi_endpoint;
	}

	ret = fi_mr_reg(prc->domain, &lanep->tx_persist,
			sizeof (lanep->tx_persist),
			FI_SEND, 0, 0, 0, &lanep->tx_mr, NULL);
	if (ret) {
		log_err("cannot register memory");
		goto err_fi_mr_reg_tx;
	}

	ret = fi_mr_reg(prc->domain, &lanep->rx_persist,
			sizeof (lanep->rx_persist),
			FI_RECV, 0, 0, 0, &lanep->rx_mr, NULL);
	if (ret) {
		log_err("cannot register memory");
		goto err_fi_mr_reg_rx;
	}

	ret = fi_ep_bind(lanep->ep, &prc->eq->fid, 0);
	if (ret) {
		log_err("cannot bind event queue");
		goto err_fi_ep_bind_eq;
	}

	ret = fi_ep_bind(lanep->ep, &prc->cq->fid, FI_TRANSMIT | FI_RECV);
	if (ret) {
		log_err("cannot bind completion queue");
		goto err_fi_ep_bind_cq;
	}

	ret = fi_accept(lanep->ep, NULL, 0);
	if (ret) {
		log_err("accept failed");
		goto err_fi_accept;
	}

	prc->lanes[lane].fi = info;

	return 0;
err_fi_accept:
err_fi_ep_bind_cq:
err_fi_ep_bind_eq:
	fi_close(&lanep->rx_mr->fid);
err_fi_mr_reg_rx:
	fi_close(&lanep->tx_mr->fid);
err_fi_mr_reg_tx:
	fi_close(&lanep->ep->fid);
err_fi_endpoint:
	fi_freeinfo(info);
	return ret;
}

static void
pmemrad_client_fabric_close_ep(struct pmemrad_client *prc, size_t lane)
{
	fi_cancel(&prc->lanes[lane].ep->fid, NULL);
	fi_close(&prc->lanes[lane].ep->fid);
	fi_close(&prc->lanes[lane].rx_mr->fid);
	fi_close(&prc->lanes[lane].tx_mr->fid);
	fi_freeinfo(prc->lanes[lane].fi);
}

static void
pmemrad_client_fabric_close(struct pmemrad_client *prc)
{
	for (size_t lane = 0; lane < prc->nlanes; lane++)
		pmemrad_client_fabric_close_ep(prc, lane);

	fi_close(&prc->pep->fid);
	fi_close(&prc->mr->fid);
	fi_close(&prc->domain->fid);
	fi_close(&prc->eq->fid);
	fi_close(&prc->fabric->fid);
	fi_freeinfo(prc->fi);
}

static ssize_t
pmemrad_client_get_ep(struct pmemrad_client *prc, fid_t fid)
{
	for (size_t i = 0; i < prc->nlanes; i++)
		if (fid == &prc->lanes[i].ep->fid)
			return (ssize_t)i;
	return -1;
}

static int
pmemrad_client_fabric_accept(struct pmemrad_client *prc)
{
	int ret;
	size_t lane = 0;
	size_t nlanes = 0;
	while (nlanes < prc->nlanes) {
		struct fi_eq_cm_entry entry;
		uint32_t event;
		ssize_t rret;

		/* XXX timeout */
		rret = fi_eq_sread(prc->eq, &event, &entry,
				sizeof (entry), -1, 0);
		if (rret != sizeof (entry)) {
			log_err("!read event");
			ret = (int)rret;
			goto err_fi_accept_ep;
		}

		if (entry.fid == &prc->pep->fid) {
			if (lane >= prc->nlanes) {
				ret = -1;
				goto err_fi_accept_ep;
			}
			if (event != FI_CONNREQ) {
				log_err("unexpected event %u\n", event);
				ret = -1;
				goto err_fi_accept_ep;
			}

			ret = pmemrad_client_fabric_accept_ep(prc,
					lane, entry.info);
			if (ret) {
				log_err("cannot accept ep[%lu]", lane);
				goto err_fi_accept_ep;
			}

			lane++;
		} else {
			ssize_t i = pmemrad_client_get_ep(prc, entry.fid);
			if (i < 0) {
				log_err("unknown ep");
				ret = -1;
				goto err_fi_accept_ep;
			}

			if (event != FI_CONNECTED) {
				log_err("unexpected cm event");
				ret = -1;
				goto err_fi_accept_ep;
			}

			struct pmemrad_client_lane *lanep = &prc->lanes[i];
			rret = fi_recv(lanep->ep, &lanep->rx_persist,
				sizeof (lanep->rx_persist),
				fi_mr_desc(lanep->rx_mr),
				0, lanep);
			if (rret < 0) {
				log_err("cannot post recv buffer");
				goto err_fi_recv;
			}


			nlanes++;
		}

	}

	log_info("connected: %s", inet_ntoa(prc->sock_addr.sin_addr));

	return 0;
err_fi_recv:
err_fi_accept_ep:
	for (size_t i = 0; i < prc->nlanes; i++)
		if (prc->lanes[i].ep)
			pmemrad_client_fabric_close_ep(prc, i);
	return ret;
}

static int
pmemrad_client_msg_open(struct pmemrad_client *prc,
	struct pmemra_msg_hdr *hdrp)
{
	struct pmemra_msg_open *msg =
		(struct pmemra_msg_open *)hdrp;

	int ret = 0;
	/* XXX */
	ASSERTeq(msg->hdr.type, PMEMRA_MSG_MAP);
	ASSERTeq(msg->hdr.size, sizeof (*msg) + msg->fname_len +
			msg->poolset_len);

	struct pmemra_msg_open_resp resp = {
		.hdr = {
			.type = PMEMRA_MSG_OPEN_RESP,
			.size = sizeof (struct pmemra_msg_open_resp),
		},
		.status = PMEMRA_ERR_FATAL,
		.rkey = 0,
		.port = 0,
		.nlanes = 0,
	};

	size_t data_ptr  = 0;

	if (msg->fname_len) {
		resp.status = PMEMRA_ERR_FILE_NAME;
		goto out_send_resp;
	}

	if (!msg->poolset_len) {
		resp.status = PMEMRA_ERR_POOLSET;
		goto out_send_resp;
	}

	if (msg->data[data_ptr + msg->poolset_len] != '\0') {
		resp.status = PMEMRA_ERR_POOLSET;
		goto out_send_resp;
	}

	log_info("map request from %s for %s",
		inet_ntoa(prc->sock_addr.sin_addr),
		&msg->data[data_ptr]);

	prc->pool = pmemrad_pdb_open(prc->pdb, &msg->data[data_ptr]);
	if (!prc->pool) {
		if (errno == EBUSY)
			resp.status = PMEMRA_ERR_BUSY;
		else if (errno == EINVAL)
			resp.status = PMEMRA_ERR_INVAL;
		goto out_send_resp;
	}

	if (prc->pool->size < msg->mem_size) {
		resp.status = PMEMRA_ERR_MEM_SIZE;
		goto out_send_resp;
	}

	prc->nlanes = msg->nlanes;
	prc->lanes = calloc(prc->nlanes, sizeof (*prc->lanes));
	if (!prc->lanes) {
		log_err("cannot allocate lanes");
		resp.status = PMEMRA_ERR_FATAL;
		goto out_send_resp;
	}

	ret = pmemrad_client_fabric_init(prc);
	if (ret) {
		resp.status = PMEMRA_ERR_FATAL;
		goto out_send_resp;
	}

	resp.status = PMEMRA_ERR_SUCCESS;
	resp.port = htons(prc->fabric_sock_addr.sin_port);
	resp.rkey = prc->rkey;
	resp.addr = (uint64_t)prc->pool->addr;
	resp.size = prc->pool->size;
	resp.nlanes = prc->nlanes;

	if (pmemrad_client_send(prc, &resp, sizeof (resp))) {
		log_err("sending response failed");
		/* XXX */
	}

	ret = pmemrad_client_fabric_accept(prc);
	if (ret) {
		log_err("fabric accept failed");
		/* XXX */
	}

	return 0;

out_send_resp:
	if (pmemrad_client_send(prc, &resp, sizeof (resp))) {
		log_err("sending response failed");
		/* XXX */
	}

	return ret;
}

static int
pmemrad_client_msg_close(struct pmemrad_client *prc,
	struct pmemra_msg_hdr *hdrp)
{
	ASSERTeq(hdrp->type, PMEMRA_MSG_MAP);
	ASSERTeq(hdrp->size, sizeof (*hdrp));

	pmemrad_client_fabric_close(prc);
	pmemrad_pdb_close(prc->pdb, prc->pool);
	close(prc->sockfd);
	prc->sockfd = -1;
	prc->run = 0;
	return 0;
}

static int
pmemrad_client_msg_create(struct pmemrad_client *prc,
	struct pmemra_msg_hdr *hdrp)
{
	/* XXX */
	return -1;
}

static int
pmemrad_client_msg_remove(struct pmemrad_client *prc,
	struct pmemra_msg_hdr *hdrp)
{
	/* XXX */
	return -1;
}

static msg_handler_t msg_handlers[] = {
	[PMEMRA_MSG_OPEN] = pmemrad_client_msg_open,
	[PMEMRA_MSG_CREATE] = pmemrad_client_msg_create,
	[PMEMRA_MSG_REMOVE] = pmemrad_client_msg_remove,
	[PMEMRA_MSG_CLOSE] = pmemrad_client_msg_close,
	[MAX_PMEMRA_MSG] = NULL,
};

static int
pmemrad_client_handle_msg(struct pmemrad_client *prc,
	struct pmemra_msg_hdr *hdrp)
{
	int ret;

	if (hdrp->type >= MAX_PMEMRA_MSG ||
		!msg_handlers[hdrp->type]) {
		log_err("malformed msg type -- %d\n", hdrp->type);
		return -1;
	}

	log_info("%s: %s", inet_ntoa(prc->sock_addr.sin_addr),
			pmemra_msg_str(hdrp->type));

	ret = msg_handlers[hdrp->type](prc, hdrp);
	if (ret < 0)
		log_err("parsing msg %s\n", pmemra_msg_str(hdrp->type));

	return ret;
}

static int
pmemrad_client_read_persists(struct pmemrad_client *prc)
{
	struct fi_cq_err_entry err;
	struct fi_cq_data_entry entry;
	ssize_t ret;
	while ((ret = fi_cq_read(prc->cq, &entry, 1)) != -FI_EAGAIN) {

		if (ret != 1) {
			log_err("error reading completion queue");
			if (ret == -FI_EAVAIL) {
				fi_cq_readerr(prc->cq, &err, 0);
				log_err("%s", fi_cq_strerror(prc->cq,
					err.prov_errno, NULL, NULL, 0));
			}
			return (int)ret;
		}

		if (entry.flags & FI_SEND) {
			continue;
		}

		struct pmemrad_client_lane *lanep = entry.op_context;

		void *addr = (void *)lanep->rx_persist.addr;
		size_t len = lanep->rx_persist.len;

		ret = fi_recv(lanep->ep, &lanep->rx_persist,
			sizeof (lanep->rx_persist), fi_mr_desc(lanep->rx_mr),
			0, lanep);
		if (ret < 0) {
			log_err("cannot post recv buffer");
			return (int)ret;
		}

		if (lanep->rx_persist.addr < (uintptr_t)prc->pool->addr ||
			lanep->rx_persist.addr + len >
			(uintptr_t)prc->pool->addr + prc->pool->size) {
			log_err("invalid address");
			return -1;
		}

		pmem_persist(addr, len);

		lanep->tx_persist.addr = ~(uint64_t)addr;
		lanep->tx_persist.len = ~(uint64_t)len;

		ret = fi_send(lanep->ep, &lanep->tx_persist,
				sizeof (lanep->tx_persist),
				fi_mr_desc(lanep->tx_mr), 0, lanep);
		if (ret) {
			log_err("!fi_send");
			return (int)ret;
		}

	}

	return 0;
}

static void *
pmemrad_client_thread(void *arg)
{
	ASSERTne(arg, NULL);
	struct pmemrad_client *prc = (struct pmemrad_client *)arg;
	struct pollfd fds = {
		.fd = prc->sockfd,
		.events = POLLIN,
	};

	int ret = -1;
	struct pmemra_msg_hdr *hdrp = malloc(sizeof (*hdrp));
	if (!hdrp) {
		log_err("!malloc");
		return (void *)((uintptr_t)-1);
	}
	while (prc->run) {
		ret = poll(&fds, 1, 100);
		if (ret < 0) {
			log_err("!poll");
			break;
		} else if (ret == 0) {
			if (prc->cq)
				pmemrad_client_read_persists(prc);
			continue;
		}

		ssize_t rret = read(prc->sockfd, hdrp, sizeof (*hdrp));
		if (rret < 0) {
			log_err("!read");
			ret = (int)rret;
			break;
		}

		if (rret == 0) {
			ret = 0;
			break;
		}

		if (rret != sizeof (*hdrp)) {
			/* XXX */
			ret = -1;
			break;
		}

		if (hdrp->size < sizeof (*hdrp)) {
			/* XXX */
			ret = -1;
			break;
		}

		struct pmemra_msg_hdr *new_hdr =
			realloc(hdrp, hdrp->size);
		if (!new_hdr) {
			/* XXX */
			ret = -1;
			break;
		}
		hdrp = new_hdr;

		if (hdrp->size > sizeof (*hdrp)) {
			rret = read(prc->sockfd, hdrp->data,
					hdrp->size - sizeof (*hdrp));
			if (rret < 0) {
				log_err("!read");
				ret = (int)rret;
				break;
			}

			if ((size_t)rret != hdrp->size - sizeof (*hdrp)) {
				/* XXX */
				ret = -1;
				break;
			}
		}

		ret = pmemrad_client_handle_msg(prc, hdrp);
		if (ret) {
			log_err("handle msg");
			break;
		}
	}

	free(hdrp);
	return (void *)((uintptr_t)ret);
}

struct pmemrad_client *
pmemrad_client_create(int sockfd, struct sockaddr_in *addr,
	struct pmemrad_pdb *pdb)
{
	struct pmemrad_client *prc = calloc(1, sizeof (*prc));
	if (!prc) {
		log_err("!client alloc");
		return prc;
	}

	prc->run = 1;
	prc->sockfd = sockfd;
	prc->pdb = pdb;
	memcpy(&prc->sock_addr, addr, sizeof (prc->sock_addr));

	int ret;
	ret = pthread_create(&prc->thread, NULL, pmemrad_client_thread, prc);
	if (ret < 0) {
		log_err("!pthread_create");
		goto err_pthread_create;
	}

	return prc;
err_pthread_create:
	free(prc);
	return NULL;
}

void
pmemrad_client_destroy(struct pmemrad_client *prc)
{
	/* XXX */
	pthread_join(prc->thread, NULL);
	free(prc->lanes);
	free(prc);
}

int
pmemrad_client_is_running(struct pmemrad_client *prc)
{
	return prc->run;
}

void
pmemrad_client_stop(struct pmemrad_client *prc)
{
	/* XXX */
	prc->run = 0;
	pthread_join(prc->thread, NULL);
	pmemrad_client_fabric_close(prc);
	pmemrad_pdb_close(prc->pdb, prc->pool);
	close(prc->sockfd);
	free(prc->lanes);
	free(prc);
}
