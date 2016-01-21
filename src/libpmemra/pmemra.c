/*
 * Copyright (c) 2015-2016, Intel Corporation
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
 * pmemra.c -- XXX
 */

#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

/* XXX */
#include <stdio.h>

#include "libpmemra.h"
#include "pmemra.h"
#include "out.h"

unsigned __thread Lane = UINT_MAX;
unsigned Lane_cur = 0;

struct pmemra_lane {
	struct fid_ep *ep;
	struct fid_cq *cq;
	struct fid_mr *rx_mr;
	struct fid_mr *tx_mr;
	struct pmemra_persist rx_persist;
	struct pmemra_persist tx_persist;
	size_t rd_size;
	void *rd_buff;
	struct fid_mr *rd_mr;
};

struct pmemra {
	int sockfd;
	struct sockaddr_in sock_addr;
	void *msg_buff;
	char *poolset_name;
	char *host_name;
	void *addr;
	size_t size;
	int raw;
	uint64_t rkey;
	uint64_t raddr;
	struct sockaddr_in fabric_addr;
	struct fi_info *fi;
	struct fid_fabric *fabric;
	struct fid_eq *eq;
	struct fid_domain *domain;
	struct fid_mr *mr;
	unsigned nlanes;
	struct pmemra_lane *lanes;
	int cq_timeout;	/* timeout value for fi_cq_sread() */
};

static void
pmemra_default_attr(struct pmemra_attr *attr)
{
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus < 1)
		ncpus = 1;

	attr->nlanes = (unsigned)ncpus * PMEMRA_DEF_NLANES_MUL;
	attr->cq_timeout = PMEMRA_DEF_CQ_TIMEOUT;
}

static int
pmemra_connect(PMEMrapool *prp, const char *hostname)
{
	struct hostent *server;

	server = gethostbyname(hostname);
	if (!server) {
		ERR("!gethostbyname");
		return -1;
	}

	prp->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (prp->sockfd < 0) {
		ERR("!openning socket");
		return -1;
	}

	int ret;

	memset(&prp->sock_addr, 0, sizeof (prp->sock_addr));
	prp->sock_addr.sin_family = AF_INET;
	prp->sock_addr.sin_port = htons(PMEMRA_PORT);
	memcpy(&prp->sock_addr.sin_addr.s_addr, server->h_addr,
			(size_t)server->h_length);

	ret = connect(prp->sockfd, (struct sockaddr *)&prp->sock_addr,
			sizeof (prp->sock_addr));
	if (ret < 0) {
		ERR("!connect");
		goto err_close_socket;
	}

	return 0;
err_close_socket:
	close(prp->sockfd);

	return ret;
}

static void
pmemra_close_connection(PMEMrapool *prp)
{
	close(prp->sockfd);
}

static int
pmemra_msg_send(PMEMrapool *prp, void *msg_buff, size_t msg_len)
{
	ssize_t ret;
	ret = write(prp->sockfd, msg_buff, msg_len);
	if (ret < 0) {
		ERR("!write");
		return (int)ret;
	}

	if ((size_t)ret != msg_len) {
		ERR("cannot send a message");
		return -1;
	}

	return 0;
}

static int
pmemra_msg_recv(PMEMrapool *prp, void *msg_buff, size_t msg_len)
{
	ssize_t ret;
	struct pmemra_msg_hdr *hdrp = (struct pmemra_msg_hdr *)msg_buff;
	ret = read(prp->sockfd, hdrp, sizeof (*hdrp));
	if (ret < 0) {
		ERR("!read");
		return (int)ret;
	}

	if ((size_t)ret != sizeof (*hdrp)) {
		ERR("malformed message");
		return -1;
	}

	if (msg_len != hdrp->size) {
		ERR("invalid message length");
		return -1;
	}

	ret = read(prp->sockfd, hdrp->data, hdrp->size - sizeof (*hdrp));
	if (ret < 0) {
		ERR("!read");
		return -1;
	}

	if ((size_t)ret != hdrp->size - sizeof (*hdrp)) {
		ERR("malformed message");
		return -1;
	}

	return 0;
}

static int
pmemra_fabric_init_lane(PMEMrapool *prp, size_t lane)
{
	int ret;
	struct fi_eq_cm_entry entry;
	uint32_t event;
	struct pmemra_lane *lanep = &prp->lanes[lane];
	struct fi_cq_attr cq_attr = {
		.size = 0,
		.flags = 0,
		.format = FI_CQ_FORMAT_CONTEXT,
		.wait_obj = FI_WAIT_UNSPEC,
		.signaling_vector = 0,
		.wait_cond = FI_CQ_COND_NONE,
		.wait_set = NULL,
	};
	lanep->rd_size = PMEMRA_DEF_READ_SIZE;
	lanep->rd_buff = malloc(lanep->rd_size);
	if (!lanep->rd_buff) {
		ERR("cannot allocate read buffer");
		ret = -1;
		goto err_malloc_rd_buff;
	}

	ret = fi_cq_open(prp->domain, &cq_attr, &lanep->cq, NULL);
	if (ret) {
		ERR("cannot open cq");
		goto err_fi_cq_open;
	}

	ret = fi_endpoint(prp->domain, prp->fi, &lanep->ep, NULL);
	if (ret) {
		ERR("cannot open endpoint");
		goto err_fi_endpoint;
	}

	ret = fi_mr_reg(prp->domain, &lanep->tx_persist,
			sizeof (lanep->tx_persist),
			FI_SEND, 0, 0, 0, &lanep->tx_mr, NULL);
	if (ret) {
		ERR("cannot register persistent memory");
		goto err_fi_mr_reg_tx;
	}

	ret = fi_mr_reg(prp->domain, &lanep->rx_persist,
			sizeof (lanep->rx_persist),
			FI_RECV, 0, 0, 0, &lanep->rx_mr, NULL);
	if (ret) {
		ERR("cannot register persistent memory");
		goto err_fi_mr_reg_rx;
	}

	ret = fi_mr_reg(prp->domain, lanep->rd_buff,
			lanep->rd_size, FI_RECV, 0, 0, 0,
			&lanep->rd_mr, NULL);
	if (ret) {
		ERR("cannot register read buffer");
		goto err_fi_mr_reg_rd;
	}


	ret = fi_ep_bind(lanep->ep, &prp->eq->fid, 0);
	if (ret) {
		ERR("cannot bind event queue");
		goto err_fi_ep_bind_eq;
	}

	ret = fi_ep_bind(lanep->ep, &lanep->cq->fid, FI_TRANSMIT | FI_RECV);
	if (ret) {
		ERR("cannot bind cq");
		goto err_fi_ep_bind_cq;
	}

	ret = fi_enable(lanep->ep);
	if (ret) {
		ERR("cannot enable ep");
		goto err_fi_enable;
	}

	ret = fi_connect(lanep->ep, prp->fi->dest_addr, NULL, 0);
	if (ret) {
		ERR("cannot connect");
		goto err_fi_connect;
	}

	ssize_t rret = fi_eq_sread(prp->eq, &event, &entry,
				sizeof (entry), -1, 0);
	if ((size_t)rret != sizeof (entry)) {
		ERR("cannot eq sread ");
		goto err_fi_eq_sread;
	}

	if (event != FI_CONNECTED ||
		entry.fid != &lanep->ep->fid) {
		ERR("unexpected event");
		goto err_unexp_event;
	}

	return 0;
err_unexp_event:
err_fi_eq_sread:
err_fi_connect:
err_fi_enable:
err_fi_ep_bind_cq:
err_fi_ep_bind_eq:
	fi_close(&lanep->rd_mr->fid);
err_fi_mr_reg_rd:
	fi_close(&lanep->rx_mr->fid);
err_fi_mr_reg_rx:
	fi_close(&lanep->tx_mr->fid);
err_fi_mr_reg_tx:
	fi_close(&lanep->ep->fid);
err_fi_endpoint:
	fi_close(&lanep->cq->fid);
err_fi_cq_open:
	free(lanep->rd_buff);
err_malloc_rd_buff:
	return ret;
}

static void
pmemra_fabric_deinit_lane(PMEMrapool *prp, size_t lane)
{
	struct pmemra_lane *lanep = &prp->lanes[lane];
	fi_shutdown(lanep->ep, 0);
	fi_close(&lanep->tx_mr->fid);
	fi_close(&lanep->rx_mr->fid);
	fi_close(&lanep->ep->fid);
	fi_close(&lanep->cq->fid);
}

static int
pmemra_fabric_init(PMEMrapool *prp, unsigned short port)
{
	int ret;

	struct fi_info *hints = fi_allocinfo();
	if (!hints) {
		ERR("cannot alloc fi_info for hints");
		return -1;
	}

	memcpy(&prp->fabric_addr, &prp->sock_addr, sizeof (prp->fabric_addr));
	prp->fabric_addr.sin_port = htons(port);

	hints->addr_format = FI_SOCKADDR_IN;
	hints->dest_addrlen = sizeof (prp->fabric_addr);
	hints->dest_addr = malloc(hints->dest_addrlen);
	if (!hints->dest_addr) {
		ERR("!cannot alloc dest addr");
		ret = -1;
		goto err_alloc_dest_addr;
	}
	memcpy(hints->dest_addr, &prp->fabric_addr, hints->dest_addrlen);

	hints->ep_attr->type = FI_EP_MSG;
	hints->domain_attr->mr_mode = FI_MR_BASIC;
	hints->caps = FI_MSG | FI_RMA;
	hints->mode = FI_CONTEXT | FI_LOCAL_MR | FI_RX_CQ_DATA;

	ret = fi_getinfo(PMEMRA_FIVERSION, NULL, NULL, 0, hints, &prp->fi);
	if (ret) {
		ERR("!fi_getinfo");
		goto err_fi_getinfo;
	}

	ret = fi_fabric(prp->fi->fabric_attr, &prp->fabric, NULL);
	if (ret) {
		ERR("cannot get fabric");
		goto err_fi_fabric;
	}

	struct fi_eq_attr eq_attr = {
		.size = 16,
		.flags = 0,
		.wait_obj = FI_WAIT_UNSPEC,
		.signaling_vector = 0,
		.wait_set = NULL,
	};

	ret = fi_eq_open(prp->fabric, &eq_attr, &prp->eq, NULL);
	if (ret) {
		ERR("cannot open event queue");
		goto err_fi_eq_open;
	}

	ret = fi_domain(prp->fabric, prp->fi, &prp->domain, NULL);
	if (ret) {
		ERR("cannot access domain");
		goto err_fi_domain;
	}

	/* XXX should be FI_READ instead of FI_REMOTE_WRITE ? */
	ret = fi_mr_reg(prp->domain, prp->addr, prp->size,
			FI_REMOTE_WRITE | FI_WRITE,
			0, 0, 0, &prp->mr, NULL);
	if (ret) {
		ERR("cannot register memory");
		goto err_fi_mr_reg;
	}

	size_t lane;
	for (lane = 0; lane < prp->nlanes; lane++) {
		ret = pmemra_fabric_init_lane(prp, lane);
		if (ret) {
			ERR("cannot init lane %lu", lane);
			goto err_fabric_init_lane;
		}
	}

	fi_freeinfo(hints);
	return 0;
err_fabric_init_lane:
	for (size_t i = 0; i < lane; i++)
		pmemra_fabric_deinit_lane(prp, lane);
	fi_close(&prp->mr->fid);
err_fi_mr_reg:
	fi_close(&prp->domain->fid);
err_fi_domain:
	fi_close(&prp->eq->fid);
err_fi_eq_open:
	fi_close(&prp->fabric->fid);
err_fi_fabric:
	fi_freeinfo(prp->fi);
err_fi_getinfo:
err_alloc_dest_addr:
	fi_freeinfo(hints);
	return ret;
}

static void
pmemra_fabric_deinit(PMEMrapool *prp)
{
	for (size_t lane = 0; lane < prp->nlanes; lane++)
		pmemra_fabric_deinit_lane(prp, lane);
	fi_close(&prp->domain->fid);
	fi_close(&prp->eq->fid);
	fi_close(&prp->fabric->fid);
	fi_freeinfo(prp->fi);
}

int
pmemra_remove(const char *hostname, const char *poolset_name)
{
	PMEMrapool *prp = calloc(1, sizeof (*prp));
	if (!prp) {
		ERR("!cannot allocate context");
		return -1;
	}

	prp->poolset_name = strdup(poolset_name);
	if (!prp->poolset_name)
		goto err_poolset_name;

	int ret;
	ret = pmemra_connect(prp, hostname);
	if (ret)
		goto err_connect;

	size_t poolset_len = strlen(prp->poolset_name) + 1;
	size_t msg_len = sizeof (struct pmemra_msg_remove) + poolset_len;
	struct pmemra_msg_remove *msg = malloc(msg_len);
	if (!msg) {
		ERR("!msg alloc");
		goto err_msg_alloc;
	}

	if (msg_len > UINT32_MAX) {
		ERR("invalid message length");
		goto err_msg_alloc;
	}

	msg->hdr.type = PMEMRA_MSG_REMOVE;
	msg->hdr.size = (uint32_t)msg_len;
	msg->poolset_len = (uint32_t)poolset_len;
	memcpy(msg->data, prp->poolset_name, poolset_len);

	ret = pmemra_msg_send(prp, msg, msg_len);
	if (ret) {
		ERR("send msg failed");
		goto err_msg_send;
	}

	struct pmemra_msg_remove_resp resp;
	ret = pmemra_msg_recv(prp, &resp, sizeof (resp));
	if (ret) {
		ERR("recv msg failed");
		goto err_msg_recv;
	}

	errno = (int)resp.status;

	free(msg);
	free(prp->poolset_name);
	free(prp);
	if (resp.status)
		return -1;
	return 0;
err_msg_recv:
err_msg_send:
	free(msg);
err_msg_alloc:
	pmemra_close_connection(prp);
err_connect:
	free(prp->poolset_name);
err_poolset_name:
	free(prp);
	return -1;
}

PMEMrapool *
pmemra_create(const char *hostname, const char *poolset_name,
		void *addr, size_t size, struct pmemra_attr *attr)
{
	LOG(3, "hostname %s poolset %s addr %p size %zu",
		hostname, poolset_name, addr, size);

	if (!attr) {
		errno = EFAULT;
		return NULL;
	}

	PMEMrapool *prp = calloc(1, sizeof (*prp));
	if (!prp) {
		ERR("!cannot allocate context");
		return NULL;
	}

	struct pmemra_attr def_attr;
	pmemra_default_attr(&def_attr);

	prp->nlanes = attr->nlanes ? attr->nlanes : def_attr.nlanes;
	prp->cq_timeout = attr->cq_timeout ? attr->cq_timeout :
		def_attr.cq_timeout;

	prp->addr = addr;
	prp->size = size;
	prp->poolset_name = strdup(poolset_name);
	if (!prp->poolset_name)
		goto err_poolset_name;

	int ret;
	ret = pmemra_connect(prp, hostname);
	if (ret)
		goto err_connect;

	size_t poolset_len = strlen(prp->poolset_name) + 1;
	size_t msg_len = sizeof (struct pmemra_msg_open) + poolset_len;
	struct pmemra_msg_open *msg = malloc(msg_len);
	if (!msg) {
		ERR("!msg alloc");
		goto err_msg_alloc;
	}

	if (msg_len > UINT32_MAX) {
		ERR("invalid message length");
		goto err_msg_alloc;
	}

	msg->hdr.type = PMEMRA_MSG_CREATE;
	msg->hdr.size = (uint32_t)msg_len;
	msg->mem_size = size;
	msg->fname_len = 0;
	msg->poolset_len = (uint32_t)poolset_len;
	msg->nlanes = prp->nlanes;
	memcpy(&msg->pool_attr, &attr->pool_attr, sizeof (msg->pool_attr));
	memcpy(msg->data, prp->poolset_name, poolset_len);

	ret = pmemra_msg_send(prp, msg, msg_len);
	if (ret) {
		ERR("send msg failed");
		goto err_msg_send;
	}

	struct pmemra_msg_open_resp resp;
	ret = pmemra_msg_recv(prp, &resp, sizeof (resp));
	if (ret) {
		ERR("recv msg failed");
		goto err_msg_recv;
	}

	LOG(1, "status %s port %d rkey 0x%jx nlanes %d raw %d",
		pmemra_err_str(resp.status),
		resp.port, resp.rkey, resp.nlanes, resp.raw);

	if (resp.status != PMEMRA_ERR_SUCCESS) {
		errno = (int)resp.status;
		goto err_resp;
	}

	memcpy(&attr->pool_attr, &resp.pool_attr, sizeof (msg->pool_attr));
	prp->nlanes = resp.nlanes;
	prp->rkey = resp.rkey;
	prp->raddr = resp.addr;
	prp->raw = resp.raw;

	prp->lanes = calloc(prp->nlanes, sizeof (*prp->lanes));
	if (!prp->lanes) {
		ERR("!cannot allocate lanes");
		goto err_alloc_lanes;
	}

	ret = pmemra_fabric_init(prp, (unsigned short)resp.port);
	if (ret) {
		ERR("fabric init");
		goto err_fabric_init;
	}

	LOG(1, "connected");
	free(msg);
	return prp;
err_fabric_init:
	free(prp->lanes);
err_alloc_lanes:
err_resp:
err_msg_recv:
err_msg_send:
	free(msg);
err_msg_alloc:
	pmemra_close_connection(prp);
err_connect:
	free(prp->poolset_name);
err_poolset_name:
	free(prp);
	return NULL;
}

PMEMrapool *
pmemra_open(const char *hostname, const char *poolset_name,
	void *addr, size_t size, struct pmemra_attr *attr)
{
	LOG(3, "hostname %s poolset %s addr %p size %zu",
		hostname, poolset_name, addr, size);

	PMEMrapool *prp = calloc(1, sizeof (*prp));
	if (!prp) {
		ERR("!cannot allocate context");
		return NULL;
	}

	struct pmemra_attr def_attr;
	pmemra_default_attr(&def_attr);

	if (!attr) {
		prp->nlanes = def_attr.nlanes;
		prp->cq_timeout = def_attr.cq_timeout;
	} else {
		prp->nlanes = attr->nlanes ? attr->nlanes : def_attr.nlanes;
		prp->cq_timeout = attr->cq_timeout ? attr->cq_timeout :
					def_attr.cq_timeout;
	}

	prp->addr = addr;
	prp->size = size;
	prp->poolset_name = strdup(poolset_name);
	if (!prp->poolset_name)
		goto err_poolset_name;

	int ret;
	ret = pmemra_connect(prp, hostname);
	if (ret)
		goto err_connect;

	size_t poolset_len = strlen(prp->poolset_name) + 1;
	size_t msg_len = sizeof (struct pmemra_msg_open) + poolset_len;
	struct pmemra_msg_open *msg = malloc(msg_len);
	if (!msg) {
		ERR("!msg alloc");
		goto err_msg_alloc;
	}

	if (msg_len > UINT32_MAX) {
		ERR("invalid message length");
		goto err_msg_alloc;
	}

	msg->hdr.type = PMEMRA_MSG_OPEN;
	msg->hdr.size = (uint32_t)msg_len;
	msg->mem_size = size;
	msg->fname_len = 0;
	msg->poolset_len = (uint32_t)poolset_len;
	msg->nlanes = prp->nlanes;
	memcpy(msg->data, prp->poolset_name, poolset_len);

	ret = pmemra_msg_send(prp, msg, msg_len);
	if (ret) {
		ERR("send msg failed");
		goto err_msg_send;
	}

	struct pmemra_msg_open_resp resp;
	ret = pmemra_msg_recv(prp, &resp, sizeof (resp));
	if (ret) {
		ERR("recv msg failed");
		goto err_msg_recv;
	}

	LOG(1, "status %s port %d rkey 0x%jx nlanes %d raw %d",
		pmemra_err_str(resp.status),
		resp.port, resp.rkey, resp.nlanes, resp.raw);

	if (resp.status != PMEMRA_ERR_SUCCESS) {
		errno = (int)resp.status;
		goto err_resp;
	}

	prp->nlanes = resp.nlanes;
	prp->rkey = resp.rkey;
	prp->raddr = resp.addr;
	prp->raw = resp.raw;

	prp->lanes = calloc(prp->nlanes, sizeof (*prp->lanes));
	if (!prp->lanes) {
		ERR("!cannot allocate lanes");
		goto err_alloc_lanes;
	}

	ret = pmemra_fabric_init(prp, (unsigned short)resp.port);
	if (ret) {
		ERR("fabric init");
		goto err_fabric_init;
	}

	LOG(1, "connected");
	free(msg);
	return prp;
err_fabric_init:
	free(prp->lanes);
err_alloc_lanes:
err_resp:
err_msg_recv:
err_msg_send:
	free(msg);
err_msg_alloc:
	pmemra_close_connection(prp);
err_connect:
	free(prp->poolset_name);
err_poolset_name:
	free(prp);
	return NULL;
}

void
pmemra_close(PMEMrapool *prp)
{
	LOG(3, "prp %p", prp);

	struct pmemra_msg_hdr msg = {
		.type = PMEMRA_MSG_CLOSE,
		.size = sizeof (struct pmemra_msg_hdr),
	};
	int ret;
	ret = pmemra_msg_send(prp, &msg, sizeof (msg));
	if (ret)
		ERR("!pmemra_msg_send");

	pmemra_fabric_deinit(prp);
	pmemra_close_connection(prp);
	free(prp->poolset_name);
	free(prp);
}

ssize_t
pmemra_read(PMEMrapool *prp, void *buff, size_t len, size_t offset)
{
	LOG(3, "prp %p buff %p len %zu offset %zu", prp, buff, len, offset);

	if (Lane == UINT_MAX)
		Lane = __sync_fetch_and_add(&Lane_cur, 1) % prp->nlanes;

	struct pmemra_lane *lanep = &prp->lanes[Lane];
	struct fi_cq_entry comp;
	struct fi_cq_err_entry err;
	struct fi_eq_entry eq_entry;
	const char *err_str;
	uint32_t event;
	ssize_t ret;

	while (len) {
		size_t rd_len = len > lanep->rd_size ? lanep->rd_size : len;
		lanep->tx_persist.addr = prp->raddr + offset;
		lanep->tx_persist.len = rd_len | PMEMRA_READ;

		ret = fi_recv(lanep->ep, lanep->rd_buff, rd_len,
				fi_mr_desc(lanep->rd_mr), 0, NULL);
		if (ret) {
			ERR("!fi_recv");
			goto err_read_event;
		}

		ret = fi_send(lanep->ep, &lanep->tx_persist,
			sizeof (lanep->tx_persist), fi_mr_desc(lanep->tx_mr),
			0, NULL);
		if (ret) {
			ERR("!fi_send");
			goto err_read_event;
		}

		ret = fi_cq_sread(lanep->cq, &comp, 1, NULL, prp->cq_timeout);
		if (ret != 1) {
			err_str = "send";
			goto err_fi_cq_sread;
		}

		ret = fi_cq_sread(lanep->cq, &comp, 1, NULL, prp->cq_timeout);
		if (ret != 1) {
			err_str = "recv";
			goto err_fi_cq_sread;
		}

		memcpy(buff, lanep->rd_buff, rd_len);
		buff = (void *)((uintptr_t)buff + rd_len);
		len -= rd_len;
		offset += rd_len;
	}

	return (ssize_t)len;
err_fi_cq_sread:
	if (ret == -FI_EAGAIN)
		ERR("%s fi_cq_sread: timeout (%i ms)!",
			err_str, prp->cq_timeout);
	if (fi_cq_readerr(lanep->cq, &err, 0) > 0)
		ERR("%s fi_cq_sread: %ld %s", err_str, ret,
			fi_cq_strerror(lanep->cq, err.prov_errno,
					err.err_data, NULL, 0));
err_read_event:
	if (fi_eq_read(prp->eq, &event, &eq_entry, sizeof (eq_entry), 0) > 0)
		ERR("event occured: %s", pmemra_event_str(event));

	return (int)ret;
}

int
pmemra_persist(PMEMrapool *prp, void *buff, size_t len)
{
	LOG(3, "prp %p buff %p len %zu", prp, buff, len);

	if (Lane == UINT_MAX)
		Lane = __sync_fetch_and_add(&Lane_cur, 1) % prp->nlanes;

	return pmemra_persist_lane(prp, buff, len, Lane);
}

static int
pmemra_fabric_persist_raw(PMEMrapool *prp, void *buff, size_t len,
	uint64_t addr, struct pmemra_lane *lanep)
{
	struct fi_cq_entry comp;
	ssize_t ret;
	struct fi_cq_err_entry err;
	const char *err_str;
	struct fi_eq_entry eq_entry;
	uint32_t event;

	ret = fi_read(lanep->ep, buff, 1, fi_mr_desc(prp->mr), 0,
			addr, prp->rkey, NULL);
	if (ret) {
		ERR("!fi_read");
		goto err_read_event;
	}

	ret = fi_cq_sread(lanep->cq, &comp, 1, NULL, prp->cq_timeout);
	if (ret != 1) {
		err_str = "read";
		goto err_fi_cq_sread;
	}


	return 0;

err_fi_cq_sread:
	if (ret == -FI_EAGAIN)
		ERR("%s fi_cq_sread: timeout (%i ms)!",
			err_str, prp->cq_timeout);
	if (fi_cq_readerr(lanep->cq, &err, 0) > 0)
		ERR("%s fi_cq_sread: %ld %s", err_str, ret,
			fi_cq_strerror(lanep->cq, err.prov_errno,
					err.err_data, NULL, 0));

err_read_event:
	if (fi_eq_read(prp->eq, &event, &eq_entry, sizeof (eq_entry), 0) > 0)
		ERR("event occured: %s", pmemra_event_str(event));

	return (int)ret;
}

static int
pmemra_fabric_persist_saw(PMEMrapool *prp, void *buff, size_t len,
	uint64_t addr, struct pmemra_lane *lanep)
{
	struct fi_cq_entry comp;
	ssize_t ret;
	struct fi_cq_err_entry err;
	const char *err_str;
	struct fi_eq_entry eq_entry;
	uint32_t event;

	lanep->tx_persist.addr = addr;
	lanep->tx_persist.len = len;

	ret = fi_recv(lanep->ep, &lanep->rx_persist, sizeof (lanep->rx_persist),
			fi_mr_desc(lanep->rx_mr), 0, NULL);
	if (ret) {
		ERR("!fi_recv");
		goto err_read_event;
	}

	ret = fi_send(lanep->ep, &lanep->tx_persist, sizeof (lanep->tx_persist),
			fi_mr_desc(lanep->tx_mr), 0, NULL);
	if (ret) {
		ERR("!fi_send");
		goto err_read_event;
	}

	ret = fi_cq_sread(lanep->cq, &comp, 1, NULL, prp->cq_timeout);
	if (ret != 1) {
		err_str = "send";
		goto err_fi_cq_sread;
	}

	ret = fi_cq_sread(lanep->cq, &comp, 1, NULL, prp->cq_timeout);
	if (ret != 1) {
		err_str = "recv";
		goto err_fi_cq_sread;
	}

	if (lanep->rx_persist.addr != ~addr ||
		lanep->rx_persist.len != ~len) {
		ERR("invalid response");
		return -1;
	}

	return 0;
err_fi_cq_sread:
	if (ret == -FI_EAGAIN)
		ERR("%s fi_cq_sread: timeout (%i ms)!",
			err_str, prp->cq_timeout);
	if (fi_cq_readerr(lanep->cq, &err, 0) > 0)
		ERR("%s fi_cq_sread: %ld %s", err_str, ret,
			fi_cq_strerror(lanep->cq, err.prov_errno,
					err.err_data, NULL, 0));

err_read_event:
	if (fi_eq_read(prp->eq, &event, &eq_entry, sizeof (eq_entry), 0) > 0)
		ERR("event occured: %s", pmemra_event_str(event));

	return (int)ret;
}

static int
pmemra_fabric_write(PMEMrapool *prp, void *buff, size_t len,
	uint64_t addr, unsigned lane)
{
	struct fi_cq_entry comp;
	ssize_t ret;
	struct pmemra_lane *lanep = &prp->lanes[lane];
	struct fi_cq_err_entry err;
	const char *err_str;
	struct fi_eq_entry eq_entry;
	uint32_t event;

	ret = fi_write(lanep->ep, buff, len, fi_mr_desc(prp->mr), 0,
			addr, prp->rkey, NULL);
	if (ret) {
		ERR("!fi_write");
		goto err_read_event;
	}

	ret = fi_cq_sread(lanep->cq, &comp, 1, NULL, prp->cq_timeout);
	if (ret != 1) {
		err_str = "write";
		goto err_fi_cq_sread;
	}


	return prp->raw ?
		pmemra_fabric_persist_raw(prp, buff, len, addr, lanep):
		pmemra_fabric_persist_saw(prp, buff, len, addr, lanep);

err_fi_cq_sread:
	if (ret == -FI_EAGAIN)
		ERR("%s fi_cq_sread: timeout (%i ms)!",
			err_str, prp->cq_timeout);
	if (fi_cq_readerr(lanep->cq, &err, 0) > 0)
		ERR("%s fi_cq_sread: %ld %s", err_str, ret,
			fi_cq_strerror(lanep->cq, err.prov_errno,
					err.err_data, NULL, 0));

err_read_event:
	if (fi_eq_read(prp->eq, &event, &eq_entry, sizeof (eq_entry), 0) > 0)
		ERR("event occured: %s", pmemra_event_str(event));

	return (int)ret;
}

int
pmemra_persist_lane(PMEMrapool *prp, void *buff, size_t len, unsigned lane)
{
	LOG(3, "prp %p buff %p len %zu lane %u", prp, buff, len, lane);

	if (lane >= prp->nlanes)
		return -1;

	uint64_t laddr = (uint64_t)prp->addr;
	uint64_t baddr = (uint64_t)buff;

	if (baddr < laddr || baddr + len > laddr + prp->size) {
		ERR("invalid address");
		return -1;
	}

	uint64_t offset = baddr - laddr;
	uint64_t addr = prp->raddr + offset;

	return pmemra_fabric_write(prp, buff, len, addr, lane);
}
