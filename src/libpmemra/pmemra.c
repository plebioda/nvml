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
 * pmemra.c -- XXX
 */

#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>

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
};

struct pmemra {
	int sockfd;
	struct sockaddr_in sock_addr;
	void *msg_buff;
	char *poolset_name;
	char *host_name;
	void *addr;
	size_t size;
	uint64_t rkey;
	uint64_t raddr;
	struct sockaddr_in fabric_addr;
	struct fi_info *fi;
	struct fid_fabric *fabric;
	struct fid_eq *eq;
	struct fi_eq_attr eq_attr;
	struct fid_domain *domain;
	struct fi_cq_attr cq_attr;
	struct fid_mr *mr;
	size_t nlanes;
	struct pmemra_lane *lanes;
};

static void
pmemra_default_attr(PMEMraattr *attr)
{
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus < 1)
		ncpus = 1;

	attr->nlanes = ncpus * PMEMRA_DEF_NLANES_MUL;
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
		ERR("malformed message");
		return -1;
	}

	if ((size_t)ret != hdrp->size - sizeof (*hdrp)) {
		ERR("malformed message");
		return -1;
	}

	return 0;
}

static int
pmemra_fabric_init(PMEMrapool *prp, unsigned short port)
{
	struct fi_eq_cm_entry entry;
	uint32_t event;
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

	ret = fi_eq_open(prp->fabric, &prp->eq_attr, &prp->eq, NULL);
	if (ret) {
		ERR("cannot open event queue");
		goto err_fi_eq_open;
	}

	ret = fi_domain(prp->fabric, prp->fi, &prp->domain, NULL);
	if (ret) {
		ERR("cannot access domain");
		goto err_fi_domain;
	}

	prp->cq_attr.size = prp->fi->tx_attr->size;
	prp->cq_attr.flags = 0;
	prp->cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	prp->cq_attr.wait_obj = FI_WAIT_NONE;
	prp->cq_attr.signaling_vector = 0;
	prp->cq_attr.wait_cond = FI_CQ_COND_NONE;
	prp->cq_attr.wait_set = NULL;

	ret = fi_mr_reg(prp->domain, prp->addr, prp->size, FI_WRITE,
			0, 0, 0, &prp->mr, NULL);
	if (ret) {
		ERR("cannot register memory");
		goto err_fi_mr_reg;
	}

	size_t lane;
	for (lane = 0; lane < prp->nlanes; lane++) {
		ret = fi_cq_open(prp->domain, &prp->cq_attr,
				&prp->lanes[lane].cq, NULL);
		if (ret) {
			ERR("cannot open cq");
			goto err_fi_cq_open;
		}
	}

	for (lane = 0; lane < prp->nlanes; lane++) {
		ret = fi_endpoint(prp->domain, prp->fi,
				&prp->lanes[lane].ep, NULL);
		if (ret) {
			ERR("cannot open endpoint");
			goto err_fi_endpoint;
		}
	}

	for (lane = 0; lane < prp->nlanes; lane++) {
		ret = fi_ep_bind(prp->lanes[lane].ep,
				&prp->eq->fid, 0);
		if (ret) {
			ERR("cannot bind event queue");
			goto err_fi_bind_eq;
		}
	}

	for (lane = 0; lane < prp->nlanes; lane++) {
		ret = fi_ep_bind(prp->lanes[lane].ep,
				&prp->lanes[lane].cq->fid, FI_TRANSMIT);
		if (ret) {
			ERR("cannot bind cq");
			goto err_fi_bind_cq;
		}
	}

	for (lane = 0; lane < prp->nlanes; lane++) {
		ret = fi_enable(prp->lanes[lane].ep);
		if (ret) {
			ERR("cannot enable ep");
			goto err_fi_enable;
		}
	}

	for (lane = 0; lane < prp->nlanes; lane++) {
		ret = fi_connect(prp->lanes[lane].ep,
				prp->fi->dest_addr, NULL, 0);
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
			entry.fid != &prp->lanes[lane].ep->fid) {
			ERR("unexpected event");
			goto err_unexp_event;
		}
	}

	fi_freeinfo(hints);
	return 0;
err_unexp_event:
err_fi_eq_sread:
	for (size_t i = 0; i < lane; i++)
		fi_shutdown(prp->lanes[i].ep, 0);
err_fi_connect:
err_fi_enable:
err_fi_bind_cq:
err_fi_bind_eq:
	lane = prp->nlanes;
err_fi_endpoint:
	for (size_t i = 0; i < lane; i++)
		fi_close(&prp->lanes[i].ep->fid);
	lane = prp->nlanes;
err_fi_cq_open:
	for (size_t i = 0; i < lane; i++)
		fi_close(&prp->lanes[i].cq->fid);
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
	for (size_t lane = 0; lane < prp->nlanes; lane++) {
		fi_shutdown(prp->lanes[lane].ep, 0);
		fi_close(&prp->lanes[lane].ep->fid);
		fi_close(&prp->lanes[lane].cq->fid);
	}
	fi_close(&prp->domain->fid);
	fi_close(&prp->eq->fid);
	fi_close(&prp->fabric->fid);
	fi_freeinfo(prp->fi);
}

PMEMrapool *
pmemra_map(const char *hostname, const char *poolset_name,
	void *addr, size_t size, PMEMraattr *attr)
{
	PMEMrapool *prp = calloc(1, sizeof (*prp));
	if (!prp) {
		ERR("!cannot allocate context");
		return NULL;
	}

	if (!attr) {
		PMEMraattr def_attr;
		pmemra_default_attr(&def_attr);
		prp->nlanes = def_attr.nlanes;
	} else {
		prp->nlanes = attr->nlanes;
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
	size_t msg_len = sizeof (struct pmemra_msg_map) + poolset_len;
	struct pmemra_msg_map *msg = malloc(msg_len);
	if (!msg) {
		ERR("!msg alloc");
		goto err_msg_alloc;
	}

	msg->hdr.type = PMEMRA_MSG_MAP;
	msg->hdr.size = msg_len;
	msg->mem_size = size;
	msg->fname_len = 0;
	msg->poolset_len = poolset_len;
	msg->nlanes = prp->nlanes;
	memcpy(msg->data, prp->poolset_name, poolset_len);

	ret = pmemra_msg_send(prp, msg, msg_len);
	if (ret) {
		ERR("send msg failed");
		goto err_msg_send;
	}

	struct pmemra_msg_map_resp resp;
	ret = pmemra_msg_recv(prp, &resp, sizeof (resp));
	if (ret) {
		ERR("recv msg failed");
		goto err_msg_recv;
	}

	printf("status %s port %d rkey 0x%jx nlanes %d\n",
		pmemra_err_str(resp.status),
		resp.port, resp.rkey, resp.nlanes);

	prp->nlanes = resp.nlanes;
	prp->rkey = resp.rkey;
	prp->raddr = resp.addr;

	prp->lanes = calloc(prp->nlanes, sizeof (*prp->lanes));
	if (!prp->lanes) {
		ERR("!cannot allocate lanes");
		goto err_alloc_lanes;
	}

	ret = pmemra_fabric_init(prp, resp.port);
	if (ret) {
		ERR("fabric init");
		goto err_fabric_init;
	}

	LOG(1, "connected\n");
	free(msg);
	return prp;
err_fabric_init:
	free(prp->lanes);
err_alloc_lanes:
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
pmemra_unmap(PMEMrapool *prp)
{
	struct pmemra_msg_hdr msg = {
		.type = PMEMRA_MSG_UNMAP,
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

int
pmemra_persist(PMEMrapool *prp, void *buff, size_t len)
{
	if (Lane == UINT_MAX)
		Lane = __sync_fetch_and_add(&Lane_cur, 1) % prp->nlanes;

	return pmemra_persist_lane(prp, buff, len, Lane);
}

static int
pmemra_fabric_write(PMEMrapool *prp, const void *buff, size_t len,
	uint64_t addr, unsigned lane)
{
	struct fi_cq_err_entry comp;
	ssize_t ret;

	ret = fi_write(prp->lanes[lane].ep, buff, len, NULL, 0,
			addr, prp->rkey, NULL);
	if (ret) {
		ERR("!fi_write failed");
		return (int)ret;
	}

	ret = fi_cq_sread(prp->lanes[lane].cq, &comp, 1, NULL, -1);
	if (ret != 1) {
		ERR("!fi_cq_sread");
		return (int)ret;
	}

	return 0;
}

int
pmemra_persist_lane(PMEMrapool *prp, void *buff, size_t len, unsigned lane)
{
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

	int ret = pmemra_fabric_write(prp, buff, len, addr, lane);
	if (ret)
		return ret;

	/* XXX durability */
	return 0;
}
