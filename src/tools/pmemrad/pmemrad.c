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
 * pmemrad.c -- XXX
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* local includes */
#include "util.h"
#include "pmemra.h"
#include "pmemrad.h"
#include "pmemrad_opts.h"
#include "pmemrad_client.h"
#include "pmemrad_pool_db.h"

struct pmemrad_client_entry {
	TAILQ_ENTRY(pmemrad_client_entry) next;
	struct pmemrad_client *client;
};

struct pmemrad {
	struct pmemrad_opts opts;
	int sockfd;
	struct pmemrad_pdb *pdb;
	TAILQ_HEAD(pmemrad_client_head, pmemrad_client_entry) clients;
};

static struct pmemrad *
pmemrad_alloc(void)
{
	struct pmemrad *prd = calloc(1, sizeof (*prd));
	if (!prd) {
		log_err("cannot allocate pmemra deamon context");
		return NULL;
	}

	TAILQ_INIT(&prd->clients);
	prd->pdb = pmemrad_pdb_alloc();
	if (!prd->pdb) {
		/* XXX */
		goto err_pdb_alloc;
	}

	return prd;
err_pdb_alloc:
	free(prd);
	return NULL;
}

static void
pmemrad_free(struct pmemrad *prd)
{
	pmemrad_pdb_free(prd->pdb);
	free(prd);
}

static struct pmemrad_client_entry *
get_first_not_running(struct pmemrad *prd)
{
	struct pmemrad_client_entry *entry;
	TAILQ_FOREACH(entry, &prd->clients, next) {
		if (!pmemrad_client_is_running(entry->client))
			return entry;
	}

	return NULL;
}

static void
pmemrad_cleanup_clients(struct pmemrad *prd)
{
	struct pmemrad_client_entry *entry;
	while ((entry = get_first_not_running(prd)) != NULL) {
		TAILQ_REMOVE(&prd->clients, entry, next);
		pmemrad_client_destroy(entry->client);
		free(entry);
	}
}

static void
pmemrad_stop(struct pmemrad *prd)
{
	while (!TAILQ_EMPTY(&prd->clients)) {
		struct pmemrad_client_entry *entry =
			TAILQ_FIRST(&prd->clients);

		pmemrad_client_stop(entry->client);
		TAILQ_REMOVE(&prd->clients, entry, next);
		free(entry);
	}
}

static int
pmemrad_start(struct pmemrad *prd, int *runp)
{
	int ret;
	struct sockaddr_in addr;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof (client_addr);
	int client_fd;

	memset(&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PMEMRA_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	prd->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (prd->sockfd < 0) {
		log_err("socket");
		return -1;
	}

	ret = bind(prd->sockfd, (struct sockaddr *)&addr, sizeof (addr));
	if (ret < 0) {
		log_err("bind");
		goto err_bind;
	}

	ret = listen(prd->sockfd, 1);
	if (ret < 0) {
		log_err("listen");
		goto err_listen;
	}

	struct pollfd fds = {
		.fd = prd->sockfd,
		.events = POLLIN,
	};

	while (*runp) {
		ret = poll(&fds, 1, 200);
		if (ret < 0) {
			if ((*runp))
				log_err("!poll");
			break;
		} else if (ret == 0) {
			pmemrad_cleanup_clients(prd);
			continue;
		}
		client_fd = accept(prd->sockfd, (struct sockaddr *)&client_addr,
				&client_len);
		if (client_fd < 0) {
			log_err("accept");
			goto err_accept;
		}

		log_info("new client %s", inet_ntoa(client_addr.sin_addr));
		struct pmemrad_client_entry *entry = malloc(sizeof (*entry));
		if (!entry) {
			log_err("cannot create client");
			continue;
		}
		entry->client = pmemrad_client_create(client_fd,
				&client_addr, prd->pdb);
		if (!entry->client) {
			free(entry);
			/* XXX */
			log_err("cannot create client");
			continue;
		}

		TAILQ_INSERT_TAIL(&prd->clients, entry, next);
	}

	log_info("terminating server");
	pmemrad_stop(prd);
	return ret;
err_accept:
err_listen:
err_bind:
	close(prd->sockfd);
	return ret;
}

static int Run;

static void
signal_handler(int signum)
{
	Run = 0;
}

int
main(int argc, char *argv[])
{
	util_init();
	struct pmemrad *prd = pmemrad_alloc();
	if (!prd)
		return 1;

	int ret;
	ret = pmemrad_parse_opts(argc, argv, &prd->opts);
	if (ret) {
		log_err("parsing options failed");
		return 1;
	}

	ret = pmemrad_pdb_add_set(prd->pdb, "pool.set");

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	Run = 1;
	ret = pmemrad_start(prd, &Run);

	pmemrad_free_opts(&prd->opts);
	pmemrad_free(prd);
	return ret;
}
