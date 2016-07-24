/*
 * Copyright 2016, Intel Corporation
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
 *     * Neither the name of the copyright holder nor the names of its
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
 * rpmem_libssh2.c -- rpmem ssh transport layer source file
 */

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <libssh2.h>

#include "util.h"
#include "out.h"
#include "rpmem_ssh.h"
#include "rpmem_common.h"
#include "rpmem_util.h"


struct rpmem_ssh {
	int sock;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
};

static int
sock_connect(const char *node, const char *service)
{
	struct addrinfo *addrinfo;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;

	int ret = getaddrinfo(node, service, &hints, &addrinfo);
	if (ret) {
		RPMEM_LOG(ERR, "!getaddrinfo");
		return ret;
	}

	int sockfd;

	for (struct addrinfo *ai = addrinfo; ai; ai = ai->ai_next) {
		sockfd = socket(ai->ai_family, ai->ai_socktype,
				ai->ai_protocol);

		if (sockfd == -1)
			continue;

		if (!connect(sockfd, ai->ai_addr, ai->ai_addrlen)) {
			break;
		}

		close(sockfd);
		sockfd = -1;
	}

	freeaddrinfo(addrinfo);

	return sockfd;
}

/*
 * get_cmd -- return command name
 */
static const char *
get_cmd(void)
{
	char *cmd = getenv(RPMEM_CMD_ENV);
	if (!cmd)
		cmd = RPMEM_DEF_CMD;

	return cmd;
}

/*
 * rpmem_ssh_open -- open ssh connection with specified node
 */
struct rpmem_ssh *
rpmem_ssh_open(const char *node, const char *service)
{
	struct rpmem_ssh *ssh = calloc(sizeof(*ssh), 1);
	if (!ssh) {
		RPMEM_LOG(ERR, "!calloc");
		goto err_calloc;
	}
	if (!service)
		service = "22";

	ssh->sock = sock_connect(node, service);
	if (ssh->sock)
		goto err_sock;

	ssh->session = libssh2_session_init();
	if (!ssh->session) {
		RPMEM_LOG(ERR, "!libssh2_session_init");
		goto err_session;
	}

	int ret;

	ret = libssh2_session_handshake(ssh->session, ssh->sock);
	if (ret) {
		RPMEM_LOG(ERR, "!libssh2_session_handshake");
		goto err_handshake;
	}

	ret = libssh2_userauth_publickey_fromfile(ssh->session, 


	return ssh;
err_handshake:
	if (libssh2_session_free(ssh->session))
		RPMEM_LOG(ERR, "!libssh2_session_free");
err_session:
	close(ssh->sock);
err_sock:
	free(ssh);
err_calloc:
	return NULL;
}

/*
 * rpmem_ssh_close -- close ssh connection
 */
int
rpmem_ssh_close(struct rpmem_ssh *rps)
{
	return -1;
}

/*
 * rpmem_ssh_send -- send data using ssh transport layer
 *
 * The data is encoded using base64.
 */
int
rpmem_ssh_send(struct rpmem_ssh *rps, const void *buff, size_t len)
{
	return -1;
}

/*
 * rpmem_ssh_recv -- receive data using ssh transport layer
 *
 * The received data is decoded using base64.
 */
int
rpmem_ssh_recv(struct rpmem_ssh *rps, void *buff, size_t len)
{
	return -1;
}

/*
 * rpmem_ssh_monitor -- check connection state of ssh
 *
 * Return value:
 * 0  - disconnected
 * 1  - connected
 * <0 - error
 */
int
rpmem_ssh_monitor(struct rpmem_ssh *rps, int nonblock)
{
	return 0;
}

/*
 * rpmem_ssh_strerror -- read error using stderr channel
 */
const char *
rpmem_ssh_strerror(struct rpmem_ssh *rps)
{
	return "";
}
