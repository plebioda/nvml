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
 * rpmem_libssh.c -- rpmem ssh transport layer source file
 */

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/types.h>
#include <libssh/libssh.h>

#include "util.h"
#include "out.h"
#include "rpmem_common.h"
#include "rpmem_ssh.h"
#include "rpmem_util.h"

/* #define ERR_BUFF_SIZE	4095 */

/* +1 in order to be sure it is always null-terminated */
/* static char error_str[ERR_BUFF_SIZE + 1]; */

struct rpmem_ssh {
	socket_t sockfd;
	ssh_session session;
	ssh_channel channel;
};

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

static socket_t
rpmem_connect(const char *node, const char *service, unsigned flags)
{
	struct addrinfo *addrinfo;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	if (flags & RPMEM_FLAGS_USE_IPV4)
		hints.ai_family = AF_INET;

	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	int ret = getaddrinfo(node, service, &hints, &addrinfo);
	if (ret)
		return -1;

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
 * rpmem_ssh_open -- open ssh connection with specified node
 */
struct rpmem_ssh *
rpmem_ssh_open(const struct rpmem_target_info *info)
{
	char *user = info->user;
	if (!user) {
		uid_t uid = geteuid();
		struct passwd *pw = getpwuid(uid);
		if (!pw) {
			RPMEM_LOG(ERR, "!getpwuid");
			goto err_pw;
		}

		user = pw->pw_name;
	}

	char *service = info->service;
	if (!service) {
		service = "22";
	}

	struct rpmem_ssh *rps = calloc(1, sizeof(*rps));
	if (!rps) {
		RPMEM_LOG(ERR, "!calloc");
		goto err_calloc;
	}

	rps->sockfd = rpmem_connect(info->node, service, info->flags);
	if (rps->sockfd < 0) {
		RPMEM_LOG(ERR, "!rpmem_connect");
		goto err_sock;
	}

	rps->session = ssh_new();
	if (!rps->session) {
		RPMEM_LOG(ERR, "!ssh_new");
		goto err_ssh_new;
	}

	int ret;
	ret = ssh_options_set(rps->session, SSH_OPTIONS_FD,
			(const void *)&rps->sockfd);
	if (ret) {
		RPMEM_LOG(ERR, "!setting ssh option -- socket");
		goto err_options_set;
	}

	ret = ssh_options_set(rps->session, SSH_OPTIONS_HOST, info->node);
	if (ret) {
		RPMEM_LOG(ERR, "!setting ssh option -- host");
		goto err_options_set;
	}

	ret = ssh_options_set(rps->session, SSH_OPTIONS_USER, user);
	if (ret) {
		RPMEM_LOG(ERR, "!setting ssh option -- user");
		goto err_options_set;
	}

	ret = ssh_connect(rps->session);
	if (ret != SSH_OK) {
		RPMEM_LOG(ERR, "ssh_connect: %s",
				ssh_get_error(rps->session));
		goto err_connect;
	}

	ret = ssh_is_server_known(rps->session);
	if (ret != SSH_SERVER_KNOWN_OK) {
		RPMEM_LOG(ERR, "ssh_is_server_known: %s",
				ssh_get_error(rps->session));
		goto err_server_known;
	}

	ret = ssh_userauth_publickey_auto(rps->session, NULL, NULL);
	if (ret == SSH_AUTH_ERROR) {
		RPMEM_LOG(ERR, "ssh_userauth_publickey_auto: %s",
				ssh_get_error(rps->session));
		goto err_auth;
	}

	rps->channel = ssh_channel_new(rps->session);
	if (!rps->channel) {
		RPMEM_LOG(ERR, "ssh_channel_new: %s",
				ssh_get_error(rps->session));
		goto err_channel_new;
	}

	ret = ssh_channel_open_session(rps->channel);
	if (ret != SSH_OK) {
		RPMEM_LOG(ERR, "ssh_channel_open_session: %s",
				ssh_get_error(rps->session));
		goto err_channel_open_session;
	}

	const char *cmd = get_cmd();
	ret = ssh_channel_request_exec(rps->channel, cmd);
	if (ret) {
		RPMEM_LOG(ERR, "ssh_channel_request_exec: %s",
				ssh_get_error(rps->session));
		goto err_channel_exec;
	}

	/*
	 * Read initial status from invoked command.
	 * This is for synchronization purposes and to make it possible
	 * to inform client that command's initialization failed.
	 */
	int32_t status;
	ret = rpmem_ssh_recv(rps, &status, sizeof(status));
	if (ret) {
		if (ret == 1 || errno == ECONNRESET)
			ERR("%s", rpmem_ssh_strerror(rps));
		else
			ERR("!%s", info->node);
		goto err_recv_status;
	}

	if (status) {
		ERR("%s: unexpected status received -- '%d'",
				info->node, status);
		goto err_status;
	}

	return rps;
err_status:
err_recv_status:
err_channel_exec:
	ssh_channel_close(rps->channel);
err_channel_open_session:
	ssh_channel_free(rps->channel);
err_channel_new:
err_auth:
err_server_known:
	ssh_disconnect(rps->session);
err_connect:
err_options_set:
	ssh_free(rps->session);
err_ssh_new:
	close(rps->sockfd);
err_sock:
	free(rps);
err_calloc:
err_pw:
	return NULL;
}

/*
 * rpmem_ssh_close -- close ssh connection
 */
int
rpmem_ssh_close(struct rpmem_ssh *rps)
{
	ssh_channel_close(rps->channel);
	ssh_channel_free(rps->channel);
	ssh_disconnect(rps->session);
	ssh_free(rps->session);
	free(rps);

	return 0;
}

/*
 * rpmem_ssh_send -- send data using ssh transport layer
 */
int
rpmem_ssh_send(struct rpmem_ssh *rps, const void *buff, size_t len)
{
	size_t wr = 0;
	const uint8_t *cbuf = buff;
	while (wr < len) {
		ssize_t sret;

		sret = ssh_channel_write(rps->channel, &cbuf[wr],
				(uint32_t)(len - wr));

		if (sret == SSH_ERROR)
			return -1;

		if (sret == 0)
			return 1;

		wr += (size_t)sret;
	}

	return 0;
}

/*
 * rpmem_ssh_recv -- receive data using ssh transport layer
 */
int
rpmem_ssh_recv(struct rpmem_ssh *rps, void *buff, size_t len)
{
	size_t rd = 0;
	uint8_t *cbuf = buff;
	while (rd < len) {
		ssize_t sret;

		sret = ssh_channel_read(rps->channel, &cbuf[rd],
				(uint32_t)(len - rd), 0);
		if (sret == SSH_ERROR)
			return -1;

		if (sret == 0)
			return 1;

		rd += (size_t)sret;
	}

	return 0;
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
	return -1;
}

/*
 * rpmem_ssh_strerror -- read error using stderr channel
 */
const char *
rpmem_ssh_strerror(struct rpmem_ssh *rps)
{
	return NULL;
}
