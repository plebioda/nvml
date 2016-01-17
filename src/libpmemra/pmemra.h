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
 * pmemra.h -- internal definitions for libpmemra
 */

#define	PMEMRA_LOG_PREFIX "libpmemra"
#define	PMEMRA_LOG_LEVEL_VAR "PMEMRA_LOG_LEVEL"
#define	PMEMRA_LOG_FILE_VAR "PMEMRA_LOG_FILE"
#define	PMEMRA_FIVERSION FI_VERSION(1, 1)
#define	PMEMRA_PORT		1234
#define	PMEMRA_MAX_LANES	UINT_MAX
#define	PMEMRA_DEF_NLANES_MUL	2

enum pmemra_msg_type {
	PMEMRA_MSG_OPEN,
	PMEMRA_MSG_OPEN_RESP,
	PMEMRA_MSG_CREATE,
	PMEMRA_MSG_CREATE_RESP,
	PMEMRA_MSG_CLOSE,
	PMEMRA_MSG_CLOSE_RESP,
	PMEMRA_MSG_REMOVE,
	PMEMRA_MSG_REMOVE_RESP,

	MAX_PMEMRA_MSG,
};

enum pmemra_err {
	PMEMRA_ERR_SUCCESS = 0,

	PMEMRA_ERR_INVAL,
	PMEMRA_ERR_FILE_NAME,
	PMEMRA_ERR_POOLSET,
	PMEMRA_ERR_MEM_SIZE,
	PMEMRA_ERR_BUSY,

	PMEMRA_ERR_FATAL,
};

struct pmemra_msg_hdr {
	uint32_t type;		/* message type */
	uint32_t size;		/* size of message */
	uint8_t data[];
};

struct pmemra_msg_open {
	struct pmemra_msg_hdr hdr; /* message header */
	uint64_t mem_size;	/* size of memory region */
	uint32_t fname_len;	/* file name length */
	uint32_t poolset_len;	/* poolset name length */
	uint32_t nlanes;	/* requested number of lanes */
	char data[];		/* NULL-terminated filename and poolset name */
};

struct pmemra_msg_open_resp {
	struct pmemra_msg_hdr hdr; /* message header */
	uint32_t status;
	uint32_t port;
	uint64_t rkey;
	uint64_t addr;
	uint64_t size;
	uint32_t nlanes;
};

struct pmemra_msg_close_resp {
	struct pmemra_msg_hdr hdr;
	uint32_t status;
};

struct pmemra_persist {
	uint64_t addr;
	uint64_t len;
};

static inline const char *
pmemra_msg_str(enum pmemra_msg_type type)
{
	switch (type) {
	case PMEMRA_MSG_OPEN:
		return "OPEN";
	case PMEMRA_MSG_OPEN_RESP:
		return "OPEN RESP";
	case PMEMRA_MSG_CREATE:
		return "CREATE";
	case PMEMRA_MSG_CREATE_RESP:
		return "CREATE RESP";
	case PMEMRA_MSG_CLOSE:
		return "CLOSE";
	case PMEMRA_MSG_REMOVE:
		return "REMOVE";
	case PMEMRA_MSG_REMOVE_RESP:
		return "REMOVE RESP";
	default:
		return "UNKNOWN";
	}
}

static inline const char *
pmemra_err_str(enum pmemra_err err)
{
	switch (err) {
	case PMEMRA_ERR_SUCCESS:
		return "success";
	case PMEMRA_ERR_INVAL:
		return "invalid argument";
	case PMEMRA_ERR_FILE_NAME:
		return "invalid file name";
	case PMEMRA_ERR_POOLSET:
		return "invalid poolset name or size";
	case PMEMRA_ERR_MEM_SIZE:
		return "memory size";
	case PMEMRA_ERR_BUSY:
		return "busy";
	case PMEMRA_ERR_FATAL:
		return "fatal error";
	default:
		return "unknown";
	}
}
