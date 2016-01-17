/*
 * Copyright (c) 2014-2015, Intel Corporation
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
 * libpmemra.h -- XXX
 */


#ifndef	LIBPMEMRA_H
#define	LIBPMEMRA_H 1

#ifdef __cplusplus
extern "C" {
#endif

#define	POOL_HDR_SIG_LEN 8
#define	POOL_HDR_UUID_LEN 16

struct pmemra_pool_attr {
	char signature[POOL_HDR_SIG_LEN];
	uint32_t major;
	uint32_t compat_features;
	uint32_t incompat_features;
	uint32_t ro_compat_features;
	unsigned char poolset_uuid[POOL_HDR_UUID_LEN];
	unsigned char uuid[POOL_HDR_UUID_LEN];
	unsigned char prev_repl_uuid[POOL_HDR_UUID_LEN];
	unsigned char next_repl_uuid[POOL_HDR_UUID_LEN];
};

struct pmemra_attr {
	unsigned nlanes;
	struct pmemra_pool_attr pool_attr;
};

typedef struct pmemra PMEMrapool;

PMEMrapool *pmemra_open(const char *hostname, const char *poolset_name,
		void *addr, size_t size, struct pmemra_attr *attr);
PMEMrapool *pmemra_create(const char *hostname, const char *poolset_name,
		void *addr, size_t size, struct pmemra_attr *attr);
int pmemra_remove(const char *hostname, const char *poolset_name);
void pmemra_close(PMEMrapool *prp);
ssize_t pmemra_read(PMEMrapool *prp, void *buff, size_t len, size_t offset);
int pmemra_persist(PMEMrapool *prp, void *addr, size_t len);
int pmemra_persist_lane(PMEMrapool *prp, void *addr, size_t len, unsigned lane);

/*
 * XXX
 */
#define	PMEMRA_MAJOR_VERSION 1
#define	PMEMRA_MINOR_VERSION 0
const char *pmemra_check_version(
		unsigned major_required,
		unsigned minor_required);

const char *pmemra_errormsg(void);

#ifdef __cplusplus
}
#endif
#endif	/* libpmemra.h */
