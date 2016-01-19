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
 * pmemrad_pool_db.h -- XXX
 */

#include <libpmemra.h>

#ifndef PMEMRAD_POOL_DB_H
#define	PMEMRAD_POOL_DB_H

struct pmemrad_pdb;

struct pmemrad_pool {
	char *name;
	void *addr;
	size_t size;
	void *desc;
};

struct pmemrad_pdb *pmemrad_pdb_alloc(const char *root_dir);
void pmemrad_pdb_free(struct pmemrad_pdb *pdb);

int pmemrad_pdb_set_dir(struct pmemrad_pdb *pdb, const char *dir);
const struct pmemrad_pool *pmemrad_pdb_open(struct pmemrad_pdb *pdb,
		const char *name);
const struct pmemrad_pool *pmemrad_pdb_create(struct pmemrad_pdb *pdb,
		const char *name, struct pmemra_pool_attr *attr);
int pmemrad_pdb_remove(struct pmemrad_pdb *pdb, const char *name);
void pmemrad_pdb_close(struct pmemrad_pdb *pdb, const struct pmemrad_pool *prp);

#endif /* PMEMRAD_POOL_DB_H  */
