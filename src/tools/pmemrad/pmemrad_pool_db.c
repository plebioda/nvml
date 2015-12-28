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
 * pmemrad_pool_db.c -- XXX
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pmemrad.h"
#include "pmemrad_pool_db.h"
#include "util.h"

struct pmemrad_pool_desc {
	struct pmemrad_pool pool;

	unsigned used;
	struct pool_set *set;
};

struct pmemrad_pdb {
	struct pmemrad_pool_desc *pools;
	size_t npools;
};

static struct pmemrad_pool *
pmemrad_pdb_get_desc(struct pmemrad_pdb *pdb, const char *name)
{
	if (!pdb->npools)
		return NULL;
	ASSERTne(pdb->pools, NULL);

	for (size_t i = 0; i < pdb->npools; i++) {
		if (strcmp(name, pdb->pools[i].pool.name) == 0)
			return &pdb->pools[i].pool;
	}

	return NULL;
}

struct pmemrad_pdb *
pmemrad_pdb_alloc(void)
{
	struct pmemrad_pdb *pdb = calloc(1, sizeof (*pdb));
	if (!pdb) {
		log_err("!pools db alloc");
		return NULL;
	}

	return pdb;
}

void
pmemrad_pdb_free(struct pmemrad_pdb *pdb)
{
	for (size_t i = 0; i < pdb->npools; i++) {
		free((char *)pdb->pools[i].pool.name);
		util_poolset_close(pdb->pools[i].set, 0);
	}
	free(pdb->pools);
	free(pdb);
}

int
pmemrad_pdb_add_dir(struct pmemrad_pdb *pdb, const char *dir)
{
	/* XXX */
	return -1;
}

int
pmemrad_pdb_add_set(struct pmemrad_pdb *pdb, const char *path)
{
	struct pool_set *set;
	int ret = util_pool_open_nocheck(&set, path, 0, 4096);
	if (ret) {
		log_err("!pool open");
		return ret;
	}

	size_t new_size = (pdb->npools + 1) * sizeof (struct pmemrad_pool_desc);
	struct pmemrad_pool_desc *pools = realloc(pdb->pools, new_size);
	if (!pools) {
		log_err("!pools realloc");
		goto err_pools_realloc;
	}

	pools[pdb->npools].used = 0;
	pools[pdb->npools].set = set;
	pools[pdb->npools].pool.desc = &pools[pdb->npools];
	pools[pdb->npools].pool.name = strdup(path);
	pools[pdb->npools].pool.addr = set->replica[0]->part[0].addr;
	pools[pdb->npools].pool.size = set->poolsize;

	pdb->npools++;
	pdb->pools = pools;

	return 0;
err_pools_realloc:
	util_poolset_close(set, 0);
	return -1;
}

int
pmemrad_pdb_scan(struct pmemrad_pdb *pdb)
{
	/* XXX */
	return -1;
}

const struct pmemrad_pool *
pmemrad_pdb_hold(struct pmemrad_pdb *pdb, const char *name)
{
	/* XXX */
	return pmemrad_pdb_get_desc(pdb, name);
}

void
pmemrad_pdb_release(struct pmemrad_pdb *pdb, const struct pmemrad_pool *prp)
{
	/* XXX */
}
