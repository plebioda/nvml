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
 * pmemrad_pool_db.c -- XXX
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>

#include "pmemrad.h"
#include "pmemrad_pool_db.h"
#include "util.h"

struct pmemrad_pool_desc {
	LIST_ENTRY(pmemrad_pool_desc) next;
	struct pmemrad_pool pool;
	struct pool_set *set;
};

struct pmemrad_pdb {
	LIST_HEAD(pool_desc_head, pmemrad_pool_desc) head;
	pthread_mutex_t lock;
	char *root_dir;
};

static void
pmemrad_pdb_pool_close(struct pmemrad_pdb *pdb, struct pmemrad_pool_desc *ppd)
{
	util_poolset_close(ppd->set, 0);
	free(ppd->pool.name);
	free(ppd);
}

struct pmemrad_pdb *
pmemrad_pdb_alloc(const char *root_dir)
{
	struct pmemrad_pdb *pdb = calloc(1, sizeof (*pdb));
	if (!pdb) {
		log_err("!pools db alloc");
		return NULL;
	}

	if (pthread_mutex_init(&pdb->lock, NULL))
		goto err_mutex_init;

	pdb->root_dir = strdup(root_dir);
	if (!pdb->root_dir) {
		log_err("!root dir alloc");
		goto err_strdup;
	}

	LIST_INIT(&pdb->head);

	return pdb;
err_strdup:
err_mutex_init:
	free(pdb);
	return NULL;
}

void
pmemrad_pdb_free(struct pmemrad_pdb *pdb)
{
	while (!LIST_EMPTY(&pdb->head)) {
		struct pmemrad_pool_desc *ppd = LIST_FIRST(&pdb->head);
		pmemrad_pdb_pool_close(pdb, ppd);
		LIST_REMOVE(ppd, next);
	}

	free(pdb);
}

static struct pmemrad_pool_desc *
pmemrad_pdb_lookup(struct pmemrad_pdb *pdb, const char *name)
{
	struct pmemrad_pool_desc *ppd;
	LIST_FOREACH(ppd, &pdb->head, next) {
		if (strcmp(name, ppd->pool.name) == 0)
			return ppd;
	}

	return NULL;
}

static char *
pmemrad_pdb_get_path(struct pmemrad_pdb *pdb, const char *name)
{
	size_t dir_len = strlen(pdb->root_dir);
	size_t name_len = strlen(name);
	size_t path_len = dir_len + name_len + 2;
	char *path = malloc(path_len);
	if (!path)
		return NULL;

	int ret = snprintf(path, path_len, "%s/%s", pdb->root_dir, name);
	if (ret < 0 || (size_t)ret != path_len - 1) {
		free(path);
		return NULL;
	}

	return path;

}

const struct pmemrad_pool *
pmemrad_pdb_create(struct pmemrad_pdb *pdb,
		const char *name, struct pmemra_pool_attr *attr)
{
	pthread_mutex_lock(&pdb->lock);

	struct pmemrad_pool_desc *ppd;

	ppd = pmemrad_pdb_lookup(pdb, name);
	if (ppd) {
		errno = EBUSY;
		goto err_unlock;
	}

	char *path = pmemrad_pdb_get_path(pdb, name);
	if (!path) {
		goto err_unlock;
	}

	struct pool_set *set;
	int ret = util_pool_create(&set, path, 0, 4096, 4096,
		attr->signature, attr->major, attr->compat_features,
		attr->incompat_features, attr->ro_compat_features,
		attr->poolset_uuid);
	if (ret) {
		log_err("!pool open");
		goto err_pool_open;
	}

	util_poolset_chmod(set, 0755);

	ppd = calloc(1, sizeof (*ppd));
	if (!ppd) {
		goto err_calloc;
	}

	ppd->set = set;
	ppd->pool.desc = ppd;
	ppd->pool.name = strdup(name);
	if (!ppd->pool.name)
		goto err_strdup;

	ppd->pool.addr = set->replica[0]->part[0].addr;
	ppd->pool.size = set->poolsize;

	LIST_INSERT_HEAD(&pdb->head, ppd, next);

	pthread_mutex_unlock(&pdb->lock);
	return &ppd->pool;
err_strdup:
	free(ppd);
err_calloc:
	util_poolset_close(set, 1);
err_pool_open:
	free(path);
err_unlock:
	pthread_mutex_unlock(&pdb->lock);
	return NULL;
}

int
pmemrad_pdb_remove(struct pmemrad_pdb *pdb, const char *name)
{
	pthread_mutex_lock(&pdb->lock);

	struct pmemrad_pool_desc *ppd;

	ppd = pmemrad_pdb_lookup(pdb, name);
	if (ppd) {
		errno = EBUSY;
		goto err_unlock;
	}

	char *path = pmemrad_pdb_get_path(pdb, name);
	if (!path) {
		goto err_unlock;
	}

	struct pool_set *set;
	int ret = util_pool_open_nocheck(&set, path, 0, 4096);
	if (ret) {
		log_err("!pool open");
		goto err_pool_open;
	}

	for (unsigned r = 0; r < set->nreplicas; r++) {
		for (unsigned p = 0; p < set->replica[r]->nparts; p++) {
			const char *part_file = set->replica[r]->part[p].path;
			unlink(part_file);
		}
	}

	util_poolset_close(set, 1);

	pthread_mutex_unlock(&pdb->lock);
	return 0;
err_pool_open:
	free(path);
err_unlock:
	pthread_mutex_unlock(&pdb->lock);
	return -1;
}

const struct pmemrad_pool *
pmemrad_pdb_open(struct pmemrad_pdb *pdb, const char *name)
{
	pthread_mutex_lock(&pdb->lock);

	struct pmemrad_pool_desc *ppd;

	ppd = pmemrad_pdb_lookup(pdb, name);
	if (ppd) {
		errno = EBUSY;
		goto err_unlock;
	}

	char *path = pmemrad_pdb_get_path(pdb, name);
	if (!path) {
		goto err_unlock;
	}

	struct pool_set *set;
	int ret = util_pool_open_nocheck(&set, path, 0, 4096);
	if (ret) {
		log_err("!pool open");
		goto err_pool_open;
	}

	ppd = calloc(1, sizeof (*ppd));
	if (!ppd) {
		goto err_calloc;
	}

	ppd->set = set;
	ppd->pool.desc = ppd;
	ppd->pool.name = strdup(name);
	if (!ppd->pool.name)
		goto err_strdup;

	ppd->pool.addr = set->replica[0]->part[0].addr;
	ppd->pool.size = set->poolsize;

	LIST_INSERT_HEAD(&pdb->head, ppd, next);

	pthread_mutex_unlock(&pdb->lock);
	return &ppd->pool;
err_strdup:
	free(ppd);
err_calloc:
	util_poolset_close(set, 0);
err_pool_open:
	free(path);
err_unlock:
	pthread_mutex_unlock(&pdb->lock);
	return NULL;
}

void
pmemrad_pdb_close(struct pmemrad_pdb *pdb, const struct pmemrad_pool *prp)
{
	pthread_mutex_lock(&pdb->lock);
	struct pmemrad_pool_desc *ppd = (struct pmemrad_pool_desc *)prp->desc;
	LIST_REMOVE(ppd, next);
	pmemrad_pdb_pool_close(pdb, ppd);
	pthread_mutex_unlock(&pdb->lock);
}
