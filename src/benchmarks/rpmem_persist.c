/*
 * Copyright 2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *      * Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived
 *        from this software without specific prior written permission.
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
 * rpmem_persist.c -- rpmem persist benchmarks definition
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/file.h>

#include "set.h"
#include "libpmem.h"
#include "librpmem.h"
#include "benchmark.h"
#include "util.h"

#define CL_ALIGNMENT 64
#define MAX_OFFSET (CL_ALIGNMENT - 1)

#define ALIGN_CL(x)\
	(((x) + CL_ALIGNMENT - 1) & ~(CL_ALIGNMENT - 1))
/*
 * rpmem_args -- benchmark specific command line options
 */
struct rpmem_args {
	char *mode;		/* operation mode: stat, seq, rand */
	bool no_warmup;		/* do not do warmup */
	bool no_memset;		/* do not call memset before each persist */
	size_t chunk_size;	/* elementary chunk size */
	size_t dest_off;	/* destination address offset */
};

/*
 * rpmem_bench -- benchmark context
 */
struct rpmem_bench {
	struct rpmem_args *pargs; /* benchmark specific arguments */
	uint64_t *offsets;	/* random/sequential address offsets */
	int n_offsets;		/* number of random elements */
	size_t fsize;		/* file size */
	size_t min_size;	/* minimum file size */
	void *addrp;		/* mapped file address */
	void *pool;		/* memory pool address */
	size_t pool_size;	/* size of memory pool */
	size_t mapped_len;	/* mapped length */
	RPMEMpool **rpp;	/* rpmem pool pointers */
	unsigned *nlanes;	/* number of lanes for each remote replica */
	unsigned nreplicas;	/* number of remote replicas */
	size_t csize_align;
};

static struct benchmark_clo rpmem_clo[] = {
	{
		.opt_short	= 'M',
		.opt_long	= "mem-mode",
		.descr		= "Memory writing mode:"
				" stat, seq[-wrap], rand[-wrap]",
		.def		= "seq",
		.off		= clo_field_offset(struct rpmem_args, mode),
		.type		= CLO_TYPE_STR,
	},
	{
		.opt_short	= 'D',
		.opt_long	= "dest-offset",
		.descr		= "Destination cache line alignment offset",
		.def		= "0",
		.off		= clo_field_offset(struct rpmem_args, dest_off),
		.type		= CLO_TYPE_UINT,
		.type_uint	= {
			.size	= clo_field_size(struct rpmem_args, dest_off),
			.base	= CLO_INT_BASE_DEC,
			.min	= 0,
			.max	= MAX_OFFSET
		}
	},
	{
		.opt_short	= 'w',
		.opt_long	= "no-warmup",
		.descr		= "Don't do warmup",
		.def		= false,
		.type		= CLO_TYPE_FLAG,
		.off	= clo_field_offset(struct rpmem_args, no_warmup),
	},
	{
		.opt_short	= 'T',
		.opt_long	= "no-memset",
		.descr		= "Don't call memset for all rpmem_persist",
		.def		= false,
		.type		= CLO_TYPE_FLAG,
		.off	= clo_field_offset(struct rpmem_args, no_memset),
	},
};

/*
 * operation_mode -- mode of operation
 */
enum operation_mode {
	OP_MODE_UNKNOWN,
	OP_MODE_STAT,	/* always use the same chunk */
	OP_MODE_SEQ,	/* use consecutive chunks */
	OP_MODE_RAND,	/* use random chunks */
	OP_MODE_SEQ_WRAP, /* use consequtive chunks, but use file size */
	OP_MODE_RAND_WRAP, /* use random chunks, but use file size */
};

/*
 * parse_op_mode -- parse operation mode from string
 */
static enum operation_mode
parse_op_mode(const char *arg)
{
	if (strcmp(arg, "stat") == 0)
		return OP_MODE_STAT;
	else if (strcmp(arg, "seq") == 0)
		return OP_MODE_SEQ;
	else if (strcmp(arg, "rand") == 0)
		return OP_MODE_RAND;
	else if (strcmp(arg, "seq-wrap") == 0)
		return OP_MODE_SEQ_WRAP;
	else if (strcmp(arg, "rand-wrap") == 0)
		return OP_MODE_RAND_WRAP;
	else
		return OP_MODE_UNKNOWN;
}

/*
 * init_offsets -- initialize offsets[] array depending on the selected mode
 */
static int
init_offsets(struct benchmark_args *args, struct rpmem_bench *mb,
	enum operation_mode op_mode)
{
	size_t n_ops_by_size = mb->pool_size /
		(args->n_threads * mb->csize_align);

	mb->n_offsets = args->n_ops_per_thread * args->n_threads;
	mb->offsets = malloc(mb->n_offsets * sizeof(*mb->offsets));
	if (!mb->offsets) {
		perror("malloc");
		return -1;
	}

	unsigned seed = args->seed;

	for (size_t i = 0; i < args->n_threads; i++) {
		for (size_t j = 0; j < args->n_ops_per_thread; j++) {
			size_t off_idx = i * args->n_ops_per_thread + j;
			size_t chunk_idx;
			switch (op_mode) {
			case OP_MODE_STAT:
				chunk_idx = i;
				break;
			case OP_MODE_SEQ:
				chunk_idx = i * args->n_ops_per_thread + j;
				break;
			case OP_MODE_RAND:
				chunk_idx = i * args->n_ops_per_thread +
					rand_r(&seed) % args->n_ops_per_thread;
				break;
			case OP_MODE_SEQ_WRAP:
				chunk_idx = i * n_ops_by_size +
					j % n_ops_by_size;
				break;
			case OP_MODE_RAND_WRAP:
				chunk_idx = i * n_ops_by_size +
					rand_r(&seed) % n_ops_by_size;
				break;
			default:
				assert(0);
				return -1;
			}

			mb->offsets[off_idx] = chunk_idx * mb->csize_align +
				mb->pargs->dest_off;
		}
	}

	return 0;
}

/*
 * do_warmup -- does the warmup by writing the whole pool area
 */
static int
do_warmup(struct rpmem_bench *mb)
{
	/* clear the entire pool */
	memset(mb->pool, 0, mb->pool_size);

	for (unsigned r = 0; r < mb->nreplicas; ++r) {
		int ret = rpmem_persist(mb->rpp[r], 0,
				mb->pool_size, 0);
		if (ret)
			return ret;
	}

	/* if no memset for each operation, do one big memset */
	if (mb->pargs->no_memset)
		memset(mb->pool, 0xFF, mb->pool_size);

	return 0;
}

/*
 * rpmem_op -- actual benchmark operation
 */
static int
rpmem_op(struct benchmark *bench, struct operation_info *info)
{
	struct rpmem_bench *mb =
		(struct rpmem_bench *)pmembench_get_priv(bench);

	assert(info->index < mb->n_offsets);

	uint64_t idx = info->worker->index * info->args->n_ops_per_thread
						+ info->index;
	size_t offset = mb->offsets[idx];
	size_t len = mb->pargs->chunk_size;

	if (!mb->pargs->no_memset) {
		void *dest = (char *)mb->pool + offset;
		/* thread id on MS 4 bits and operation id on LS 4 bits */
		int c = ((info->worker->index & 0xf) << 4) +
			((0xf & info->index));
		memset(dest, c, len);
	}

	int ret = 0;
	for (unsigned r = 0; r < mb->nreplicas; ++r) {
		assert(info->worker->index < mb->nlanes[r]);

		ret = rpmem_persist(mb->rpp[r], offset, len,
				info->worker->index);
		if (ret) {
			fprintf(stderr, "rpmem_persist replica #%u: %s\n",
					r, rpmem_errormsg());
			return ret;
		}
	}

	return 0;
}

/*
 * rpmem_map_file -- map local file
 */
static int
rpmem_map_file(const char *path, struct rpmem_bench *mb, size_t size)
{
	int mode;
#ifndef _WIN32
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
#else
	mode = S_IWRITE | S_IREAD;
#endif

	mb->addrp = pmem_map_file(path, size, PMEM_FILE_CREATE, mode,
		&mb->mapped_len, NULL);

	if (!mb->addrp)
		return -1;

	return 0;
}

/*
 * rpmem_unmap_file -- unmap local file
 */
static int
rpmem_unmap_file(struct rpmem_bench *mb)
{
	return pmem_unmap(mb->addrp, mb->mapped_len);
}

/*
 * rpmem_poolset_init -- read poolset file and initialize benchmark accordingly
 */
static int
rpmem_poolset_init(const char *path, struct rpmem_bench *mb,
	struct benchmark_args *args)
{
	struct pool_set *set;
	struct pool_replica *rep;
	struct remote_replica *remote;

	struct rpmem_pool_attr attr;
	memset(&attr, 0, sizeof(attr));
	int ret = snprintf(attr.signature, sizeof(attr.signature),
			"PMEMBENCH");
	if (ret < 0) {
		perror("snprintf");
		return -1;
	}

	/* read and validate poolset */
	if (util_poolset_read(&set, path)) {
		fprintf(stderr, "Invalid poolset file '%s'\n", path);
		return -1;
	}

	assert(set);
	if (set->nreplicas < 2) {
		fprintf(stderr, "No replicas defined\n");
		goto err_poolset_free;
	}

	if (set->remote == 0) {
		fprintf(stderr, "No remote replicas defined\n");
		goto err_poolset_free;
	}

	for (unsigned i = 1; i < set->nreplicas; ++i) {
		if (!set->replica[i]->remote) {
			fprintf(stderr, "Local replicas are not supported\n");
			goto err_poolset_free;
		}
	}

	/* read and validate master replica */
	rep = set->replica[0];

	assert(rep);
	assert(rep->remote == NULL);
	if (rep->nparts != 1) {
		fprintf(stderr, "Multipart master replicas "
				"are not supported\n");
		goto err_poolset_free;
	}

	if (rep->repsize < mb->min_size) {
		fprintf(stderr, "A master replica is too small (%zu < %zu)\n",
			rep->repsize, mb->min_size);
		goto err_poolset_free;
	}

	struct pool_set_part *part = &rep->part[0];
	if (rpmem_map_file(part->path, mb, rep->repsize - POOL_HDR_SIZE)) {
		perror(part->path);
		goto err_poolset_free;
	}

	mb->pool_size = mb->mapped_len - POOL_HDR_SIZE;
	mb->pool = (void *)((uintptr_t)mb->addrp + POOL_HDR_SIZE);

	/* prepare remote replicas */
	mb->nreplicas = set->nreplicas - 1;
	mb->nlanes = malloc(mb->nreplicas * sizeof(unsigned));
	if (mb->nlanes == NULL) {
		perror("malloc");
		goto err_unmap_file;
	}

	mb->rpp = malloc(mb->nreplicas * sizeof(RPMEMpool *));
	if (mb->rpp == NULL) {
		perror("malloc");
		goto err_free_lanes;
	}

	unsigned r;
	for (r = 0; r < mb->nreplicas; ++r) {
		remote = set->replica[r + 1]->remote;

		assert(remote);

		mb->nlanes[r] = args->n_threads;

		mb->rpp[r] = rpmem_create(remote->node_addr, remote->pool_desc,
			mb->pool, mb->pool_size, &mb->nlanes[r], &attr);
		if (!mb->rpp[r]) {
			perror("rpmem_create");
			goto err_rpmem_close;
		}

		if (mb->nlanes[r] < args->n_threads) {
			fprintf(stderr, "Number of threads too large for "
				"replica #%u (max: %u)\n", r, mb->nlanes[r]);
			r++; /* close current replica */
			goto err_rpmem_close;
		}
	}

	util_poolset_free(set);
	return 0;

err_rpmem_close:
	for (unsigned i = 0; i < r; i++)
		rpmem_close(mb->rpp[i]);
	free(mb->rpp);

err_free_lanes:
	free(mb->nlanes);

err_unmap_file:
	rpmem_unmap_file(mb);

err_poolset_free:
	util_poolset_free(set);
	return -1;
}

/*
 * rpmem_poolset_fini -- close opened local and remote replicas
 */
static void
rpmem_poolset_fini(struct rpmem_bench *mb)
{
	for (unsigned r = 0; r < mb->nreplicas; ++r) {
		rpmem_close(mb->rpp[r]);
	}

	rpmem_unmap_file(mb);
}

/*
 * rpmem_set_fsize -- compute file size based on benchmark arguments
 */
static void
rpmem_set_fsize(struct rpmem_bench *mb, enum operation_mode op_mode,
		struct benchmark_args *args)
{
	mb->csize_align = ALIGN_CL(mb->pargs->chunk_size);

	switch (op_mode) {
	case OP_MODE_STAT:
		mb->fsize = mb->csize_align * args->n_threads;
		mb->min_size = mb->fsize;
		break;
	case OP_MODE_SEQ:
	case OP_MODE_RAND:
		mb->fsize = mb->csize_align *
			    args->n_ops_per_thread * args->n_threads;
		mb->min_size = mb->fsize;
		break;
	case OP_MODE_SEQ_WRAP:
	case OP_MODE_RAND_WRAP:
		/* use actual file size and wrap chunks if necessary */
		mb->fsize = 0;
		/* at least one chunk per thread to avoid false sharing */
		mb->min_size = mb->csize_align * args->n_threads;
		break;
	default:
		assert(0);
	}

	if (mb->fsize) {
		mb->fsize = PAGE_ALIGNED_UP_SIZE(mb->fsize);
		mb->fsize += POOL_HDR_SIZE;
	}

	mb->min_size += POOL_HDR_SIZE;
}

/*
 * rpmem_init -- initialization function
 */
static int
rpmem_init(struct benchmark *bench, struct benchmark_args *args)
{
	assert(bench != NULL);
	assert(args != NULL);
	assert(args->opts != NULL);

	struct rpmem_bench *mb = malloc(sizeof(struct rpmem_bench));
	if (!mb) {
		perror("malloc");
		return -1;
	}

	mb->pargs = args->opts;
	mb->pargs->chunk_size = args->dsize;

	enum operation_mode op_mode = parse_op_mode(mb->pargs->mode);
	if (op_mode == OP_MODE_UNKNOWN) {
		fprintf(stderr, "Invalid operation mode argument '%s'\n",
			mb->pargs->mode);
		goto err_parse_mode;
	}

	rpmem_set_fsize(mb, op_mode, args);

	if (rpmem_poolset_init(args->fname, mb, args)) {
		goto err_poolset_init;
	}

	/* initialize offsets[] array depending on benchmark args */
	if (init_offsets(args, mb, op_mode) < 0) {
		goto err_init_offsets;
	}

	if (!mb->pargs->no_warmup) {
		if (do_warmup(mb) != 0) {
			fprintf(stderr, "do_warmup() function failed.\n");
			goto err_warmup;
		}
	}

	pmembench_set_priv(bench, mb);

	return 0;
err_warmup:
	free(mb->offsets);
err_init_offsets:
	rpmem_poolset_fini(mb);
err_poolset_init:
err_parse_mode:
	free(mb);
	return -1;
}

/*
 * rpmem_exit -- benchmark cleanup function
 */
static int
rpmem_exit(struct benchmark *bench, struct benchmark_args *args)
{
	struct rpmem_bench *mb =
		(struct rpmem_bench *)pmembench_get_priv(bench);
	rpmem_poolset_fini(mb);
	free(mb->offsets);
	free(mb);
	return 0;
}

/* Stores information about benchmark. */
static struct benchmark_info rpmem_info = {
	.name		= "rpmem_persist",
	.brief		= "Benchmark for rpmem_persist() operation",
	.init		= rpmem_init,
	.exit		= rpmem_exit,
	.multithread	= true,
	.multiops	= true,
	.operation	= rpmem_op,
	.measure_time	= true,
	.clos		= rpmem_clo,
	.nclos		= ARRAY_SIZE(rpmem_clo),
	.opts_size	= sizeof(struct rpmem_args),
	.rm_file	= true,
	.allow_poolset	= true,
};

REGISTER_BENCHMARK(rpmem_info);
