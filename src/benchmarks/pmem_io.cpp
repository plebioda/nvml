#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <libpmem.h>
#include <string.h>
#include <emmintrin.h>
#include <immintrin.h>

#include "benchmark.hpp"

#define PAGE_SIZE 4096

struct pmem_io {
	void *addr;
	size_t len;
	int is_pmem;
	int prefault;
	size_t op_size;
	size_t op_cnt;
};

struct pmem_io_args {
	char *op;
};

struct pmem_io_data {
	union {
		uint64_t d64[8];
	} cl;
};

static struct benchmark_info pmem_io_info;

static int
pmem_io_op_mov_persist(struct benchmark *bench, struct operation_info *info)
{
	struct pmem_io *pio = (struct pmem_io *)pmembench_get_priv(bench);
	uint8_t *data = (uint8_t *)pio->addr;
	size_t idx = (info->index * info->args->dsize) % pio->len;
	struct pmem_io_data *pd = (struct pmem_io_data *)&data[idx];

	for (size_t i = 0; i < pio->op_cnt; i++) {
		pd[0].cl.d64[i] = 1;
	}

	pmem_persist(&pd[0].cl.d64[0], pio->op_size * pio->op_cnt);

	return 0;
}

static int
pmem_io_op_mov_clflush(struct benchmark *bench, struct operation_info *info)
{
	struct pmem_io *pio = (struct pmem_io *)pmembench_get_priv(bench);
	uint8_t *data = (uint8_t *)pio->addr;
	size_t idx = (info->index * info->args->dsize) % pio->len;
	struct pmem_io_data *pd = (struct pmem_io_data *)&data[idx];

	for (size_t i = 0; i < pio->op_cnt; i++) {
		pd[0].cl.d64[i] = 1;
	}

	for (size_t i = 0; i < pio->op_cnt; i++) {
		_mm_clflush(&pd[0].cl.d64[i]);
	}

	return 0;
}

static struct ops {
	const char *name;
	size_t size;
	int (*op)(struct benchmark *, struct operation_info *);
} pmem_io_ops[] {
	{"mov+persist",		8,		pmem_io_op_mov_persist},
	{"mov+clflush",		8,		pmem_io_op_mov_clflush},

	{NULL, 0, NULL}
};

static void
pmem_io_init_op(struct benchmark *bench, struct benchmark_args *args)
{
	struct ops *ops = pmem_io_ops;
	struct pmem_io_args *arg = (struct pmem_io_args *)args->opts;
	struct pmem_io *pio = (struct pmem_io *)pmembench_get_priv(bench);
	while (ops->name != NULL) {
		if (strcmp(arg->op, ops->name) == 0) {
			pmem_io_info.operation = ops->op;
			pio->op_size = ops->size;
			break;
		}

		ops++;
	}

	pio->op_cnt = args->dsize / pio->op_size;
}

static int
pmem_io_init(struct benchmark *bench, struct benchmark_args *args)
{
	struct pmem_io *pio = (struct pmem_io *)malloc(sizeof(*pio));
	assert(pio != NULL);
	pio->prefault = 1;

	pmembench_set_priv(bench, pio);

	int flags = 0;
	if (args->fsize)
		flags |= PMEM_FILE_CREATE;

	pio->addr = pmem_map_file(args->fname, args->fsize, flags, args->fmode,
			&pio->len, &pio->is_pmem);
	assert(pio->addr != NULL);

	if (pio->prefault) {
		uint8_t *p = (uint8_t *)pio->addr;
		for (size_t i = 0; i < pio->len; i += PAGE_SIZE)
			p[i] = 0;
	}


	pmem_io_init_op(bench, args);

	return 0;
}

static int
pmem_io_exit(struct benchmark *bench, struct benchmark_args *args)
{
	struct pmem_io *pio = (struct pmem_io *)pmembench_get_priv(bench);

	pmem_unmap(pio->addr, pio->len);
	free(pio);

	return 0;
}

static struct benchmark_clo pmem_io_clo[1];

CONSTRUCTOR(pmem_io_costructor)
void
pmem_io_costructor(void)
{
	pmem_io_clo[0].opt_long = "op";
	pmem_io_clo[0].descr = "operation";
	pmem_io_clo[0].type = CLO_TYPE_STR;
	pmem_io_clo[0].off = clo_field_offset(struct pmem_io_args, op);
	pmem_io_clo[0].def = "mov+persist";

	pmem_io_info.name = "pmem_io";
	pmem_io_info.brief = "Benchmark for different patterns of accessing PMEM";
	pmem_io_info.init = pmem_io_init;
	pmem_io_info.exit = pmem_io_exit;
	pmem_io_info.multithread = true;
	pmem_io_info.multiops = true;
	pmem_io_info.clos = pmem_io_clo;
	pmem_io_info.nclos = ARRAY_SIZE(pmem_io_clo);
	pmem_io_info.opts_size = sizeof(struct pmem_io_args);
//	pmem_.rm_file = true;
	pmem_io_info.allow_poolset = false;
	REGISTER_BENCHMARK(pmem_io_info);
}
