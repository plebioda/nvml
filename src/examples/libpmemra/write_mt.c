/*
 * Copyright (c) 2016, Intel Corporation
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY LOG OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * write_mt.c -- XXX
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libpmemra.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define	TIMEOUT 1000

uint8_t *buff;
size_t buff_size;
size_t nthreads;
size_t size;
size_t count;
PMEMrapool *prp;


static void *
worker(void *arg)
{
	size_t id = (size_t)arg;
	uint8_t *ptr = &buff[id * size];
	memset(ptr, id, size);
	for (size_t i = 0; i < count; i++) {
		pmemra_persist_lane(prp, ptr, size, id, TIMEOUT);
	}

	return NULL;
}

int
main(int argc, char *argv[])
{
	if (argc != 5) {
		printf("usage: %s <addr> <threads> <size> <count>\n", argv[0]);
		return 1;
	}
	const char *addr = argv[1];
	nthreads = atoi(argv[2]);
	size = atoi(argv[3]);
	count = atoi(argv[4]);

	buff_size = size * nthreads;
	buff = malloc(buff_size);
	if (!buff) {
		perror("malloc");
		return -1;
	}

	struct pmemra_attr attr = {
		.nlanes = nthreads,
	};

	prp = pmemra_open(addr, "pool.set",
			buff, buff_size, &attr);
	if (!prp) {
		perror("pmemra_map");
		return -1;
	}

	pthread_t threads[nthreads];
	for (size_t id = 0; id < nthreads; id++)
		pthread_create(&threads[id], NULL, worker, (void *)id);

	for (size_t id = 0; id < nthreads; id++)
		pthread_join(threads[id], NULL);

	pmemra_close(prp);
}
