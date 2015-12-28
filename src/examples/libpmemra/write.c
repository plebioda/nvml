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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY LOG OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * write.c -- XXX
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libpmemra.h>
#include <time.h>
#include <unistd.h>

#define	NLANES		4
#define	BUFF_SIZE	256

int
main(int argc, char *argv[])
{
	char buff[NLANES * BUFF_SIZE];
	time_t timer;
	struct tm* tm_info;

	if (argc != 2) {
		printf("usage: %s <addr>", argv[0]);
		return 1;
	}

	PMEMraattr attr = {
		.nlanes = NLANES,
	};

	PMEMrapool *prp = pmemra_map(argv[1], "pool.set", buff, sizeof (buff), &attr);
	if (!prp) {
		perror("pmemra_map");
		return -1;
	}

	for (unsigned lane = 0; lane < NLANES; lane++) {
		time(&timer);
		tm_info = localtime(&timer);

		strftime(&buff[lane * BUFF_SIZE], BUFF_SIZE,
			"Hello World ! %Y:%m:%d %H:%M:%S", tm_info);
		printf("Lane %u: %s\n", lane, &buff[lane * BUFF_SIZE]);

		if (pmemra_persist_lane(prp, &buff[lane * BUFF_SIZE], BUFF_SIZE, lane)) {
			perror("pmemra_persist");
			return -1;
		}
		sleep(1);
	}
	pmemra_unmap(prp);
}
