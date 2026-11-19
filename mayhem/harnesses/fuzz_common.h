/* Shared helpers for the DPDK fuzz harnesses (mayhem/ layer). */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

/* Bring up the EAL once, without hugepages, PCI, shared config or telemetry: the harnesses only
 * need rte_malloc and an mbuf pool. lcore 0 is pinned to the first CPU of our affinity mask so
 * the EAL starts on any host cpuset. */
static void fuzz_eal_init(void)
{
	cpu_set_t set;
	int cpu = 0;
	if (sched_getaffinity(0, sizeof(set), &set) == 0) {
		for (int i = 0; i < CPU_SETSIZE; i++)
			if (CPU_ISSET(i, &set)) { cpu = i; break; }
	}
	static char lcores[64];
	snprintf(lcores, sizeof(lcores), "--lcores=0@%d", cpu);
	char *argv[] = { "fuzz", lcores, "--no-huge", "--no-pci", "--no-shconf", "--in-memory",
			 "--no-telemetry", "-m", "128", "--log-level=*:crit", NULL };
	int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;
	if (rte_eal_init(argc, argv) < 0) {
		fprintf(stderr, "rte_eal_init failed\n");
		abort();
	}
}

#define FUZZ_POOL_SIZE 4096
static struct rte_mempool *fuzz_pool;

static void fuzz_pool_init(void)
{
	fuzz_pool = rte_pktmbuf_pool_create("fuzz_pool", FUZZ_POOL_SIZE, 0, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	if (fuzz_pool == NULL) {
		fprintf(stderr, "rte_pktmbuf_pool_create failed\n");
		abort();
	}
}

/* Called at the end of every input: the harness frees everything it allocated, so a pool that is
 * not full again means the library leaked (or double-freed) mbufs. Without this check a drained
 * pool would silently turn every later input into a no-op. The pool has no per-lcore cache, so
 * the count is exact. */
static void fuzz_pool_check(void)
{
	unsigned int avail = rte_mempool_avail_count(fuzz_pool);
	if (avail != FUZZ_POOL_SIZE) {
		fprintf(stderr, "mbuf pool: %u of %u mbufs free after the input (leak or double free)\n",
			avail, FUZZ_POOL_SIZE);
		abort();
	}
}

/* Copy data into an mbuf chain whose segments hold at most seg bytes each (seg 0 = one segment
 * as large as the data room allows). Returns NULL if the pool is exhausted or data is too long. */
static struct rte_mbuf *fuzz_make_pkt(const uint8_t *data, size_t len, size_t seg)
{
	struct rte_mbuf *head = rte_pktmbuf_alloc(fuzz_pool);
	if (head == NULL)
		return NULL;
	size_t max = rte_pktmbuf_tailroom(head);
	if (seg == 0 || seg > max)
		seg = max;
	size_t off = 0;
	do {
		size_t n = len - off < seg ? len - off : seg;
		char *p = rte_pktmbuf_append(head, (uint16_t)n);
		if (p == NULL) { rte_pktmbuf_free(head); return NULL; }
		memcpy(p, data + off, n);
		off += n;
		if (off < len) {
			struct rte_mbuf *next = rte_pktmbuf_alloc(fuzz_pool);
			if (next == NULL || rte_pktmbuf_chain(head, next) != 0) {
				rte_pktmbuf_free(next);
				rte_pktmbuf_free(head);
				return NULL;
			}
		}
	} while (off < len);
	return head;
}
#endif
