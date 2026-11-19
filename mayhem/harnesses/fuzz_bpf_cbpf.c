/*
 * Classic BPF (pcap filter) -> eBPF: rte_bpf_convert() translates a cBPF program (bpf_convert.c),
 * then rte_bpf_load() validates/JITs it and rte_bpf_exec() runs it on a packet mbuf, the way a
 * pcap-filter capture applies it.
 *
 * Input: byte 0 = number of cBPF instructions N (0..255), then N 8-byte struct bpf_insn
 * (code, jt, jf, k); the remaining bytes are the packet the filter is run on.
 * rte_bpf_convert() allocates with rte_zmalloc(), so the EAL is brought up once.
 */
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <pcap/bpf.h>
#include <rte_bpf.h>
#include <rte_malloc.h>
#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_eal_init();
	fuzz_pool_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return 0;
	size_t n = data[0];
	if (n == 0 || size < 1 + n * sizeof(struct bpf_insn))
		return 0;
	struct bpf_insn insns[256];
	memcpy(insns, data + 1, n * sizeof(struct bpf_insn));
	const uint8_t *pkt = data + 1 + n * sizeof(struct bpf_insn);
	size_t pkt_len = size - 1 - n * sizeof(struct bpf_insn);

	struct bpf_program prog = { .bf_len = (unsigned int)n, .bf_insns = insns };
	struct rte_bpf_prm *prm = rte_bpf_convert(&prog);
	if (prm == NULL)
		return 0;
	struct rte_bpf *bpf = rte_bpf_load(prm);
	if (bpf != NULL) {
		struct rte_mbuf *m = fuzz_make_pkt(pkt, pkt_len, 0);
		if (m != NULL) {
			volatile uint64_t rc = rte_bpf_exec(bpf, m);
			(void)rc;
			rte_pktmbuf_free(m);
		}
		rte_bpf_destroy(bpf);
	}
	rte_free(prm);
	fuzz_pool_check();
	return 0;
}
