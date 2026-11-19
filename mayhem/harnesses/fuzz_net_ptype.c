/*
 * Packet type parser: rte_net_get_ptype() over an Ethernet frame (L2/VLAN/QinQ/MPLS, IPv4 options,
 * IPv6 extension headers, L4, and tunnels: GRE, NVGRE, VXLAN, GENEVE, GTP, IP-in-IP ...), the way a
 * PMD or application classifies received packets.
 *
 * Input: byte 0 selects the mbuf layout (0 = one segment, else segments of 8*byte0 bytes — real
 * mbuf data rooms are 8-byte multiples — which exercises the rte_pktmbuf_read() copy path across segment boundaries); the rest is the frame.
 */
#include <stdint.h>
#include <rte_net.h>
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
	struct rte_mbuf *m = fuzz_make_pkt(data + 1, size - 1, (size_t)data[0] * 8);
	if (m == NULL)
		return 0;
	struct rte_net_hdr_lens hdr_lens;
	volatile uint32_t pt = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
	(void)pt;
	pt = rte_net_get_ptype(m, NULL, RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK);
	rte_pktmbuf_free(m);
	fuzz_pool_check();
	return 0;
}
