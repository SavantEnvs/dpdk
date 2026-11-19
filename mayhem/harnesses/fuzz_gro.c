/*
 * Generic receive offload: rte_gro_reassemble_burst() merging a burst of packets with every GRO
 * type enabled (TCP/IPv4, TCP/IPv6, UDP/IPv4 fragments, VXLAN-encapsulated TCP and UDP).
 *
 * Input: a sequence of records [u16 little-endian length][length bytes], each an Ethernet frame
 * (at most 32). As a receive path does before GRO, each frame's packet_type and header lengths
 * come from rte_net_get_ptype() (outer lengths for tunnelled frames).
 */
#include <stdint.h>
#include <rte_gro.h>
#include <rte_net.h>
#include "fuzz_common.h"

#define MAX_PKTS 32

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_eal_init();
	fuzz_pool_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rte_mbuf *pkts[MAX_PKTS];
	uint16_t n = 0;
	size_t off = 0;
	while (off + 2 <= size && n < MAX_PKTS) {
		size_t len = (size_t)data[off] | ((size_t)data[off + 1] << 8);
		off += 2;
		if (len > size - off)
			len = size - off;
		struct rte_mbuf *m = fuzz_make_pkt(data + off, len, 0);
		off += len;
		if (m == NULL)
			continue;
		struct rte_net_hdr_lens hl;
		memset(&hl, 0, sizeof(hl));
		m->packet_type = rte_net_get_ptype(m, &hl, RTE_PTYPE_ALL_MASK);
		if (m->packet_type & RTE_PTYPE_TUNNEL_MASK) {
			m->outer_l2_len = hl.l2_len;
			m->outer_l3_len = hl.l3_len;
			m->l2_len = hl.l4_len + hl.tunnel_len + hl.inner_l2_len;
			m->l3_len = hl.inner_l3_len;
			m->l4_len = hl.inner_l4_len;
		} else {
			m->l2_len = hl.l2_len;
			m->l3_len = hl.l3_len;
			m->l4_len = hl.l4_len;
		}
		pkts[n++] = m;
	}
	if (n == 0)
		return 0;
	struct rte_gro_param param = {
		.gro_types = RTE_GRO_TCP_IPV4 | RTE_GRO_IPV4_VXLAN_TCP_IPV4 | RTE_GRO_UDP_IPV4 |
			     RTE_GRO_IPV4_VXLAN_UDP_IPV4 | RTE_GRO_TCP_IPV6,
		.max_flow_num = 4,
		.max_item_per_flow = 8,
	};
	uint16_t nb = rte_gro_reassemble_burst(pkts, n, &param);
	for (uint16_t i = 0; i < nb; i++)
		rte_pktmbuf_free(pkts[i]);
	fuzz_pool_check();
	return 0;
}
