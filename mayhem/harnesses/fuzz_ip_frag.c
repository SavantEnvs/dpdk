/*
 * IPv4/IPv6 fragment reassembly: rte_ipv4_frag_reassemble_packet() and
 * rte_ipv6_frag_reassemble_packet() feeding a fresh reassembly table (rte_ip_frag_table_create)
 * a sequence of fragments, with entry expiry, death-row freeing and table teardown.
 *
 * Input: a sequence of records [u16 little-endian length][length bytes], each an IP packet
 * starting at its IP header (l2_len = 0). Per the API contract the caller sets l3_len from the
 * header (IPv4: IHL*4; IPv6: fixed header + fragment extension header), so a record too short to
 * hold that header, or one that is not a fragment, is not passed to the library.
 * The table and death row are created and destroyed per input.
 */
#include <stdint.h>
#include <netinet/in.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_cycles.h>
#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_eal_init();
	fuzz_pool_init();
	return 0;
}

static struct rte_ip_frag_death_row dr;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rte_ip_frag_tbl *tbl = rte_ip_frag_table_create(16, 4, 64, 8, SOCKET_ID_ANY);
	if (tbl == NULL)
		abort();
	dr.cnt = 0;
	uint64_t tms = 0;
	size_t off = 0;
	while (off + 2 <= size) {
		size_t len = (size_t)data[off] | ((size_t)data[off + 1] << 8);
		off += 2;
		if (len > size - off)
			len = size - off;
		const uint8_t *p = data + off;
		off += len;
		tms++;
		if (len < 1)
			continue;
		struct rte_mbuf *m = fuzz_make_pkt(p, len, 0);
		if (m == NULL)
			continue;
		m->l2_len = 0;
		struct rte_mbuf *out = NULL;
		if ((p[0] >> 4) == 4 && len >= sizeof(struct rte_ipv4_hdr)) {
			struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
			size_t l3 = (size_t)(ip->version_ihl & 0xf) * 4;
			if (l3 < sizeof(*ip) || l3 > len || !rte_ipv4_frag_pkt_is_fragmented(ip)) {
				rte_pktmbuf_free(m);
				continue;
			}
			m->l3_len = (uint16_t)l3;
			out = rte_ipv4_frag_reassemble_packet(tbl, &dr, m, tms, ip);
		} else if ((p[0] >> 4) == 6 &&
			   len >= sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_ipv6_fragment_ext)) {
			struct rte_ipv6_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
			struct rte_ipv6_fragment_ext *fh = rte_ipv6_frag_get_ipv6_fragment_header(ip);
			if (fh == NULL) {
				rte_pktmbuf_free(m);
				continue;
			}
			m->l3_len = sizeof(*ip) + sizeof(*fh);
			out = rte_ipv6_frag_reassemble_packet(tbl, &dr, m, tms, ip, fh);
		} else {
			rte_pktmbuf_free(m);
			continue;
		}
		if (out != NULL)
			rte_pktmbuf_free(out);
		rte_ip_frag_free_death_row(&dr, 0);
	}
	rte_ip_frag_table_del_expired_entries(tbl, &dr, tms + 1000);
	rte_ip_frag_free_death_row(&dr, 0);
	rte_ip_frag_table_destroy(tbl);
	fuzz_pool_check();
	return 0;
}
