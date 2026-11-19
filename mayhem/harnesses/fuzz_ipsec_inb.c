/*
 * IPsec inbound ESP processing on the inline-crypto path: rte_ipsec_pkt_process() on a session of
 * type RTE_SECURITY_ACTION_TYPE_INLINE_CRYPTO, i.e. inline_inb_tun_pkt_process() /
 * inline_inb_trs_pkt_process() -> esp_inb_pkt_process(): ESP trailer parsing (pad length, pad
 * bytes, next header), ESP/IV/ICV removal over segmented mbufs, inner/outer L3 header rewrite,
 * and the anti-replay window / ESN update. On this path the NIC has already decrypted the packet,
 * so every byte the library parses is attacker-controlled.
 *
 * The session is set up the way DPDK's own app/test/test_ipsec.c inline tests do it: a real SA
 * from rte_ipsec_sa_init() and dummy security session/context handles, which
 * rte_ipsec_session_prepare() only checks for non-NULL on the inline-crypto path (ses.c).
 *
 * Input:
 *   byte 0   SA config: bits 0-1 mode (0/3 transport, 1 tunnel IPv4, 2 tunnel IPv6),
 *            bit 2 inner/transport proto IPv6 (else IPv4), bit 3 ESN, bit 4 RTE_IPSEC_SAFLAG_SQN_ATOM,
 *            bits 5-7 algorithm (NULL/HMAC-SHA1, AES-CBC/HMAC-SHA256, AES-CTR/HMAC-SHA1,
 *            3DES-CBC/HMAC-MD5, AES-GCM, AES-CCM, CHACHA20-POLY1305, AES-CBC/HMAC-SHA512).
 *            AES-GMAC is left out: rte_ipsec_sa_init() takes &xfn->cipher with xfn == NULL for
 *            it (sa.c fill_crypto_xform), UB that UBSan reports on SA setup, before any packet.
 *   byte 1   replay window size index
 *   bytes 2-9  initial (E)SN, little endian
 *   then records [u16 LE length][u8 flags][length bytes]: one Ethernet frame each. flags bit 0
 *   sets RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED (NIC-reported failure), bits 1-4 pick an mbuf
 *   segment size of 128..1088 bytes (multi-segment packets) or one segment. Records are processed in bursts of up to 32.
 * rte_ipsec_pkt_process() requires l2_len/l3_len to be set correctly (rte_ipsec.h); they come
 * from rte_net_get_ptype(), and a frame whose L2/L3 headers are not IPv4/IPv6 or do not fit in
 * the frame is not passed to the library. The SA and all mbufs are created and freed per input.
 */
#include <stdint.h>
#include <netinet/in.h>
#include <rte_ip.h>
#include <rte_net.h>
#include <rte_crypto_sym.h>
#include <rte_security.h>
#include <rte_ipsec.h>
#include <rte_malloc.h>
#include "fuzz_common.h"

#define BURST 32

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_eal_init();
	fuzz_pool_init();
	return 0;
}

/* Opaque handles: rte_ipsec_session_prepare() stores the session pointer in the security
 * session's opaque_data (rte_security_session_opaque_data_set) and never touches the ctx. */
static uint64_t dummy_sec_ses[16] __attribute__((aligned(64)));
static uint64_t dummy_sec_ctx[16] __attribute__((aligned(64)));

static void setup_xforms(unsigned int algo, struct rte_crypto_sym_xform *x)
{
	memset(x, 0, 2 * sizeof(*x));
	switch (algo) {
	case 4: case 5: case 6:
		x[0].type = RTE_CRYPTO_SYM_XFORM_AEAD;
		x[0].aead.op = RTE_CRYPTO_AEAD_OP_DECRYPT;
		x[0].aead.algo = algo == 4 ? RTE_CRYPTO_AEAD_AES_GCM :
				 algo == 5 ? RTE_CRYPTO_AEAD_AES_CCM :
					     RTE_CRYPTO_AEAD_CHACHA20_POLY1305;
		x[0].aead.digest_length = 16;
		x[0].aead.aad_length = 8;
		x[0].aead.iv.length = 12;
		return;
	}
	/* inbound non-AEAD order: AUTH then CIPHER (sa.c fill_crypto_xform) */
	static const enum rte_crypto_auth_algorithm auth[] = {
		RTE_CRYPTO_AUTH_SHA1_HMAC, RTE_CRYPTO_AUTH_SHA256_HMAC,
		RTE_CRYPTO_AUTH_SHA1_HMAC, RTE_CRYPTO_AUTH_MD5_HMAC,
		0, 0, 0, RTE_CRYPTO_AUTH_SHA512_HMAC };
	static const uint16_t icv[] = { 12, 16, 12, 12, 0, 0, 0, 32 };
	static const enum rte_crypto_cipher_algorithm cipher[] = {
		RTE_CRYPTO_CIPHER_NULL, RTE_CRYPTO_CIPHER_AES_CBC,
		RTE_CRYPTO_CIPHER_AES_CTR, RTE_CRYPTO_CIPHER_3DES_CBC,
		0, 0, 0, RTE_CRYPTO_CIPHER_AES_CBC };
	x[0].type = RTE_CRYPTO_SYM_XFORM_AUTH;
	x[0].auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
	x[0].auth.algo = auth[algo];
	x[0].auth.digest_length = icv[algo];
	x[0].next = &x[1];
	x[1].type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	x[1].cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	x[1].cipher.algo = cipher[algo];
}

static void run_burst(struct rte_ipsec_session *ss, struct rte_mbuf **mb, uint16_t n)
{
	if (n == 0)
		return;
	(void)rte_ipsec_pkt_process(ss, mb, n);
	/* Good and bad mbufs both stay owned by the caller (rte_ipsec.h). */
	for (uint16_t i = 0; i < n; i++)
		rte_pktmbuf_free(mb[i]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint32_t win[] = { 0, 32, 64, 128, 256, 1024, 4096, 63 };
	if (size < 10)
		return -1;
	uint8_t cfg = data[0];
	uint64_t sqn = 0;
	for (int i = 0; i < 8; i++)
		sqn |= (uint64_t)data[2 + i] << (8 * i);

	struct rte_crypto_sym_xform xf[2];
	setup_xforms(cfg >> 5, xf);

	struct rte_ipsec_sa_prm prm;
	memset(&prm, 0, sizeof(prm));
	prm.ipsec_xform.spi = 0x1234;
	prm.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	prm.ipsec_xform.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	prm.ipsec_xform.options.esn = (cfg >> 3) & 1;
	prm.ipsec_xform.replay_win_sz = win[data[1] & 7];
	prm.ipsec_xform.esn.value = sqn;
	prm.flags = (cfg & 0x10) ? RTE_IPSEC_SAFLAG_SQN_ATOM : 0;
	prm.crypto_xform = xf;
	uint8_t inner = (cfg & 4) ? IPPROTO_IPV6 : IPPROTO_IPIP;
	unsigned int mode = cfg & 3;
	if (mode == 1 || mode == 2) {
		prm.ipsec_xform.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
		prm.ipsec_xform.tunnel.type = mode == 1 ? RTE_SECURITY_IPSEC_TUNNEL_IPV4 :
							  RTE_SECURITY_IPSEC_TUNNEL_IPV6;
		prm.tun.next_proto = inner;
	} else {
		prm.ipsec_xform.mode = RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT;
		prm.trs.proto = inner;
	}

	int sz = rte_ipsec_sa_size(&prm);
	if (sz <= 0)
		abort();  /* every config this harness builds is valid */
	struct rte_ipsec_sa *sa = rte_zmalloc(NULL, sz, RTE_CACHE_LINE_SIZE);
	if (sa == NULL)
		abort();
	int rc = rte_ipsec_sa_init(sa, &prm, sz);
	if (rc <= 0 || rc > sz) {
		fprintf(stderr, "rte_ipsec_sa_init(cfg=0x%02x) = %d\n", cfg, rc);
		abort();
	}
	struct rte_ipsec_session ss;
	memset(&ss, 0, sizeof(ss));
	ss.sa = sa;
	ss.type = RTE_SECURITY_ACTION_TYPE_INLINE_CRYPTO;
	ss.security.ses = (struct rte_security_session *)dummy_sec_ses;
	ss.security.ctx = (struct rte_security_ctx *)dummy_sec_ctx;
	if (rte_ipsec_session_prepare(&ss) != 0)
		abort();

	struct rte_mbuf *mb[BURST];
	uint16_t n = 0;
	size_t off = 10;
	while (off + 3 <= size) {
		size_t len = (size_t)data[off] | ((size_t)data[off + 1] << 8);
		uint8_t flags = data[off + 2];
		off += 3;
		if (len > size - off)
			len = size - off;
		const uint8_t *p = data + off;
		off += len;
		/* 0 = one segment; else 128..1088-byte segments, the range of real mbuf data rooms */
		size_t k = (flags >> 1) & 0xf;
		size_t seg = k ? 64 + k * 64 : 0;
		struct rte_mbuf *m = fuzz_make_pkt(p, len, seg);
		if (m == NULL)
			continue;
		struct rte_net_hdr_lens hl;
		memset(&hl, 0, sizeof(hl));
		uint32_t pt = rte_net_get_ptype(m, &hl, RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
		if ((!RTE_ETH_IS_IPV4_HDR(pt) && !RTE_ETH_IS_IPV6_HDR(pt)) ||
		    (RTE_ETH_IS_IPV4_HDR(pt) && hl.l3_len < sizeof(struct rte_ipv4_hdr)) ||
		    (size_t)hl.l2_len + hl.l3_len > len) {
			rte_pktmbuf_free(m);
			continue;
		}
		m->packet_type = pt;
		m->l2_len = hl.l2_len;
		m->l3_len = hl.l3_len;
		m->ol_flags |= RTE_MBUF_F_RX_SEC_OFFLOAD;
		if (flags & 1)
			m->ol_flags |= RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED;
		mb[n++] = m;
		if (n == BURST) {
			run_burst(&ss, mb, n);
			n = 0;
		}
	}
	run_burst(&ss, mb, n);

	rte_ipsec_sa_fini(sa);
	rte_free(sa);
	fuzz_pool_check();
	return 0;
}
