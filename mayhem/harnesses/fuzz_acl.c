/*
 * Packet classifier: rte_acl_add_rules() + rte_acl_build() (rule trie construction and run-time
 * node generation, acl_bld.c / acl_gen.c) over an IPv4 5-tuple field layout, then
 * rte_acl_classify_alg() of a batch of keys with every classify implementation the CPU supports
 * (scalar, SSE, AVX2, AVX512). All implementations must return the same results for the same
 * built context; a disagreement aborts.
 *
 * Input: byte 0 = number of rules R (1..16), byte 1 = categories selector; then R rules of
 * sizeof(struct acl5_rule) raw bytes (category mask, priority, userdata, 5 x value/mask-range;
 * rte_acl_add_rules() itself rejects invalid ones); the remaining bytes are 16-byte keys
 * (at most 32). A fresh ACL context is created and freed per input.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_acl.h>
#include "fuzz_common.h"

RTE_ACL_RULE_DEF(acl5_rule, 5);

struct key5 {
	uint8_t proto;
	uint32_t src;
	uint32_t dst;
	uint16_t sport;
	uint16_t dport;
} __attribute__((packed));

#define MAX_RULES 16
#define MAX_KEYS 32
#define KEY_SZ 16

static const struct rte_acl_field_def defs[5] = {
	{ .type = RTE_ACL_FIELD_TYPE_BITMASK, .size = 1, .field_index = 0, .input_index = 0,
	  .offset = offsetof(struct key5, proto) },
	{ .type = RTE_ACL_FIELD_TYPE_MASK, .size = 4, .field_index = 1, .input_index = 1,
	  .offset = offsetof(struct key5, src) },
	{ .type = RTE_ACL_FIELD_TYPE_MASK, .size = 4, .field_index = 2, .input_index = 2,
	  .offset = offsetof(struct key5, dst) },
	{ .type = RTE_ACL_FIELD_TYPE_RANGE, .size = 2, .field_index = 3, .input_index = 3,
	  .offset = offsetof(struct key5, sport) },
	{ .type = RTE_ACL_FIELD_TYPE_RANGE, .size = 2, .field_index = 4, .input_index = 3,
	  .offset = offsetof(struct key5, dport) },
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_eal_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return 0;
	uint32_t nr = (uint32_t)(data[0] % MAX_RULES) + 1;
	/* categories must be 1 or a multiple of RTE_ACL_RESULTS_MULTIPLIER, <= RTE_ACL_MAX_CATEGORIES */
	static const uint32_t cats[] = { 1, 4, 8, 16 };
	uint32_t ncat = cats[data[1] & 3];
	if (size < 2 + nr * sizeof(struct acl5_rule))
		return 0;
	struct acl5_rule rules[MAX_RULES];
	memcpy(rules, data + 2, nr * sizeof(struct acl5_rule));
	/* rte_acl.h (struct rte_acl_field): for a MASK field mask_range is the prefix length
	 * ("1.2.3.4/32 value=0x1020304, mask_range=32"), so a rule with a longer prefix than the
	 * field has bits is outside the API contract. */
	for (uint32_t i = 0; i < nr; i++)
		for (int f = 0; f < 5; f++)
			if (defs[f].type == RTE_ACL_FIELD_TYPE_MASK &&
			    rules[i].field[f].mask_range.u64 > defs[f].size * 8u)
				return -1;
	const uint8_t *kp = data + 2 + nr * sizeof(struct acl5_rule);
	size_t nk = (size - 2 - nr * sizeof(struct acl5_rule)) / KEY_SZ;
	if (nk > MAX_KEYS)
		nk = MAX_KEYS;

	struct rte_acl_param prm = {
		.name = "fuzz_acl",
		.socket_id = SOCKET_ID_ANY,
		.rule_size = RTE_ACL_RULE_SZ(5),
		.max_rule_num = MAX_RULES,
	};
	struct rte_acl_ctx *ctx = rte_acl_create(&prm);
	if (ctx == NULL)
		abort();
	if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)rules, nr) == 0) {
		struct rte_acl_config cfg = { .num_categories = ncat, .num_fields = 5,
					      .max_size = 64 << 20 };
		memcpy(cfg.defs, defs, sizeof(defs));
		if (rte_acl_build(ctx, &cfg) == 0 && nk > 0) {
			uint8_t keys[MAX_KEYS][KEY_SZ];
			const uint8_t *kptr[MAX_KEYS];
			for (size_t i = 0; i < nk; i++) {
				memcpy(keys[i], kp + i * KEY_SZ, KEY_SZ);
				kptr[i] = keys[i];
			}
			static const enum rte_acl_classify_alg algs[] = {
				RTE_ACL_CLASSIFY_SCALAR, RTE_ACL_CLASSIFY_SSE, RTE_ACL_CLASSIFY_AVX2,
				RTE_ACL_CLASSIFY_AVX512X16, RTE_ACL_CLASSIFY_AVX512X32,
			};
			uint32_t ref[MAX_KEYS * RTE_ACL_MAX_CATEGORIES];
			uint32_t res[MAX_KEYS * RTE_ACL_MAX_CATEGORIES];
			int have_ref = 0;
			for (size_t a = 0; a < sizeof(algs) / sizeof(algs[0]); a++) {
				memset(res, 0, sizeof(res));
				if (rte_acl_classify_alg(ctx, kptr, res, (uint32_t)nk, ncat, algs[a]) != 0)
					continue;
				if (!have_ref) {
					memcpy(ref, res, sizeof(ref));
					have_ref = 1;
				} else if (memcmp(ref, res, nk * ncat * sizeof(uint32_t)) != 0) {
					fprintf(stderr, "ACL classify mismatch: alg %d vs scalar\n", algs[a]);
					abort();
				}
			}
		}
	}
	rte_acl_free(ctx);
	return 0;
}
