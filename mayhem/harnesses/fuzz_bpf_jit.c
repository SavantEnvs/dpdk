/*
 * eBPF x86 JIT vs interpreter, differentially: rte_bpf_load() then, when the JIT produced native
 * code (rte_bpf_get_jit), run both the interpreter (rte_bpf_exec) and the JIT-ed function on
 * identical copies of the context and abort() if the return value or the memory they wrote differ.
 * The validator only accepts programs it proved memory-safe and loop-free, so both engines must
 * agree on every accepted program; a mismatch is a JIT (or interpreter) miscompilation.
 *
 * Input: byte 0 is ignored (kept so seeds are shared with fuzz_bpf_exec); the rest is an array of
 * 8-byte struct rte_ebpf_insn. The program argument is a pointer to a 64-byte context.
 * Two external symbols are offered: a 5-argument function (xsym 0) and a 64-byte variable.
 * The context and the variable are reset before every input.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_bpf.h>
#include <rte_log.h>

#define MAX_INS 4096

static uint8_t fz_var[64];

static uint64_t fz_func(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
	return (a ^ (b << 1)) + (c * 3) - (d | e);
}

static const struct rte_bpf_xsym fz_xsym[] = {
	{
		.name = "fz_func",
		.type = RTE_BPF_XTYPE_FUNC,
		.func = {
			.val = fz_func,
			.nb_args = 5,
			.args = {
				[0] = { .type = RTE_BPF_ARG_RAW, .size = sizeof(uint64_t) },
				[1] = { .type = RTE_BPF_ARG_RAW, .size = sizeof(uint64_t) },
				[2] = { .type = RTE_BPF_ARG_RAW, .size = sizeof(uint64_t) },
				[3] = { .type = RTE_BPF_ARG_RAW, .size = sizeof(uint64_t) },
				[4] = { .type = RTE_BPF_ARG_RAW, .size = sizeof(uint64_t) },
			},
			.ret = { .type = RTE_BPF_ARG_RAW, .size = sizeof(uint64_t) },
		},
	},
	{
		.name = "fz_var",
		.type = RTE_BPF_XTYPE_VAR,
		.var = {
			.val = fz_var,
			.desc = { .type = RTE_BPF_ARG_PTR, .size = sizeof(fz_var) },
		},
	},
};

static void reset(uint8_t *ctx, size_t n)
{
	for (size_t i = 0; i < n; i++)
		ctx[i] = (uint8_t)(i * 7 + 1);
	memset(fz_var, 0x5a, sizeof(fz_var));
}

/* Library log output only slows the fuzzer down; the level is fixed once and never changed. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	rte_log_set_global_level(RTE_LOG_CRIT);
	return 0;
}

/* JIT-ed code is a bare mmap()ed page with no UBSan function-type prologue: UBSan's `function`
 * check would read the 8 bytes before the entry (unmapped) on every call, so it is off for this
 * one indirect call only. */
__attribute__((no_sanitize("function")))
static uint64_t call_jit(uint64_t (*f)(void *), void *ctx)
{
	return f(ctx);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1 + sizeof(struct rte_ebpf_insn))
		return 0;
	size_t nb = (size - 1) / sizeof(struct rte_ebpf_insn);
	if (nb > MAX_INS)
		nb = MAX_INS;

	struct rte_ebpf_insn ins[MAX_INS];
	memcpy(ins, data + 1, nb * sizeof(ins[0]));

	struct rte_bpf_prm prm = {
		.ins = ins,
		.nb_ins = (uint32_t)nb,
		.xsym = fz_xsym,
		.nb_xsym = 2,
		.prog_arg = { .type = RTE_BPF_ARG_PTR, .size = 64 },
	};
	struct rte_bpf *bpf = rte_bpf_load(&prm);
	if (bpf == NULL)
		return 0;

	struct rte_bpf_jit jit;
	if (rte_bpf_get_jit(bpf, &jit) == 0 && jit.func != NULL) {
		uint8_t ctx_i[64], ctx_j[64], var_i[64];
		reset(ctx_i, sizeof(ctx_i));
		uint64_t rc_i = rte_bpf_exec(bpf, ctx_i);
		memcpy(var_i, fz_var, sizeof(var_i));

		reset(ctx_j, sizeof(ctx_j));
		uint64_t rc_j = call_jit(jit.func, ctx_j);

		if (rc_i != rc_j || memcmp(ctx_i, ctx_j, sizeof(ctx_i)) != 0 ||
		    memcmp(var_i, fz_var, sizeof(var_i)) != 0) {
			fprintf(stderr, "BPF JIT/interpreter mismatch: interp rc=%#llx jit rc=%#llx "
				"ctx %s var %s\n", (unsigned long long)rc_i, (unsigned long long)rc_j,
				memcmp(ctx_i, ctx_j, sizeof(ctx_i)) ? "differs" : "same",
				memcmp(var_i, fz_var, sizeof(var_i)) ? "differs" : "same");
			abort();
		}
	}
	rte_bpf_destroy(bpf);
	return 0;
}
