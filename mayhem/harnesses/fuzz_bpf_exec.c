/*
 * eBPF load + interpreter: rte_bpf_load() (validator, value-set evaluation, x86 JIT compile)
 * then rte_bpf_exec() (interpreter) on a 64-byte context.
 *
 * Input: byte 0 selects the program argument type (bit 0: RAW scalar instead of a 64-byte
 * pointer); the rest is an array of 8-byte struct rte_ebpf_insn.
 * Two external symbols are offered: a 5-argument function (xsym 0) and a 64-byte variable.
 * The context and the variable are reset before every input.
 */
#include <stdint.h>
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

/* Library log output only slows the fuzzer down; the level is fixed once and never changed. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	rte_log_set_global_level(RTE_LOG_CRIT);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1 + sizeof(struct rte_ebpf_insn))
		return 0;
	uint8_t mode = data[0];
	size_t nb = (size - 1) / sizeof(struct rte_ebpf_insn);
	if (nb > MAX_INS)
		nb = MAX_INS;

	struct rte_ebpf_insn ins[MAX_INS];
	memcpy(ins, data + 1, nb * sizeof(ins[0]));

	uint8_t ctx[64];
	for (size_t i = 0; i < sizeof(ctx); i++)
		ctx[i] = (uint8_t)(i * 7 + 1);
	memset(fz_var, 0x5a, sizeof(fz_var));

	struct rte_bpf_prm prm = {
		.ins = ins,
		.nb_ins = (uint32_t)nb,
		.xsym = fz_xsym,
		.nb_xsym = 2,
	};
	if (mode & 1)
		prm.prog_arg = (struct rte_bpf_arg){ .type = RTE_BPF_ARG_RAW, .size = sizeof(uint64_t) };
	else
		prm.prog_arg = (struct rte_bpf_arg){ .type = RTE_BPF_ARG_PTR, .size = sizeof(ctx) };

	struct rte_bpf *bpf = rte_bpf_load(&prm);
	if (bpf == NULL)
		return 0;
	void *arg = (mode & 1) ? (void *)(uintptr_t)0x123456789abcdef0ULL : (void *)ctx;
	volatile uint64_t rc = rte_bpf_exec(bpf, arg);
	(void)rc;
	rte_bpf_destroy(bpf);
	return 0;
}
