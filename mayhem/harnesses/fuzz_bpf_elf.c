/*
 * eBPF ELF loader: rte_bpf_elf_load() on the input as an ELF object file (section ".text"),
 * which walks the ELF sections/symbols/relocations (bpf_load_elf.c), patches external symbol
 * references, then validates and loads the program; an accepted program is run once with
 * rte_bpf_exec() on a 64-byte context.
 *
 * The loader takes a path, so the input is written to a private mkstemp() file under $TMPDIR
 * (removed again before returning). External symbols: fz_func (5 RAW args) and fz_var (64 bytes),
 * both reset before every input.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rte_bpf.h>
#include <rte_log.h>

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
	const char *tmp = getenv("TMPDIR");
	char path[4096];
	snprintf(path, sizeof(path), "%s/fuzz_bpf_elf.XXXXXX", tmp && *tmp ? tmp : "/tmp");
	int fd = mkstemp(path);
	if (fd < 0)
		abort();
	size_t off = 0;
	while (off < size) {
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0)
			abort();
		off += (size_t)w;
	}
	close(fd);

	uint8_t ctx[64];
	for (size_t i = 0; i < sizeof(ctx); i++)
		ctx[i] = (uint8_t)(i * 7 + 1);
	memset(fz_var, 0x5a, sizeof(fz_var));

	struct rte_bpf_prm prm = {
		.xsym = fz_xsym,
		.nb_xsym = 2,
		.prog_arg = { .type = RTE_BPF_ARG_PTR, .size = sizeof(ctx) },
	};
	struct rte_bpf *bpf = rte_bpf_elf_load(&prm, path, ".text");
	unlink(path);
	if (bpf != NULL) {
		volatile uint64_t rc = rte_bpf_exec(bpf, ctx);
		(void)rc;
		rte_bpf_destroy(bpf);
	}
	return 0;
}
