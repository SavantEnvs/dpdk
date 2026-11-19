/*
 * INI configuration parser: rte_cfgfile_load() / rte_cfgfile_load_with_params() on the input as
 * a configuration file, then walk every section and entry through the query API, as DPDK apps
 * (e.g. the QoS scheduler config) consume it.
 *
 * Input: byte 0 picks the parse flags (bit 0: CFG_FLAG_GLOBAL_SECTION, bit 1:
 * CFG_FLAG_EMPTY_VALUES, bit 2: use load_with_params with comment character byte 1); the rest is
 * the file, written to a private mkstemp() file under $TMPDIR and removed before returning.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rte_cfgfile.h>
#include <rte_log.h>

static void walk(struct rte_cfgfile *cfg)
{
	int ns = rte_cfgfile_num_sections(cfg, NULL, 0);
	if (ns <= 0)
		return;
	if (ns > 256)
		ns = 256;
	char **names = calloc((size_t)ns, sizeof(char *));
	for (int i = 0; i < ns; i++)
		names[i] = malloc(CFG_NAME_LEN);
	int got = rte_cfgfile_sections(cfg, names, ns);
	for (int i = 0; i < got; i++) {
		int ne = rte_cfgfile_section_num_entries(cfg, names[i]);
		(void)rte_cfgfile_has_section(cfg, names[i]);
		if (ne > 0) {
			struct rte_cfgfile_entry *e = calloc((size_t)ne, sizeof(*e));
			int k = rte_cfgfile_section_entries(cfg, names[i], e, ne);
			for (int j = 0; j < k; j++) {
				const char *v = rte_cfgfile_get_entry(cfg, names[i], e[j].name);
				if (v != NULL)
					(void)strlen(v);
				(void)rte_cfgfile_has_entry(cfg, names[i], e[j].name);
			}
			free(e);
		}
		char sname[CFG_NAME_LEN];
		struct rte_cfgfile_entry e1;
		(void)rte_cfgfile_section_entries_by_index(cfg, i, sname, &e1, 1);
	}
	for (int i = 0; i < ns; i++)
		free(names[i]);
	free(names);
}

/* Library log output only slows the fuzzer down; the level is fixed once and never changed. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	rte_log_set_global_level(RTE_LOG_CRIT);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return 0;
	uint8_t mode = data[0];
	char comment = (char)data[1];
	const char *tmp = getenv("TMPDIR");
	char path[4096];
	snprintf(path, sizeof(path), "%s/fuzz_cfgfile.XXXXXX", tmp && *tmp ? tmp : "/tmp");
	int fd = mkstemp(path);
	if (fd < 0)
		abort();
	size_t off = 2;
	while (off < size) {
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0)
			abort();
		off += (size_t)w;
	}
	close(fd);

	int flags = 0;
	if (mode & 1)
		flags |= CFG_FLAG_GLOBAL_SECTION;
	if (mode & 2)
		flags |= CFG_FLAG_EMPTY_VALUES;
	struct rte_cfgfile *cfg;
	if (mode & 4) {
		struct rte_cfgfile_parameters params;
		memset(&params, 0, sizeof(params));
		params.comment_character = comment;
		cfg = rte_cfgfile_load_with_params(path, flags, &params);
	} else {
		cfg = rte_cfgfile_load(path, flags);
	}
	unlink(path);
	if (cfg != NULL) {
		walk(cfg);
		rte_cfgfile_close(cfg);
	}
	return 0;
}
