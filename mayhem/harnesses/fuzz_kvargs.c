/*
 * Key/value argument parser: rte_kvargs_parse() and rte_kvargs_parse_delim() on a device-argument
 * string (key=value pairs, lists in [ ], ...), as drivers parse --vdev/--allow devargs, followed by
 * the lookup and processing API.
 *
 * Input: byte 0 selects the parser (bit 0: restrict to a fixed valid-key list, bit 1: use
 * parse_delim with ':' as an extra delimiter); the rest is the argument string (NUL-terminated
 * copy).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <rte_kvargs.h>
#include <rte_log.h>

static const char *const keys[] = { "iface", "queues", "mac", "list", "path", "x", NULL };

static int handler(const char *key, const char *value, void *opaque)
{
	size_t *n = opaque;
	*n += strlen(key) + (value ? strlen(value) : 0);
	return 0;
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
	if (size < 1)
		return 0;
	uint8_t mode = data[0];
	char *s = malloc(size);
	memcpy(s, data + 1, size - 1);
	s[size - 1] = '\0';

	const char *const *vk = (mode & 1) ? keys : NULL;
	struct rte_kvargs *kv = (mode & 2) ? rte_kvargs_parse_delim(s, vk, ":")
					   : rte_kvargs_parse(s, vk);
	if (kv != NULL) {
		size_t n = 0;
		(void)rte_kvargs_count(kv, NULL);
		(void)rte_kvargs_process(kv, NULL, handler, &n);
		for (int i = 0; keys[i] != NULL; i++) {
			(void)rte_kvargs_count(kv, keys[i]);
			(void)rte_kvargs_get(kv, keys[i]);
			(void)rte_kvargs_process(kv, keys[i], handler, &n);
			(void)rte_kvargs_process_opt(kv, keys[i], handler, &n);
		}
		rte_kvargs_free(kv);
	}
	free(s);
	return 0;
}
