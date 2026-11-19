/*
 * Interactive command-line library: cmdline_in() feeds the input as keystrokes through rdline/vt100
 * (line editing, escape sequences, history, TAB completion, '?' help) and runs completed lines
 * through cmdline_parse() against a command set covering every token parser (fixed and choice
 * strings, any-string, multi-word string, all integer widths, IPv4/IPv6 address and network,
 * Ethernet address, port list, bool). Each input line is also passed to cmdline_parse(),
 * cmdline_parse_check() and iterated through cmdline_complete() directly.
 *
 * A fresh struct cmdline is created per input; its output goes to /dev/null.
 * Command callbacks only read their parsed result.
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <cmdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_bool.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_portlist.h>
#include <cmdline_parse_string.h>

static volatile size_t sink;

/* show port|queue|all <u16> <ipaddr> */
struct cmd_show { cmdline_fixed_string_t kw, what; uint16_t id; cmdline_ipaddr_t ip; };
static void cmd_show_cb(void *r, struct cmdline *cl, void *d)
{ (void)cl; (void)d; struct cmd_show *s = r; sink += s->id + s->ip.family; }
static cmdline_parse_token_string_t show_kw = TOKEN_STRING_INITIALIZER(struct cmd_show, kw, "show");
static cmdline_parse_token_string_t show_what = TOKEN_STRING_INITIALIZER(struct cmd_show, what, "port#queue#all");
static cmdline_parse_token_num_t show_id = TOKEN_NUM_INITIALIZER(struct cmd_show, id, RTE_UINT16);
static cmdline_parse_token_ipaddr_t show_ip = TOKEN_IPADDR_INITIALIZER(struct cmd_show, ip);
static cmdline_parse_inst_t cmd_show = { .f = cmd_show_cb, .help_str = "show port|queue|all <id> <ip>",
	.tokens = { &show_kw, &show_what, &show_id, &show_ip, NULL } };

/* set mac <ether> | set ports <portlist> | set flag <bool> */
struct cmd_mac { cmdline_fixed_string_t kw, sub; struct rte_ether_addr mac; };
static void cmd_mac_cb(void *r, struct cmdline *cl, void *d)
{ (void)cl; (void)d; struct cmd_mac *s = r; sink += s->mac.addr_bytes[0]; }
static cmdline_parse_token_string_t set_kw = TOKEN_STRING_INITIALIZER(struct cmd_mac, kw, "set");
static cmdline_parse_token_string_t mac_sub = TOKEN_STRING_INITIALIZER(struct cmd_mac, sub, "mac");
static cmdline_parse_token_etheraddr_t mac_val = TOKEN_ETHERADDR_INITIALIZER(struct cmd_mac, mac);
static cmdline_parse_inst_t cmd_mac = { .f = cmd_mac_cb, .help_str = "set mac <mac>",
	.tokens = { &set_kw, &mac_sub, &mac_val, NULL } };

struct cmd_ports { cmdline_fixed_string_t kw, sub; cmdline_portlist_t pl; };
static void cmd_ports_cb(void *r, struct cmdline *cl, void *d)
{ (void)cl; (void)d; struct cmd_ports *s = r; sink += s->pl.map; }
static cmdline_parse_token_string_t ports_kw = TOKEN_STRING_INITIALIZER(struct cmd_ports, kw, "set");
static cmdline_parse_token_string_t ports_sub = TOKEN_STRING_INITIALIZER(struct cmd_ports, sub, "ports");
static cmdline_parse_token_portlist_t ports_val = TOKEN_PORTLIST_INITIALIZER(struct cmd_ports, pl);
static cmdline_parse_inst_t cmd_ports = { .f = cmd_ports_cb, .help_str = "set ports <list>",
	.tokens = { &ports_kw, &ports_sub, &ports_val, NULL } };

struct cmd_flag { cmdline_fixed_string_t kw, sub; uint8_t on; };
static void cmd_flag_cb(void *r, struct cmdline *cl, void *d)
{ (void)cl; (void)d; struct cmd_flag *s = r; sink += s->on; }
static cmdline_parse_token_string_t flag_kw = TOKEN_STRING_INITIALIZER(struct cmd_flag, kw, "set");
static cmdline_parse_token_string_t flag_sub = TOKEN_STRING_INITIALIZER(struct cmd_flag, sub, "flag");
static cmdline_parse_token_bool_t flag_val = TOKEN_BOOL_INITIALIZER(struct cmd_flag, on);
static cmdline_parse_inst_t cmd_flag = { .f = cmd_flag_cb, .help_str = "set flag <bool>",
	.tokens = { &flag_kw, &flag_sub, &flag_val, NULL } };

/* add <anystring> <i64> <ipv4net> <ipv6> */
struct cmd_add { cmdline_fixed_string_t kw, name; int64_t v; cmdline_ipaddr_t net, ip6; };
static void cmd_add_cb(void *r, struct cmdline *cl, void *d)
{ (void)cl; (void)d; struct cmd_add *s = r; sink += strlen(s->name) + (size_t)s->v; }
static cmdline_parse_token_string_t add_kw = TOKEN_STRING_INITIALIZER(struct cmd_add, kw, "add");
static cmdline_parse_token_string_t add_name = TOKEN_STRING_INITIALIZER(struct cmd_add, name, NULL);
static cmdline_parse_token_num_t add_v = TOKEN_NUM_INITIALIZER(struct cmd_add, v, RTE_INT64);
static cmdline_parse_token_ipaddr_t add_net = TOKEN_IPV4NET_INITIALIZER(struct cmd_add, net);
static cmdline_parse_token_ipaddr_t add_ip6 = TOKEN_IPV6_INITIALIZER(struct cmd_add, ip6);
static cmdline_parse_inst_t cmd_add = { .f = cmd_add_cb, .help_str = "add <name> <int> <net> <ip6>",
	.tokens = { &add_kw, &add_name, &add_v, &add_net, &add_ip6, NULL } };

/* num <u8> <i8> <i16> <u32> <i32> <u64> <ipnet> */
struct cmd_num { cmdline_fixed_string_t kw; uint8_t a; int8_t b; int16_t c; uint32_t d; int32_t e;
	uint64_t f; cmdline_ipaddr_t net; };
static void cmd_num_cb(void *r, struct cmdline *cl, void *d)
{ (void)cl; (void)d; struct cmd_num *s = r; sink += s->a + (size_t)s->f; }
static cmdline_parse_token_string_t num_kw = TOKEN_STRING_INITIALIZER(struct cmd_num, kw, "num");
static cmdline_parse_token_num_t num_a = TOKEN_NUM_INITIALIZER(struct cmd_num, a, RTE_UINT8);
static cmdline_parse_token_num_t num_b = TOKEN_NUM_INITIALIZER(struct cmd_num, b, RTE_INT8);
static cmdline_parse_token_num_t num_c = TOKEN_NUM_INITIALIZER(struct cmd_num, c, RTE_INT16);
static cmdline_parse_token_num_t num_d = TOKEN_NUM_INITIALIZER(struct cmd_num, d, RTE_UINT32);
static cmdline_parse_token_num_t num_e = TOKEN_NUM_INITIALIZER(struct cmd_num, e, RTE_INT32);
static cmdline_parse_token_num_t num_f = TOKEN_NUM_INITIALIZER(struct cmd_num, f, RTE_UINT64);
static cmdline_parse_token_ipaddr_t num_net = TOKEN_IPNET_INITIALIZER(struct cmd_num, net);
static cmdline_parse_inst_t cmd_num = { .f = cmd_num_cb, .help_str = "num <u8> <i8> <i16> <u32> <i32> <u64> <net>",
	.tokens = { &num_kw, &num_a, &num_b, &num_c, &num_d, &num_e, &num_f, &num_net, NULL } };

/* echo <multi word string> */
struct cmd_echo { cmdline_fixed_string_t kw; cmdline_multi_string_t text; };
static void cmd_echo_cb(void *r, struct cmdline *cl, void *d)
{ (void)d; struct cmd_echo *s = r; cmdline_printf(cl, "%s\n", s->text); }
static cmdline_parse_token_string_t echo_kw = TOKEN_STRING_INITIALIZER(struct cmd_echo, kw, "echo");
static cmdline_parse_token_string_t echo_text = TOKEN_STRING_INITIALIZER(struct cmd_echo, text, TOKEN_STRING_MULTI);
static cmdline_parse_inst_t cmd_echo = { .f = cmd_echo_cb, .help_str = "echo <text...>",
	.tokens = { &echo_kw, &echo_text, NULL } };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	rte_log_set_global_level(RTE_LOG_CRIT);
	return 0;
}

static cmdline_parse_ctx_t ctx[] = { &cmd_show, &cmd_mac, &cmd_ports, &cmd_flag, &cmd_add,
	&cmd_num, &cmd_echo, NULL };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > 65536)
		return 0;
	/* cmdline_free() closes the descriptors it was given, so each input gets its own. */
	int fd_null = open("/dev/null", O_RDWR);
	if (fd_null < 0)
		abort();
	struct cmdline *cl = cmdline_new(ctx, "> ", fd_null, fd_null);
	if (cl == NULL)
		abort();
	cmdline_in(cl, (const char *)data, (int)size);

	char *copy = malloc(size + 1);
	memcpy(copy, data, size);
	copy[size] = '\0';
	char *save = NULL;
	for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		(void)cmdline_parse_check(cl, line);
		(void)cmdline_parse(cl, line);
		int state = 0;
		char dst[256];
		for (int i = 0; i < 64; i++) {
			int r = cmdline_complete(cl, line, &state, dst, sizeof(dst));
			if (r <= 0 || r == CMDLINE_PARSE_COMPLETED_BUFFER)
				break;
		}
	}
	free(copy);
	cmdline_free(cl);
	return 0;
}
