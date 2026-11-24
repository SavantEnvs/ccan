#include "config.h"
/* ccan/opt: parse a fuzzed argv (NUL-separated words) against a fixed option table
 * covering every converter type, with both opt_early_parse and opt_parse. */
#include <ccan/opt/opt.h>
#include <stdarg.h>
#include "common.h"

static bool b; static int i; static unsigned int u; static long l; static float f;
static double d; static char *str; static int inc; static long long ll;
static unsigned long long ull; static long long ss;

static void noerr(const char *fmt, ...) { (void)fmt; }

static char *noarg_cb(void *arg) { (void)arg; return NULL; }

static const struct opt_table table[] = {
	OPT_WITHOUT_ARG("--bool|-b", opt_set_bool, &b, "bool"),
	OPT_WITHOUT_ARG("--no-bool", opt_set_invbool, &b, "invbool"),
	OPT_WITH_ARG("--boolarg", opt_set_bool_arg, opt_show_bool, &b, "boolarg"),
	OPT_WITH_ARG("--int|-i", opt_set_intval, opt_show_intval, &i, "int"),
	OPT_WITH_ARG("--uint|-u", opt_set_uintval, opt_show_uintval, &u, "uint"),
	OPT_WITH_ARG("--long|-l", opt_set_longval, opt_show_longval, &l, "long"),
	OPT_WITH_ARG("--float|-f", opt_set_floatval, opt_show_floatval, &f, "float"),
	OPT_WITH_ARG("--double", opt_set_doubleval, opt_show_doubleval, &d, "double"),
	OPT_WITH_ARG("--str|-s", opt_set_charp, opt_show_charp, &str, "str"),
	OPT_WITHOUT_ARG("-v|--verbose", opt_inc_intval, &inc, "inc"),
	OPT_WITH_ARG("--bi", opt_set_longlongval_bi, opt_show_longlongval_bi, &ll, "bi"),
	OPT_WITH_ARG("--ubi", opt_set_ulonglongval_bi, opt_show_ulonglongval_bi, &ull, "ubi"),
	OPT_WITH_ARG("--si", opt_set_longlongval_si, opt_show_longlongval_si, &ss, "si"),
	OPT_EARLY_WITHOUT_ARG("--early|-e", noarg_cb, NULL, "early"),
	OPT_ENDTABLE
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf = fuzz_strdup(data, size);
	size_t n = 1, k;
	for (k = 0; k < size; k++)
		n += buf[k] == '\0';
	char **argv = calloc(n + 2, sizeof(char *));
	argv[0] = (char *)"prog";
	argv[1] = buf;
	for (k = 0, n = 2; k < size; k++)
		if (buf[k] == '\0')
			argv[n++] = buf + k + 1;
	argv[n] = NULL;
	int argc = (int)n;

	b = false; i = 0; u = 0; l = 0; f = 0; d = 0; str = NULL; inc = 0;
	ll = 0; ull = 0; ss = 0;
	opt_register_table(table, NULL);
	opt_early_parse(argc, argv, noerr);
	opt_parse(&argc, argv, noerr);
	free(opt_usage("prog", NULL));
	opt_free_table();
	free(argv);
	free(buf);
	return 0;
}
