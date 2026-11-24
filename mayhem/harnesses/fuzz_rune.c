#include "config.h"
/* ccan/rune: parse runes from base64 and from the string form, re-encode, and test
 * them against a fixed master rune with a callback that evaluates every alternative. */
#include <ccan/rune/rune.h>
#include <ccan/tal/str/str.h>
#include "common.h"

static const char *check(const tal_t *ctx, const struct rune *rune,
			 const struct rune_altern *alt, void *arg)
{
	(void)rune; (void)arg;
	if (alt->fieldname[0] == 'i')
		return rune_alt_single_int(ctx, alt, 42);
	if (alt->fieldname[0] == 'm')
		return rune_alt_single_missing(ctx, alt);
	return rune_alt_single_str(ctx, alt, "value", 5);
}

static void exercise(const tal_t *ctx, const struct rune *master, struct rune *r)
{
	char *str = rune_to_string(ctx, r);
	char *b64 = rune_to_base64(ctx, r);
	struct rune *again = rune_from_base64(ctx, b64);
	(void)str; (void)again;
	rune_is_derived_anyversion(master, r);
	rune_test(ctx, master, r, check, NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const u8 secret[16] = "ccan-fuzz-secret";
	char *ctx = tal(NULL, char);
	struct rune *master = rune_new(ctx, secret, sizeof(secret), NULL);
	char *s = tal_strndup(ctx, (const char *)data, size);
	struct rune *r;

	r = rune_from_base64n(ctx, (const char *)data, size);
	if (r)
		exercise(ctx, master, r);
	r = rune_from_string(ctx, s);
	if (r)
		exercise(ctx, master, r);
	rune_restr_from_string(ctx, (const char *)data, size);
	tal_free(ctx);
	return 0;
}
