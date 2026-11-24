#include "config.h"
/* ccan/json_escape: escape arbitrary bytes and unescape them back (must round-trip),
 * and treat the input itself as an escaped JSON string. */
#include <ccan/json_escape/json_escape.h>
#include <ccan/tal/str/str.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *ctx = tal(NULL, char);
	char *s = tal_strndup(ctx, (const char *)data, size);
	size_t slen = strlen(s);

	struct json_escape *esc = json_escape_len(ctx, s, slen);
	const char *un = json_escape_unescape(ctx, esc);
	/* unescape may fail (it does not handle the \u escapes json_escape emits for
	 * control characters), but when it succeeds it must give back the input. */
	if (un && strcmp(un, s) != 0)
		abort();
	json_escape_needed(s, slen);
	json_escape_string_(ctx, data, size);
	json_partial_escape(ctx, s);
	json_escape_unescape_len(ctx, (const char *)data, size);
	tal_free(ctx);
	return 0;
}
