#include "config.h"
/* ccan/json_out: a small bytecode over the JSON writer. Each op byte picks
 * start/end of an object or array, addstr/add with fixed formats fed fuzz bytes,
 * a splice of a nested writer, or a consume. Nesting is tracked so the API's
 * own start/end asserts (contract) are never violated by the harness. */
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <wchar.h>
#include "common.h"

#define MAXDEPTH 32

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *ctx = tal(NULL, char);
	struct json_out *jout = json_out_new(ctx);
	char stack[MAXDEPTH];
	int depth = 0;
	size_t p = 0;

	json_out_start(jout, NULL, '{');
	stack[depth++] = '{';
	while (p < size) {
		uint8_t op = data[p++];
		uint8_t len = p < size ? data[p++] : 0;
		if (len > size - p)
			len = size - p;
		const char *arg = (const char *)data + p;
		p += len;
		const char *field = stack[depth - 1] == '{' ? "f" : NULL;
		char *argz = tal_strndup(ctx, arg, len);

		switch (op % 9) {
		case 0:
		case 1:
			if (depth < MAXDEPTH) {
				char t = op % 9 == 0 ? '{' : '[';
				json_out_start(jout, field, t);
				stack[depth++] = t;
			}
			break;
		case 2:
			if (depth > 1)
				json_out_end(jout, stack[--depth] == '{' ? '}' : ']');
			break;
		case 3:
			json_out_addstr(jout, field, argz);
			break;
		case 4:
			json_out_addstrn(jout, field, arg, len);
			break;
		case 5:
			json_out_add(jout, field, true, "%.*s", (int)len, arg);
			break;
		case 6: {
			/* Wide-char conversion can fail (negative vsnprintf return). */
			wchar_t w[2] = { 0, 0 };
			if (len >= 4)
				memcpy(&w[0], arg, sizeof(w[0]));
			json_out_add(jout, field, true, "%ls", w);
			break;
		}
		case 7: {
			struct json_out *sub = json_out_new(ctx);
			json_out_start(sub, NULL, '[');
			json_out_addstr(sub, NULL, argz);
			json_out_end(sub, ']');
			json_out_finished(sub);
			json_out_add_splice(jout, field, sub);
			break;
		}
		case 8: {
			size_t clen;
			json_out_contents(jout, &clen);
			json_out_consume(jout, clen < len ? clen : len);
			break;
		}
		}
	}
	while (depth > 0)
		json_out_end(jout, stack[--depth] == '{' ? '}' : ']');
	json_out_finished(jout);
	size_t clen;
	json_out_contents(jout, &clen);
	tal_free(ctx);
	return 0;
}
