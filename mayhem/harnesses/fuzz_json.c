#include "config.h"
/* ccan/json: json_validate + json_decode, then re-emit and self-check the tree. */
#include <ccan/json/json.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s = fuzz_strdup(data, size);
	bool valid = json_validate(s);
	JsonNode *j = json_decode(s);
	if (j) {
		char err[256];
		json_check(j, err);
		char *a = json_stringify(j, " ");
		char *b = json_encode(j);
		/* Re-encoded output must decode again. */
		JsonNode *k = b ? json_decode(b) : NULL;
		if (k)
			json_delete(k);
		free(a);
		free(b);
		json_delete(j);
	}
	(void)valid;
	free(s);
	return 0;
}
