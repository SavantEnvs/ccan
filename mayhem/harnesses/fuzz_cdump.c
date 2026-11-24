#include "config.h"
/* ccan/cdump: extract enum/struct/union definitions from C source text. */
#include <ccan/cdump/cdump.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s = fuzz_strdup(data, size);
	char *ctx = tal(NULL, char);
	char *problems = NULL;
	struct cdump_definitions *defs = cdump_extract(ctx, s, &problems);
	if (defs) {
		strmap_get(&defs->structs, "a");
		strmap_get(&defs->enums, "a");
		strmap_get(&defs->unions, "a");
	}
	tal_free(ctx);
	free(s);
	return 0;
}
