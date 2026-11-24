#include "config.h"
/* ccan/graphql: lexer + recursive-descent parser of a GraphQL executable document. */
#include <ccan/graphql/graphql.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s = fuzz_strdup(data, size);
	char *ctx = tal(NULL, char);
	struct list_head *tokens = NULL;
	struct graphql_executable_document *doc = NULL;
	graphql_lexparse(ctx, s, &tokens, &doc);
	tal_free(ctx);
	free(s);
	return 0;
}
