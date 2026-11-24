#include "config.h"
/* ccan/ccan_tokenizer: tokenize C source (strings, numbers, preprocessor lines),
 * then run the module's own token_list_sanity_check, as its test/run.c does for
 * files. The buffer is NUL-terminated past orig_size like test/run.c's reader. */
#include <ccan/ccan_tokenizer/ccan_tokenizer.h>
#include <ccan/talloc/talloc.h>
#include <stdio.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static FILE *devnull;
	if (!devnull)
		devnull = fopen("/dev/null", "w");
	tok_message_queue mq;
	queue_init(mq, NULL);
	char *text = talloc_size(NULL, size + 1);
	memcpy(text, data, size);
	text[size] = '\0';
	struct token_list *tl = tokenize(text, text, size, &mq);
	/* The checker walks every token; its verdict is not an oracle here, because
	 * upstream's handling of a backslash pair before a newline already fails it, which would make
	 * the target stop on that logic quirk instead of exploring for memory errors. */
	token_list_sanity_check(tl, devnull);
	talloc_free(text);
	queue_free(mq);
	return 0;
}
