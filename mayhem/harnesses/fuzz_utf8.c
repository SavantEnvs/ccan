#include "config.h"
/* ccan/utf8 decoder state machine and ccan/charset validator/reader. */
#include <ccan/utf8/utf8.h>
#include <ccan/charset/charset.h>
#include <errno.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct utf8_state st;
	char out[UTF8_MAX_LEN];
	size_t k;

	utf8_state_init(&st);
	for (k = 0; k < size; k++) {
		if (utf8_decode(&st, (char)data[k]) && errno == 0)
			utf8_encode(st.c, out);
	}

	const char *s = (const char *)data;
	if (utf8_validate(s, size)) {
		char *z = fuzz_strdup(data, size);
		const char *q = z, *e = z + size;
		while (q < e) {
			uchar_t c;
			int len = utf8_read_char(q, &c);
			char w[4];
			utf8_write_char(c, w);
			q += len > 0 ? len : 1;
		}
		free(z);
	}
	for (k = 0; k < size; ) {
		int len = utf8_validate_char(s + k, s + size);
		k += len > 0 ? (size_t)len : 1;
	}
	return 0;
}
