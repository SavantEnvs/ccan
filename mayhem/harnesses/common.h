/* Shared helpers for the ccan fuzz harnesses. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* NUL-terminated copy of the fuzz input (most ccan parsers take C strings). */
static char *fuzz_strdup(const uint8_t *data, size_t size)
{
	char *s = malloc(size + 1);
	if (!s)
		abort();
	memcpy(s, data, size);
	s[size] = '\0';
	return s;
}
