#include "config.h"
/* ccan/bdelta: apply a fuzzed binary patch to a fuzzed old buffer, and round-trip
 * bdelta_diff(old, rest) -> bdelta_patch, which must reproduce rest exactly.
 * Input: 2-byte little-endian old length, old bytes, then the patch/new bytes. */
#include <ccan/bdelta/bdelta.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return -1;
	size_t olen = data[0] | (data[1] << 8);
	data += 2; size -= 2;
	if (olen > size)
		olen = size;
	const uint8_t *old = data, *rest = data + olen;
	size_t rlen = size - olen;
	void *out = NULL; size_t outlen = 0;

	if (bdelta_patch(old, olen, rest, rlen, &out, &outlen) == BDELTA_OK)
		free(out);

	void *patch = NULL; size_t plen = 0;
	if (bdelta_diff(old, olen, rest, rlen, &patch, &plen) == BDELTA_OK) {
		out = NULL;
		if (bdelta_patch(old, olen, patch, plen, &out, &outlen) != BDELTA_OK ||
		    outlen != rlen || (rlen && memcmp(out, rest, rlen) != 0))
			abort(); /* diff/patch round trip broke */
		free(out);
		free(patch);
	}
	return 0;
}
