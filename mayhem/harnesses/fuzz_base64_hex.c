#include "config.h"
/* ccan/base64 and ccan/str/hex decoders: decode into an exact-size and a
 * fuzz-chosen (possibly too small) buffer; successful decodes must re-encode. */
#include <ccan/base64/base64.h>
#include <ccan/str/hex/hex.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return -1;
	size_t small = data[0];
	const char *src = (const char *)data + 1;
	size_t slen = size - 1;

	size_t dlen = base64_decoded_length(slen);
	char *dst = malloc(dlen + 1);
	ssize_t n = base64_decode(dst, dlen, src, slen);
	if (n >= 0) {
		size_t elen = base64_encoded_length(n) + 1;
		char *enc = malloc(elen);
		if (base64_encode(enc, elen, dst, n) < 0)
			abort();
		free(enc);
	}
	free(dst);

	dst = malloc(small ? small : 1);
	base64_decode(dst, small, src, slen);
	free(dst);

	size_t hlen = hex_data_size(slen);
	unsigned char *hb = malloc(hlen + 1);
	if (hex_decode(src, slen, hb, hlen)) {
		char *he = malloc(hex_str_size(hlen));
		if (!hex_encode(hb, hlen, he, hex_str_size(hlen)))
			abort();
		free(he);
	}
	free(hb);
	return 0;
}
