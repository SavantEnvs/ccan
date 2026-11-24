#include "config.h"
/* ccan/rfc822: lazy RFC 822 header parse, unfolding, name lookup and body split. */
#include <ccan/rfc822/rfc822.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rfc822_msg *msg = rfc822_start(NULL, (const char *)data, size);
	struct rfc822_header *hdr;
	if (!msg)
		return 0;
	rfc822_for_each_header(msg, hdr) {
		rfc822_header_errors(msg, hdr);
		rfc822_header_raw_content(msg, hdr);
		rfc822_header_raw_name(msg, hdr);
		rfc822_header_raw_value(msg, hdr);
		rfc822_header_unfolded_value(msg, hdr);
	}
	for (hdr = rfc822_first_header_of_name(msg, "To"); hdr;
	     hdr = rfc822_next_header_of_name(msg, hdr, "To"))
		rfc822_header_unfolded_value(msg, hdr);
	rfc822_body(msg);
	rfc822_free(msg);
	return 0;
}
