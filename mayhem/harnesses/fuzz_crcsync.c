#include "config.h"
/* ccan/crcsync: rolling-CRC block matcher. Input header: blocksize byte, crcbits
 * byte, reference length byte; then reference bytes, then the stream fed in
 * fuzz-chosen chunk sizes. */
#include <ccan/crcsync/crcsync.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 3)
		return -1;
	unsigned blocksize = (data[0] % 64) + 1;
	unsigned crcbits = (data[1] % 64) + 1;
	size_t rlen = data[2];
	data += 3; size -= 3;
	if (rlen > size)
		rlen = size;
	const uint8_t *ref = data, *stream = data + rlen;
	size_t slen = size - rlen;
	unsigned nblocks = (rlen + blocksize - 1) / blocksize;
	if (nblocks == 0)
		return 0;
	/* crc_context_new contract: tail_size < blocksize, the final partial block. */
	size_t tail = rlen % blocksize;

	uint64_t *crcs = calloc(nblocks, sizeof(uint64_t));
	crc_of_blocks(ref, rlen, blocksize, crcbits, crcs);
	struct crc_context *ctx = crc_context_new(blocksize, crcbits, crcs, nblocks, tail);
	size_t off = 0;
	while (off < slen) {
		long res;
		size_t chunk = (stream[off] % 32) + 1;
		if (chunk > slen - off)
			chunk = slen - off;
		size_t used = crc_read_block(ctx, &res, stream + off, chunk);
		off += used;
		if (used == 0 && res == 0)
			break;
	}
	while (crc_read_flush(ctx) != 0)
		;
	crc_context_free(ctx);
	free(crcs);
	return 0;
}
