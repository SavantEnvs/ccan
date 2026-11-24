#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
/* ccan/ttxml: xml_load() reads an XML file by path. Stage the input in an
 * in-memory file (memfd, opened via /proc/self/fd) so no writable filesystem
 * is needed; fall back to a temp file in the cwd, then $TMPDIR. Never abort on
 * staging failure: that would make every input a "crash". */
#include <ccan/ttxml/ttxml.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "common.h"

static int write_all(int fd, const uint8_t *data, size_t size)
{
	while (size) {
		ssize_t n = write(fd, data, size);
		if (n <= 0)
			return -1;
		data += n;
		size -= n;
	}
	return 0;
}

static void parse(const char *path)
{
	XmlNode *x = xml_load(path);
	if (x) {
		XmlNode *f = xml_find(x, "a");
		if (f)
			xml_attr(f, "b");
		xml_attr(x, "b");
		xml_free(x);
	}
}

/* ttxml's xml_feed() returns at EOF without advancing read_index, so any
 * document whose last token runs into EOF (trailing text, an unterminated tag
 * name, attribute or quoted value) makes xml_parse()/xml_read_attr() spin,
 * allocating until OOM. Nearly every mutation hits that, so libFuzzer could
 * not complete its first iterations. The harness therefore terminates the
 * document: it closes any open quote/tag and every element (one "</>" per
 * '<' in the input, plus slack), so parsing ends at a top-level "</". The
 * fuzzed bytes are parsed unchanged; only the tail is ours. */
static const char tail_open[] = "\"'>";
static const char tail_close[] = "</>";

static int write_doc(int fd, const uint8_t *data, size_t size)
{
	size_t opens = 2, i;
	for (i = 0; i < size; i++)
		opens += data[i] == '<';
	if (write_all(fd, data, size) || write_all(fd, (const uint8_t *)tail_open, 3))
		return -1;
	for (i = 0; i < opens; i++)
		if (write_all(fd, (const uint8_t *)tail_close, 3))
			return -1;
	return write_all(fd, (const uint8_t *)"\n", 1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char path[4096];
	int fd = memfd_create("ttxml", 0);
	if (fd >= 0) {
		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
		if (write_doc(fd, data, size) == 0 && access(path, R_OK) == 0) {
			parse(path);
			close(fd);
			return 0;
		}
		close(fd);
	}
	const char *dirs[] = { ".", getenv("TMPDIR"), "/tmp" };
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		if (!dirs[i] || !*dirs[i])
			continue;
		snprintf(path, sizeof(path), "%s/ttxml-XXXXXX", dirs[i]);
		fd = mkstemp(path);
		if (fd < 0)
			continue;
		int ok = write_doc(fd, data, size) == 0;
		close(fd);
		if (ok)
			parse(path);
		unlink(path);
		return 0;
	}
	return 0;
}
