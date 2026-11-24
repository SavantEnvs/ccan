#include "config.h"
/* ccan/fdpass: fdpass_recv() validates an SCM_RIGHTS message read off a socket.
 * The harness is the peer: from the input it builds a sendmsg() with a chosen
 * payload length, 0..2 control messages each carrying 0..8 fds (dups of
 * /dev/null), and sends it over an AF_UNIX socketpair; fdpass_recv() reads it.
 * Every fd is closed each iteration, and fds leaked by fdpass_recv on a rejected
 * message are detected by checking the next free descriptor number. */
#include <ccan/fdpass/fdpass.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include "common.h"

#define MAXFDS 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 3)
		return -1;
	size_t paylen = data[0] % 8;
	int ncmsg = data[1] % 3;
	int nfds[2] = { data[2] % (MAXFDS + 1), (data[2] >> 4) % (MAXFDS + 1) };
	int sock_type = (data[2] & 0x80) ? SOCK_DGRAM : SOCK_STREAM;
	const uint8_t *payload = data + 3;
	size_t avail = size - 3;
	if (paylen > avail)
		paylen = avail;

	int probe = open("/dev/null", O_RDONLY);
	close(probe);
	int sv[2];
	if (socketpair(AF_UNIX, sock_type, 0, sv) != 0)
		abort();

	int sent[2][MAXFDS];
	int c, k, total = 0;
	char cbuf[2 * CMSG_SPACE(sizeof(int) * MAXFDS)];
	memset(cbuf, 0, sizeof(cbuf));
	struct msghdr msg = { 0 };
	struct iovec iov;
	char one = 0;
	iov.iov_base = paylen ? (void *)payload : &one;
	iov.iov_len = paylen ? paylen : 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	size_t clen = 0;
	for (c = 0; c < ncmsg; c++)
		clen += CMSG_SPACE(sizeof(int) * nfds[c]);
	if (clen) {
		msg.msg_control = cbuf;
		msg.msg_controllen = clen;
		struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
		for (c = 0; c < ncmsg && cm; c++, cm = CMSG_NXTHDR(&msg, cm)) {
			cm->cmsg_level = SOL_SOCKET;
			cm->cmsg_type = SCM_RIGHTS;
			cm->cmsg_len = CMSG_LEN(sizeof(int) * nfds[c]);
			for (k = 0; k < nfds[c]; k++) {
				sent[c][k] = open("/dev/null", O_RDONLY);
				total++;
			}
			memcpy(CMSG_DATA(cm), sent[c], sizeof(int) * nfds[c]);
		}
	}
	ssize_t r = sendmsg(sv[0], &msg, MSG_DONTWAIT);
	for (c = 0; c < ncmsg; c++)
		for (k = 0; k < nfds[c]; k++)
			close(sent[c][k]);
	close(sv[0]);
	if (r >= 0) {
		int fd = fdpass_recv(sv[1]);
		if (fd >= 0)
			close(fd);
	}
	close(sv[1]);
	/* All descriptors are closed: the lowest free one must be where it began. */
	int after = open("/dev/null", O_RDONLY);
	close(after);
	if (after != probe)
		abort(); /* fdpass_recv leaked a received descriptor */
	(void)total;
	return 0;
}
