/*
 * svcadd - does this build let uid 2000 register a binder service?
 *
 * Why this matters: the only binder path that can *wake* a wait head reached through a
 * freed thread is binder_send_failed_reply()/wake_up_interruptible(&target_thread->wait)
 * with target_thread = t->from (binder.c:1191/1208, and 1419-1428/1704-1712). For that,
 * the freed thread must still be referenced by a *live* transaction, which in 3.18 means
 * queuing an unanswered synchronous call into another process's todo and then letting that
 * process die (binder_release_work -> binder_send_failed_reply). Owning the peer process
 * is trivial; *addressing* its node is not -- the only in-road to another proc's node is
 * servicemanager, so shell must be allowed both binder:call and service_manager:add.
 *
 * This tool just asks that question, and lets the device answer it: we register a service
 * and then confirm with the framework's own lookup ("service check") instead of trusting a
 * hand-derived parcel order -- AOSP's C servicemanager and libbinder disagree in my memory,
 * so both orders are tried and the *observable* decides.
 *
 * Reversible: the entry disappears with the process, and nothing is written to flash.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BINDER_WRITE_READ 0xc0306201
#define BC_TRANSACTION 0x40406300
#define BC_FREE_BUFFER 0x40086303
#define BR_OK 0x00000000
#define BR_NOOP 0x0000720C
#define BR_TRANSACTION_COMPLETE 0x00007206
#define BR_REPLY 0x80407203
#define BR_FAILED_REPLY 0x80407204
#define BR_DEAD_REPLY 0x80407205

#define SVC_MGR_ADD_SERVICE 1
#define SVC_MGR_CHECK_SERVICE 2

struct flat_obj {
	uint32_t type;
	uint32_t flags;
	uint64_t binder;
	uint64_t cookie;
};
#define BINDER_TYPE_BINDER 0x73626e64	/* 'sbnD' */

struct txn_data {
	uint64_t handle;
	uint64_t cookie;
	uint32_t code;
	uint32_t flags;
	uint32_t sender_pid;
	uint32_t sender_euid;
	uint64_t data_size;
	uint64_t offsets_size;
	uint64_t buffer;
	uint64_t offsets;
};
struct bwr {
	uint64_t write_size, write_consumed, write_buffer;
	uint64_t read_size, read_consumed, read_buffer;
};

/* the name as libbinder writes it: u32 char-count then UTF-16 with NUL, 4-byte aligned */
static size_t put_name(unsigned char *p, const char *name)
{
	size_t n = strlen(name);
	size_t i, chars = n + 1;
	*(uint32_t *)p = (uint32_t)chars;
	p += 4;
	for (i = 0; i < chars; i++)
		*(uint16_t *)(p + i * 2) = (uint16_t)(unsigned char) name[i];
	i = chars * 2;
	while (i % 8) { p[i] = 0; i++; }
	return 4 + i;
}

static int roundtrip(int fd, unsigned char *wbuf, size_t wlen, unsigned char *rbuf,
                     size_t rlen, const char *tag)
{
	struct bwr b;
	int rc;
	size_t off = 0;

	memset(&b, 0, sizeof b);
	b.write_buffer = (uint64_t)(unsigned long)wbuf;
	b.write_size = wlen;
	errno = 0;
	rc = ioctl(fd, BINDER_WRITE_READ, &b);
	printf("%-12s write rc=%d errno=%d consumed=%llu\n", tag, rc, errno,
	       (unsigned long long)b.write_consumed);
	if (rc)
		return -1;
	memset(&b, 0, sizeof b);
	b.read_buffer = (uint64_t)(unsigned long)rbuf;
	b.read_size = rlen;
	errno = 0;
	rc = ioctl(fd, BINDER_WRITE_READ, &b);
	printf("%-12s read  rc=%d errno=%d consumed=%llu cmds:", tag, rc, errno,
	       (unsigned long long)b.read_consumed);
	while (off + 4 <= b.read_consumed) {
		uint32_t c;
		memcpy(&c, rbuf + off, 4);
		printf(" %08x", c);
		off += 4;
		if (c == BR_REPLY)
			off += 64;
	}
	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	const char *name = argc > 1 ? argv[1] : "xplay6q";
	int order = argc > 2 ? atoi(argv[2]) : 0;	/* 0=name first, 1=binder first */
	unsigned char buf[512], offs[64], wbuf[8 + 512 + 64], rbuf[512];
	struct txn_data t;
	struct flat_obj fo;
	size_t blen = 0, olen = 0, nlen;
	int fd;

	fd = open("/dev/binder", O_RDONLY);
	if (fd < 0) {
		printf("open /dev/binder: %s\n", strerror(errno));
		return 1;
	}

	memset(buf, 0, sizeof buf);
	memset(offs, 0, sizeof offs);
	nlen = put_name(buf, name);

	memset(&fo, 0, sizeof fo);
	fo.type = BINDER_TYPE_BINDER;
	fo.flags = 0x00000000 | 0x00000000;	/* not FLAG_ONEWAY, no accepts_fds */
	fo.binder = 0x1234;			/* arbitrary local descriptor */
	fo.cookie = 0x4321;

	if (order == 0) {
		/* [name][flat object] -- the order AOSP's C servicemanager parses */
		blen = nlen;
		memcpy(buf + blen, &fo, sizeof fo);
		*(uint64_t *)offs = blen;
		olen = 8;
		blen += sizeof fo;
	} else {
		/* [flat object][name] -- the order libbinder's writeStrongBinder first */
		memcpy(buf, &fo, sizeof fo);
		*(uint64_t *)offs = 0;
		olen = 8;
		blen = sizeof fo;
		memcpy(buf + blen, buf, 0);
		nlen = put_name(buf + blen, name);
		blen += nlen;
	}

	memset(wbuf, 0, sizeof wbuf);
	*(uint32_t *)wbuf = BC_TRANSACTION;
	memset(&t, 0, sizeof t);
	t.handle = 0;				/* the context manager */
	t.code = SVC_MGR_ADD_SERVICE;
	t.flags = 0;				/* synchronous, so we get a reply */
	t.data_size = blen;
	t.offsets_size = olen;
	t.buffer = (uint64_t)(unsigned long)buf;
	t.offsets = (uint64_t)(unsigned long)offs;
	memcpy(wbuf + 8, &t, sizeof t);

	if (roundtrip(fd, wbuf, 8 + sizeof t, rbuf, sizeof rbuf, "add") < 0)
		return 2;

	/* now ask for it by name -- a nonzero handle in the reply means it stuck */
	memset(buf, 0, sizeof buf);
	memset(wbuf, 0, sizeof wbuf);
	*(uint32_t *)wbuf = BC_TRANSACTION;
	memset(&t, 0, sizeof t);
	t.handle = 0;
	t.code = SVC_MGR_CHECK_SERVICE;
	t.data_size = put_name(buf, name);
	t.buffer = (uint64_t)(unsigned long)buf;
	memcpy(wbuf + 8, &t, sizeof t);
	roundtrip(fd, wbuf, 8 + sizeof t, rbuf, sizeof rbuf, "check");
	printf("then verify out-of-band with:  service check %s\n", name);
	return 0;
}
