/* tools/kcore_read.c -- read kernel virtual addresses straight out of /proc/kcore.
 *
 * Why: every "the write landed" claim so far has been an *inference* from readv()==expected,
 * and today's alias test showed how weak that inference is -- a batch whose redirect never
 * happened still consumes the whole feed and prints a perfect number.  /proc/kcore gives the
 * bytes the kernel itself maps, so a write is checked by reading it back, not by trusting the
 * copy's length.  Needs root (CAP_SYS_ADMIN in open_kcore) and, on this phone, Permissive.
 *
 * Only segments the kernel registered in its kcore list are addressable (the linear map, so
 * .text/.data/.bss all are); a VA we mapped ourselves through a pgd entry is not in that list
 * and is reported as "no segment".
 *
 * usage: kcore_read phdrs
 *        kcore_read <hex-va> [nbytes=16]
 */
#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fd;
static Elf64_Phdr *ph;
static int nthr;

static int load_headers(void)
{
	Elf64_Ehdr eh;
	if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh) {
		printf("cannot read ELF header of /proc/kcore\n");
		return -1;
	}
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64) {
		printf("not a 64-bit ELF\n");
		return -1;
	}
	nthr = eh.e_phnum;
	ph = calloc(eh.e_phnum, sizeof *ph);
	if (!ph) {
		printf("OOM\n");
		return -1;
	}
	if (pread(fd, ph, (size_t)eh.e_phnum * eh.e_phentsize, eh.e_phoff) !=
	    (ssize_t)((size_t)eh.e_phnum * eh.e_phentsize)) {
		printf("cannot read program headers\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("usage: kcore_read phdrs | kcore_read <hex-va> [nbytes]\n");
		return 2;
	}
	fd = open("/proc/kcore", O_RDONLY);
	if (fd < 0) {
		perror("open /proc/kcore (needs root; on this phone also Permissive)");
		return 1;
	}
	if (load_headers() != 0)
		return 1;

	if (!strcmp(argv[1], "phdrs")) {
		int i;
		printf("segments in /proc/kcore (PT_LOAD only):\n");
		for (i = 0; i < nthr; i++) {
			if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0)
				continue;
			printf("  va=0x%016llx memsz=0x%012llx off=0x%012llx\n",
			       (unsigned long long)ph[i].p_vaddr, (unsigned long long)ph[i].p_memsz,
			       (unsigned long long)ph[i].p_offset);
		}
		return 0;
	}

	unsigned long long va = strtoull(argv[1], NULL, 16);
	int n = argc > 2 ? atoi(argv[2]) : 16;
	unsigned char buf[256];
	int i, j, hit = 0;
	if (n < 1 || n > (int)sizeof buf) {
		printf("nbytes must be 1..%d\n", (int)sizeof buf);
		return 2;
	}
	for (i = 0; i < nthr; i++) {
		unsigned long long v = ph[i].p_vaddr, sz = ph[i].p_memsz;
		if (ph[i].p_type != PT_LOAD || sz == 0)
			continue;
		if (va < v || va + n > v + sz)
			continue;
		hit = 1;
		if (pread(fd, buf, n, ph[i].p_offset + (va - v)) != n) {
			perror("pread");
			return 1;
		}
		printf("0x%016llx (segment va=0x%016llx size=0x%llx):", va, v, sz);
		for (j = 0; j < n; j++)
			printf(" %02x", buf[j]);
		printf("\n");
		for (j = 0; j + 4 <= n; j += 4)
			printf("  +0x%-4x word=0x%08x\n", j,
			       (unsigned)(buf[j] | buf[j + 1] << 8 | buf[j + 2] << 16 | buf[j + 3] << 24));
	}
	if (!hit)
		printf("0x%016llx -> no kcore segment (the kernel did not map this VA in its own list;"
		       " a self-made alias window is invisible here)\n", va);
	return hit ? 0 : 3;
}
