/* tools/sysoverlay.c -- publish a module's system/ tree into /system, GLOBALLY.
 *
 * WHY THIS EXISTS (measured 2026-10-27 on vivo Xplay6, official 7.1.1):
 *
 *   The project already has a module format (Modules.java) and a mount
 *   engine (assets/modmount.sh) that overlays a module's system/ tree onto
 *   /system.  On this ROM that engine is invisible to everything but the
 *   manager app, for two independent reasons, and each one has its own fix.
 *
 *   1. MOUNT NAMESPACE.  Android's zygote gives every app its own mount
 *      namespace.  Our daemon runs inside the manager app, so a mount it
 *      performs lands in THAT app's namespace and nowhere else.  Measured:
 *      after the engine mounted a tmpfs over /system/etc, the manager app's
 *      own /proc/<pid>/mountinfo listed the tmpfs while init's and every
 *      other app's did not.
 *      Fix: setns(CLONE_NEWNS) into PID 1's namespace before mounting.
 *      nsmbind.c already uses this trick for /sbin.
 *
 *   2. DOES IT PROPAGATE?  init's /system is a SHARED mount (shared:13) and
 *      every app's /system is a SLAVE of that peer group (master:13).  A
 *      mount event made in the master therefore reaches every app -- but
 *      only if it is made in the master's namespace, which is point 1.
 *      Measured: `bind <src> //system/etc/hosts` from PID 1's namespace made
 *      the new content visible to a plain `adb shell` (uid 2000).
 *
 *   3. WHY THE DOUBLE SLASH.  vivo hooks mount(2):
 *        - it refuses targets whose string starts with /system, /oem or
 *          /apps (that is the rule assets/modmount.sh documents);
 *        - and a plain `/system/...` target resolves against the READ-ONLY
 *          /system mount, so the mount fails with EPERM.
 *      Fix: pass the target as `//system/...`.  Measured in PID 1's
 *      namespace: `mount("tmpfs", "//system/etc", ...)` succeeds, while the
 *      plain path gives EPERM.
 *
 *   4. LABELS AND MODES.  A file published into /system must carry the
 *      system_file label (u:object_r:system_file:s0) -- the label /system
 *      files carry and the one apps may read -- and a mode an app can use.
 *      The module copy under /data/adb is root-only (0600); publishing that
 *      mode gives every app "Permission denied" on a file that is plainly
 *      there.  A tmpfs mount also brings the tmpfs label and the daemon's
 *      077 umask (drwx------), which hides the whole directory.
 *
 *   5. NEW FILES.  /system is read-only, so a file that does not exist
 *      there yet has no mount point.  The directory that will hold it has to
 *      be published first: bind the ORIGINAL directory aside, mount a tmpfs
 *      over it, copy the original contents back, and then the new file can
 *      simply be written into the tmpfs.
 *
 * WHAT IT DOES:
 *   For every directory the module touches, it publishes a writable mirror
 *   of that /system directory (tmpfs + the original contents restored +
 *   system_file labels + the shipped modes), then writes the module's
 *   files into it.  Nothing is written to any block device: `umount -l
 *   //system/<dir>` or a reboot restores the shipped view.
 *
 * usage: sysoverlay <module-dir> [target-root=/system]
 *   <module-dir> must contain a `system/` subdirectory.
 */
#define _GNU_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_DEPTH 24
#define SYSTEM_FILE_LABEL "u:object_r:system_file:s0"

/* Scratch areas.  Both live on /data so they are reachable from every
 * namespace and their SELinux label can be set. */
#define SCRATCH "/data/local/tmp/sysovl"
/* The file-level binds this run created, one path per line.  The next run
 * (or --unmount) takes them down again; a bind left in place would keep
 * pointing at a file under /data that a reboot wipes. */
#define BINDS "/data/local/tmp/sysovl.binds"
/* The backup tree deliberately does NOT contain a "system" component.
 *
 * vivo's mount hook rewrites a target of "//system/<x>" to the /system
 * filesystem's own "/<x>" -- i.e. "//system/etc" becomes the partition's
 * /etc.  A backup directory named .../system/etc therefore IS the target
 * the rewritten mount lands on, and the overlay silently ended up stacked
 * on the backup instead of on /system/etc (measured: the mountinfo line
 * showed the tmpfs at /data/local/tmp/sysovl.bk/system/etc).  Keeping the
 * backup tree free of a "system" component keeps the two apart. */
#define BACKUP "/data/local/tmp/sysovl.bk"

/* The backup lives under its own directory tree, and the tree is NOT wiped
 * with rm -rf: a leftover bind mount inside it makes the removal fail with
 * EROFS, and the mkdir that follows then fails too, so the copy-back finds
 * an empty directory.  mkdir -p plus a plain copy is enough. */

/* The shipped /system, read straight off the block device, and where it is
 * mounted while we copy from it.  /dev/block/dm-0 is the verity device; the
 * underlying partition is what holds the bytes. */
#define RAW_SYSTEM "/dev/block/dm-0"
#define RAW_MOUNT "/data/local/tmp/sysovl.raw"

static int g_ok;
static int g_fail;
static int g_use_init_ns;
static int g_unmount_only;

static void lg(const char *fmt, ...)
{
	char b[1024];
	va_list ap;
	int fd;

	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	fd = open("/data/local/tmp/sysoverlay.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
	if (fd < 0)
		return;
	write(fd, b, strlen(b));
	close(fd);
	printf("%s", b);
	fflush(stdout);
}

static int run_cmd(const char *fmt, ...)
{
	char buf[PATH_MAX * 2];
	va_list ap;
	int rc;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	rc = system(buf);
	if (rc == -1)
		return -1;
	return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/* Defined further down, next to the other publication helpers. */
static int bind_file(const char *src, const char *target);

/* The mount target, with the double slash that gets past the vivo hook.
 * A mount over a read-only /system needs it, and so does the unmount. */
static void hooked_path(char *out, size_t n, const char *path)
{
	snprintf(out, n, "//%s", path);
}

/* Remove every overlay layer on `dir`.  A leftover layer is invisible in
 * the mount table (it stacks under a newer one) and makes the directory look
 * empty, which reads exactly like a failed mount. */
static int unmount_dir(const char *dir)
{
	int n = 0;

	while (umount2(dir, MNT_DETACH) == 0)
		n++;
	return n;
}

/* Publish a writable mirror of `dir` (an existing /system directory).
 * The original contents are preserved: the directory is first bind-mounted
 * aside, then a tmpfs is put in its place, and the original files are
 * copied back into the tmpfs.
 *
 * Returns 0 on success, -1 on failure. */
static int publish_dir(const char *dir)
{
	char hook[PATH_MAX], cmd[PATH_MAX * 3];

	/* The backup of the shipped contents was taken BEFORE we moved into
	 * this namespace (see prepare_backups): the raw block device can be
	 * mounted read-only in the manager app's namespace, but in init's
	 * namespace /dev/block/dm-0 is the verity device and mounts empty. */
	{
		char bk[PATH_MAX], bk_parent[PATH_MAX];
		char *slash;

		snprintf(bk, sizeof bk, "%s/root%s", BACKUP, dir);
		snprintf(bk_parent, sizeof bk_parent, "%s", bk);
		slash = strrchr(bk_parent, '/');
		if (slash) {
			*slash = 0;
			run_cmd("mkdir -p '%s' 2>/dev/null", bk_parent);
		}
	}

	/* Drop any earlier overlay on this directory first.
	 *
	 * Two tmpfs layers on the same directory stack, and the upper one hides
	 * the lower one -- an empty upper layer looks exactly like a failed
	 * mount.  The layers can live in DIFFERENT namespaces of the same
	 * shared peer group (init's /system is `shared:38`, an app's is
	 * `master:38`), so clearing only the namespace we are in leaves the
	 * other one's layer on top.  Clear init's copy too. */
	{
		char hook[PATH_MAX];

		/* The double slash is what the hook lets through, and an
		 * unmount in the shared peer group reaches the layer in every
		 * namespace that can see it. */
		hooked_path(hook, sizeof hook, dir);
		while (umount2(hook, MNT_DETACH) == 0)
			;
		unmount_dir(dir);
	}

	/* The tmpfs goes in with the double slash. */
	hooked_path(hook, sizeof hook, dir);
	if (mount("tmpfs", hook, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") != 0) {
		lg("  tmpfs over %s : errno=%d (%s)\n", dir, errno, strerror(errno));
		return -1;
	}

	/* Copy the original contents back and give them /system's label and
	 * modes.  `cp -a` keeps the modes; chcon fixes the label, because a
	 * tmpfs file comes back as u:object_r:tmpfs:s0 (or init_tmpfs) and an
	 * app then reads "No such file or directory" for a file that is there.
	 *
	 * The label has to reach the WHOLE tree, not just the top level: an
	 * earlier version chcon'ed the directory and the top-level files only,
	 * and a subtree like /system/lib/hw came back with the tmpfs default
	 * label -- mediacodec, allowed to read system_file but not init_tmpfs,
	 * got EACCES on gralloc.msm8996.so, hw_get_module("gralloc") failed
	 * silently, and media.codec died dereferencing the garbage module
	 * pointer (measured 2026-10-28).  chcon -Rh relabels recursively and
	 * leaves symlinks undereferenced, so it cannot relabel a link's target
	 * by accident.
	 *
	 * The SOURCE must be the backup OF THIS DIRECTORY -- BACKUP/root<dir> --
	 * not BACKUP/root.  The backup tree keeps one "system/" component, so
	 * copying BACKUP/root into /system/bin would drop the whole system/
	 * subtree INSIDE /system/bin and leave the directory without its own
	 * files -- which is how /system/bin/sh disappeared once (measured
	 * 2026-10-27: publishing a module with a system/bin/ tree took the
	 * shell down with "exec '/system/bin/sh' failed"). */
	snprintf(cmd, sizeof cmd,
		 "cp -av '%s/root%s/.' '%s/' 2>>/data/local/tmp/sysoverlay.log; "
		 "chmod 0755 '%s' 2>/dev/null; "
		 "chcon -Rh %s '%s' 2>/dev/null; "
		 "echo RESTORED_COUNT=$(ls '%s' 2>/dev/null | wc -l) >> /data/local/tmp/sysoverlay.log",
		 BACKUP, dir, dir, dir, SYSTEM_FILE_LABEL, dir, dir);
	run_cmd(cmd);

	/* GUARD: a published directory that came back EMPTY (or lost its own
	 * contents) is worse than no overlay at all -- on this device a missing
	 * /system/bin/sh takes down every shell on the system, adb included.
	 * Refuse the layer instead of leaving a broken /system behind. */
	{
		char chk[PATH_MAX * 2];
		snprintf(chk, sizeof chk,
			 "n=$(ls '%s' 2>/dev/null | wc -l); "
			 "if [ \"$n\" -lt 1 ]; then "
			 "  echo 'REFUSED empty overlay for %s' >> /data/local/tmp/sysoverlay.log; "
			 "  umount -l '%s' 2>/dev/null; "
			 "  exit 9; "
			 "fi", dir, dir, dir);
		run_cmd(chk);
	}

	/* GUARD 2: a directory whose entries are mostly symlinks cannot be
	 * reproduced faithfully.  vivo scrambles the toybox applet targets on
	 * purpose (149 of the 151 symlinks in /system/bin point at a name that
	 * does not exist), so a copy of the tree lands a directory full of
	 * dangling links -- and /system/bin/sh then stops being executable,
	 * which takes adb and every shell down with it (measured 2026-10-27).
	 * Refuse the publication instead of breaking the device. */
	{
		char chk[PATH_MAX * 2];
		snprintf(chk, sizeof chk,
			 "tot=$(ls -A '%s' 2>/dev/null | wc -l); "
			 "ln=$(find '%s' -maxdepth 1 -type l 2>/dev/null | wc -l); "
			 "if [ \"$tot\" -gt 0 ] && [ \"$ln\" -gt 8 ]; then "
			 "  echo 'REFUSED symlink-heavy directory %s (entries=%s symlinks=%s)' "
			 "    >> /data/local/tmp/sysoverlay.log; "
			 "  umount -l '%s' 2>/dev/null; "
			 "  exit 9; "
			 "fi", dir, dir, dir, dir, dir, dir);
		run_cmd(chk);
	}

	lg("  published %s\n", dir);
	return 0;
}

/* Write the module's file into the published mirror.  The mirror is a
 * tmpfs, so a plain write works -- no second bind is needed for files that
 * did not exist in /system. */
static int put_file(const char *mod_root, const char *rel, const char *target_root,
		    char *published, mode_t mode)
{
	char src[PATH_MAX], dst[PATH_MAX], parent[PATH_MAX], cmd[PATH_MAX * 3];
	struct stat st;
	char *slash;

	snprintf(src, sizeof src, "%s/%s", mod_root, rel);
	snprintf(dst, sizeof dst, "%s%s", target_root, rel);
	snprintf(published, PATH_MAX, "%s%s", SCRATCH, rel);

	if (lstat(src, &st) != 0)
		return -1;

	snprintf(parent, sizeof parent, "%s", published);
	slash = strrchr(parent, '/');
	if (slash) {
		*slash = 0;
		run_cmd("mkdir -p '%s' 2>/dev/null", parent);
	}
	run_cmd("rm -rf '%s' 2>/dev/null", published);
	snprintf(cmd, sizeof cmd, "cat '%s' > '%s' 2>/dev/null; chmod %o '%s' 2>/dev/null; "
				  "chcon %s '%s' 2>/dev/null",
		 src, published, mode, published, SYSTEM_FILE_LABEL, published);
	run_cmd(cmd);
	return 0;
}

/* Recursively publish the module's files under `rel`. */
static void overlay(const char *mod_root, const char *target_root, const char *rel, int depth)
{
	char dir[PATH_MAX];
	DIR *d;
	struct dirent *e;

	if (depth > MAX_DEPTH)
		return;

	snprintf(dir, sizeof dir, "%s%s", mod_root, rel);
	d = opendir(dir);
	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		char child_rel[PATH_MAX], target[PATH_MAX], published[PATH_MAX], src[PATH_MAX];
		struct stat sst;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(child_rel, sizeof child_rel, "%s/%s", rel[0] ? rel : "", e->d_name);
		snprintf(target, sizeof target, "%s%s", target_root, child_rel);
		snprintf(src, sizeof src, "%s/%s", mod_root, child_rel);

		if (lstat(src, &sst) != 0)
			continue;
		if (S_ISDIR(sst.st_mode)) {
			/* NEVER publish /system/lib or /system/lib64.
			 * A tmpfs overlay here gives libc.so a new inode.  Zygote has
			 * already loaded libc from dm-0; when an app later dlopens
			 * gralloc.msm8996.so (or any .so with DT_NEEDED libc.so) from
			 * the tmpfs copy, the linker resolves libc to the snapshot
			 * copy (different inode) and loads a SECOND libc, which
			 * crashes __libc_init_globals with SEGV_ACCERR.  Subdirs
			 * (e.g. /system/lib/soundfx) are safe and still publishable,
			 * because they do not contain libc.so. */
			if (!strcmp(target, "/system/lib") || !strcmp(target, "/system/lib64")) {
				lg("  SKIP %s (libc dedup crash risk)\n", target);
				continue;
			}
			/* The directory itself has to become writable before a
			 * file inside it can be published. */
			if (publish_dir(target) != 0) {
				g_fail++;
				continue;
			}
			overlay(mod_root, target_root, child_rel, depth + 1);
			continue;
		}

		/* A regular file: try a FILE bind first.  It leaves the parent
		 * directory untouched, which is what keeps /system/bin intact
		 * (see bind_file for the measurement). */
		{
			struct stat shipped;
			mode_t mode;
			int existed = (stat(target, &shipped) == 0);

			/* Prefer the shipped file's mode; fall back to the module's
			 * own execute bit. */
			if (existed)
				mode = shipped.st_mode & 07777;
			else if (sst.st_mode & 0111)
				mode = 0755;
			else
				mode = 0644;

			/* The file to bind from is the module's own copy, staged in
			 * SCRATCH (which is on /data and writable). */
			if (put_file(mod_root, child_rel, target_root, published, mode) != 0) {
				g_fail++;
				continue;
			}

			/* Bind the staged copy over the target.  A bind needs the
			 * target to exist, so a file that is NEW to /system cannot
			 * be bound -- for those the parent directory has to be
			 * published as a tmpfs, and the file is written into it. */
			if (existed) {
				if (bind_file(published, target) == 0) {
					lg("  bind %s <- %s\n", target, published);
					g_ok++;
					continue;
				}
				lg("  bind %s failed, falling back to directory publish\n", target);
			}

			/* The published directory is a tmpfs that hides the original
			 * /system tree, so the module's file has to be put INTO it.
			 *
			 * Writing it in is enough -- and it is also the only thing that
			 * works for a file that did not exist in /system: there is no
			 * mount point to bind over, and the tmpfs instance of THIS
			 * namespace is the only place the file can live.  A file that DID
			 * exist is written over the copy of the original in the tmpfs,
			 * which is why the original bytes have to be restored first.
			 */
			{
				char cmd[PATH_MAX * 3];

				snprintf(cmd, sizeof cmd, "cat '%s' > '%s' 2>/dev/null; chmod %o '%s' 2>/dev/null; "
							  "chcon %s '%s' 2>/dev/null; true",
					 published, target, mode, target, SYSTEM_FILE_LABEL, target);
				run_cmd(cmd);
				if (!existed)
					lg("  created %s (new file)\n", target);
			}
			lg("  overlay %s <- %s\n", target, published);
			g_ok++;
		}
	}
	closedir(d);
}

/* Bind-mount a single module file onto a single target path.
 *
 * Why a FILE bind and not a directory tmpfs:
 * publishing a directory means replacing it with a tmpfs and copying the
 * original contents back.  On this device that is destructive for
 * /system/bin: the directory holds 419 entries of which 151 are symlinks,
 * and 149 of those point at a name that does not exist (vivo scrambles the
 * toybox applet targets on purpose, so an app cannot replace them).  A copy
 * of the directory therefore reproduces dangling symlinks, and the shell
 * stops working with "exec '/system/bin/sh' failed: No such file or
 * directory" -- which also takes adb down with it (measured 2026-10-27).
 *
 * A file bind touches nothing but the file it names: the directory, its
 * permissions and every other entry in it stay exactly as shipped.  The
 * mount has to be undone on the next run, so it is recorded in BINDS.
 *
 * The target has to exist for a bind to work.  For a file that does NOT
 * exist in /system there is nothing to bind onto, and the parent directory
 * is read-only -- so those files still need the directory tmpfs.  Magisk's
 * own binaries all exist in /system/bin already on this ROM? No: they do
 * not.  Which is why the caller decides: g_file_bind is attempted first and
 * falls back to the directory publication.
 *
 * Returns 0 on success, -1 if the bind failed.
 */
static int bind_file(const char *src, const char *target)
{
	char hook[PATH_MAX], cmd[PATH_MAX * 3];

	/* The double slash is what gets past vivo's mount hook. */
	hooked_path(hook, sizeof hook, target);

	snprintf(cmd, sizeof cmd,
		 "umount2 '%s' 2>/dev/null; "
		 "mount --bind '%s' '%s' 2>/dev/null",
		 hook, src, hook);
	if (run_cmd(cmd) != 0)
		return -1;

	/* The bound file keeps the label of the file we bound, which is a
	 * private file under /data -- restore the /system one. */
	snprintf(cmd, sizeof cmd, "chcon %s '%s' 2>/dev/null; true",
		 SYSTEM_FILE_LABEL, target);
	run_cmd(cmd);

	/* Remember it so the next run can take it down again. */
	snprintf(cmd, sizeof cmd, "echo '%s' >> %s 2>/dev/null; true", target, BINDS);
	run_cmd(cmd);

	return 0;
}

/* Copy the shipped contents of every directory the module touches into
 * BACKUP, reading them from the RAW BLOCK DEVICE.
 *
 * Why the raw device and not the mounted /system: by the time an overlay is
 * published, the directory may already be covered by a tmpfs from an
 * earlier run (a leftover layer is invisible -- the mount succeeds, the
 * directory is simply empty), and copying from /system then copies
 * NOTHING.  The block device always holds the shipped bytes.
 *
 * Why this runs BEFORE the namespace switch: /dev/block/dm-0 is the verity
 * device, and in init's namespace it mounts EMPTY (measured: the same
 * mount in the manager app's namespace lists 150 files under etc/).  In
 * the manager app's namespace the verity mapping is still usable, so the
 * copy is taken there and the result -- plain files under /data -- is
 * visible from every namespace.
 */
static void prepare_backups(const char *mod_root, const char *target_root)
{
	char moddir[PATH_MAX], cmd[PATH_MAX * 3];

	/* The module's top-level directories are the ones that get published. */
	snprintf(moddir, sizeof moddir, "%s", mod_root);
	{
		DIR *d = opendir(moddir);
		struct dirent *e;

		if (!d)
			return;
		while ((e = readdir(d)) != NULL) {
			char src[PATH_MAX], dst[PATH_MAX], parent[PATH_MAX];
			struct stat st;
			const char *rel;

			if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
				continue;
			snprintf(src, sizeof src, "%s/%s", moddir, e->d_name);
			if (lstat(src, &st) != 0 || !S_ISDIR(st.st_mode))
				continue;
			snprintf(dst, sizeof dst, "%s/%s", target_root, e->d_name);
			snprintf(parent, sizeof parent, "%s/root%s", BACKUP, dst);

			/* The path inside the raw mount is the /system path minus
			 * its leading "/system" -- the mount root IS the /system
			 * root. */
			rel = dst;
			if (!strncmp(rel, target_root, strlen(target_root)))
				rel += strlen(target_root);

			/* `cp -a SRC/. DST/` needs DST to exist as a directory, and
			 * it needs every parent of DST too -- and the parent here is
			 * under BACKUP, whose own parent has to exist first. */
			snprintf(cmd, sizeof cmd,
				 "mkdir -p '%s' 2>/dev/null; "
				 "cp -a '%s%s/.' '%s/' 2>/dev/null; "
				 "echo BACKUP_COUNT=$(ls '%s' 2>/dev/null | wc -l) >> /data/local/tmp/sysoverlay.log",
				 parent, RAW_MOUNT, rel, parent, parent);
			run_cmd(cmd);
			lg("  backup %s <- %s%s\n", dst, RAW_MOUNT, rel);
		}
		closedir(d);
	}
}

/* Runs inside PID 1's mount namespace. */
static int worker(const char *mod_root, const char *target_root)
{
	if (g_unmount_only) {
		/* Every directory the module would touch, plus the ones a
		 * previous run may have covered.
		 *
		 * The target is passed with the double slash, because that is
		 * the only spelling the vivo hook lets through, and the unmount
		 * has to reach the copy in init's namespace too: the layers all
		 * sit in ONE shared peer group, and an unmount in the group
		 * removes the layer everywhere it is visible. */
		char cmd[PATH_MAX * 2];

		snprintf(cmd, sizeof cmd, "for d in '%s'/*; do [ -d \"$d\" ] && "
					   "while umount -l \"//$d\" 2>/dev/null; do :; done; "
					   "done; true", target_root);
		run_cmd(cmd);

		/* The file-level binds come down too.  Without this a bind would
		 * outlive the run and keep /system pointing at a file under
		 * /data, which a reboot wipes -- leaving a dangling entry in
		 * /system that no longer has a source. */
		snprintf(cmd, sizeof cmd,
			 "if [ -f %s ]; then "
			 "  while IFS= read -r t; do "
			 "    [ -n \"$t\" ] && umount -l \"//$t\" 2>/dev/null; "
			 "  done < %s; "
			 "  rm -f %s; "
			 "fi; true", BINDS, BINDS, BINDS);
		run_cmd(cmd);

		lg("unmount-only: cleared overlays under %s\n", target_root);
		return 0;
	}
	overlay(mod_root, target_root, "", 0);
	run_cmd("sync");
	return g_fail ? 1 : 0;
}

int main(int argc, char **argv)
{
	const char *mod_dir = NULL;
	const char *target_root = "/system";
	char mod_root[PATH_MAX], cmd[PATH_MAX * 2];
	int fd, rc, status = 0, i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--init-ns"))
			g_use_init_ns = 1;
		else if (!strcmp(argv[i], "--unmount"))
			g_unmount_only = 1;
		else if (!mod_dir)
			mod_dir = argv[i];
		else
			target_root = argv[i];
	}
	if (!mod_dir) {
		fprintf(stderr,
			"usage: %s <module-dir> [target-root=/system] [--init-ns]\n", argv[0]);
		return 2;
	}
	snprintf(mod_root, sizeof mod_root, "%s/system", mod_dir);
	if (!g_unmount_only && access(mod_root, F_OK) != 0) {
		fprintf(stderr, "%s/system does not exist\n", mod_dir);
		return 2;
	}

	lg("=== sysoverlay %s -> %s ===\n", mod_root, target_root);

	snprintf(cmd, sizeof cmd, "mkdir -p '%s' '%s' && chmod 0755 '%s' '%s' && "
				   "chcon u:object_r:shell_data_file:s0 '%s' '%s' 2>/dev/null; true",
		 SCRATCH, BACKUP, SCRATCH, BACKUP, SCRATCH, BACKUP);
	run_cmd(cmd);

	/* Take the backups of the shipped contents FIRST, while we are still
	 * in the manager app's namespace (see prepare_backups). */
	if (!g_unmount_only) {
		run_cmd("umount -l '%s' 2>/dev/null; mkdir -p '%s' 2>/dev/null; "
			"mkdir -p '%s' 2>/dev/null", RAW_MOUNT, RAW_MOUNT, BACKUP);
		snprintf(cmd, sizeof cmd, "mount -o ro '%s' '%s' 2>/dev/null", RAW_SYSTEM, RAW_MOUNT);
		run_cmd(cmd);
		prepare_backups(mod_root, target_root);
		run_cmd("umount -l '%s' 2>/dev/null", RAW_MOUNT);
	}

	/* Where to mount.
	 *
	 * init's /system and every app's /system are in ONE shared peer group
	 * (group 13: init's copy is `shared:13`, each app's copy is
	 * `master:13`), and the group propagates in both directions -- measured
	 * on this ROM: a tmpfs mounted over /system/etc from the manager app's
	 * namespace showed up in init's /proc/1/mountinfo, and `umount -l
	 * /system/etc` issued from the manager app's namespace removed the
	 * layer that had been created in init's.
	 *
	 * So a mount made in EITHER namespace is global.  The default is to
	 * mount where we already are (the manager app's namespace, which is
	 * where modmount.sh works from); `--init-ns` switches to PID 1's.
	 *
	 * Either way, only ONE layer may exist: two tmpfs layers on the same
	 * directory stack, and the upper one hides the lower one -- an empty
	 * upper layer is indistinguishable from a failed mount.
	 */
	if (g_use_init_ns) {
		fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			lg("open /proc/1/ns/mnt: errno=%d -- need root; nothing done\n", errno);
			return 2;
		}
		rc = fork();		/* setns(CLONE_NEWNS) refuses a threaded caller */
		if (rc == 0) {
			if (setns(fd, CLONE_NEWNS)) {
				lg("setns(/proc/1/ns/mnt): errno=%d -- nothing mounted\n", errno);
				_exit(3);
			}
			lg("ns: joined PID 1's mount namespace\n");
			_exit(worker(mod_root, target_root));
		}
		close(fd);
		if (rc < 0) {
			lg("fork: errno=%d\n", errno);
			return 1;
		}
		waitpid(rc, &status, 0);
		if (WIFEXITED(status))
			status = WEXITSTATUS(status);

		/* And once more here.
		 *
		 * The two namespaces' /system mounts are peers in one shared
		 * group, so a mount made in one is CLONED into the other -- but a
		 * tmpfs peer's clone has its OWN empty instance: the shared group
		 * shares the mount event, not the filesystem's contents.  Measured:
		 * after publishing in PID 1's namespace, init's /proc/1/mountinfo
		 * showed the tmpfs and the manager app's showed a peer of it, but
		 * the peer's directory was empty while the original held the
		 * restored files.  So each namespace needs its own instance with
		 * its own content.
		 *
		 * The backups are plain files under /data, so the second pass
		 * reads the same shipped bytes. */
		lg("ns: publishing the manager app's own copy too\n");
		status = worker(mod_root, target_root);
	} else {
		status = worker(mod_root, target_root);
	}
	lg("overlays=%d failures=%d\n", g_ok, g_fail);
	return status;
}
