#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* Passive: stat + open + close. Never ioctl, never transfers data,
   never touches a block device. */
static const char *nodes[] = {
  "kgsl", "kgsl-3d0", "kgsl-2d0", "kgsl-2d1", "binder", "hwbinder", "vndbinder",
  "ashmem", "ion", "sw_sync", "st_events", "xt_qtaguid", "keychord", "uinput",
  "uhid", "tun", "fuse", "msm_audio_cal", "msm_hweffects", "hbtp_vm", "hbtp_input",
  "memory_bandwidth", "network_throughput", "network_latency", "pta", "qce", "diag",
  "smd0", "smd4", "smd5", "smd6", "smd7", "adsprpc-smd", "sdsprpc-smd", "uio0",
  "uio1", "mhi_uci0", "jpeg0", "jpeg1", "jpeg2", "jpeg3", "video0", "video1",
  "video17", "video32", "video33", "video34", "video35", "mdss_rotator", "goodix_fp",
  "qbt1000", "sensors", "seemplog", "avtimer", "msm_pacman", "ramdump_adsp",
  "ramdump_modem", "ramdump_venus", "ramdump_a530_zap", "smem_log", "rfkill",
  "loop-control", "hw_random", "vga_arbiter", "cpu_dma_latency", "device-mapper",
  "msm_rtac", "mtp_usb", "usb_accessory", "rmnet_ctrl", "dpl_ctrl", "ccid_ctrl",
  "coresight-tmc-etf", "log_main", "log_events", "log_radio", "psaux", "null",
  "zero", "random", "urandom", "socket", "prop", "nmea", "gps", "alarm",
  "qseecom", "tzdriver", "spidev0.0", "i2c-0", "i2c-2", "ttyMSM0", "ptp0",
  "msm_perf", "time_sync", "radio0", "fm_transmitter", "usf_tsonar", "adsp",
  "mp3", "pps", "ttyGS0", "fb0", "graphics/fb0", "input/event0", "input/mice",
  "tfa98xx", "tfa98xx_cfg", "es9038", "msm_adsp_sleepmon", "ipc_logging",
  "socket/zygote", "socket/logd", "socket/logdr", "socket/tombstoned",
  "qemud", "block/loop0", NULL
};

int main(void)
{
  int i;
  printf("%-22s %-9s %-6s %-9s %-11s %-11s %s\n",
         "node", "exist", "mode", "uid:gid", "rd", "wr", "rdwr");
  for (i = 0; nodes[i]; i++) {
    char p[128];
    struct stat st;
    int have_stat = (stat(p, &st) == 0);
    int rd, wr, rw, fd;
    snprintf(p, sizeof p, "/dev/%s", nodes[i]);
    if (stat(p, &st) != 0) continue;            /* silent when absent */
    int fd_only = -1; (void)fd_only;
    errno = 0; fd = open(p, O_RDONLY | O_NONBLOCK); rd = fd < 0 ? errno : 0; if (fd >= 0) close(fd);
    errno = 0; fd = open(p, O_WRONLY | O_NONBLOCK); wr = fd < 0 ? errno : 0; if (fd >= 0) close(fd);
    errno = 0; fd = open(p, O_RDWR   | O_NONBLOCK); rw = fd < 0 ? errno : 0; if (fd >= 0) close(fd);
#define W(e) ((e) == 0 ? "OK" : ((e) == EACCES ? "EACCES" : ((e) == EPERM ? "EPERM" : \
          ((e) == EBUSY ? "EBUSY" : ((e) == ENODEV ? "ENODEV" : \
          ((e) == ENOENT ? "ENOENT" : strerror(e)))))))
    if (rd == ENOENT && wr == ENOENT && rw == ENOENT && !have_stat) continue;
    printf("%-22s %-9s %04o  %d:%-7d %-11s %-11s %s\n",
           nodes[i], have_stat ? "yes" : "stat!",
           have_stat ? (unsigned)(st.st_mode & 07777) : 0u,
           have_stat ? (int)st.st_uid : -1, have_stat ? (int)st.st_gid : -1,
           W(rd), W(wr), W(rw));
  }
  return 0;
}
