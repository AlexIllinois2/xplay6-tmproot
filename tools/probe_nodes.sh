#!/system/bin/sh
# Passive attack-surface probe: stat + open(O_RDONLY/O_WRONLY) with zero bytes moved.
# No ioctl, no data transfer, no write to any partition.
LIST="kgsl kgsl-3d0 kgsl-2d0 kgsl-2d1 binder hwbinder vndbinder ashmem ion sw_sync st_events
xt_qtaguid keychord uinput uhid tun fuse msm_audio_cal msm_hweffects hbtp_vm hbtp_input
memory_bandwidth network_throughput network_latency pta qce diag smd0 smd4 smd5 smd6 smd7
adsprpc-smd sdsprpc-smd uio0 uio1 mhi_uci0 jpeg0 jpeg1 jpeg2 jpeg3 video0 video1 video17
video32 video33 video34 video35 mdss_rotator goodix_fp qbt1000 sensors seemplog avtimer
msm_pacman ramdump_adsp ramdump_modem ramdump_venus ramdump_a530_zap smem_log rfkill
loop-control hw_random vga_arbiter cpu_dma_latency device-mapper msm_rtac mtp_usb
usb_accessory rmnet_ctrl dpl_ctrl ccid_ctrl coresight-tmc-etf log_main log_events
log_radio psaux null zero random urandom socket prop nmea gps alarm ion_system"
for n in $LIST; do
  p="/dev/$n"
  a=$(ls -lL "$p" 2>&1)
  case "$a" in *"No such file"*) continue;; esac
  dd if="$p" of=/dev/null bs=1 count=0 2>/dev/null && r=OK || r=$(dd if="$p" of=/dev/null bs=1 count=0 2>&1 | sed -e 's/.*: //')
  dd of="$p" bs=1 count=0 2>/dev/null && w=OK || w=$(dd of="$p" bs=1 count=0 2>&1 | sed -e 's/.*: //' | head -1)
  set -- $a
  printf '%-20s %-12s %-8s r=%-20s w=%s\n' "$n" "$1" "$3:$4" "$r" "$w"
done
