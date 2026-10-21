#!/system/bin/sh
# Android 6 tuning baseline, live half.  Read-only on every partition; the only writes
# are under /data/local/tmp/audlive (tmpfs-backed /data, wiped by a reboot).
# Why "now": mixer values, DAPM state and the framework's loaded profiles exist only
# while this boot is up, and /data/data/com.vivo.audiofx holds the owner's own presets,
# which no firmware package contains.
set -u
P=/data/local/tmp/audlive
rm -rf $P
mkdir -p $P

echo "[1/7] alsa kernel view"
for f in $(find /proc/asound -type f 2>/dev/null); do
	out=$P/proc_asound/${f#/proc/asound/}
	mkdir -p "$(dirname $out)" 2>/dev/null
	cat $f > $out 2>/dev/null
done
tinymix -D 0 > $P/tinymix-D0.txt 2>&1

echo "[2/7] dapm / codec / dai state (debugfs)"
cp -R /sys/kernel/debug/asoc $P/debugfs_asoc 2>/dev/null
for f in afe_loopback afe_loopback_gain audio_in_latency_measurement_node \
	audio_out_latency_measurement_node; do
	cat /sys/kernel/debug/$f > $P/dbg_$f.txt 2>&1
done

echo "[3/7] framework side"
dumpsys media.audio_flinger > $P/dumpsys_audio_flinger.txt 2>&1
dumpsys media.audio_policy > $P/dumpsys_audio_policy.txt 2>&1
dumpsys audio > $P/dumpsys_audio.txt 2>&1
dumpsys voiceinteraction > $P/dumpsys_voiceinteraction.txt 2>&1
service list > $P/service_list.txt 2>&1
getprop > $P/getprop.txt 2>&1

echo "[4/7] the tuner app's own data (owner settings)"
pm list packages -3 -f > $P/packages_3rd.txt 2>&1
pm list packages -s -f > $P/packages_sys.txt 2>&1
for pkg in com.vivo.audiofx com.android.settings; do
	D=/data/data/$pkg
	ls -lR $D > $P/ls_data_$pkg.txt 2>&1
	tar -czf $P/data_$pkg.tgz -C $D . 2>/dev/null
done

echo "[5/7] shipped config + HAL bytes (the portable half)"
tar -czf $P/etc_audio.tgz -C / \
	system/etc/audio_effects.conf system/etc/audio_platform_info.xml \
	system/etc/audio_platform_info_i2s.xml system/etc/audio_policy.conf \
	system/etc/init.qcom.audio.sh system/etc/aanc_tuning_mixer.txt \
	system/etc/mixer_paths.xml system/etc/mixer_paths_dtp.xml \
	system/etc/mixer_paths_i2s.xml system/etc/mixer_paths_tasha.xml \
	system/etc/mixer_paths_tasha.PD1610.xml system/etc/mixer_paths_tasha.PD1610LG4.xml \
	system/etc/ftm-mixerpath.PD1610.xml system/etc/ftm-mixerpath.PD1516A.xml \
	system/etc/ftm-mixerpath.TD1503.xml system/etc/ftm-mixerpath.default.xml \
	system/etc/sound_trigger_mixer_paths.xml \
	system/etc/sound_trigger_mixer_paths_wcd9330.xml \
	system/etc/sound_trigger_platform_info.xml \
	system/etc/surround_sound_3mic system/etc/acdbdata \
	system/etc/media_codecs.xml system/etc/media_codecs_vivo_audio.xml \
	system/etc/media_codecs_vivo_video.xml system/etc/media_codecs_google_audio.xml \
	system/etc/media_codecs_google_telephony.xml system/etc/media_codecs_google_video.xml \
	system/etc/media_codecs_performance.xml system/etc/media_profiles.xml \
	vendor/etc/audio_effects.conf vendor/etc/audio_output_policy.conf \
	2>/dev/null
tar -czf $P/hal_audio.tgz -C / \
	system/lib64/hw/audio.primary.msm8996.so system/lib64/hw/audio_policy.default.so \
	system/lib64/hw/audio.a2dp.default.so system/lib64/hw/audio.r_submix.default.so \
	system/lib64/hw/audio.usb.default.so system/lib64/hw/audio.primary.default.so \
	system/lib64/soundfx vendor/lib64/soundfx \
	2>/dev/null

echo "[6/7] the effect graph the framework is actually holding"
ls -l /system/lib64/soundfx /vendor/lib64/soundfx > $P/ls_soundfx.txt 2>&1
cat /proc/asound/cards > $P/cards.txt 2>&1
for p in $(grep -l audio /proc/*/maps 2>/dev/null | cut -d/ -f3 | sort -u | head -8); do
	echo "== pid $p $(cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ')" >> $P/loaders.txt
	grep -aiE "audio|soundfx|acdb|SVA|adsp" /proc/$p/maps 2>/dev/null | awk '{print $6}' \
		| sort -u >> $P/loaders.txt
done

echo "[7/7] pack"
du -sh $P/* 2>/dev/null
tar -czf /data/local/tmp/audlive.tgz -C /data/local/tmp audlive
ls -l /data/local/tmp/audlive.tgz
echo DONE-LIVE-CAPTURE
