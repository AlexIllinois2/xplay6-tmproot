月虹提权助手 v1.9.39 —— 源码包构建说明（新增 1.17.12 固件支持）
=============================================================

v1.9.39 相对 v1.9.38 的唯一功能变化：**PD1610_D_1.17.12（Android 6.0.1，
内核 3.18.20-perf-geb775ef-dirty，2017-01-20）正式进入受支持名单**，
与 1.15.1（3.18.20-perf-gb6998a3）并列；未知内核一律拒写。

机制变化
--------
1. tools/clobber.c 的 route-6 目标不再是一组全局常量，而是按运行内核的 UTS release
   自选的档案表（/proc/sys/kernel/osrelease 前缀匹配，未知 refuse）：
     · 6.0.1-1.15.1 : enforce 0xffffffc00189be74 / modprobe 0xffffffc001635a30 /
                       perm_map 0xffffffc00189f4d0 / 豁免位 {164,241,494,627}
     · 6.0.1-1.17.12: enforce 0xffffffc00189cff4 / modprobe 0xffffffc001635a30（与 1.15.1 同 VA）/
                       perm_map 0xffffffc0018a0650 / 豁免位 {164,242,496,629}
   豁免位是 1.17.12 实载策略的编号：art/pol1712-live.bin 是 root 下从
   /sys/fs/selinux/policy 倒出的活策略（255620 B，md5 652486d079b3105843ab57ee096f4d52），
   tools/gen_policy_tsv.py 把它解析成 art/policy-types-1712-live.tsv。
   功能证明（不是纸面推导）：v1.9.39 的 map-only 链一次种下 {164,242,496,629} 后，
   su 通道在 getenforce=Enforcing 下应答 uid=0（2026-10-25 11:03 logcat 证人行）。
2. 门禁：
   · tools/gate_constants.py 新增 6.0.1-1712 臂——不用 pgdalias（名字门臂未移植到该内核），
     而是从 fw/1712/Image + art/kallsyms-1712-real.txt 独立重推三个地址：
     modprobe 取唯一 "/sbin/modprobe" 字面量并对 kallsyms 交叉核对；
     selinux_enforcing 取 enforcing_setup 的 adrp+str 对；perm_map 取
     security_load_policy 引用次数最多的静态对象（policydb）+0x1b0。与 clobber.c 不符即拒。
   · tools/exempt_bits_check.py 新增 1712 臂——esc_exempt_1712 必须等于活策略 tsv 里
     kernel/qti_init_shell/init/untrusted_app 的编号，且节点容量 ≤4。
3. su 名字门（sugate）臂仍只有 1.15.1 的推导：在 1.17.12 上 nativeSugate 明确 refuse
   （“改名客户端”路线不受影响：sux / rootsh）。
4. tools/run_temproot.sh 增加 3.18.20-perf-geb775ef* 内核分支（adb 侧双常量）。

构建
----
与历版相同（SDK build-tools 35.0.0 / platform android-34 / NDK 29.0.13846066）：

    SDK=/path/to/Android/Sdk bash tools/apk/build.sh

全门禁构建需要三枚内核镜像（瘦包不含，哈希见 INTEGRITY.txt B 段，
从对应 ROM boot.img 的 kernel blob 解 gzip 即得；1.17.12 的 blob 是
gzip(Image)+vivo头+dtb 的复合体，Image 在其后约 8.5MB 处开始）：
    fw/Image        1.15.1（route-6 6.0.1-1.15.1 档案 + pgdalias 6.0.1 臂的权威）
    fw/7/Image      7.1.1（route-7/8 的权威）
    fw/1712/Image   1.17.12（6.0.1-1712 门禁臂的权威，24479888 B）

装机的坑（1.17.12 实测）：vivo 对 `adb install -r` 覆盖安装会静默回
INSTALL_FAILED_CANCELLED_BY_USER（无弹窗）；先 `adb uninstall com.xplay6.temproot`
再 `pm install` 即正常。

验收记录（2026-10-25，PD1610 1.17.12 全新刷机 + 清数据后）
--------------------------------------------------------
· gate_constants.py 22 对全 ok（含 6.0.1-1712 三地址独立重推）
· exempt_bits_check.py：esc_exempt_1712 == 活策略 {164,242,496,629}，2 节点 @0xffffffc001635a78
· APK route 6：mapOnly=1 第 1 次尝试即 daemon up，modprobe 读回=ours；
  种图后自动翻回 Enforcing，su 通道证人 0|Enforcing
· adb 路：clobber CLI（档案自选）+ rootsh + mpp 全通，rootsh 应答 uid=0
· 回归未做：1.15.1 与 7.1.1 路线本轮没上机（常量未动，门禁比对通过）
