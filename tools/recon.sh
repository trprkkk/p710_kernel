#!/system/bin/sh
# =====================================================================
#  Rakuten Hand (P710 / Tinno, SM7125 atoll, Android 10) リコン収集スクリプト
#  用途: 一時root計画に必要な「端末の実状態」を1回で集める
#  実行:  adb push tools/recon.sh /data/local/tmp/ && adb shell sh /data/local/tmp/recon.sh > recon.txt 2>&1
#  注意:  読み取りのみ。書き込みや再起動は行わない。
# =====================================================================
export PATH=/sbin:/system/bin:/system/xbin:$PATH

echo "################ 1. BUILD / PATCH LEVEL ################"
getprop | grep -E "ro\.(build|bootimage|vendor|system|product|odm)\.(fingerprint|version|build\.version|date)" | sort
echo "--- SPL (framework / vendor / bootimage) ---"
for p in ro.build.version.security_patch ro.vendor.build.version.security_patch \
         ro.bootimage.build.version.security_patch ro.system.build.version.security_patch \
         ro.product.build.version.security_patch ro.odm.build.version.security_patch; do
  printf "%-45s %s\n" "$p" "$(getprop $p)"
done
echo "--- AVB / bootloader state ---"
for p in ro.boot.veritymode ro.boot.veritymode.managed ro.boot.flash.locked ro.boot.vbmeta.device_state \
         ro.boot.vbmeta.hash_alg ro.boot.vbmeta.digest ro.boot.vbmeta.size ro.boot.slot_suffix \
         ro.boot.hardware ro.boot.hardware.platform ro.boot.bootloader ro.boot.baseband ro.boot.verifiedbootstate; do
  printf "%-45s %s\n" "$p" "$(getprop $p)"
done
echo "--- kernel ---"
cat /proc/version
uname -a
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
echo "--- 起動時間 / 再起動の痕跡 ---"
uptime 2>/dev/null; cat /proc/stat | head -3

echo
echo "################ 2. KERNEL CONFIG (running) ################"
if [ -r /proc/config.gz ]; then
  zcat /proc/config.gz > /data/local/tmp/config.gz.dump && echo "config dumped: /data/local/tmp/config.gz.dump ($(wc -l < /data/local/tmp/config.gz.dump) lines)"
  grep -E "CONFIG_(USER_NS|BPF|KASAN|SLAB_FREELIST|RANDOMIZE_BASE|MODULES|SECURITY_SELINUX|IKCONFIG|DEVMEM|STRICT_DEVMEM|TUN|NF_TABLES|IO_URING|KGSL|TOUCHSCREEN_HIMAX|HIMAX|ION|ASHMEM|DMABUF|HARDENED_USERCOPY|ARM64_PAN|RANDOMIZE_MODULE_REGION)" /data/local/tmp/config.gz.dump
else
  echo "/proc/config.gz は読めない (未設定 or 権限なし)"
fi
echo "--- sysctl 状態 ---"
for s in kernel.unprivileged_bpf_disabled kernel.dmesg_restrict kernel.kptr_restrict \
         kernel.perf_event_paranoid kernel.yama.ptrace_scope kernel.unprivileged_userns_clone \
         vm.mmap_min_addr net.ipv4.ping_group_range; do
  printf "%-40s %s\n" "$s" "$(cat /proc/sys/$(echo $s | tr . /) 2>/dev/null)"
done

echo
echo "################ 3. SELinux ################"
getenforce
cat /sys/fs/selinux/enforce 2>/dev/null
cat /sys/fs/selinux/policyvers 2>/dev/null
cat /sys/fs/selinux/policy > /data/local/tmp/sepolicy.bin 2>/dev/null && echo "policy dumped: /data/local/tmp/sepolicy.bin ($(wc -c < /data/local/tmp/sepolicy.bin) bytes)"

echo
echo "################ 4. /dev インベントリ (perm + label) ################"
ls -lZ /dev 2>/dev/null
echo "--- 特に重要なノード ---"
for d in /dev/kgsl-3d0 /dev/kgsl-2d0 /dev/kgsl-3d1 /dev/ion /dev/ashmem /dev/dma_heap \
         /dev/binder /dev/hwbinder /dev/vndbinder /dev/fuse /dev/net/tun /dev/tun \
         /dev/diag /dev/adsprpc-smd /dev/fastrpc /dev/qce /dev/qseecom /dev/tee0 /dev/teepriv0 \
         /dev/video0 /dev/media0 /dev/v4l-subdev0 /dev/msm_rotator /dev/graphics/fb0; do
  [ -e "$d" ] && ls -ldZ "$d"
done
ls -ldZ /dev/dma_heap/* 2>/dev/null

echo
echo "################ 5. /proc ・ /sys の書き込み可能候補 (0666/0660) ################"
ls -lZ /proc 2>/dev/null | grep -vE "^d|^total" | grep -E "^-........w|^-.....w" 
echo "--- himax / touch / tinno 関連 ---"
ls -lZ /proc 2>/dev/null | grep -Ei "himax|touch|gesture|hx|tinno|tp_"
ls -lZ /sys/class 2>/dev/null | head -40
echo "--- sysfs で world-writable なもの (先頭500件走査) ---"
find /sys -maxdepth 4 -perm -o+w -type f 2>/dev/null | head -40

echo
echo "################ 6. パーティション ################"
ls -l /dev/block/by-name/ 2>/dev/null || ls -l /dev/block/bootdevice/by-name/ 2>/dev/null
cat /proc/partitions
df -h 2>/dev/null | head -20
mount 2>/dev/null | grep -E " / | /vendor | /system | /data " 

echo
echo "################ 7. サービス / 権限のヒント ################"
getprop | grep -Ei "selinux|keystore|keymaster|tee|widevine|secure" | sort | head -20
pm list packages -s 2>/dev/null | head -30
echo "--- 到達可能な binder サービス(hwbinder/binder) ---"
ls -lZ /dev/socket 2>/dev/null | head -20
id
cat /proc/self/attr/current 2>/dev/null

echo
echo "################ 8. dmesg(可能なら) ################"
dmesg 2>&1 | tail -5
echo "################ DONE ################"
