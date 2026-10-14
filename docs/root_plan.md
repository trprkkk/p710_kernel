# Rakuten Hand 4G (P710AE) root 化 実行計画

対象: `P710AE_10.0_RMN_JP_154` / Android 10 / Snapdragon 720G (atoll, SM7125) / SPL 2023-01-01
前提条件（ユーザー確認済み）:

* **BLU (bootloader unlock) は不可** — fastboot が無い。書き込み手段は「一時root からの `dd`」のみ。
* **AVB は AOSP 公開テストキー (testkey_rsa4096) がそのまま使われている** → 秘密鍵が公開されているので、
  boot / vbmeta を自分で再署名できる（= 改変しても検証が通る）。
* 端末は文鎮化リスクと隣り合わせなので、**書き込み前に必ずダンプを取る**。

全体の流れ:

```
[1] 一時root 獲得 (カーネル exploit)      ← ここが唯一の難所。docs/analysis_report.md §3 参照
        ↓
[2] boot / vbmeta をダンプ & バックアップ  ← 失敗したら書き戻すため必須
        ↓
[3] Magisk で boot.img をパッチ
        ↓
[4] tools/patch_vbmeta.py で vbmeta を再署名（テストキー）
        ↓
[5] dd で boot / vbmeta を書き込み → 再起動
        ↓
[6] Magisk が起動 → 恒久 root（以後は通常の Magisk 運用）
```

---

## 1. 一時root の獲得

* 候補と状況は `docs/analysis_report.md` §3 を参照。
  **現時点の主軸は kgsl（`/dev/kgsl-3d0` = アプリから ioctl を叩ける）**。binder 系（CVE-2023-20938）は
  ソース実測の結果「このカーネル系統では成立しない」に修正済み（§3.1）。
* 実機確認用トリガ: `tools/build_trigger_poc.sh` でビルド → `/data/local/tmp/trigger_hwbinder` を実行。
  → 落ちれば「端末が 5.4/5.10 形の binder を持ち込んでいる＝想定外の朗報」、無反応なら想定どおり
  （＝判定不能ではなく「4.14/CAF 形であることの傍証」）。
* 得られた root（`uid=0` のシェル or 一時的な権限昇格）は、**以下の手順の実行にだけ使う**。

> 一時root が取れない限り、この計画は先に進めない。まず §3 の候補を潰していくこと。

---

## 2. バックアップ（必須・最初にやること）

一時root のシェル（`adb shell` → `su` 相当）で:

```sh
# パーティション名の確認
ls -l /dev/block/by-name/ | grep -E "boot|vbmeta|dtbo"

# サイズ確認 (書き込み時の --partition-size に使う)
blockdev --getsize64 /dev/block/by-name/boot
blockdev --getsize64 /dev/block/by-name/vbmeta

# ダンプ (サイズは上の値に合わせる。dd はブロック単位)
dd if=/dev/block/by-name/boot   of=/data/local/tmp/boot_orig.img
dd if=/dev/block/by-name/vbmeta of=/data/local/tmp/vbmeta_orig.img
sync

# ハッシュを控える（復旧時の照合用）
sha256sum /data/local/tmp/boot_orig.img /data/local/tmp/vbmeta_orig.img
```

PC 側に吸い出す:

```sh
adb pull /data/local/tmp/boot_orig.img    .
adb pull /data/local/tmp/vbmeta_orig.img  .
adb pull /data/local/tmp/boot_flash.img   .   # 手順 4 の出力
adb pull /data/local/tmp/vbmeta_flash.img .
```

---

## 3. Magisk で boot.img をパッチ

方法 **A（推奨・PC 不要）**: 端末に Magisk アプリを入れて
「インストール → ファイルを選択してパッチ」→ 生成された `magisk_patched-*.img` を PC にコピー。

方法 **B（PC 側で完結）**: Magisk の `boot_patch.sh` と `magiskboot`（同梱バイナリ）で
`boot_orig.img` をパッチ。

どちらの場合も **出力イメージのサイズは元と一致しないことがある**（ramdisk の再圧縮など）。
手順 4 の `--partition-size` は「元の boot パーティションサイズ」を渡すこと。

> Magisk が「AVB 2.0 / dm-verity」を無効化しようとするオプション（`KEEPVERITY` 等）は、
> この端末では **AVB を自分で再署名する** ので不要。ramdisk 側の fstab 改変（force-encrypt 解除）も必須ではない。

---

## 4. vbmeta 再署名（テストキー）

```sh
python3 tools/patch_vbmeta.py \
    --vbmeta  vbmeta_orig.img \
    --boot    magisk_patched.img \
    --key     tools/avb/keys/testkey_rsa4096.pem \
    --partition boot \
    --partition-size 4194304 \
    --out-boot   boot_flash.img \
    --out-vbmeta vbmeta_flash.img
```

* `--partition-size` は手順 2 で調べた **boot パーティションの実サイズ**。
* 実行例（合成イメージでの動作確認済み）:

```
== vbmeta ==
  algorithm      : SHA256_RSA4096 (type=2)
  flags          : 0
  rollback_index : 0 (location=0)
  descriptors:
  hash   name=boot         image_size=1048576 alg=sha256 salt=0011223344556677.. digest=215bd05014c0030b.. flags=0
== patch 対象 ==
  partition      : boot
  image_size     : 1048576 -> 1048576
  salt           : 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  digest         : 215bd05014c0030ba71fdf78383f36f3f36fa99fed0a2fb4520a58d578540a05 -> 00083783...
  vbmeta 署名    : SHA256_RSA4096 (512 バイト) OK
== 出力 ==
  boot   : 4194304 バイト (ハッシュ対象 1048576 バイト)
  vbmeta : 4096 バイト (元 4096 バイト)
```

内容確認と検証（PC 側）:

```sh
# 記述子一覧を見る
python3 tools/patch_vbmeta.py --vbmeta vbmeta_orig.img --info

# できあがった vbmeta の署名・boot ハッシュを検証（テストキーの公開鍵で）
mkdir -p verify && cp boot_flash.img verify/boot.img && cp vbmeta_flash.img verify/vbmeta.img
python3 tools/avb/avbtool.py verify_image \
    --image verify/vbmeta.img \
    --key   tools/avb/keys/testkey_rsa4096_pub.pem
#  → "vbmeta: Successfully verified SHA256_RSA4096 vbmeta struct" と
#    "boot: Successfully verified sha256 hash ..." が出れば OK
```

仕組み（内部でやっていること）:

1. vbmeta の AVB0 ヘッダ / 認証ブロック / 補助ブロックを分解
2. `boot` の hash 記述子の `image_size` と `digest` を更新
   （`digest = SHA256(salt ‖ boot_image[0:image_size])`、salt は元の記述子のものを再利用）
3. 埋め込み公開鍵をテストキーの公開鍵に差し替え（鍵長が同じなのでサイズ不変）
4. `hash = SHA256(header ‖ aux)`、`signature = RSA-PKCS1v1.5(hash)` を再計算
   （アルゴリズムはヘッダの `algorithm_type` に従う。実機は SHA256_RSA4096 の想定）
5. 元と同じ長さにゼロ詰めして出力（他パーティションの記述子は一切変更しない）

> `--disable-verification` を付けると vbmeta のフラグに VERIFICATION_DISABLED を立てられるが、
> ロック BL では無視されることが多い。**基本はテストキー再署名で通す**ので通常は不要。

---

## 5. 書き込みと再起動

```sh
adb push boot_flash.img   /data/local/tmp/
adb push vbmeta_flash.img /data/local/tmp/

# 一時root のシェルで:
dd if=/data/local/tmp/boot_flash.img   of=/dev/block/by-name/boot   bs=4096
dd if=/data/local/tmp/vbmeta_flash.img of=/dev/block/by-name/vbmeta bs=4096
sync

# 書き込み結果の照合（任意だが推奨）
sha256sum /data/local/tmp/boot_flash.img
dd if=/dev/block/by-name/boot bs=4096 count=$((SIZE/4096)) | sha256sum   # 一致すること

reboot
```

再起動後、Magisk アプリで「root 化」できていれば完了。以降は通常の Magisk 運用。

---

## 6. 失敗時のリカバリ

* 起動ループ等になった場合、**通常は fastboot も recovery も使えない**（BLU 不可・書き込み手段は一時root のみ）。
  つまり「一時root を再取得できない状態」になると復旧できない可能性が高い。
* そのため:
  1. 手順 2 のダンプ（boot / vbmeta）を必ず保存し、`sha256` を控える。
  2. 書き込み前に `verify_image` で必ず検証を通す。
  3. 可能なら **boot と vbmeta の書き込みを分けず、同時に**行い、`sync` して即再起動。
     （中途半端な状態で起動しないように）
  4. 端末が EDL (9008) に入れる場合は、QFil / QDL で full dump を書き戻す道が残る
     （要: ローダファイル。入手できるかは別途確認）。
* Magisk 側で問題が起きた場合は、Magisk の「アンインストール（boot イメージの復元）」で
  `boot_orig.img` を書き戻せば元に戻る。

---

## 7. 役割分担（実機コマンドのお願い）

以下は実機がないと進められないので、実行して結果を共有してほしい:

```sh
# (1) 端末リコン一式（読み取りのみ・1 コマンド）
adb push tools/recon.sh /data/local/tmp/
adb shell sh /data/local/tmp/recon.sh > recon.txt 2>&1
adb pull /data/local/tmp/sepolicy.bin .
adb pull /data/local/tmp/config.gz.dump .

# (2) 一時root が取れたら（手順 2 のダンプ + パーティション一覧）
adb shell "ls -l /dev/block/by-name/ | head -40"
adb shell "cat /proc/partitions"

# (3) Magisk パッチ後のイメージ（サイズ確認）
adb shell "ls -l /sdcard/Download/magisk_patched-*.img"
```

---

## 8. ファイル一覧

| ファイル | 用途 |
|---|---|
| `tools/patch_vbmeta.py` | vbmeta の boot 記述子更新 + テストキー再署名 + 書き込み用 boot 生成 |
| `tools/avb/avbtool.py` | AOSP external/avb の avbtool（オフライン同梱） |
| `tools/avb/keys/testkey_rsa4096.pem` / `_pub.pem` | AOSP 公開テストキー（実機 AVB と同一） |
| `tools/recon.sh` | 端末リコン（読み取り専用） |
| `tools/build_trigger_poc.sh` | CVE-2023-20938 トリガのビルド |
| `docs/analysis_report.md` | ソース解析レポート（候補・根拠） |
