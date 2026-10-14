# Rakuten Hand (P710 / Tinno / SM7125 atoll / Android 10) 一時root に向けたカーネルソース解析レポート

対象: `trprkkk/p710_kernel` (fork of `TINNO-RD/p710_kernel`) / `msm-4.14`
端末: Rakuten Hand 4G (P710AE_10.0_RMN_JP_154, SPL 2023-01-01, BL アンロック不可)
カーネル: `Linux localhost 4.14.117-perf #1 SMP PREEMPT Thu Nov 21 23:35:05 CST 2024 aarch64` / SELinux Enforcing

---

## 0. 結論（先に要点）

1. **手元のソースは「TINNO-RD 本家の 2020-10-23 公開版そのもの」**（1 バイトも改変なし。blob SHA 一致で確認）。
   つまりこれは **Android 10 ローンチ時の GPL ソース**であり、**2024-11-21 にビルドされた現在の端末カーネルそのものではない**。
   → 「ソースに無い＝端末に無い」とは限らない。**端末カーネルの実際のパッチ水準が最大の未知数**で、まずこれを確定させるのが最優先。

2. **端末カーネルのパッチ水準は `ro.bootimage.build.version.security_patch` で概ね判る**（boot イメージの SPL）。
   Android の framework SPL (2023-01-01) とは別物なので、必ず確認すること（`tools/recon.sh` に含めた）。

3. 汎用カーネル側で 2023-01 以降に修正され、このソース（2020 版）に**入っていない**ものが 439 件見つかった（機械照合）。
   ただし **アプリ/shell から到達できて、かつ公開手法がある**ものは限られる。到達可能面（binder / kgsl / ベンダ独自 proc）で有力なのは次の 2 系統:

   - **(A) binder `binder_transaction_buffer_release()` の不整合（CVE-2023-20938 系）**
     - 修正（`binder: fix UAF caused by faulty buffer cleanup` / FROMLIST `66cba6260a95` → AOSP `2218752325a9`、2023-05、ASB 2023-07）は
       **4.14 系に一切バックポートされていない**（AOSP `deprecated/android-4.14-stable` の binder 最終修正は 2023-06 のメモリリーク修正のみ、linux-4.14.y も同様）＝ **4.14 端末は恒久的に未修正**。
     - **ただし重要**: 本ソースの binder は CAF 独自バリアントで、脆弱形状（`is_failure && failed_at ? failed_at : 全体を解放`）ではなく
       `is_failure ? failed_at : 全体を解放` かつ `binder_free_buf()` が `is_failure=false` 固定になっている。
       この形は「エラー経路で failed_at==0 のとき *何も解放しない*」＝ upstream の**修正後**と同じ意味論なので、
       **既知のトリガ（エラー経路での過剰デクリメント）は本ソースでは成立しない**。
       CAF 系 msm-4.14 の別ツリー 3 種（Motorola 2024-07 版 / sm8150 LA.UM.9.1.r1-12000 / caf_msm-4.14）も同じ形状であることを確認済み。
       → **端末も同じ形状である可能性が高い**が、端末カーネルが CAF 経由で binder を更新していた場合は形状が変わり得るので、
         **実機でトリガを 1 回走らせて確定させる**価値がある（用意済み: 下記 §4 / `tools/build_trigger_poc.sh`）。
   - **(B) kgsl（Adreno / `/dev/kgsl-3d0`）**: アプリから直接 ioctl を叩ける**唯一級の広い攻撃面**。
     CAF は msm-4.14 に対して 2023〜2026 年に多数の kgsl セキュリティ修正を出しており（§3.2 の表）、
     2020 年版ソースには**構造的に存在しない修正**も多い（例: `iommu_addr_in_svm_ranges()` のラップアラウンド検査 = 2023-09 修正は本ソースに該当関数自体が無い）。
     → 「2020 年版コード vs CAF 最新 kgsl」の差分監査が**次の最有力作業**。

4. 到達性（ソース＋AOSP 既定ポリシーからの推定、実機で要確認）:
   - 到達**可**: `/dev/binder`, `/dev/hwbinder`（全アプリ）, `/dev/kgsl-3d0`（全アプリ＝GPU 直叩き）, `/proc/android_touch/*`（Himax、**0666**）, `/proc/tgeseture_config`（Tinno、**0666**）
   - 到達**不可**: `/dev/video*` `/dev/media*`（`system:camera` 0660＝ユーザ実測どおり）, `/dev/diag`, `/dev/adsprpc-smd`, `/dev/qseecom`, `/dev/snd/*` 等

5. `USER_NS` は**無効**（`p710-perf_defconfig` に `CONFIG_USER_NS` なし）＝ userns 前提の新しい LPE（nf_tables 系など）は**全滅**。
   `CONFIG_TUN=y` だが `/dev/net/tun` は非公開。CAP_NET_ADMIN が要る net/sched・netfilter 系も**アプリ/shell からは不可**。

---

## 1. 検証済みの事実（エビデンス）

| 項目 | 確認内容 |
|---|---|
| ソース同一性 | `git hash-object` と GitHub Contents API の `sha` が一致: `drivers/android/binder.c`, `drivers/gpu/msm/kgsl.c`, `kgsl_iommu.c`, `kgsl_pool.c`, `Makefile`, `arch/arm64/configs/vendor/p710-perf_defconfig`, `README.txt` |
| ソース日付 | `TINNO-RD/p710_kernel` の `pushed_at = 2020-10-23T06:21:11Z`（fork も同一内容） |
| カーネル版 | `Makefile`: 4.14.117 / `CONFIG_LOCALVERSION="-perf"` |
| 対象 SoC | CAF `msm-4.14` + atoll（SM7125）向け `p710-perf_defconfig`（Qualcomm 720G） |
| セキュリティ構成 | `CONFIG_SECURITY_SELINUX=y`（enforcing）, `HARDENED_USERCOPY=y`, `SLAB_FREELIST_HARDENED=y`, `SLAB_FREELIST_RANDOM=y`, `RANDOMIZE_BASE=y`, `CONFIG_DEVMEM is not set`, `IKCONFIG_PROC=y`（`/proc/config.gz` が読める可能性） |
| 未設定 | `CONFIG_USER_NS`（無効）, `CONFIG_SLUB_DEBUG`（無効）, `CONFIG_KASAN`（無効） |
| 有効なベンダドライバ | `CONFIG_TOUCHSCREEN_HIMAX_CHIPSET/I2C/INCELL/IC_HX83112/DEBUG=y` → `/proc/android_touch/{HSEN,SMWP,GESTURE,debug_level,vendor,attn,int_en,layout,CRC_test,ITO_test,...}` が **0666** で生える |
| Tinno 独自 | `tinno/common_features/tgesture/tgesture.c` → `/proc/tgeseture_config`（**0666**、`count<=240` の検査あり。単純な overflow は無し） |

---

## 2. 手法（再現可能なツール）

`tools/missing_fixes.py` / `tools/missing_fixes2.py` は、参照カーネルツリーの各コミットのパッチを **hunk 単位**で手元ツリーと突き合わせ、

* 修正前コードが手元にあり、修正後コードが無い → **MISSING（未修正）**
* 修正後コードがある → applied
* どちらも不明 → unknown

を判定する。参照ツリーは GitHub から取得（このサンドボックスから到達できる範囲）:

| 参照 | 用途 | 取得 |
|---|---|---|
| `gregkh/linux` tag `v4.14.336`（2024-01-10, 4.14 EOL） | 4.14.y の最後までの修正 | `git clone --filter=blob:none --branch v4.14.336` |
| `aosp-mirror/kernel_common` `deprecated/android-4.14-stable` | 『Android 固有』修正の有無（binder 等） | 同上（`--shallow-since=2020-10-01`） |
| **`LineageOS/android_kernel_samsung_sm7125`** | **同一 SoC（SM7125/atoll）**で CAF `LA.UM.9.1.r1-16400`(2024-11) + openela 4.14 まで更新されたツリー。kgsl 等 CAF ドライバの最新修正の出所 | 同上（2023-01 以降） |

出力データ: `analysis/missing_fixes.json`（4.14 stable 2023-01 以降 / 439 件）、`analysis/full_run_2023-01.log`、`analysis/los_scan.log`（LOS 基準、実行中/再実行可）。

---

## 3. 解析結果

### 3.1 binder（CVE-2023-20938 系）— 「4.14 に修正が来ていない」が「形状が違う」

* 脆弱コード（upstream 5.4/5.10 の 2023-05 以前）:

```c
off_end_offset = is_failure && failed_at ? failed_at :
                 off_start_offset + buffer->offsets_size;
...
err_copy_data_failed:
        binder_transaction_buffer_release(target_proc, t->buffer, buffer_offset /* =0 のことがある */, true);
```
  → エラーが「offsets ループ開始前」に起きると `failed_at==0` 扱いで**バッファ全体を解放**＝未処理オブジェクトの参照カウントを過剰に減算 → `binder_node`(kmalloc-128) UAF。

* 修正版（`binder_release_entire_buffer()` 分離＋`off_end_offset` を明示）は **AOSP 5.4/5.10 のみ**。4.14 へは未バックポート（確認済み）。
* **本ソースの形状**（`drivers/android/binder.c:2422`）:

```c
off_end_offset = is_failure ? failed_at :
                 off_start_offset + buffer->offsets_size;
```
  さらに `binder_free_buf()` は `binder_transaction_buffer_release(proc, buffer, 0, false)` 固定（`is_failure=false`）。
  → エラー経路で `failed_at==0` のときは**何も解放しない**（＝upstream 修正版と同じ意味論）。**既知トリガは成立しない**。
  ただしこれは「本ソース」の話。端末カーネルは 4 年新しいので、実機で確認する（§4）。

* 実機確認用のトリガ: `0xAtharv/CVE-2023-20938-Public`（研究用に公開されているトリガ、`/dev/hwbinder` を使用）を
  **aarch64 静的バイナリにビルドするスクリプト**を用意した（`tools/build_trigger_poc.sh`）。既にビルド済みの成果物も置いてある（§4）。

### 3.2 kgsl（Adreno, `/dev/kgsl-3d0` = アプリ到達可）— CAF の修正タイムライン

LineageOS sm7125 ツリーの履歴から抽出した、**msm-4.14 系 kgsl の 2023 年以降のセキュリティ修正**（すべて `drivers/gpu/msm/`）:

| 日付 | 修正 | 内容/意味 | 本ソース(2020)の状況 |
|---|---|---|---|
| 2023-02-13 | `msm: kgsl: Make sure that pool pages don't have any extra references` | pool ページの参照カウント不整合（UAF 系） | 構造が異なる（要監査） |
| 2023-02-14 | `msm: kgsl: Use dma_buf_get() to get dma_buf structure` | `iterate_fd()`〜`dma_buf_get()` 間の TOCTOU を塞ぐ | **部分的に既存**（`iterate_fd` はあるが一致チェック無し＝軽微な不整合のみ） |
| 2023-03-28 | `msm: kgsl: Keep postamble packets in a privileged buffer` | postamble パケットを特権バッファへ（GPU 経由の攻撃面封じ） | **無い**（GPU 経由 primitive の候補） |
| 2023-09-14 | `msm: kgsl: Prevent wrap around during user address mapping` | `gpuaddr+size` のラップアラウンド検査（SVM マッピング） | **関数自体が無い**（旧 SVM コードに別の形の穴がある可能性） |
| 2023-12-20 | `msm: kgsl: Do not release dma and anon buffers if unmap fails` | unmap 失敗時に解放しない（UAF 防止） | `kgsl_destroy_ion(struct kgsl_dma_buf_meta *)` と旧シグネチャ。**ガード無し** |
| 2024-02-02 | `msm: kgsl: Update the protect register list` | 保護レジスタ追加（ユーザが書けると GPU 制御が奪える） | **無い**（要確認） |
| 2024-06-10 | `msm: kgsl: Fix error handling during drawctxt switch` | drawctxt 切替時のエラー処理（UAF 系） | 構造が異なる（要監査） |
| 2025-08-19 | `kgsl: Avoid use after free in kgsl_destroy_ion()` | `entry->priv_data = NULL` 追加 | 端末ビルド(2024-11)より後 |
| 2026-01-19 | `kgsl: Prevent sign extension on alignments` | アラインメントの符号拡張（OOB） | 端末ビルドより後 |

> 端末カーネルが CAF のどのタグ相当かで「未修正の段」が決まる。**2023-01 相当なら 2023-02 以降が全部候補**、2024-11 相当なら 2025-08/2026-01 のみが候補、という具合に絞れる。

### 3.3 その他の到達可能面（抜粋）

* **Himax タッチ** `/proc/android_touch/*`（0666）: 大半の write ハンドラは `len >= 80` を検査しており単純 overflow は無い。
  ただし `himax_proc_DD_debug_write()` は `len` が短い場合に**未初期化スタック**を読む（`buf_tmp[2]/[6]/[10]` 参照）等、無害とは言い切れない実装。
  SELinux ラベル（`u:object_r:proc` 系か、ベンダ独自タイプか）によって到達性が決まるため **実機の `ls -lZ` が必要**。
* **Tinno tgesture** `/proc/tgeseture_config`（0666）: 検査あり、単純な穴は見当たらず。
* 4.14 stable（2023-01 以降）の未修正候補 439 件のうち、アプリ/shell から cap 無しで届くものは
  * `net/` の一部（`af_unix`, `ipv4/igmp`, `dccp`(要SELinux確認), `packet`(要 CAP_NET_RAW=アプリ保持の可能性)）
  * `fs/` の一部（**マウントが必要なため実質不可**）
  * であり、**netfilter/net_sched（CAP_NET_ADMIN 必須）は不可**。リストは `analysis/full_run_2023-01.log`。

---

## 4. 実機での確認手順（次にやること）

```bash
# (1) 端末リコン（読み取りのみ・1 コマンドで全部集める）
adb push tools/recon.sh /data/local/tmp/
adb shell sh /data/local/tmp/recon.sh > recon.txt 2>&1
adb pull /data/local/tmp/sepolicy.bin .      # 可能なら（SELinux ポリシー）
adb pull /data/local/tmp/config.gz.dump .    # 可能なら（実行中カーネルの config）

# 最優先で見たい値:
adb shell getprop ro.bootimage.build.version.security_patch   # ← 端末カーネルのパッチ水準
adb shell getprop ro.vendor.build.version.security_patch
adb shell getprop ro.boot.veritymode; adb shell getprop ro.boot.flash.locked
adb shell uname -a

# (2) binder の形状確認（トリガ実行・※ 万一未修正なら kernel panic の可能性あり＝要バックアップ意識）
bash tools/build_trigger_poc.sh ./artifacts        # zig(pip) or NDK で aarch64 静的バイナリ
adb push artifacts/trigger_hwbinder /data/local/tmp/
adb shell chmod 755 /data/local/tmp/trigger_hwbinder
adb shell /data/local/tmp/trigger_hwbinder
#   → 端末が落ちる/再起動 → 未修正の疑い大（攻撃成立の可能性）
#   → 何も起きない        → 修正済み or トリガ不成立（判定不能）

# (3) 到達性の実測（例: kgsl / himax）
adb shell ls -lZ /dev/kgsl-3d0 /dev/ion /dev/ashmem /dev/binder /dev/hwbinder
adb shell ls -lZ /proc/android_touch/ /proc/tgeseture_config
```

可能なら **(4) 端末の boot.img を入手**（OTA パッケージ、または後述の一時root 確立後 `dd`）。
これが手に入れば、こちらのソースをビルドした `Image` と比べることで**どの修正が入っているか**を直接特定できる（＝推測が消える）。

---

## 5. root 化までのロードマップ（AVB = AOSP テストキー前提）

1. **一時root**: §3 の候補のどれかで kernel R/W あるいは `cred` 書き換え（SELinux permissive 化 or `task_security_struct` 改変）→ `setuid(0)` シェル。
2. **バックアップ（最重要）**: 変更前に必ず現行イメージを吸い出す。
   ```bash
   ls -l /dev/block/by-name/
   dd if=/dev/block/by-name/boot  of=/data/local/tmp/boot_orig.img
   dd if=/dev/block/by-name/vbmeta of=/data/local/tmp/vbmeta_orig.img   # 存在すれば
   ```
3. **Magisk パッチ**: 吸い出した `boot_orig.img` を Magisk アプリ「インストール → boot イメージを選択してパッチ」に投入（または `magiskboot` で手動）。
4. **AVB 再署名（テスト鍵）**: `avbtool` + AOSP 公開テスト鍵（`external/avb/test/data/testkey_rsa4096.pem`。GitHub ミラーあり）で
   `avbtool add_hash_footer --image boot_patched.img --partition_name boot --partition_size <実サイズ> --key testkey_rsa4096.pem --algorithm SHA256_RSA4096`
   → boot のハッシュが変わるため **vbmeta も再生成/再署名が必要**（既存 vbmeta の boot 記述子の digest だけ差し替えて再署名する方法が安全。詳細は `docs/root_plan.md`）。
5. **書き込み**: `dd if=/data/local/tmp/boot_patched.img of=/dev/block/by-name/boot`（+ 必要なら vbmeta）。
6. **再起動して Magisk が機能すれば恒久 root**。失敗時は 2 のバックアップを書き戻して復旧。
7. `dm-verity` が有効な場合、`vbmeta` の `HASHTREE_DISABLED/VERIFICATION_DISABLED` フラグ方式も選択肢（ロック BL で無視される実装もあるため、まずは 4 の正攻法）。

> 注意: BL アンロック不可なので **fastboot での書き込みは不可**。書き込みは必ず「一時root を得た後の `dd`」で行う。
> つまり **一時root が取れない限りこの計画は進まない**。§3/§4 が本計画の唯一のボトルネック。

---

## 6. リスク

* カーネル exploit は成功率が確率的。panic → 再起動（データ破損の可能性は低いがゼロではない）。
* パーティション書き込みを誤ると**文鎮化**。手順 2 のバックアップと、書き込み前の `sha256sum` 突き合わせを必須とする。
* AVB/dm-verity の整合が崩れた状態で再起動すると、最悪**起動不能**（この場合も `dd` で書き戻せる手段が残らない可能性があるため、vbmeta のバックアップも必ず取る）。

---

## 7. 付録: 主要ファイル

```
docs/analysis_report.md      … 本レポート
docs/root_plan.md            … 一時root→Magisk→AVB 再署名の詳細手順
tools/patch_vbmeta.py        … vbmeta の boot 記述子を更新してテストキーで再署名
tools/avb/avbtool.py         … AOSP external/avb の avbtool（オフライン同梱）
tools/avb/keys/              … AOSP 公開テストキー（testkey_rsa4096.pem / _pub.pem）
tools/recon.sh               … 端末リコン（読み取り専用・1 発で全部集める）
tools/build_trigger_poc.sh   … CVE-2023-20938 トリガを aarch64 静的バイナリにビルド
tools/missing_fixes.py       … 4.14 stable との未修正修正の機械照合（作業用コピー）
tools/missing_fixes2.py      … 任意の参照ツリー（例: LineageOS sm7125）との照合（作業用コピー）

作業用ワークスペース（本リポジトリ外）:
  /home/user/analysis/       … 照合結果 missing_fixes.json（439 件）/ full_run_2023-01.log など
  /home/user/ref/            … 参照カーネルツリー（linux336 / los7125 / moto / aosp414）
```
