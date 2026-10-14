#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_vbmeta.py — 既存の vbmeta イメージを「書き換えた boot」に合わせて貼り替え・再署名する

背景:
  Rakuten Hand (P710) の AVB は AOSP 公開テストキー (testkey_rsa4096) で署名されている。
  つまり秘密鍵が手元にあるので、Magisk で書き換えた boot イメージに合わせて
  vbmeta の boot 記述子 (hash ディスクリプタ) を更新し、テストキーで再署名できる。
  これが「fastboot 不可・BLU 不可」の端末で恒久 root を入れるための要。

処理の流れ:
  1. vbmeta イメージを AVB0 ヘッダ / 認証ブロック / 補助ブロックに分解
  2. 対象パーティション (既定 boot) の hash 記述子を見つけ、
     image_size と digest を新しいイメージに合わせて書き換える
     (digest = Hash(salt || image[0:image_size]) — salt は元の記述子のものを再利用)
  3. 埋め込み公開鍵を、署名に使う鍵の公開鍵に差し替える (鍵長が同じ場合)
  4. hash と署名を再計算し、元と同じ長さの vbmeta を出力
  5. boot イメージを partition_size に合わせて整え (末尾フッタ付きフルパーティション化) 出力

使い方:
  python3 tools/patch_vbmeta.py \
      --vbmeta vbmeta_orig.img \
      --boot   magisk_patched.img \
      --key    tools/avb/keys/testkey_rsa4096.pem \
      --partition-size 4194304 \
      --out-boot   boot_flash.img \
      --out-vbmeta vbmeta_flash.img

  情報表示だけ (書き換えなし):
  python3 tools/patch_vbmeta.py --vbmeta vbmeta_orig.img --info

オプション:
  --partition NAME       対象パーティション名 (既定: boot)
  --partition-size N     boot のパーティションサイズ (省略時はパディングしない)
  --disable-verification vbmeta のフラグに VERIFICATION_DISABLED(2) を立てる
                         ※ロック BL では無視されることがある。基本は再署名で通す。
  --no-footer            boot 出力に末尾フッタを付けない
  --dry-run              検証と計算のみ行い、ファイルを書かない

注意:
  * --partition-size は「実機の boot パーティションサイズ」と一致させること
    (adb shell 'blockdev --getsize64 /dev/block/by-name/boot' などで取得)
  * 実行前に必ず vbmeta / boot の原本をバックアップすること
"""

import argparse
import binascii
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "avb"))

import avbtool  # noqa: E402  (tools/avb/avbtool.py)


class PatchError(Exception):
    pass


# algorithm_type -> 名前 (avbtool.ALGORITHMS の逆引き)
def algorithm_name_from_type(atype):
    for name, alg in avbtool.ALGORITHMS.items():
        if alg.algorithm_type == atype:
            return name
    raise PatchError("未知の algorithm_type: {}".format(atype))


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def parse_descriptors(region):
    """補助ブロック内のディスクリプタ列を (offset, tag, num_bytes_following) で列挙する。

    ディスクリプタは [tag(8) + num_bytes_following(8)] + 本体(num_bytes_following バイト)。
    つまり全体長 = 16 + num_bytes_following。
    """
    out = []
    off = 0
    n = len(region)
    while off + 16 <= n:
        tag, nbf = struct.unpack_from("!QQ", region, off)
        if nbf % 8 != 0 or off + 16 + nbf > n:
            break
        out.append((off, tag, nbf))
        off += 16 + nbf
    return out


def desc_bytes_at(region, off, nbf):
    return region[off:off + 16 + nbf]


def describe_descriptors(aux, h):
    """人が読める形で記述子一覧を返す"""
    region = aux[h.descriptors_offset:h.descriptors_offset + h.descriptors_size]
    lines = []
    for off, tag, nbf in parse_descriptors(region):
        if tag == 2:  # AVB_DESCRIPTOR_TAG_HASH
            d = avbtool.AvbHashDescriptor(desc_bytes_at(region, off, nbf))
            lines.append("  hash   name=%-12s image_size=%d alg=%s salt=%s digest=%s flags=%d"
                         % (d.partition_name, d.image_size, d.hash_algorithm,
                            binascii.hexlify(d.salt).decode()[:16] + "..",
                            binascii.hexlify(d.digest).decode()[:16] + "..", d.flags))
        elif tag == 1:
            lines.append("  hashtree (offset=%d, %d bytes)" % (off, 16 + nbf))
        elif tag == 3:
            lines.append("  kernel_cmdline")
        elif tag == 4:
            d = avbtool.AvbChainPartitionDescriptor(desc_bytes_at(region, off, nbf))
            lines.append("  chain  rollback_index_location=%d name=%s"
                         % (d.rollback_index_location, d.partition_name))
        elif tag == 0:
            d = avbtool.AvbPropertyDescriptor(desc_bytes_at(region, off, nbf))
            lines.append("  prop   %s=%s" % (d.key, d.value))
        else:
            lines.append("  tag=%d (%d bytes)" % (tag, 16 + nbf))
    return lines


def boot_data_and_size(raw):
    """boot イメージ生バイト列から (データ本体, ハッシュ対象サイズ) を求める。
    末尾に AVB フッタがあればその original_image_size を、無ければ全体長を使う。"""
    data_size = len(raw)
    if len(raw) >= avbtool.AvbFooter.SIZE:
        try:
            footer = avbtool.AvbFooter(raw[-avbtool.AvbFooter.SIZE:])
            # フッタの magic が合っていれば「AVB 済みイメージ」
            if footer.magic == b"AVBf" and 0 < footer.original_image_size <= len(raw):
                data_size = footer.original_image_size
        except (LookupError, struct.error):
            pass
    return raw[:data_size], data_size


def build_boot_partition_image(raw, partition_size, want_footer=True):
    """書き込み用の boot パーティションイメージを作る。
    data + ゼロ詰め + 末尾 64 バイトの AVB フッタ (フッタは実機検証には使われないが、
    ストックと同じ「フルパーティション + フッタ」レイアウトにしておく)"""
    data, data_size = boot_data_and_size(raw)
    if partition_size is None:
        return data, data_size
    if not want_footer:
        if len(data) > partition_size:
            raise PatchError("boot イメージ (%d) がパーティション (%d) より大きい"
                             % (len(data), partition_size))
        buf = bytearray(partition_size)
        buf[0:len(data)] = data
        return bytes(buf), data_size
    if data_size + avbtool.AvbFooter.SIZE > partition_size:
        raise PatchError("boot データ (%d) + フッタ 64 がパーティション (%d) に収まらない。"
                         "Magisk 側でパーティションサイズを指定してパッチするか、"
                         "--partition-size を見直すこと" % (data_size, partition_size))
    buf = bytearray(partition_size)
    buf[0:data_size] = data
    footer = avbtool.AvbFooter()
    footer.original_image_size = data_size
    footer.vbmeta_offset = 0
    footer.vbmeta_size = 0
    buf[partition_size - avbtool.AvbFooter.SIZE:] = footer.encode()
    return bytes(buf), data_size


def main(argv=None):
    ap = argparse.ArgumentParser(description="vbmeta の boot 記述子を差し替えて再署名する")
    ap.add_argument("--vbmeta", required=True, help="元の vbmeta イメージ (パーティション dump)")
    ap.add_argument("--boot", help="Magisk 適用後の boot イメージ")
    ap.add_argument("--key", default=os.path.join(HERE, "avb", "keys", "testkey_rsa4096.pem"),
                    help="署名に使う秘密鍵 (既定: AOSP テストキー)")
    ap.add_argument("--partition", default="boot", help="対象パーティション名 (既定 boot)")
    ap.add_argument("--partition-size", type=int, default=None,
                    help="対象パーティションのサイズ (バイト)。指定時はそのサイズに整える")
    ap.add_argument("--out-boot", default="boot_flash.img")
    ap.add_argument("--out-vbmeta", default="vbmeta_flash.img")
    ap.add_argument("--disable-verification", action="store_true",
                    help="vbmeta フラグに VERIFICATION_DISABLED を立てる (通常は不要)")
    ap.add_argument("--no-footer", action="store_true", help="boot 出力にフッタを付けない")
    ap.add_argument("--info", action="store_true", help="vbmeta の内容表示のみ")
    ap.add_argument("--dry-run", action="store_true", help="書き込まずに検証のみ")
    args = ap.parse_args(argv)

    vb = read_file(args.vbmeta)
    if vb[0:4] != b"AVB0":
        raise PatchError("--vbmeta の先頭が AVB0 ではない。vbmeta パーティションの生 dump を渡すこと")

    h = avbtool.AvbVBMetaHeader(vb[0:avbtool.AvbVBMetaHeader.SIZE])
    auth_size = h.authentication_data_block_size
    aux_size = h.auxiliary_data_block_size
    blob_len = avbtool.AvbVBMetaHeader.SIZE + auth_size + aux_size
    if blob_len > len(vb):
        raise PatchError("vbmeta が壊れている (ヘッダの示す長さ %d > ファイル長 %d)" % (blob_len, len(vb)))

    aux = bytearray(vb[avbtool.AvbVBMetaHeader.SIZE + auth_size:
                       avbtool.AvbVBMetaHeader.SIZE + auth_size + aux_size])

    alg_name = algorithm_name_from_type(h.algorithm_type)
    print("== vbmeta ==")
    print("  algorithm      : %s (type=%d)" % (alg_name, h.algorithm_type))
    print("  flags          : %d%s%s" % (
        h.flags,
        " HASHTREE_DISABLED" if h.flags & 1 else "",
        " VERIFICATION_DISABLED" if h.flags & 2 else ""))
    print("  rollback_index : %d (location=%d)" % (h.rollback_index, h.rollback_index_location))
    print("  release_string : %r" % h.release_string)
    print("  descriptors:")
    for line in describe_descriptors(aux, h):
        print(line)

    if args.info:
        return 0

    if not args.boot:
        raise PatchError("--boot が必要 (--info 以外)")

    # 対象記述子を探す
    region = aux[h.descriptors_offset:h.descriptors_offset + h.descriptors_size]
    target = None
    for off, tag, nbf in parse_descriptors(region):
        if tag != 2:
            continue
        desc_bytes = desc_bytes_at(region, off, nbf)
        d = avbtool.AvbHashDescriptor(desc_bytes)
        if d.partition_name == args.partition:
            target = (off, d)
            break
    if target is None:
        raise PatchError("vbmeta に %r の hash 記述子が無い" % args.partition)

    off, desc = target
    salt = bytes(desc.salt)
    digest_len = len(desc.digest)
    hash_alg = desc.hash_algorithm or "sha256"
    if digest_len != len(hashlib.new(hash_alg).digest()):
        raise PatchError("記述子の digest 長 %d が %s と一致しない" % (digest_len, hash_alg))

    raw_boot = read_file(args.boot)
    data, data_size = boot_data_and_size(raw_boot)
    new_digest = hashlib.new(hash_alg, salt)
    new_digest.update(data[:data_size])
    new_digest = new_digest.digest()

    print("== patch 対象 ==")
    print("  partition      : %s" % desc.partition_name)
    print("  image_size     : %d -> %d" % (desc.image_size, data_size))
    print("  salt           : %s" % binascii.hexlify(salt).decode())
    print("  digest         : %s -> %s"
          % (binascii.hexlify(desc.digest).decode(), binascii.hexlify(new_digest).decode()))

    # 記述子内を書き換え (サイズは変わらない)
    struct.pack_into("!Q", aux, h.descriptors_offset + off + 16, data_size)
    digest_off = (h.descriptors_offset + off + avbtool.AvbHashDescriptor.SIZE
                  + len(desc.partition_name.encode("utf-8")) + len(salt))
    aux[digest_off:digest_off + digest_len] = new_digest

    # 公開鍵の差し替え (同じ鍵長のときのみ)
    with avbtool.load_public_key(args.key) as key:
        enc_key = key.encode()
        if len(enc_key) != h.public_key_size:
            raise PatchError("鍵長が合わない (vbmeta 埋め込み %d バイト / 指定鍵 %d バイト)。"
                             "同じ鍵サイズの秘密鍵を指定すること"
                             % (h.public_key_size, len(enc_key)))
        aux[h.public_key_offset:h.public_key_offset + h.public_key_size] = enc_key

        if args.disable_verification:
            h.flags |= 2

        header_blob = h.encode()
        content = header_blob + bytes(aux)

        if alg_name == "NONE":
            print("  !! vbmeta は無署名 (algorithm=NONE) のため署名は生成しない")
            auth_blob = bytearray(auth_size)
        else:
            binary_hash = hashlib.new(avbtool.ALGORITHMS[alg_name].hash_name)
            binary_hash.update(content)
            binary_hash = binary_hash.digest()
            signature = key.sign(alg_name, content, None, None)
            auth_blob = bytearray(auth_size)
            auth_blob[h.hash_offset:h.hash_offset + h.hash_size] = binary_hash
            auth_blob[h.signature_offset:h.signature_offset + h.signature_size] = signature
            print("  vbmeta 署名    : %s (%d バイト) OK" % (alg_name, len(signature)))

    out_vbmeta = bytes(header_blob) + bytes(auth_blob) + bytes(aux)
    if len(out_vbmeta) > len(vb):
        raise PatchError("新しい vbmeta (%d) が元 (%d) より大きい" % (len(out_vbmeta), len(vb)))
    # 元と同じ長さへゼロ詰め (パーティション全体を書くため)
    out_vbmeta = out_vbmeta + b"\x00" * (len(vb) - len(out_vbmeta))

    out_boot, out_boot_size = build_boot_partition_image(
        raw_boot, args.partition_size, want_footer=not args.no_footer)

    print("== 出力 ==")
    print("  boot   : %d バイト (ハッシュ対象 %d バイト)" % (len(out_boot), out_boot_size))
    print("  vbmeta : %d バイト (元 %d バイト)" % (len(out_vbmeta), len(vb)))
    if args.dry_run:
        print("  (dry-run: ファイルは書いていない)")
        return 0

    with open(args.out_boot, "wb") as f:
        f.write(out_boot)
    with open(args.out_vbmeta, "wb") as f:
        f.write(out_vbmeta)
    print("  書き出し: %s / %s" % (args.out_boot, args.out_vbmeta))
    print("""
次の手順 (実機):
  # 現状バックアップ
  adb shell su -c 'dd if=/dev/block/by-name/boot   of=/data/local/tmp/boot_orig.img'
  adb shell su -c 'dd if=/dev/block/by-name/vbmeta of=/data/local/tmp/vbmeta_orig.img'
  # 書き込み (一時root の shell から)
  adb shell su -c 'dd if=/data/local/tmp/boot_flash.img   of=/dev/block/by-name/boot'
  adb shell su -c 'dd if=/data/local/tmp/vbmeta_flash.img of=/dev/block/by-name/vbmeta'
  sync && reboot
""")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PatchError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        sys.exit(2)
