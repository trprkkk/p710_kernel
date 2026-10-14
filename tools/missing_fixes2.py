#!/usr/bin/env python3
"""
参照ツリー(REF, 例: LineageOS sm7125 = CAF LA.UM.9.1.r1-16400 + openela 4.14 + vendor patches)
の各コミットについて、その修正が「手元の vendor ツリー(TREE)に入っているか」を hunk 単位で判定する。

使い方: python3 missing_fixes2.py <since> [path_filter_regex]
"""
import os, re, subprocess, sys, json

REF = "/home/user/ref/los7125"
TREE = "/home/user/p710_kernel/msm-4.14"

# アプリ/shell から到達しうるサブシステムのみ（SELinux 制約は別途）
PATHS = (
    "drivers/android/", "drivers/staging/android/", "drivers/dma-buf/",
    "drivers/gpu/msm/", "net/", "kernel/", "mm/", "ipc/", "fs/", "security/",
    "lib/", "crypto/", "drivers/tty/", "drivers/char/", "drivers/misc/",
    "drivers/usb/gadget/", "drivers/media/platform/msm/", "drivers/soc/qcom/",
    "drivers/power/", "drivers/input/", "drivers/iommu/", "drivers/base/",
    "drivers/nfc/", "drivers/bluetooth/", "drivers/gnss", "block/", "arch/arm64/",
)

STRONG = re.compile(
    r"(uaf|use[- ]after|double[- ]free|out[- ]of[- ]bounds|\boob\b|overflow|underflow|"
    r"type confusion|privilege|escalat|escape|sandbox|info[- ]?leak|uninitialized|"
    r"refcount|refcnt|kasan|memory corruption|slab|integer|signedness|off-by|"
    r"missing (check|bounds|valid|sanity|validation|lock)|crafted|malformed|"
    r"attacker|untrusted|freed|dos|denial|race|corrupt|validate|sanity|bounds|"
    r"null[- ]?pointer|null[- ]?ptr|security|vulnerab|cve-|oops|KERNEL-|prevent|"
    r"fix .*(check|validation|error)|protect)", re.I)
WEAK = re.compile(r"(annotate data[- ]race|documentation|typo|comment|kcsan|whitespace|"
                  r"cleanup|refactor|rename|checkpatch|warning|checker)", re.I)

def run(cmd, cwd=None, timeout=900):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)

def norm(s):
    return re.sub(r"\s+", " ", s.strip())

def main():
    since = sys.argv[1] if len(sys.argv) > 1 else "2023-01-01"
    log = run(["git", "log", "--format=%H%x01%ad%x01%s", "--date=short",
               f"--since={since}", "HEAD"], cwd=REF)
    recs = []
    for line in log.stdout.splitlines():
        parts = line.split("\x01")
        if len(parts) < 3:
            continue
        sha, date, subj = parts
        if not STRONG.search(subj) or WEAK.search(subj):
            continue
        show = run(["git", "show", "--format=", "--no-color", "--unified=3", sha], cwd=REF)
        diff = show.stdout
        if not diff:
            continue
        files, cur = {}, None
        for ln in diff.splitlines():
            if ln.startswith("+++ b/"):
                cur = ln[6:]; files.setdefault(cur, [])
            elif ln.startswith("@@") and cur:
                files[cur].append({"rm": [], "ad": []})
            elif cur and files[cur]:
                h = files[cur][-1]
                if ln.startswith("-") and not ln.startswith("---"):
                    h["rm"].append(ln[1:])
                elif ln.startswith("+") and not ln.startswith("+++"):
                    h["ad"].append(ln[1:])
        nfiles = {f: h for f, h in files.items() if f.startswith(PATHS)}
        if not nfiles:
            continue
        missing = total = 0
        miss_files = []
        for f, hunks in nfiles.items():
            p = os.path.join(TREE, f)
            if not os.path.exists(p):
                continue
            try:
                content = re.sub(r"\s+", " ", open(p, encoding="utf-8", errors="replace").read())
            except Exception:
                continue
            fm = 0
            for h in hunks:
                rm = [norm(x) for x in h["rm"] if len(norm(x)) > 3]
                ad = [norm(x) for x in h["ad"] if len(norm(x)) > 3]
                if not rm and not ad:
                    continue
                rp = sum(1 for x in rm if x in content) / len(rm) if rm else 0
                ap = sum(1 for x in ad if x in content) / len(ad) if ad else 0
                total += 1
                if ad and ap > 0.6:
                    continue
                if rm and rp > 0.6 and ap < 0.4:
                    fm += 1
            if fm:
                miss_files.append((f, fm))
                missing += fm
        if missing:
            recs.append({"sha": sha, "date": date, "subject": subj,
                         "missing": missing, "hunks": total,
                         "files": miss_files})
    recs.sort(key=lambda r: r["date"], reverse=True)
    json.dump(recs, open("/home/user/analysis/missing_fixes_los.json", "w"), indent=1)
    print(f"candidates: {len(recs)}  (since {since})")
    for r in recs:
        print(f"{r['date']} {r['sha'][:10]} miss={r['missing']:3d}/{r['hunks']:3d} {r['subject'][:78]}")
        for f, c in r["files"][:4]:
            print(f"        {f} ({c})")

if __name__ == "__main__":
    main()
