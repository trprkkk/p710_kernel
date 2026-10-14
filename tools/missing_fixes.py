#!/usr/bin/env python3
"""
4.14 stable の「指定日以降のセキュリティ修正」が、手元の vendor カーネルツリーに
入っているかどうかを機械的に判定するツール。

判定ロジック (hunk 単位):
  - そのパッチの削除行(=修正前コード)が手元ファイルに存在し、
    かつ追加行(=修正後コード)が存在しない  -> "missing" (未修正の疑い)
  - 追加行が存在する                          -> "applied"
  - どちらも判定不能                          -> "unknown"
"""
import os, re, subprocess, sys, json, hashlib

REF = "/home/user/ref/l14"
TREE = "/home/user/p710_kernel/msm-4.14"

KEYWORDS = re.compile(
    r"(uaf|use[- ]after|double[- ]free|oob|out[- ]of[- ]bounds|out of bounds|"
    r"overflow|underflow|oob|race|security|cve-|kasan|missing (check|bound|valid|lock|"
    r"sanity|error)|null ?ptr|dereference|unsigned|integer|overflow|"
    r"info ?leak|leak of memory|uninitialized|bounds|escape|sandbox|"
    r"elevation|privilege|dos|denial of service|corrupt|malformed|crafted|"
    r"slab|refcount|double|type confusion|untrusted|attacker)",
    re.I)

def run(cmd, cwd=None, timeout=300):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)

def norm(line):
    return re.sub(r"\s+", " ", line.strip())

def load_tree_file(path):
    p = os.path.join(TREE, path)
    if not os.path.exists(p):
        return None
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        return None

def main():
    since = sys.argv[1] if len(sys.argv) > 1 else "2023-01-01"
    log = run(["git", "log", "--format=%H%x01%ad%x01%s%x01%b%x02",
               "--date=short", f"--since={since}", "v4.14.336"], cwd=REF)
    entries = [e for e in log.stdout.split("\x02") if e.strip()]
    out = []
    for e in entries:
        parts = e.strip().split("\x01")
        if len(parts) < 4:
            continue
        sha, date, subj, body = parts[0], parts[1], parts[2], parts[3]
        blob = subj + " " + body
        if not KEYWORDS.search(blob):
            continue
        # get patch
        show = run(["git", "show", "--format=", "--no-color", "--unified=3", sha], cwd=REF, timeout=600)
        diff = show.stdout
        if not diff:
            continue
        files = {}
        cur = None
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                cur = line[6:]
                files.setdefault(cur, [])
            elif line.startswith("@@") and cur:
                files[cur].append({"hdr": line, "removed": [], "added": []})
            elif cur and files[cur]:
                h = files[cur][-1]
                if line.startswith("-") and not line.startswith("---"):
                    h["removed"].append(line[1:])
                elif line.startswith("+") and not line.startswith("+++"):
                    h["added"].append(line[1:])
        res = {"sha": sha, "date": date, "subject": subj, "files": {}, "score": None}
        tot = miss = 0
        for f, hunks in files.items():
            content = load_tree_file(f)
            if content is None:
                continue
            ncontent = re.sub(r"\s+", " ", content)
            fmiss = 0
            fh = []
            for h in hunks:
                rm = [norm(x) for x in h["removed"] if len(norm(x)) > 3]
                ad = [norm(x) for x in h["added"] if len(norm(x)) > 3]
                if not rm and not ad:
                    continue
                rm_present = sum(1 for x in rm if x in ncontent) / len(rm) if rm else 0
                ad_present = sum(1 for x in ad if x in ncontent) / len(ad) if ad else 0
                if ad and ad_present > 0.6:
                    state = "applied"
                elif rm and rm_present > 0.6 and ad_present < 0.4:
                    state = "MISSING"
                    fmiss += 1
                else:
                    state = "unknown"
                tot += 1
                fh.append(state)
            res["files"][f] = {"states": fh, "missing": fmiss}
            miss += fmiss
        res["score"] = (miss, tot)
        if miss:
            out.append(res)
    out.sort(key=lambda r: (-r["score"][0], r["date"]))
    json.dump(out, open("/home/user/analysis/missing_fixes.json", "w"), indent=1)
    print(f"candidates with missing hunks: {len(out)}")
    for r in out[:80]:
        print(f"{r['score'][0]:2d}/{r['score'][1]:2d} {r['date']} {r['sha'][:10]} {r['subject'][:80]}")
        for f, v in r["files"].items():
            if v["missing"]:
                print(f"      - {f}  (missing hunks: {v['missing']})")

if __name__ == "__main__":
    main()
