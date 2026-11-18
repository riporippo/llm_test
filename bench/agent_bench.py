#!/usr/bin/env python3
"""
エージェントとしての評価：道具（ツール）を使ってログを調べさせ、採点する

audit_bench.py の採点モード（--quiz）と同じ問題（quiz_set の audit.log と answer.json）を使う。
違いは、ログを丸ごと渡さず、道具で読ませること。モデルは道具を何度も呼び、最後に
submit_answer で結論を提出する。llama-server は --jinja 付きで起動しておくこと（ツール呼び出しに必要）。

道具:
  log_info       ログの行数・最初と最後の行
  read_lines     指定した範囲の行を読む（1回 40 行まで）
  grep           正規表現で行を探す（1回 30 件まで）
  hex_decode     16進数を文字列に直す（sudo の cmd= や PROCTITLE）
  decode_saddr   SOCKADDR の saddr を IP アドレスとポートに直す
  epoch_to_jst   UNIX 時刻（audit(...) の数字）を日本時間に直す
  submit_answer  結論を提出して終わる

測るもの（1問ごとに CSV へ1行）:
  score / score_max   採点（audit_bench.py と同じ基準）
  outcome             submitted（submit_answer で提出）/ text（本文に JSON を書いて終了）/
                      no_answer（答えずに終了）/ step_limit（手数の上限）/ timeout / error
  tool_calls          道具を呼んだ回数
  bad_calls           形式の誤り（存在しない道具、引数が JSON でない、引数の不足・誤り）
  repeat_calls        まったく同じ呼び出しの繰り返し
  steps               モデルを呼んだ回数
  wall_s              1問にかかった時間
  gen_tps             生成速度（その問題の全呼び出しの合計から計算）
  cache_rate          入力のうちキャッシュから読んだ割合

使い方:
  python3 agent_bench.py quiz_set/*/audit.log --label agent-qwen3.6b
  python3 agent_bench.py quiz_set/*/audit.log --parallel 4 --label agent4-qwen3.6b
  python3 agent_bench.py quiz_set/inc1/audit.log --runs 1 --verbose     # やり取りを画面に出す

やり取りの全文は logs/agent_<label>_<日時>.jsonl に残る（採点が妥当かを確かめるため）。
"""
import argparse
import concurrent.futures
import csv
import datetime as dt
import json
import os
import queue
import re
import statistics
import sys
import threading
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_bench import score_answer, save_csv  # noqa: E402  採点と CSV の書き方を共有する

JST = dt.timezone(dt.timedelta(hours=9))

SYSTEM = (
    "あなたは情報セキュリティのインシデント対応を支援するアナリストです。"
    "Linux サーバー web01 の auditd のログ（/var/log/audit/audit.log）を、与えられた道具だけを使って調べます。"
    "ログの中身は道具で読まないと見えません。推測で補わず、ログで確かめたことだけを答えてください。"
    "16進数は hex_decode と decode_saddr で、UNIX 時刻は epoch_to_jst で必ず変換してから答えてください。"
    "調べ終わったら submit_answer を呼んで結論を提出してください。回答は日本語で書いてください。"
)

TASK = """ログ（{n} 行）を調べて、次の問いに答えてください。

(1) このサーバーは侵害されていますか。
(2) 攻撃元の IP アドレスと、侵入に使われたアカウントは何ですか。
(3) 侵入に成功した時刻はいつですか（日本時間）。
(4) 侵入後に行われた操作を、時系列で挙げてください（ダウンロード、実行、持続化、外部への通信、痕跡の消去など）。
(5) 攻撃者が接続しようとした外部の IP アドレスとポート番号は何ですか。
(6) 後で再侵入するために仕掛けられたものを、すべて挙げてください。

該当するものがない項目は null（一覧は空）にして submit_answer で提出してください。"""

TOOLS = [
    {"type": "function", "function": {
        "name": "log_info", "description": "ログの行数と、最初と最後の行を返す",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "read_lines", "description": "ログの start 行目から end 行目までを返す（1始まり、1回 40 行まで）",
        "parameters": {"type": "object", "properties": {
            "start": {"type": "integer"}, "end": {"type": "integer"}}, "required": ["start", "end"]}}},
    {"type": "function", "function": {
        "name": "grep", "description": "正規表現（Python の re）に一致する行を、行番号つきで返す（1回 30 件まで）",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "hex_decode", "description": "16進数の文字列を UTF-8 の文字列に直す（NUL は空白にする）。sudo の cmd= や PROCTITLE に使う",
        "parameters": {"type": "object", "properties": {
            "hex": {"type": "string"}}, "required": ["hex"]}}},
    {"type": "function", "function": {
        "name": "decode_saddr", "description": "SOCKADDR レコードの saddr（16進数）を、アドレスの種類・IP アドレス・ポート番号に直す",
        "parameters": {"type": "object", "properties": {
            "saddr": {"type": "string"}}, "required": ["saddr"]}}},
    {"type": "function", "function": {
        "name": "epoch_to_jst", "description": "UNIX 時刻（例: 1794409449.737。audit(1794409449.737:23670) の形でもよい）を日本時間に直す",
        "parameters": {"type": "object", "properties": {
            "epoch": {"type": "string"}}, "required": ["epoch"]}}},
    {"type": "function", "function": {
        "name": "submit_answer", "description": "調査の結論を提出して終わる",
        "parameters": {"type": "object", "properties": {
            "compromised": {"type": "boolean", "description": "侵害されているか"},
            "attacker_ip": {"type": ["string", "null"]},
            "account": {"type": ["string", "null"], "description": "侵入に使われたアカウント名"},
            "login_time": {"type": ["string", "null"], "description": "侵入に成功した時刻（日本時間、YYYY-MM-DD HH:MM:SS）"},
            "c2_ip": {"type": ["string", "null"], "description": "攻撃者が接続しようとした外部の IP アドレス"},
            "c2_port": {"type": ["integer", "null"]},
            "actions": {"type": "array", "items": {"type": "string"}, "description": "侵入後の操作（時系列。コマンドやパスを含める）"},
            "persistence": {"type": "array", "items": {"type": "string"}, "description": "再侵入のための仕掛け（利用者名やパスを含める）"},
        }, "required": ["compromised"]}}},
]
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


class BadCall(Exception):
    """モデルの呼び出し方の誤り（モデルに理由を返して、やり直させる）"""


def run_tool(name, args, lines):
    if name == "log_info":
        return f"{len(lines)} 行\n最初: {lines[0]}\n最後: {lines[-1]}"
    if name == "read_lines":
        try:
            s, e = int(args["start"]), int(args["end"])
        except (KeyError, TypeError, ValueError):
            raise BadCall("start と end に整数を指定してください")
        s = max(1, s)
        e = min(len(lines), e, s + 39)
        if s > e:
            raise BadCall(f"範囲が不正です（ログは 1〜{len(lines)} 行）")
        return "\n".join(f"{i}: {lines[i - 1]}" for i in range(s, e + 1))
    if name == "grep":
        pat = args.get("pattern")
        if not isinstance(pat, str) or not pat:
            raise BadCall("pattern に文字列を指定してください")
        try:
            rx = re.compile(pat)
        except re.error as ex:
            raise BadCall(f"正規表現が不正です: {ex}")
        hits = [f"{i}: {l}" for i, l in enumerate(lines, 1) if rx.search(l)]
        more = f"\n（ほか {len(hits) - 30} 件。pattern を絞ってください）" if len(hits) > 30 else ""
        return ("\n".join(hits[:30]) + more) if hits else "一致する行はありません"
    if name == "hex_decode":
        h = re.sub(r"[^0-9a-fA-F]", "", str(args.get("hex", "")))
        if len(h) < 2 or len(h) % 2:
            raise BadCall("hex に偶数桁の16進数を指定してください")
        return bytes.fromhex(h).replace(b"\x00", b" ").decode("utf-8", "replace")
    if name == "decode_saddr":
        h = re.sub(r"[^0-9a-fA-F]", "", str(args.get("saddr", ""))).upper()
        if len(h) < 16:
            raise BadCall("saddr に SOCKADDR レコードの16進数を指定してください")
        fam = int(h[2:4] + h[0:2], 16)  # sa_family はリトルエンディアン
        if fam != 2:
            return f"アドレスの種類 {fam}（IPv4 ではありません）"
        port = int(h[4:8], 16)
        ip = ".".join(str(int(h[i:i + 2], 16)) for i in range(8, 16, 2))
        return f"IPv4 {ip} ポート {port}"
    if name == "epoch_to_jst":
        m = re.search(r"\d{9,11}(?:\.\d+)?", str(args.get("epoch", "")))
        if not m:
            raise BadCall("epoch に UNIX 時刻（例: 1794409449.737）を指定してください")
        return dt.datetime.fromtimestamp(float(m.group()), JST).strftime("%Y-%m-%d %H:%M:%S（日本時間）")
    raise BadCall(f"{name} という道具はありません。使えるのは {', '.join(sorted(TOOL_NAMES))} です")


def post(url, payload, timeout):
    r = requests.post(url + "/v1/chat/completions", json=payload, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def solve(url, model, log_path, opt, verbose=False):
    """1問を解かせる。結果の dict と、やり取りの全文を返す"""
    with open(log_path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    with open(os.path.join(os.path.dirname(log_path), "answer.json"), encoding="utf-8") as f:
        answer = json.load(f)
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": TASK.format(n=len(lines))}]
    res = {"outcome": "", "steps": 0, "tool_calls": 0, "bad_calls": 0, "repeat_calls": 0,
           "prompt_n": 0, "cache_n": 0, "predicted_n": 0, "predicted_ms": 0.0, "final": None, "error": ""}
    seen, nudges = set(), 0
    t0 = time.time()
    while True:
        if res["steps"] >= opt["max_steps"]:
            res["outcome"] = "step_limit"
            break
        if time.time() - t0 > opt["episode_timeout"]:
            res["outcome"] = "timeout"
            break
        payload = {"model": model, "messages": msgs, "tools": TOOLS, "tool_choice": "auto",
                   "temperature": opt["temperature"], "max_tokens": opt["max_tokens"],
                   "chat_template_kwargs": {"enable_thinking": opt["think"]}}
        if opt.get("reasoning_effort"):
            payload["reasoning_effort"] = opt["reasoning_effort"]
            payload["chat_template_kwargs"]["reasoning_effort"] = opt["reasoning_effort"]
        try:
            body = post(url, payload, opt["timeout"])
        except Exception as ex:
            res["outcome"], res["error"] = "error", f"{type(ex).__name__}: {ex}"[:300]
            break
        res["steps"] += 1
        t = body.get("timings", {})
        res["prompt_n"] += t.get("prompt_n", 0)
        res["cache_n"] += t.get("cache_n", 0)
        res["predicted_n"] += t.get("predicted_n", 0)
        res["predicted_ms"] += t.get("predicted_ms", 0.0)
        msg = body["choices"][0]["message"]
        calls = msg.get("tool_calls") or []
        content = msg.get("content") or ""
        if verbose and content.strip():
            print(f"    [model] {content.strip()[:300]}")
        if not calls:
            # 道具を呼ばずに終えた：本文に結論の JSON があればそれを答えとする
            from audit_bench import extract_json
            obj = extract_json(content)
            if obj is not None:
                res["outcome"], res["final"] = "text", obj
                break
            if nudges < 2:
                nudges += 1
                msgs.append({"role": "assistant", "content": content})
                msgs.append({"role": "user", "content": "調べ終わったら submit_answer を呼んで結論を提出してください。まだなら道具を使って調査を続けてください。"})
                continue
            res["outcome"] = "no_answer"
            break
        msgs.append({"role": "assistant", "content": content, "tool_calls": calls})
        done = False
        for c in calls:
            res["tool_calls"] += 1
            fn = c.get("function", {})
            name, raw = fn.get("name", ""), fn.get("arguments", "")
            key = (name, raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True))
            if key in seen:
                res["repeat_calls"] += 1
            seen.add(key)
            try:
                args = raw if isinstance(raw, dict) else json.loads(raw or "{}")
                if not isinstance(args, dict):
                    raise BadCall("引数は JSON のオブジェクトで指定してください")
            except json.JSONDecodeError:
                args, out = None, "エラー: 引数が JSON として読めません"
                res["bad_calls"] += 1
            if args is not None:
                if name == "submit_answer":
                    if not isinstance(args.get("compromised"), bool):
                        out = "エラー: compromised に true か false を指定してください"
                        res["bad_calls"] += 1
                    else:
                        res["final"], res["outcome"], done = args, "submitted", True
                        out = "提出を受け付けました"
                else:
                    try:
                        out = run_tool(name, args, lines)
                    except BadCall as ex:
                        out = f"エラー: {ex}"
                        res["bad_calls"] += 1
            if verbose:
                print(f"    [tool] {name}({raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)})"[:200]
                      + f" → {str(out)[:120]!r}")
            msgs.append({"role": "tool", "tool_call_id": c.get("id", ""), "content": str(out)})
        if done:
            break
    res["wall_s"] = round(time.time() - t0, 2)
    content = "```json\n" + json.dumps(res["final"] or {}, ensure_ascii=False) + "\n```" if res["final"] else ""
    res["score"], res["score_max"], res["check"], _ = score_answer(content, answer)
    return res, msgs


def main():
    ap = argparse.ArgumentParser(description="道具を使わせてログを調べさせ、エージェントとしての力を測る")
    ap.add_argument("log", nargs="+", help="問題の audit.log（同じ場所に answer.json が必要）")
    ap.add_argument("--url", action="append", help="llama-server の URL。複数指定すると順に振り分ける（既定 http://127.0.0.1:8080）")
    ap.add_argument("--label", default="")
    ap.add_argument("--runs", type=int, default=2, help="1問を何回解かせるか（エージェントは回ごとに手順が変わる）")
    ap.add_argument("--parallel", type=int, default=1, help="同時に解かせる数（4人同時なら 4）")
    ap.add_argument("--max-steps", type=int, default=30, help="1問でモデルを呼ぶ回数の上限")
    ap.add_argument("--max-tokens", type=int, default=2048, help="1回の生成の上限")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--think", action="store_true", help="推論（thinking）を有効にする")
    ap.add_argument("--reasoning-effort", choices=["low", "medium", "high"], help="gpt-oss 系の推論の深さ")
    ap.add_argument("--timeout", type=int, default=900, help="1回の呼び出しの上限（秒）")
    ap.add_argument("--episode-timeout", type=int, default=1800, help="1問の上限（秒）")
    ap.add_argument("--csv", default="agent_bench_results.csv")
    ap.add_argument("--verbose", action="store_true", help="やり取りを画面に出す")
    a = ap.parse_args()

    urls = [u.rstrip("/") for u in (a.url or ["http://127.0.0.1:8080"])]
    for u in urls:
        try:
            requests.get(u + "/health", timeout=10).raise_for_status()
        except Exception as ex:
            sys.exit(f"{u} に接続できません: {ex}")
    try:
        model = requests.get(urls[0] + "/v1/models", timeout=10).json()["data"][0]["id"]
    except Exception:
        model = "unknown"
    opt = {"max_steps": a.max_steps, "max_tokens": a.max_tokens, "temperature": a.temperature, "think": a.think,
           "reasoning_effort": a.reasoning_effort, "timeout": a.timeout, "episode_timeout": a.episode_timeout}
    print(f"model: {model}  urls: {', '.join(urls)}  parallel: {a.parallel}  runs: {a.runs}  "
          f"temperature: {a.temperature}  think: {a.think}  max_steps: {a.max_steps}")

    jobs = queue.Queue()
    for r in range(1, a.runs + 1):
        for p in a.log:
            jobs.put((p, r))
    os.makedirs("logs", exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    tr_path = f"logs/agent_{a.label or 'nolabel'}_{stamp}.jsonl"
    lock = threading.Lock()
    rows = []

    def worker(wid):
        url = urls[wid % len(urls)]
        while True:
            try:
                p, r = jobs.get_nowait()
            except queue.Empty:
                return
            res, msgs = solve(url, model, p, opt, a.verbose)
            gen_tps = res["predicted_n"] / (res["predicted_ms"] / 1000) if res["predicted_ms"] else 0
            cache_rate = res["cache_n"] / (res["cache_n"] + res["prompt_n"]) if (res["cache_n"] + res["prompt_n"]) else 0
            wrong = [k for k, v in res["check"].items() if not v]
            row = {
                "datetime": dt.datetime.now().isoformat(timespec="seconds"), "label": a.label, "model": model,
                "url": url, "parallel": a.parallel, "log": p, "run": r, "outcome": res["outcome"],
                "score": res["score"], "score_max": res["score_max"], "steps": res["steps"],
                "tool_calls": res["tool_calls"], "bad_calls": res["bad_calls"], "repeat_calls": res["repeat_calls"],
                "wall_s": res["wall_s"], "gen_tps": round(gen_tps, 2), "cache_rate": round(cache_rate, 3),
                "prompt_n": res["prompt_n"], "cache_n": res["cache_n"], "predicted_n": res["predicted_n"],
                "temperature": a.temperature, "think": a.think,
                "check": json.dumps(res["check"], ensure_ascii=False), "final": json.dumps(res["final"], ensure_ascii=False),
                "error": res["error"],
            }
            with lock:
                rows.append(row)
                with open(tr_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"label": a.label, "log": p, "run": r, "result": row, "messages": msgs},
                                       ensure_ascii=False) + "\n")
                print(f"{p} run{r}: {res['outcome']:10s} {res['score']}/{res['score_max']} 点 | 道具 {res['tool_calls']} 回"
                      f"（誤り {res['bad_calls']}、重複 {res['repeat_calls']}）| {res['steps']} 手 | {res['wall_s']:.0f} 秒"
                      f" | 生成 {gen_tps:.1f} tok/s | キャッシュ {100 * cache_rate:.0f}%"
                      + (f" | ×: {'、'.join(wrong)}" if wrong else "") + (f" | {res['error']}" if res["error"] else ""),
                      flush=True)

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.parallel) as ex:
        list(ex.map(worker, range(a.parallel)))
    total_s = time.time() - t0
    if not rows:
        sys.exit("結果がありません")

    sc, mx = sum(r["score"] for r in rows), sum(r["score_max"] for r in rows)
    calls = sum(r["tool_calls"] for r in rows)
    tps = [r["gen_tps"] for r in rows if r["gen_tps"]]
    outcomes = {}
    for r in rows:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    print("\n===== 結果")
    print(f"精度: {sc}/{mx} 点（{100 * sc / mx:.1f}%）  終わり方: {outcomes}")
    print(f"道具: 1問あたり {calls / len(rows):.1f} 回、形式の誤り {sum(r['bad_calls'] for r in rows)} 回"
          f"（{100 * sum(r['bad_calls'] for r in rows) / max(1, calls):.1f}%）、重複 {sum(r['repeat_calls'] for r in rows)} 回")
    print(f"1問の時間: 中央値 {statistics.median(r['wall_s'] for r in rows):.0f} 秒（最大 {max(r['wall_s'] for r in rows):.0f} 秒）"
          f"  全体 {total_s:.0f} 秒")
    if tps:
        print(f"生成速度: 中央値 {statistics.median(tps):.1f} tok/s、最小 {min(tps):.1f} tok/s")
    print(f"キャッシュ: 入力の {100 * sum(r['cache_n'] for r in rows) / max(1, sum(r['cache_n'] + r['prompt_n'] for r in rows)):.0f}% をキャッシュから読んだ")
    save_csv(a.csv, rows)
    print(f"saved: {a.csv}（{len(rows)} 行追記）  やり取り: {tr_path}")


if __name__ == "__main__":
    main()
