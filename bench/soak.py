#!/usr/bin/env python3
"""
長時間の連続稼働試験（同時利用を想定）

llama-server に、台本（turns_edu.txt と同じ書式）のシナリオを、複数の「学生」
（スレッド）から指定時間だけ繰り返し投げ続ける。1リクエストごとに CSV へ追記するので、
途中で止めてもそこまでの結果は残る。標準ライブラリのみ使用。

使い方:
  python3 soak.py --hours 8 --users 4 --label soak-gpt-oss-20b-head
  python3 soak.py --minutes 2 --users 2        # 動作確認（2分）

llama-server 側は、同時に捌く本数を --users に合わせる（例: -np 4）。
  -c は 1本あたりの文脈 × 本数（例: 8k × 4 = -c 32768）にする。

出力:
  soak_<label>_<日時>.csv   1リクエスト1行（時刻・ユーザー・シナリオ・速度・エラー）
  10分ごとに画面へ集計（直近10分の件数・生成速度の中央値・エラー数）
"""
import argparse
import csv
import datetime as dt
import json
import os
import random
import statistics
import threading
import time
import urllib.error
import urllib.request

SYSTEM = (
    "あなたは大学の授業を手伝うティーチングアシスタントです。"
    "学生の質問に、日本語でわかりやすく、正確に答えてください。"
)


def load_script(path: str) -> list:
    scen, cur = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.rstrip("\n")
            if not s.strip() or s.lstrip().startswith("#"):
                continue
            if s.strip() == "---":
                if cur:
                    scen.append(cur)
                cur = []
                continue
            cur.append(s.replace("\\n", "\n"))
    if cur:
        scen.append(cur)
    return scen


def post(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


class Writer:
    def __init__(self, path: str):
        self.path, self.lock, self.rows = path, threading.Lock(), []
        self.fields = ["datetime", "elapsed_min", "user", "scenario", "turn", "ok", "error",
                       "prompt_n", "cache_n", "prompt_tps", "predicted_n", "predicted_tps",
                       "wall_s", "finish_reason", "content_chars", "reasoning_chars"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=self.fields).writeheader()

    def add(self, row: dict) -> None:
        with self.lock:
            self.rows.append(row)
            with open(self.path, "a", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=self.fields).writerow(row)


def student(uid: int, a, scen: list, deadline: float, t_start: float, out: Writer, stop: threading.Event):
    rng = random.Random(uid)
    url = a.url.rstrip("/") + "/v1/chat/completions"
    while not stop.is_set() and time.time() < deadline:
        si = rng.randrange(len(scen))
        msgs = [{"role": "system", "content": SYSTEM}]
        for ti, user in enumerate(scen[si], 1):
            if stop.is_set() or time.time() >= deadline:
                return
            msgs.append({"role": "user", "content": user})
            payload = {"messages": msgs, "temperature": 0.7, "max_tokens": a.max_tokens,
                       "cache_prompt": True,
                       "chat_template_kwargs": {"enable_thinking": False}}
            if a.reasoning_effort:
                payload["reasoning_effort"] = a.reasoning_effort
            t0 = time.time()
            row = {"datetime": dt.datetime.now().isoformat(timespec="seconds"),
                   "elapsed_min": round((t0 - t_start) / 60, 1), "user": uid,
                   "scenario": si + 1, "turn": ti, "ok": False, "error": ""}
            try:
                r = post(url, payload, a.timeout)
                t = r.get("timings", {})
                msg = r["choices"][0]["message"]
                content = msg.get("content") or ""
                row.update(ok=True, prompt_n=t.get("prompt_n"), cache_n=t.get("cache_n"),
                           prompt_tps=round(t.get("prompt_per_second", 0), 2),
                           predicted_n=t.get("predicted_n"),
                           predicted_tps=round(t.get("predicted_per_second", 0), 2),
                           finish_reason=r["choices"][0].get("finish_reason"),
                           content_chars=len(content),
                           reasoning_chars=len(msg.get("reasoning_content") or ""))
                msgs.append({"role": "assistant", "content": content})
            except urllib.error.HTTPError as e:
                row["error"] = f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"
            except Exception as e:  # 接続断・タイムアウトなど。記録して続ける
                row["error"] = f"{type(e).__name__}: {e}"[:200]
            row["wall_s"] = round(time.time() - t0, 2)
            out.add(row)
            if not row["ok"]:
                time.sleep(10)  # サーバーが落ちているときに空回りしない
                break
            time.sleep(rng.uniform(0, a.think_time))  # 学生が回答を読んで次を打つ時間


def report(rows: list, since: float, label: str) -> None:
    rec = [r for r in rows if r["elapsed_min"] >= since]
    ok = [r for r in rec if r["ok"]]
    gen = [r["predicted_tps"] for r in ok if r.get("predicted_n")]
    wall = [r["wall_s"] for r in ok]
    msg = f"[{dt.datetime.now():%H:%M}] {label} 直近: {len(ok)} 件成功 / エラー {len(rec) - len(ok)}"
    if gen:
        msg += f" | 生成 中央値 {statistics.median(gen):.1f} tok/s（最小 {min(gen):.1f}）"
    if wall:
        msg += f" | 応答 中央値 {statistics.median(wall):.1f}s（最大 {max(wall):.1f}s）"
    print(msg, flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="長時間の連続稼働試験")
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--script", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "turns_edu.txt"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--hours", type=float)
    g.add_argument("--minutes", type=float)
    ap.add_argument("--users", type=int, default=4, help="同時に使う学生の数（スレッド数）")
    ap.add_argument("--think-time", type=float, default=20, help="次の質問までの待ち時間の上限（秒、0〜この値の一様乱数）")
    ap.add_argument("--max-tokens", type=int, default=1024)
    ap.add_argument("--reasoning-effort", choices=["low", "medium", "high"], help="gpt-oss 系の推論の深さ")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--report-min", type=float, default=10, help="画面に集計を出す間隔（分）")
    ap.add_argument("--label", default="soak")
    a = ap.parse_args()

    dur = (a.hours * 3600) if a.hours else (a.minutes * 60 if a.minutes else 8 * 3600)
    scen = load_script(a.script)
    path = f"soak_{a.label}_{dt.datetime.now():%Y%m%d-%H%M}.csv"
    out = Writer(path)
    t_start = time.time()
    deadline = t_start + dur
    print(f"開始 {dt.datetime.now():%H:%M}  終了予定 {dt.datetime.fromtimestamp(deadline):%m-%d %H:%M}  "
          f"users={a.users}  シナリオ {len(scen)} 本  記録: {path}", flush=True)

    stop = threading.Event()
    ths = [threading.Thread(target=student, args=(u + 1, a, scen, deadline, t_start, out, stop), daemon=True)
           for u in range(a.users)]
    for i, th in enumerate(ths):
        th.start()
        time.sleep(1 + i)  # 一斉スタートを避ける
    try:
        last = 0.0
        while any(th.is_alive() for th in ths):
            time.sleep(5)
            el = (time.time() - t_start) / 60
            if el - last >= a.report_min:
                report(out.rows, last, a.label)
                last = el
    except KeyboardInterrupt:
        print("\n中断します（実行中のリクエストの終了を待たずに終了）")
        stop.set()

    ok = [r for r in out.rows if r["ok"]]
    print(f"\n===== 終了 {dt.datetime.now():%H:%M}  計 {len(out.rows)} 件（成功 {len(ok)} / エラー {len(out.rows) - len(ok)}）")
    report(out.rows, 0, a.label + " 全体")
    if ok:
        # 前半と後半の生成速度を比べる（長時間で劣化していないか）
        half = (time.time() - t_start) / 120
        a1 = [r["predicted_tps"] for r in ok if r["elapsed_min"] < half and r.get("predicted_n")]
        a2 = [r["predicted_tps"] for r in ok if r["elapsed_min"] >= half and r.get("predicted_n")]
        if a1 and a2:
            print(f"  生成速度 前半 {statistics.median(a1):.1f} / 後半 {statistics.median(a2):.1f} tok/s（中央値）")
    print(f"  記録: {path}")


if __name__ == "__main__":
    main()
