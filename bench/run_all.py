#!/usr/bin/env python3
"""
調査の自動実行：モデルごとに llama-server を起動 → 測定 → 停止、を順に繰り返す

models.json に書いたモデルを1つずつ、段階（phase）ごとに次の流れで処理する。
  1. llama-server を起動する（出力は logs/ に保存）
  2. 読み込みが終わるのを待つ（初回はダウンロードも含む）
  3. audit_bench.py で測定する（結果は audit_bench_results.csv に追記）
  4. llama-server を止め、次へ進む
途中で失敗したモデルは記録して飛ばし、残りを続ける。標準ライブラリのみ使用
（audit_bench.py が requests を使う）。

段階:
  quiz    精度。1人・文脈 16k で quiz_set の全問を採点          → label は quiz-<名前>
  speed4  調査2。4人同時・文脈 8k×4 で out_audit のログを要約    → label は research2-<名前>
  speed1  調査1と同じ条件。1人・文脈 8k で out_audit のログを要約 → label は research1-<名前>

使い方（Head で、bench ディレクトリから）:
  python3 run_all.py --dry-run                 # 実行するコマンドを表示するだけ
  python3 run_all.py                           # models.json の全モデルで quiz と speed4
  python3 run_all.py --phases quiz             # 精度だけ
  python3 run_all.py --only qwen3.6,glm4.7     # 一部のモデルだけ
  python3 run_all.py --force                   # 測定済みのものもやり直す

測定済み（CSV に同じ label の行がある）の組み合わせは飛ばすので、途中で止まっても
同じコマンドをもう一度実行すれば続きから再開できる。

長時間かかるので tmux の中で実行し、Worker のスリープは切っておくこと。
"""
import argparse
import csv
import datetime as dt
import glob
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# 段階ごとの設定。server は llama-server に足すオプション、bench は audit_bench.py の引数
PHASES = {
    "quiz": {
        "prefix": "quiz-",
        "server": ["-c", "16384", "-np", "1"],
        "logs": "quiz_set/*/audit.log",
        "bench": ["--quiz", "--runs", "1", "--max-tokens", "4096"],  # 2048 だと長い回答が途中で切れた
    },
    "speed4": {
        "prefix": "research2-",
        "server": ["-c", "32768", "-np", "4"],
        "logs": "out_audit/audit.log",
        "bench": ["--parallel", "4", "--runs", "3"],
    },
    "speed1": {
        "prefix": "research1-",
        "server": ["-c", "8192", "-np", "1"],
        "logs": "out_audit/audit.log",
        "bench": ["--runs", "3"],
    },
}


def now() -> str:
    return dt.datetime.now().strftime("%H:%M:%S")


def health(base: str) -> str:
    """ok / loading / down のどれかを返す"""
    try:
        with urllib.request.urlopen(base + "/health", timeout=5) as r:
            return "ok" if r.status == 200 else "loading"
    except urllib.error.HTTPError as e:
        return "loading" if e.code == 503 else "down"
    except Exception:
        return "down"


def done_labels(csv_path: str) -> set:
    if not os.path.exists(csv_path):
        return set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        return {r.get("label", "") for r in csv.DictReader(f)}


def placement(log_path: str) -> str:
    """起動ログから、重みがどこに何 MiB 載ったか（CUDA0 / RPC0 / CPU）を拾う"""
    out = []
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"(\S+) model buffer size\s*=\s*([\d.]+ \w+)", line)
                if m:
                    out.append(f"{m.group(1)}={m.group(2)}")
    except OSError:
        pass
    return ", ".join(out)


def last_error(log_path: str) -> str:
    """起動ログの最後のエラー行（失敗の理由を表示するため）"""
    err = ""
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if re.search(r"\bE\b|error|failed|out of memory", line, re.I):
                    err = line.strip()
    except OSError:
        pass
    return err[-300:]


def stop_server(proc: subprocess.Popen, base: str) -> None:
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    # ポートが空くのを待つ
    for _ in range(30):
        if health(base) == "down":
            break
        time.sleep(1)


def main() -> None:
    ap = argparse.ArgumentParser(description="モデルごとに llama-server を起動して測定する")
    ap.add_argument("--models", default=os.path.join(HERE, "models.json"))
    ap.add_argument("--phases", default="quiz,speed4", help="実行する段階（カンマ区切り）: " + ", ".join(PHASES))
    ap.add_argument("--only", help="この名前のモデルだけ（カンマ区切り）")
    ap.add_argument("--force", action="store_true", help="測定済みでもやり直す")
    ap.add_argument("--dry-run", action="store_true", help="コマンドを表示するだけで実行しない")
    ap.add_argument("--server-bin", help="llama-server の場所（省略時は models.json の値）")
    ap.add_argument("--csv", default="audit_bench_results.csv")
    ap.add_argument("--load-timeout-min", type=float, default=240,
                    help="読み込み（ダウンロードを含む）を待つ上限（分）")
    ap.add_argument("--cooldown", type=float, default=15, help="停止してから次を起動するまでの待ち時間（秒）")
    a = ap.parse_args()

    with open(a.models, encoding="utf-8") as f:
        cfg = json.load(f)
    server_bin = os.path.expanduser(a.server_bin or cfg.get("server_bin", "~/llama.cpp/build/bin/llama-server"))
    host, port = cfg.get("host", "127.0.0.1"), int(cfg.get("port", 8080))
    base = f"http://{host}:{port}"
    common = list(cfg.get("server_common", []))
    phases = [p.strip() for p in a.phases.split(",") if p.strip()]
    for p in phases:
        if p not in PHASES:
            sys.exit(f"不明な段階: {p}（使えるのは {', '.join(PHASES)}）")
    models = cfg["models"]
    if a.only:
        want = {x.strip() for x in a.only.split(",")}
        unknown = want - {m["name"] for m in models}
        if unknown:
            sys.exit(f"models.json にないモデル名: {', '.join(sorted(unknown))}")
        models = [m for m in models if m["name"] in want]

    os.chdir(HERE)  # ログの場所（quiz_set/ など）と CSV を bench/ からの相対で扱う
    os.makedirs("logs", exist_ok=True)
    if not a.dry_run:
        if not os.path.exists(server_bin):
            sys.exit(f"llama-server が見つかりません: {server_bin}（--server-bin か models.json の server_bin で指定）")
        if health(base) != "down":
            sys.exit(f"{base} で既に何かが動いています。先に止めてください（別の llama-server が残っていませんか）")

    done = set() if a.force else done_labels(a.csv)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    summary_path = f"logs/run_all_{stamp}.csv"
    summary = []
    plan = [(m, p) for m in models for p in phases]  # モデルごとに全段階を済ませる（ダウンロード済みのうちに）
    print(f"[{now()}] {len(models)} モデル × {len(phases)} 段階 = {len(plan)} 件")

    for n, (m, phase) in enumerate(plan, 1):
        ph = PHASES[phase]
        label = ph["prefix"] + m["name"]
        logs = sorted(glob.glob(ph["logs"]))
        extra = m.get("server_extra", {})
        server_cmd = ([server_bin, "-hf", m["hf"]] + common + ph["server"]
                      + list(extra.get("all", [])) + list(extra.get(phase, []))
                      + ["--host", host, "--port", str(port)])
        bench_cmd = ([sys.executable, "audit_bench.py"] + logs + ph["bench"]
                     + list(m.get("bench_extra", {}).get(phase, []))
                     + ["--label", label, "--url", base, "--csv", a.csv])
        print(f"\n===== [{now()}] ({n}/{len(plan)}) {label}")
        row = {"label": label, "model": m["hf"], "phase": phase, "status": "", "load_s": "",
               "bench_s": "", "placement": "", "note": "", "server_cmd": " ".join(server_cmd)}
        summary.append(row)

        if label in done:
            print("  測定済みなので飛ばします（やり直すなら --force）")
            row["status"] = "skipped"
            continue
        if not logs:
            print(f"  ログが見つかりません: {ph['logs']}")
            row.update(status="no_logs")
            continue
        print("  server: " + " ".join(server_cmd))
        print("  bench : " + " ".join(bench_cmd[:2]) + f" （ログ {len(logs)} 本） " + " ".join(bench_cmd[2 + len(logs):]))
        if a.dry_run:
            row["status"] = "dry-run"
            continue

        server_log = f"logs/server_{label}_{stamp}.log"
        bench_log = f"logs/bench_{label}_{stamp}.log"
        proc = None
        try:
            # ---- 起動して、読み込みが終わるのを待つ
            t0 = time.time()
            with open(server_log, "w") as lf:
                proc = subprocess.Popen(server_cmd, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
            state, last_note = "loading", t0
            while True:
                if proc.poll() is not None:
                    state = "exited"
                    break
                if health(base) == "ok":
                    state = "ok"
                    break
                if time.time() - t0 > a.load_timeout_min * 60:
                    state = "timeout"
                    break
                if time.time() - last_note > 300:
                    print(f"  [{now()}] 読み込み中…（{(time.time() - t0) / 60:.0f} 分経過。ログ: {server_log}）")
                    last_note = time.time()
                time.sleep(3)
            row["load_s"] = round(time.time() - t0)
            row["placement"] = placement(server_log)
            if state != "ok":
                row["status"] = "load_failed" if state == "exited" else "load_timeout"
                row["note"] = last_error(server_log)
                print(f"  ! 起動に失敗しました（{row['status']}）: {row['note']}")
                print(f"    ログ: {server_log}")
                continue
            print(f"  [{now()}] 起動しました（{row['load_s']} 秒）。配置: {row['placement'] or '不明'}")

            # ---- 測定（出力は画面とファイルの両方へ）
            t1 = time.time()
            with open(bench_log, "w", encoding="utf-8") as bf:
                bp = subprocess.Popen(bench_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      text=True, encoding="utf-8", errors="replace")
                echo = True
                for line in bp.stdout:
                    bf.write(line)
                    if line.startswith("----- 回答"):
                        echo = False  # 回答の全文は画面には出さない（ファイルと CSV には残る）
                    if echo:
                        print("  | " + line.rstrip())
                rc = bp.wait()
            row["bench_s"] = round(time.time() - t1)
            if rc != 0:
                row["status"] = "bench_failed"
                row["note"] = "llama-server が途中で止まった" if proc.poll() is not None else f"audit_bench.py が終了コード {rc}"
                print(f"  ! 測定に失敗しました: {row['note']}（ログ: {bench_log}、{server_log}）")
            elif proc.poll() is not None:
                row["status"] = "server_died"
                row["note"] = "測定の途中で llama-server が止まった（一部の結果だけ CSV に入っている）: " + last_error(server_log)
                print(f"  ! {row['note']}（ログ: {server_log}）")
            else:
                row["status"] = "ok"
                print(f"  [{now()}] 測定が終わりました（{row['bench_s']} 秒）")
        except KeyboardInterrupt:
            row["status"] = "interrupted"
            print("\n中断します。llama-server を止めています…")
            if proc is not None:
                stop_server(proc, base)
            break
        finally:
            if proc is not None:
                stop_server(proc, base)
            with open(summary_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(row.keys()))
                w.writeheader()
                w.writerows(summary)
        time.sleep(a.cooldown)  # GPU（Worker 側も）のメモリが解放されるのを待つ

    # ---- まとめ
    print(f"\n===== [{now()}] まとめ")
    for r in summary:
        print(f"  {r['label']:32s} {r['status']:13s} 読み込み {str(r['load_s']):>5s} 秒  測定 {str(r['bench_s']):>5s} 秒  {r['note']}")
    if not a.dry_run:
        print(f"  記録: {summary_path}（起動コマンドと重みの配置も入っています）")
        print(f"  結果: {a.csv}  → python3 report.py で一覧にできます")


if __name__ == "__main__":
    main()
