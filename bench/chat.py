#!/usr/bin/env python3
"""
llama-server 用の対話チャット（動作確認・品質の手見用）

llama-server の OpenAI 互換 API（/v1/chat/completions）にストリーミングで接続し、
会話履歴を保ったまま対話する。1ターンごとに速度を表示する。
  - 最初のトークンまでの時間（TTFT）
  - 入力処理速度・生成速度（llama-server の timings）
  - 推論（thinking）と回答それぞれのおおよその文字数
標準ライブラリのみ使用（追加インストール不要）。

使い方:
  python3 chat.py                                  # 127.0.0.1:8080 に接続して対話
  python3 chat.py --url http://10.20.0.5:8080      # 別の台の llama-server
  python3 chat.py --think                          # 推論（thinking）を有効にして開始
  python3 chat.py --system-file sys.txt            # システムプロンプトをファイルから
  python3 chat.py --script turns.txt --label M2-gpt-oss-120b-worker
                                                   # 台本モード：1行＝1ターンで自動実行し、ログを残す

対話中のコマンド:
  /help            コマンド一覧
  /reset           会話履歴を消す（システムプロンプトは残す）
  /system <文>     システムプロンプトを変更して履歴を消す
  /think on|off    推論（thinking）の有効・無効を切り替える
  /show on|off     推論の中身を画面に出すかどうか（既定 on）
  /temp <数値>     temperature を変更
  /max <数値>      1回の最大生成トークン数を変更
  /retry           直前の質問をもう一度投げる（直前の回答は捨てる）
  /stats           このセッションの速度の集計
  /save [ファイル] 会話を JSON で保存
  /quit            終了（Ctrl-D でも可）
  \"\"\"             複数行の入力を開始・終了（貼り付け用）

台本ファイルの書式:
  - 1行が1ターン（前のターンの履歴を引き継ぐ）
  - 空行と # で始まる行は無視
  - '---' の行で会話をリセット（別のシナリオとして扱う）
  - 行中の \\n は改行に置き換える

ログ:
  --log（既定 chat_log.jsonl）に、1ターン1行で質問・回答・推論・速度を追記する。
  モデル同士の回答を後で比べるために使う（--label でモデル名と載せ方を付けておく）。
"""
import argparse
import datetime as dt
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request

try:
    import readline  # noqa: F401  入力行の編集・履歴（Linux/WSL）
except ImportError:
    pass

DEFAULT_SYSTEM = (
    "あなたは大学の授業を手伝うティーチングアシスタントです。"
    "学生の質問に、日本語でわかりやすく、正確に答えてください。"
    "わからないことは、わからないと答えてください。"
)

# 端末の色（NO_COLOR 環境変数か --no-color で無効）
C_DIM, C_USER, C_INFO, C_RESET = "\033[2m", "\033[1;36m", "\033[33m", "\033[0m"


def color(on: bool):
    global C_DIM, C_USER, C_INFO, C_RESET
    if not on:
        C_DIM = C_USER = C_INFO = C_RESET = ""


# ---------------------------------------------------------------- HTTP
def get_json(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def server_info(base: str) -> dict:
    info = {"model": "?", "n_ctx": None, "build": ""}
    try:
        p = get_json(base + "/props")
        info["n_ctx"] = p.get("default_generation_settings", {}).get("n_ctx") or p.get("n_ctx")
        info["model"] = os.path.basename(p.get("model_path", "")) or info["model"]
        info["build"] = p.get("build_info", "")
    except Exception:
        pass
    try:
        m = get_json(base + "/v1/models")
        if m.get("data"):
            info["model"] = m["data"][0].get("id", info["model"])
    except Exception:
        pass
    return info


def stream_chat(base: str, messages: list, opt: dict, show_reasoning: bool, timeout: int = 1800) -> dict:
    """SSE で受け取りながら画面に出す。最後に回答・推論・速度をまとめて返す"""
    payload = {
        "messages": messages,
        "stream": True,
        "stream_options": {"include_usage": True},
        "temperature": opt["temperature"],
        "max_tokens": opt["max_tokens"],
        "cache_prompt": True,  # 対話なので前のターンのキャッシュを使う
        # Qwen 系などの思考オン・オフ。対応しないテンプレートでは無視される
        "chat_template_kwargs": {"enable_thinking": opt["think"]},
    }
    if opt.get("reasoning_effort"):
        payload["reasoning_effort"] = opt["reasoning_effort"]  # gpt-oss / GLM 系
    req = urllib.request.Request(base + "/v1/chat/completions",
                                 data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json",
                                          "Accept": "text/event-stream"})
    content, reasoning = [], []
    timings, usage, finish, model = {}, {}, None, ""
    t0 = time.perf_counter()
    t_first = None
    in_reasoning = False
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            for raw in r:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    ev = json.loads(data)
                except json.JSONDecodeError:
                    continue
                model = ev.get("model", model)
                if ev.get("timings"):
                    timings = ev["timings"]
                if ev.get("usage"):
                    usage = ev["usage"]
                for ch in ev.get("choices", []):
                    d = ch.get("delta", {}) or {}
                    rc = d.get("reasoning_content")
                    c = d.get("content")
                    if (rc or c) and t_first is None:
                        t_first = time.perf_counter()
                    if rc:
                        reasoning.append(rc)
                        if show_reasoning:
                            if not in_reasoning:
                                sys.stdout.write(C_DIM + "[推論] ")
                                in_reasoning = True
                            sys.stdout.write(rc)
                            sys.stdout.flush()
                    if c:
                        if in_reasoning:
                            sys.stdout.write(C_RESET + "\n\n")
                            in_reasoning = False
                        content.append(c)
                        sys.stdout.write(c)
                        sys.stdout.flush()
                    if ch.get("finish_reason"):
                        finish = ch["finish_reason"]
    except KeyboardInterrupt:
        finish = "interrupted"
        sys.stdout.write(C_RESET + "\n（中断しました）")
    except urllib.error.HTTPError as e:
        sys.stdout.write(C_RESET)
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:500]}")
    except urllib.error.URLError as e:
        sys.stdout.write(C_RESET)
        raise RuntimeError(f"接続できません: {e.reason}（llama-server は起動していますか？ --url を確認）")
    if in_reasoning:
        sys.stdout.write(C_RESET)
    sys.stdout.write("\n")
    wall = time.perf_counter() - t0
    return {
        "content": "".join(content),
        "reasoning": "".join(reasoning),
        "finish_reason": finish,
        "model": model,
        "wall_s": wall,
        "ttft_s": (t_first - t0) if t_first else None,
        "timings": timings,
        "usage": usage,
    }


# ---------------------------------------------------------------- 表示・記録
def stat_line(res: dict) -> str:
    t = res["timings"]
    parts = []
    if res["ttft_s"] is not None:
        parts.append(f"TTFT {res['ttft_s']:.2f}s")
    if t:
        parts.append(f"入力 {t.get('prompt_n', 0)} tok（キャッシュ {t.get('cache_n', 0)}）"
                     f" {t.get('prompt_per_second', 0):.1f} tok/s")
        parts.append(f"生成 {t.get('predicted_n', 0)} tok {t.get('predicted_per_second', 0):.1f} tok/s")
    elif res["usage"]:
        u = res["usage"]
        parts.append(f"入力 {u.get('prompt_tokens')} tok / 生成 {u.get('completion_tokens')} tok")
    parts.append(f"計 {res['wall_s']:.1f}s")
    if res["reasoning"]:
        parts.append(f"推論 {len(res['reasoning'])} 字 / 回答 {len(res['content'])} 字")
    if res["finish_reason"] not in (None, "stop"):
        parts.append(f"終了理由={res['finish_reason']}")
    return C_INFO + "  ── " + " | ".join(parts) + C_RESET


def append_log(path: str, rec: dict) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def print_stats(hist: list) -> None:
    rows = [h for h in hist if h["timings"]]
    if not rows:
        print("  まだ記録がありません")
        return
    gen = [h["timings"]["predicted_per_second"] for h in rows if h["timings"].get("predicted_n", 0) > 0]
    pp = [h["timings"]["prompt_per_second"] for h in rows if h["timings"].get("prompt_n", 0) > 16]
    ttft = [h["ttft_s"] for h in rows if h["ttft_s"] is not None]
    print(f"  ターン数 {len(rows)}")
    if gen:
        print(f"  生成速度  中央値 {statistics.median(gen):.1f} tok/s（最小 {min(gen):.1f} / 最大 {max(gen):.1f}）")
    if pp:
        print(f"  入力処理  中央値 {statistics.median(pp):.1f} tok/s（17 トークン以上の入力のみ）")
    if ttft:
        print(f"  TTFT      中央値 {statistics.median(ttft):.2f}s（最大 {max(ttft):.2f}s）")


# ---------------------------------------------------------------- 入力
def read_user() -> str:
    line = input(C_USER + "you> " + C_RESET)
    if line.strip() != '"""':
        return line
    buf = []
    while True:
        l2 = input(C_DIM + "...> " + C_RESET)
        if l2.strip() == '"""':
            return "\n".join(buf)
        buf.append(l2)


def load_script(path: str) -> list:
    """台本を [シナリオ1のターン列, シナリオ2のターン列, ...] にして返す"""
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


# ---------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description="llama-server 用の対話チャット")
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--system", default=DEFAULT_SYSTEM, help="システムプロンプト（空文字で無し）")
    ap.add_argument("--system-file", help="システムプロンプトをファイルから読む")
    ap.add_argument("--think", action="store_true", help="推論（thinking）を有効にする（既定は無効）")
    ap.add_argument("--reasoning-effort", choices=["low", "medium", "high", "max"],
                    help="gpt-oss / GLM 系の推論の深さ")
    ap.add_argument("--hide-reasoning", action="store_true", help="推論の中身を画面に出さない")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--max-tokens", type=int, default=2048)
    ap.add_argument("--label", default="", help="ログに残すモデル名・載せ方（例: M2-gpt-oss-120b-worker）")
    ap.add_argument("--log", default="chat_log.jsonl", help="1ターン1行の記録先（空文字で記録しない）")
    ap.add_argument("--script", help="台本モード：ファイルの各行を順に投げる")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
    color(not a.no_color and not os.environ.get("NO_COLOR") and sys.stdout.isatty())

    base = a.url.rstrip("/")
    system = a.system
    if a.system_file:
        with open(a.system_file, encoding="utf-8") as f:
            system = f.read().strip()
    opt = {"temperature": a.temperature, "max_tokens": a.max_tokens,
           "think": a.think, "reasoning_effort": a.reasoning_effort}
    show_reasoning = not a.hide_reasoning

    info = server_info(base)
    print(C_INFO + f"server={base}  model={info['model']}  n_ctx={info['n_ctx']}  "
          f"think={'on' if opt['think'] else 'off'}  temp={opt['temperature']}  max={opt['max_tokens']}" + C_RESET)
    session = dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    def new_messages():
        return [{"role": "system", "content": system}] if system else []

    messages = new_messages()
    hist = []

    def ask(user: str, scenario: int = 0, turn: int = 0) -> bool:
        messages.append({"role": "user", "content": user})
        try:
            res = stream_chat(base, messages, opt, show_reasoning)
        except RuntimeError as e:
            print(C_INFO + f"  エラー: {e}" + C_RESET)
            messages.pop()
            return False
        messages.append({"role": "assistant", "content": res["content"]})
        print(stat_line(res))
        hist.append(res)
        if info["n_ctx"] and res["timings"]:
            used = res["timings"].get("prompt_n", 0) + res["timings"].get("cache_n", 0) + res["timings"].get("predicted_n", 0)
            if used > 0.85 * int(info["n_ctx"]):
                print(C_INFO + f"  ! 文脈の {used}/{info['n_ctx']} トークンを使っています。/reset を検討してください" + C_RESET)
        t = res["timings"] or {}
        append_log(a.log, {
            "datetime": dt.datetime.now().isoformat(timespec="seconds"),
            "session": session, "label": a.label, "model": res["model"] or info["model"],
            "build": info["build"], "scenario": scenario, "turn": turn,
            "think": opt["think"], "temperature": opt["temperature"],
            "user": user, "content": res["content"], "reasoning": res["reasoning"],
            "finish_reason": res["finish_reason"], "ttft_s": res["ttft_s"], "wall_s": round(res["wall_s"], 2),
            "prompt_n": t.get("prompt_n"), "cache_n": t.get("cache_n"),
            "prompt_tps": t.get("prompt_per_second"), "predicted_n": t.get("predicted_n"),
            "predicted_tps": t.get("predicted_per_second"),
        })
        return True

    # ---- 台本モード
    if a.script:
        for si, turns in enumerate(load_script(a.script), 1):
            messages[:] = new_messages()
            print(C_INFO + f"\n===== シナリオ {si}（{len(turns)} ターン）" + C_RESET)
            for ti, user in enumerate(turns, 1):
                print(C_USER + "you> " + C_RESET + user)
                if not ask(user, si, ti):
                    break
                print()
        print(C_INFO + "\n===== 集計" + C_RESET)
        print_stats(hist)
        if a.log:
            print(f"  ログ: {a.log}")
        return

    # ---- 対話モード
    print("  /help でコマンド一覧、\"\"\" で複数行入力、Ctrl-C で生成を中断、Ctrl-D で終了")
    last_user = None
    while True:
        try:
            user = read_user()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        s = user.strip()
        if not s:
            continue
        if s.lower() in ("exit", "quit", "bye"):  # / を付け忘れた終了も受け付ける
            break
        if s.startswith("/"):
            cmd, _, arg = s.partition(" ")
            arg = arg.strip()
            if cmd in ("/quit", "/exit", "/q"):
                break
            elif cmd == "/help":
                print(__doc__[__doc__.index("対話中のコマンド"):__doc__.index("台本ファイルの書式")])
            elif cmd == "/reset":
                messages[:] = new_messages()
                print("  履歴を消しました")
            elif cmd == "/system":
                system = arg
                messages[:] = new_messages()
                print(f"  システムプロンプトを変更し、履歴を消しました（{len(system)} 字）")
            elif cmd == "/think" and arg in ("on", "off"):
                opt["think"] = arg == "on"
                print(f"  think={arg}")
            elif cmd == "/show" and arg in ("on", "off"):
                show_reasoning = arg == "on"
                print(f"  推論の表示={arg}")
            elif cmd == "/temp":
                try:
                    opt["temperature"] = float(arg)
                    print(f"  temperature={opt['temperature']}")
                except ValueError:
                    print("  例: /temp 0.2")
            elif cmd == "/max":
                try:
                    opt["max_tokens"] = int(arg)
                    print(f"  max_tokens={opt['max_tokens']}")
                except ValueError:
                    print("  例: /max 4096")
            elif cmd == "/retry":
                if last_user is None or len(messages) < 2 or messages[-1]["role"] != "assistant":
                    print("  やり直す質問がありません")
                    continue
                messages.pop()  # 直前の回答
                messages.pop()  # 直前の質問（ask で入れ直す）
                ask(last_user)
            elif cmd == "/stats":
                print_stats(hist)
            elif cmd == "/save":
                path = arg or f"chat_{session}.json"
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"server": base, "model": info["model"], "label": a.label,
                               "messages": messages}, f, ensure_ascii=False, indent=2)
                print(f"  保存しました: {path}")
            else:
                print("  不明なコマンドです。/help を見てください")
            continue
        last_user = user
        ask(user)
    print_stats(hist)


if __name__ == "__main__":
    main()
