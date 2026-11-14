#!/usr/bin/env python3
"""
audit_bench_results.csv を、モデルごとの一覧（精度と速度）にまとめる。標準ライブラリのみ。

使い方:
  python3 report.py                          # 画面に表を出す
  python3 report.py --md > 結果.md           # Markdown の表で出す

label の先頭で段階を見分ける（run_all.py が付ける名前）。
  quiz-<名前>       精度（--quiz）
  research1-<名前>  1人での速度
  research2-<名前>  4人同時での速度
"""
import argparse
import collections
import csv
import statistics as st

PREFIXES = ("quiz-", "research1-", "research2-")


def med(xs):
    return st.median(xs) if xs else None


def fmt(x, digits=1, unit=""):
    return "―" if x is None else f"{x:.{digits}f}{unit}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default="audit_bench_results.csv")
    ap.add_argument("--md", action="store_true", help="Markdown の表で出す")
    ap.add_argument("--min-tps", type=float, default=10.0,
                    help="速度の合格基準：4人同時での1人あたりの生成の最小値（tok/s）")
    a = ap.parse_args()

    by = collections.OrderedDict()  # 名前 → 段階 → 行
    with open(a.csv, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for p in PREFIXES:
                if r["label"].startswith(p):
                    name = r["label"][len(p):]
                    # 調査1の手入力の label（research1-qwen3.6b など）も、そのままの名前で載せる
                    # 同じ条件（ログ・回・何本目）を測り直した行は、新しいほうで置き換える
                    key = (r["log"], r["run"], r.get("slot", ""))
                    by.setdefault(name, {}).setdefault(p, collections.OrderedDict())[key] = r
    for ph in by.values():
        for p in list(ph):
            ph[p] = list(ph[p].values())

    head = ["モデル", "精度", "正答率", "JSON", "1人 生成", "4人 生成（1人あたり）", "4人 最小", "4人 全員完了", "速度の合否"]
    rows = []
    for name, ph in by.items():
        q = [r for r in ph.get("quiz-", []) if r.get("score") not in ("", None)]
        s1 = ph.get("research1-", [])
        s4 = [r for r in ph.get("research2-", []) if r.get("parallel") not in ("", "1", None)]
        score = sum(int(r["score"]) for r in q)
        smax = sum(int(r["score_max"]) for r in q)
        g4 = [float(r["predicted_tps"]) for r in s4]
        rows.append([
            name,
            f"{score}/{smax}" if q else "―",
            fmt(100 * score / smax, 1, "%") if smax else "―",
            f"{sum(1 for r in q if r.get('json_ok') == 'True')}/{len(q)}" if q else "―",
            fmt(med([float(r["predicted_tps"]) for r in s1]), 1, " tok/s"),
            fmt(med(g4), 1, " tok/s"),
            fmt(min(g4) if g4 else None, 1, " tok/s"),
            fmt(med([float(r["wall_s"]) for r in s4]), 0, " 秒"),
            # 合格基準：4人同時のとき、1人あたりの生成の最小値が MIN_TPS 以上
            "―" if not g4 else ("○" if min(g4) >= a.min_tps else "×"),
        ])
    if not rows:
        print("quiz- / research1- / research2- で始まる label の行がありません")
        return
    if a.md:
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for r in rows:
            print("| " + " | ".join(r) + " |")
    else:
        for r in [head] + rows:
            print("  ".join(f"{c:<22s}" if i == 0 else f"{c:>14s}" for i, c in enumerate(r)))

    # 精度の項目ごとの内訳（どこで間違えたか）
    import json
    print("\n項目ごとの正答数" + ("（精度）" if not a.md else ""))
    for name, ph in by.items():
        items = collections.OrderedDict()
        for r in ph.get("quiz-", []):
            if r.get("score") in ("", None):
                continue
            for k, v in json.loads(r["check"]).items():
                items.setdefault(k, []).append(bool(v))
        wrong = [f"{k} {sum(v)}/{len(v)}" for k, v in items.items() if sum(v) < len(v)]
        if items:
            print(f"- {name}: " + ("全問正解" if not wrong else "、".join(wrong)))


if __name__ == "__main__":
    main()
