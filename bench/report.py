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
import json
import re
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
    ap.add_argument("--min-acc", type=float, default=85.0,
                    help="精度の合格基準：正答率（%%）。あわせて誤検知ゼロを求める")
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

    head = ["モデル", "精度", "正答率", "誤検知", "打ち切り", "1人 生成", "4人 生成（1人あたり）", "4人 最小", "4人 全員完了",
            "速度", "精度の合否", "総合"]
    rows = []
    for name, ph in by.items():
        q = [r for r in ph.get("quiz-", []) if r.get("score") not in ("", None)]
        s1 = ph.get("research1-", [])
        s4 = [r for r in ph.get("research2-", []) if r.get("parallel") not in ("", "1", None)]
        score = sum(int(r["score"]) for r in q)
        smax = sum(int(r["score_max"]) for r in q)
        g4 = [float(r["predicted_tps"]) for r in s4]
        # 誤検知：侵害なしのログで「侵害あり」と判定した数（check の「侵害なしと判定」が False で、JSON の compromised が true）
        fp = 0
        for r in q:
            if "clean" in r["log"]:
                c = json.loads(r["check"])
                if not c.get("侵害なしと判定", True) and re.search(r'"compromised"\s*:\s*true', r["content"]):
                    fp += 1
        # 打ち切り：生成が上限で切れた回（推論で上限を使い切ると回答が空になり、点が不当に低くなる）
        cut = sum(1 for r in q if r.get("finish_reason") == "length")
        # 1人での生成速度：調査1がなければ、精度の測定（1人で実施）の値を使う（* 付き）
        g1 = [float(r["predicted_tps"]) for r in s1]
        g1_note = ""
        if not g1:
            g1 = [float(r["predicted_tps"]) for r in q if int(r.get("predicted_n") or 0) > 50]
            g1_note = "*"
        acc = 100 * score / smax if smax else None
        speed_ok = None if not g4 else min(g4) >= a.min_tps
        if not q:
            acc_ok = None
        elif cut:
            acc_ok = "要再測定"
        else:
            acc_ok = acc >= a.min_acc and fp == 0
        mark = lambda v: "―" if v is None else (v if isinstance(v, str) else ("○" if v else "×"))
        overall = ("○" if speed_ok and acc_ok is True else
                   "―" if speed_ok is None or acc_ok is None or acc_ok == "要再測定" else "×")
        rows.append([
            name,
            f"{score}/{smax}" if q else "―",
            fmt(acc, 1, "%") if smax else "―",
            str(fp) if q else "―",
            f"{cut}/{len(q)}" if q else "―",
            fmt(med(g1), 1, " tok/s") + g1_note,
            fmt(med(g4), 1, " tok/s"),
            fmt(min(g4) if g4 else None, 1, " tok/s"),
            fmt(med([float(r["wall_s"]) for r in s4]), 0, " 秒"),
            mark(speed_ok), mark(acc_ok), overall,
        ])
    if not rows:
        print("quiz- / research1- / research2- で始まる label の行がありません")
        compare_report(a.csv, a.md, a.min_tps)
        agent_report("agent_bench_results.csv", a.md, a.min_tps)
        return
    if a.md:
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for r in rows:
            print("| " + " | ".join(r) + " |")
    else:
        for r in [head] + rows:
            print("  ".join(f"{c:<22s}" if i == 0 else f"{c:>14s}" for i, c in enumerate(r)))

    print("\n基準：速度＝4人同時の1人あたりの生成の最小値が {:.0f} tok/s 以上。精度＝正答率 {:.0f}% 以上かつ誤検知 0。"
          "誤検知＝侵害なしのログで「侵害あり」と判定した数。打ち切り＝生成が上限で切れた回（あれば精度は要再測定）。"
          "1人 生成の * は精度の測定（1人）の値".format(a.min_tps, a.min_acc))
    # 精度の項目ごとの内訳（どこで間違えたか）
    compare_report(a.csv, a.md, a.min_tps)
    agent_report("agent_bench_results.csv", a.md, a.min_tps)
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


def compare_report(path, md, min_tps):
    """label が cmp- で始まる測定（構成・エンジンの比較）を並べる"""
    by = collections.OrderedDict()
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["label"].startswith("cmp-"):
                by.setdefault(r["label"], collections.OrderedDict())[(r["log"], r["run"], r.get("slot", ""))] = r
    if not by:
        return
    head = ["label", "件数", "計り方", "最初の出力まで（中央値）", "生成 中央値", "生成 最小", "全員完了（中央値）", "全体の生成量", "速度の合否"]
    rows = []
    for label, d in by.items():
        rs = list(d.values())
        g = [float(r["predicted_tps"]) for r in rs if float(r["predicted_tps"] or 0) > 0]
        # 全体の生成量：同時に投げた1セットの生成トークン数の合計 ÷ そのセットの全員完了時間（セットごとの中央値）
        sets = collections.defaultdict(list)
        for r in rs:
            sets[(r["log"], r["run"])].append(r)
        thr = [sum(int(x["predicted_n"]) for x in v) / float(v[0]["wall_s"]) for v in sets.values() if float(v[0].get("wall_s") or 0) > 0]
        rows.append([
            label, str(len(rs)), rs[0].get("timing") or "server",
            fmt(med([float(r["prompt_ms"]) / 1000 for r in rs]), 1, " 秒"),
            fmt(med(g), 1, " tok/s"), fmt(min(g) if g else None, 1, " tok/s"),
            fmt(med([float(r["wall_s"]) for r in rs if r.get("wall_s")]), 0, " 秒"),
            fmt(med(thr), 1, " tok/s"),
            ("○" if g and min(g) >= min_tps else "×"),
        ])
    print("\n構成・エンジンの比較（label が cmp- で始まるもの）")
    if md:
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for r in rows:
            print("| " + " | ".join(r) + " |")
    else:
        for r in [head] + rows:
            print("  ".join(f"{c:<40s}" if i == 0 else f"{c:>12s}" for i, c in enumerate(r)))
    print("最初の出力まで：要求を送ってから最初のトークンが届くまで（入力処理と順番待ちを含む）．"
          "全体の生成量：同時に投げた1セットの生成トークン数の合計を，全員が終わるまでの時間で割った値")


def agent_report(path, md, min_tps):
    """agent_bench_results.csv（エージェントの測定）をモデルごとにまとめる"""
    import os
    if not os.path.exists(path):
        return
    by = collections.OrderedDict()
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            by.setdefault(r["label"], collections.OrderedDict())[(r["log"], r["run"])] = r  # 測り直しは新しいほうで置き換え
    head = ["label", "精度", "正答率", "提出できた", "道具/問", "形式の誤り", "1問の時間", "生成 中央値", "生成 最小", "速度の合否"]
    rows = []
    for label, d in by.items():
        rs = list(d.values())
        sc, mx = sum(int(r["score"]) for r in rs), sum(int(r["score_max"]) for r in rs)
        calls = sum(int(r["tool_calls"]) for r in rs)
        bad = sum(int(r["bad_calls"]) for r in rs)
        tps = [float(r["gen_tps"]) for r in rs if float(r["gen_tps"] or 0) > 0]
        rows.append([
            label, f"{sc}/{mx}", fmt(100 * sc / mx, 1, "%") if mx else "―",
            f"{sum(1 for r in rs if r['outcome'] == 'submitted')}/{len(rs)}",
            fmt(calls / len(rs), 1), fmt(100 * bad / calls, 1, "%") if calls else "―",
            fmt(med([float(r["wall_s"]) for r in rs]), 0, " 秒"),
            fmt(med(tps), 1, " tok/s"), fmt(min(tps) if tps else None, 1, " tok/s"),
            ("○" if tps and min(tps) >= min_tps else "×") if label.startswith(("agent4-", "cmp-")) or "agent4" in label else "―",
        ])
    print("\nエージェント（agent_bench_results.csv）")
    if md:
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for r in rows:
            print("| " + " | ".join(r) + " |")
    else:
        for r in [head] + rows:
            print("  ".join(f"{c:<30s}" if i == 0 else f"{c:>12s}" for i, c in enumerate(r)))


if __name__ == "__main__":
    main()
