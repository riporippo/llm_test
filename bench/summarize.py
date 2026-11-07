#!/usr/bin/env python3
"""prompt_speed.py の CSV を条件（label）ごとに集計する。標準ライブラリのみ。

使い方:
    python3 summarize.py prompt_speed_12.csv
    python3 summarize.py prompt_speed_results.csv prompt_speed_12.csv --label gemma

出力:
    - サイズごとの中央値（prompt tok/s、prompt_ms、生成 tok/s、wall）
    - run1_extra = 1回目の wall − 2・3回目の wall の中央値
      （llama-server の timings の外でかかった時間。プロンプトキャッシュ保存の疑い）
    - prompt_ms を入力トークン数で直線回帰した結果
      固定の上乗せ(秒) = 切片、実効 tok/s = 1 / 傾き
      （固定の上乗せが数秒あれば、コンテキストチェックポイントの疑い）
"""
import argparse
import collections
import csv
import statistics as st


def linfit(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None, None
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return slope, my - slope * mx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--label", help="この文字列を含む label だけ表示")
    a = ap.parse_args()

    groups = collections.OrderedDict()
    for path in a.csv:
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if a.label and a.label not in r["label"]:
                    continue
                groups.setdefault(r["label"], collections.OrderedDict()) \
                      .setdefault(int(r["normal_lines"]), []).append(r)

    for label, sizes in groups.items():
        print(f"\n=== {label} ===")
        print(f"{'lines':>5} {'prompt_n':>8} {'prompt_tps':>10} {'prompt_ms':>9} "
              f"{'gen_tps':>7} {'wall':>6} {'run1_extra':>10} {'cache_n':>7}")
        xs, ys = [], []
        for lines, rs in sorted(sizes.items()):
            rs.sort(key=lambda r: int(r["run"]))
            med = lambda c: st.median(float(r[c]) for r in rs)
            later = [float(r["wall_s"]) for r in rs[1:]] or [float(rs[0]["wall_s"])]
            extra = float(rs[0]["wall_s"]) - st.median(later)
            cache = max(int(r["cache_n"]) for r in rs)
            pn = int(rs[0]["prompt_n"])
            print(f"{lines:>5} {pn:>8} {med('prompt_tps'):>10.1f} {med('prompt_ms'):>9.0f} "
                  f"{med('predicted_tps'):>7.2f} {med('wall_s'):>6.2f} {extra:>10.2f} {cache:>7}")
            for r in rs:
                xs.append(int(r["prompt_n"]))
                ys.append(float(r["prompt_ms"]))
        slope, icpt = linfit(xs, ys)
        if slope:
            print(f"  直線回帰: prompt_ms = {icpt/1000:.2f} 秒 + 入力トークン ÷ {1000/slope:.0f} tok/s"
                  f"  （固定の上乗せ {icpt/1000:.2f} 秒）")


if __name__ == "__main__":
    main()
