#!/usr/bin/env python3
"""
文字列を QR コードに変換する

使い方:
  python3 qr.py "http://10.20.0.5:8080"                 # 端末に QR コードを表示
  python3 qr.py "http://10.20.0.5:8080" -o server.png   # PNG で保存（Pillow が必要）
  python3 qr.py "こんにちは" -o hello.svg                # SVG で保存（Pillow 不要）
  echo "標準入力から" | python3 qr.py -o out.png         # 引数を省くと標準入力を読む
  python3 qr.py "URL" -o big.png --box 20 --ec H        # 大きく・誤り訂正を強く

必要なもの:
  pip install qrcode            # 端末表示と SVG だけなら、これだけでよい
  pip install "qrcode[pil]"     # PNG / JPG などの画像も出す場合

誤り訂正レベル（--ec）:
  L 約7% / M 約15%（既定） / Q 約25% / H 約30% の欠けまで読める。
  強くするほど QR コードが細かく（大きく）なる。

日本語などの非 ASCII 文字は UTF-8 で格納する（一般的なスマホのカメラで読める）。
"""
import argparse
import os
import sys

try:
    import qrcode
    import qrcode.constants
except ImportError:
    sys.exit("qrcode が入っていません: pip install qrcode （PNG も出すなら pip install \"qrcode[pil]\"）")

EC = {
    "L": qrcode.constants.ERROR_CORRECT_L,
    "M": qrcode.constants.ERROR_CORRECT_M,
    "Q": qrcode.constants.ERROR_CORRECT_Q,
    "H": qrcode.constants.ERROR_CORRECT_H,
}


def make_qr(text: str, ec: str = "M", box: int = 10, border: int = 4) -> "qrcode.QRCode":
    qr = qrcode.QRCode(version=None, error_correction=EC[ec], box_size=box, border=border)
    qr.add_data(text.encode("utf-8"))  # 日本語も確実に UTF-8 のバイト列として入れる
    qr.make(fit=True)                  # 内容に合わせて最小のバージョン（大きさ）を選ぶ
    return qr


def save(qr: "qrcode.QRCode", path: str, fg: str, bg: str) -> None:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".svg":
        import qrcode.image.svg
        img = qr.make_image(image_factory=qrcode.image.svg.SvgPathFillImage)
        img.save(path)
        return
    try:
        img = qr.make_image(fill_color=fg, back_color=bg)
    except ImportError:
        sys.exit("PNG などの画像には Pillow が必要です: pip install \"qrcode[pil]\"（SVG なら不要）")
    if ext in (".jpg", ".jpeg"):
        img = img.convert("RGB")
    img.save(path)


def main() -> None:
    ap = argparse.ArgumentParser(description="文字列を QR コードに変換する")
    ap.add_argument("text", nargs="?", help="QR コードにする文字列（省略時は標準入力）")
    ap.add_argument("-o", "--output", help="保存先（.png / .jpg / .svg など）。省略時は端末に表示")
    ap.add_argument("--ec", choices=list(EC), default="M", help="誤り訂正レベル（既定 M）")
    ap.add_argument("--box", type=int, default=10, help="1マスのピクセル数（画像のとき。既定 10）")
    ap.add_argument("--border", type=int, default=4, help="周りの余白のマス数（既定 4。4 未満は読みにくくなる）")
    ap.add_argument("--fg", default="black", help="前景色（PNG のとき）")
    ap.add_argument("--bg", default="white", help="背景色（PNG のとき）")
    ap.add_argument("--show", action="store_true", help="保存するときも端末に表示する")
    a = ap.parse_args()

    text = a.text if a.text is not None else sys.stdin.read().rstrip("\n")
    if not text:
        sys.exit("文字列が空です")

    try:
        qr = make_qr(text, a.ec, a.box, a.border)
    except (qrcode.exceptions.DataOverflowError, ValueError):  # 版によって最大サイズ超えは ValueError になる
        sys.exit(f"文字列が長すぎて QR コードに入りません（{len(text.encode('utf-8'))} バイト）。--ec L にすると少し増やせます")

    n = qr.modules_count
    print(f"バージョン {qr.version}（{n}×{n} マス）、誤り訂正 {a.ec}、{len(text.encode('utf-8'))} バイト", file=sys.stderr)

    if a.output:
        save(qr, a.output, a.fg, a.bg)
        print(f"保存しました: {a.output}", file=sys.stderr)
    if not a.output or a.show:
        # 端末表示：上下2マスを1文字（▀▄█）にまとめる。黒地の端末でも読めるよう invert=True
        qr.print_ascii(out=sys.stdout, invert=True)


if __name__ == "__main__":
    main()
