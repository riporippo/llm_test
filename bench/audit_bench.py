import argparse
import concurrent.futures
import csv
import datetime
import json
import os
import re
import statistics
import sys

import requests

BASE_URL = "http://127.0.0.1:8080/"  # llama-server は http（https にすると SSL エラーで繋がらない）
MAX_TOKENS = 1024  # 1回の生成の上限（--max-tokens で変更）
TEMPERATURE = 0.7  # 要約モードの既定。採点モード（--quiz）では 0 にする
THINK = False  # 推論（thinking）を使うか（--think）
TIMEOUT = 1800  # 秒。大きいモデルで長い入力を処理すると時間がかかる


def health_check():
	try:
		res = requests.get(BASE_URL + "health", timeout=10)
	except requests.exceptions.RequestException as e:
		print(f"接続できません: {e}")
		return False
	if res.status_code == 200:
		return True
	else:
		# 503 はモデルの読み込み中
		print(f"Health: {res.status_code} - {res.text}")
		return False


# ---------------------------------------------------------------- 採点モード（--quiz）
QUIZ_SYSTEM = (
	"あなたは情報セキュリティのインシデント対応を支援するアナリストです。"
	"与えられた auditd のログだけを根拠に、日本語で回答してください。"
	"ログに書かれていないことを推測で補わないでください。"
)

# 自動で採点するために、回答の最後に決まった形の JSON を書かせる
QUIZ_JSON_INSTRUCTION = """
回答の最後に、結論を次の形式の JSON で、```json のコードブロックに入れて出力してください。
該当するものがない項目は null（一覧は空の []）にしてください。
```json
{
  "compromised": true または false,
  "attacker_ip": "攻撃元の IP アドレス",
  "account": "侵入に使われたアカウント名",
  "login_time": "侵入に成功した時刻（日本時間、YYYY-MM-DD HH:MM:SS）",
  "c2_ip": "攻撃者が接続しようとした外部の IP アドレス",
  "c2_port": ポート番号（数値）,
  "actions": ["侵入後の操作を時系列で。コマンドやファイルのパスを含める"],
  "persistence": ["再侵入のために仕掛けられたもの。利用者名やファイルのパスを含める"]
}
```
"""

JST = datetime.timezone(datetime.timedelta(hours=9))


def load_question(log_path):
	"""gen_audit_log.py が audit.log と同じ場所に出す question.txt を読む"""
	path = os.path.join(os.path.dirname(os.path.abspath(log_path)), "question.txt")
	with open(path, encoding="utf-8") as f:
		lines = f.read().splitlines()
	# 侵害なしの対照用ログには、1行目に人向けの注記（正解）が入っているので除く
	lines = [l for l in lines if not l.startswith("（このファイルは侵害を含まない対照用")]
	return "\n".join(lines)


def extract_json(content):
	"""回答から最後の JSON を取り出す（取り出せなければ None）"""
	blocks = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.S)
	if not blocks:
		i, j = content.find("{"), content.rfind("}")
		blocks = [content[i:j + 1]] if 0 <= i < j else []
	for block in reversed(blocks):
		try:
			obj = json.loads(block)
			if isinstance(obj, dict):
				return obj
		except json.JSONDecodeError:
			continue
	return None


def is_empty(value):
	"""「該当なし」とみなす値か"""
	if value is None or value == [] or value == {}:
		return True
	return str(value).strip().lower() in ("", "null", "none", "n/a", "na", "-", "不明", "なし", "該当なし", "無し")


def time_matches(text, epoch, tolerance=60):
	"""text の中に、正解の時刻（JST）から tolerance 秒以内の時刻が書かれているか"""
	truth = datetime.datetime.fromtimestamp(epoch, JST)
	for m in re.finditer(r"(?:(\d{4})[-/年](\d{1,2})[-/月](\d{1,2})日?[ T]?)?(\d{1,2}):(\d{2}):(\d{2})", str(text)):
		y, mo, d, h, mi, sec = m.groups()
		try:
			if y:
				t = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), tzinfo=JST)
			else:  # 日付がなければ、正解と同じ日として比べる
				t = truth.replace(hour=int(h), minute=int(mi), second=int(sec), microsecond=0)
		except ValueError:
			continue
		if abs((t - truth).total_seconds()) <= tolerance:
			return True
	return False


def score_answer(content, answer):
	"""回答を answer.json と照らして採点する。戻り値は (点, 満点, 項目ごとの正誤, JSON を取り出せたか)"""
	obj = extract_json(content)
	json_ok = obj is not None
	if obj is None:
		obj = {}
	low = content.lower()

	if not answer.get("compromised"):
		# 侵害なしの対照用ログ：侵害ありと答えたり、攻撃元や仕掛けを挙げたりしたら減点
		detail = {
			"侵害なしと判定": obj.get("compromised") is False,
			"攻撃元を挙げていない": json_ok and is_empty(obj.get("attacker_ip")),
			"仕掛けを挙げていない": json_ok and is_empty(obj.get("persistence")),
		}
		return sum(detail.values()), len(detail), detail, json_ok

	def field(name):
		return str(obj.get(name) or "").strip()

	# 操作と仕掛けは、JSON の一覧に書かれた文字列から探す（JSON がなければ回答の全文から探す）
	listed = (json.dumps([obj.get("actions"), obj.get("persistence")], ensure_ascii=False).lower()
		if json_ok else low)
	user = answer.get("backdoor_user", "sysupd").lower()
	script = answer.get("script", "upd.sh").lower()
	c2 = answer["c2"]
	detail = {
		"侵害ありと判定": obj.get("compromised") is True,
		"攻撃元 IP": field("attacker_ip") == answer["attacker_ip"] if json_ok else answer["attacker_ip"] in content,
		"アカウント": field("account") == answer["account"] if json_ok else answer["account"] in content,
		"侵入時刻（±60秒）": time_matches(field("login_time") if json_ok else content, answer["login_success"]["epoch"]),
		"接続先 IP": field("c2_ip") == c2["ip"] if json_ok else c2["ip"] in content,
		"接続先ポート": field("c2_port").split(".")[0] == str(c2["port"]) if json_ok else str(c2["port"]) in content,
		"スクリプトの取得・実行": script in listed,
		"UID 0 の利用者の追加": user in listed,
		"cron の仕掛け": "cron" in listed,
		"SSH 鍵の仕掛け": "authorized_keys" in listed,
		"痕跡の消去": "bash_history" in listed or "履歴" in listed,
	}
	return sum(detail.values()), len(detail), detail, json_ok


def chat(model_name, prompt, question=None):
	url = f"{BASE_URL}v1/chat/completions"
	headers = {"Content-Type": "application/json"}
	if question is None:
		# 要約モード（速度の測定用）
		messages = [
			{
				"role": "system",
				"content": "you are log analyser. you will be given a auditd log and you will analyse it and give a summary of the log in a few sentences."
			},
			{
				"role": "user",
				"content": "This is the auditd log: " + prompt
			}
		]
	else:
		# 採点モード：ログのあとに設問と、JSON で結論を書く指示を付ける
		messages = [
			{"role": "system", "content": QUIZ_SYSTEM},
			{"role": "user", "content": "```\n" + prompt + "\n```\n\n" + question + QUIZ_JSON_INSTRUCTION},
		]
	data = {
		"model": model_name,
		"messages": messages,
		"temperature": TEMPERATURE,
		"stream": False,
		"max_tokens": MAX_TOKENS,
		"cache_prompt": False,  # 毎回入力を処理し直す（2回目以降だけ速く見えるのを防ぐ）
		"chat_template_kwargs": {"enable_thinking": THINK},  # Qwen 系の思考オン・オフ（対応しないモデルでは無視される）
	}
	try:
		res = requests.post(url, headers=headers, json=data, timeout=TIMEOUT)
	except requests.exceptions.RequestException as e:
		print(f"Error: {e}")
		return None, None, None, None, None, None, None, None, None
	if res.status_code == 200:
		body = res.json()
		message = body["choices"][0]["message"]
		content = message.get("content") or ""
		# finish_reason: stop なら最後まで書けた。length は上限で打ち切られた
		# reasoning_chars: 推論（thinking）の文字数。回答が空でこれが大きければ、推論だけで上限を使い切っている
		finish_reason = body["choices"][0].get("finish_reason")
		reasoning_chars = len(message.get("reasoning_content") or "")
		# prompt_n: 入力プロンプトのトークン数
		# prompt_ms: 入力プロンプトの読み込み時間
		# prompt_per_token_ms: 1トークン当たりの入力プロンプトの読み込み時間
		# predicted_n: 出力のトークン数
		# predicted_ms: 出力の生成時間
		# predicted_per_token_ms: 1トークン当たりの出力の生成時間
		t = body["timings"]
		prompt_n = t["prompt_n"]
		prompt_ms = t["prompt_ms"]
		prompt_per_token_ms = t["prompt_per_token_ms"]
		predicted_n = t["predicted_n"]
		predicted_ms = t["predicted_ms"]
		predicted_per_token_ms = t["predicted_per_token_ms"]
		return content, prompt_n, prompt_ms, prompt_per_token_ms, predicted_n, predicted_ms, predicted_per_token_ms, finish_reason, reasoning_chars
	else:
		print(f"Error: {res.status_code} - {res.text}")
		return None, None, None, None, None, None, None, None, None


def get_model_name():
	"""llama-server が読み込んでいるモデル名を取る（記録用）"""
	try:
		res = requests.get(BASE_URL + "v1/models", timeout=10)
		return res.json()["data"][0]["id"]
	except Exception:
		return "unknown"


def get_n_ctx():
	"""llama-server の文脈長（全スロットの合計）。取れなければ None"""
	try:
		props = requests.get(BASE_URL + "props", timeout=10).json()
		slots = props.get("total_slots") or 1
		n = props.get("default_generation_settings", {}).get("n_ctx") or props.get("n_ctx")
		return int(n) * int(slots) if n else None  # /props の n_ctx は1スロットあたり
	except Exception:
		return None


def count_tokens(text):
	"""llama-server の /tokenize でトークン数を数える。取れなければ None"""
	try:
		res = requests.post(BASE_URL + "tokenize", json={"content": text}, timeout=60)
		return len(res.json()["tokens"])
	except Exception:
		return None


def load_answer(log_path):
	"""gen_audit_log.py が audit.log と同じ場所に出す answer.json を読む（なければ None）"""
	path = os.path.join(os.path.dirname(os.path.abspath(log_path)), "answer.json")
	if not os.path.exists(path):
		return None
	with open(path, encoding="utf-8") as f:
		return json.load(f)


def check_answer(content, answer):
	"""回答に正解のキーワードが入っているかを簡単に確かめる（中身の正しさは人が読んで判断する）"""
	if answer is None:
		return {}
	if not answer.get("compromised"):
		# 侵害なしの対照用ログ：攻撃者の IP などを挙げていたら、でっち上げの疑い
		return {"no_false_alarm": "203.0.113.45" not in content and "198.51.100.23" not in content}
	return {
		"attacker_ip": answer["attacker_ip"] in content,
		"account": answer["account"] in content,
		"c2_ip": answer["c2"]["ip"] in content,
		"sysupd": "sysupd" in content,
	}


def save_csv(path, rows):
	"""CSV に追記する。列が増えた場合は、既存の行も新しい列に合わせて書き直す"""
	fields = list(rows[0].keys())
	old = []
	if os.path.exists(path):
		with open(path, newline="", encoding="utf-8") as f:
			reader = csv.DictReader(f)
			old = list(reader)
			for name in reader.fieldnames or []:
				if name not in fields:
					fields.append(name)
	with open(path, "w", newline="", encoding="utf-8") as f:
		w = csv.DictWriter(f, fieldnames=fields, restval="")
		w.writeheader()
		w.writerows(old + rows)


def main():
	global BASE_URL, MAX_TOKENS, TEMPERATURE, THINK
	parser = argparse.ArgumentParser(description="auditd ログの分析で、速さ（要約モード）と精度（--quiz）を測る")
	parser.add_argument("log", nargs="+", help="分析させる audit.log（gen_audit_log.py の出力など）。複数指定できる")
	parser.add_argument("--quiz", action="store_true",
		help="採点モード：question.txt の設問に答えさせ、answer.json と照らして採点する")
	parser.add_argument("--think", action="store_true", help="推論（thinking）を有効にする")
	parser.add_argument("--temperature", type=float, help="既定は要約モード 0.7、採点モード 0")
	parser.add_argument("--runs", type=int, default=3, help="測定回数（このほかにウォームアップ1回）")
	parser.add_argument("--label", default="", help="記録用の名前（例: 調査1-gpt-oss-120b）")
	parser.add_argument("--url", default=BASE_URL)
	parser.add_argument("--csv", default="audit_bench_results.csv")
	parser.add_argument("--parallel", type=int, default=1,
		help="同時に投げる本数（調査2は 4）。llama-server 側も -np をこの数に、-c を 1本分×本数にする")
	parser.add_argument("--max-tokens", type=int, help="1回の生成の上限（既定は要約モード 1024、採点モード 2048）")
	args = parser.parse_args()
	BASE_URL = args.url.rstrip("/") + "/"
	MAX_TOKENS = args.max_tokens or (2048 if args.quiz else MAX_TOKENS)
	TEMPERATURE = args.temperature if args.temperature is not None else (0.0 if args.quiz else TEMPERATURE)
	THINK = args.think

	print("Starting benchmark...")
	print("Health Check")
	if health_check():
		print("Health check passed")
	else:
		print("Health check failed")
		sys.exit(1)

	model_name = get_model_name()
	n_ctx = get_n_ctx()
	print(f"model: {model_name}  n_ctx: {n_ctx}  mode: {'quiz' if args.quiz else 'summary'}"
		f"  temperature: {TEMPERATURE}  think: {THINK}  max_tokens: {MAX_TOKENS}")

	# ウォームアップ（1回目は GPU の準備などで遅くなりやすいので捨てる）
	print("warm-up ...")
	chat(model_name, "type=DAEMON_START msg=audit(0.000:1): op=start res=success")

	rows = []
	for log_path in args.log:
		with open(log_path, encoding="utf-8") as f:
			log_text = f.read()
		answer = load_answer(log_path)
		question = None
		if args.quiz:
			if answer is None:
				print(f"{log_path}: answer.json がないので採点できません")
				sys.exit(1)
			question = load_question(log_path)
		print(f"\nlog: {log_path}（{len(log_text.splitlines())} 行、{len(log_text):,} 文字）")
		# 文脈に収まるかを先に確かめる（収まらないと回答が途中で切れ、採点が不当に低くなる）
		n_in = count_tokens(log_text + (question or "") + (QUIZ_JSON_INSTRUCTION if args.quiz else ""))
		if n_ctx and n_in and n_in + MAX_TOKENS > n_ctx / max(1, args.parallel):
			print(f"  ! 入力 約{n_in} + 生成上限 {MAX_TOKENS} トークンが、1本あたりの文脈（{n_ctx // max(1, args.parallel)}）を超えます。"
				"llama-server の -c を大きくするか、ログを短くしてください")

		for i in range(args.runs):
			# --parallel 本を同時に投げる（1 なら従来どおり1本ずつ）
			t_start = datetime.datetime.now()
			with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as ex:
				results = list(ex.map(lambda _: chat(model_name, log_text, question), range(args.parallel)))
			wall_s = (datetime.datetime.now() - t_start).total_seconds()
			ok_tokens = 0
			for slot, result in enumerate(results, 1):
				content, prompt_n, prompt_ms, prompt_per_token_ms, predicted_n, predicted_ms, predicted_per_token_ms, finish_reason, reasoning_chars = result
				name = f"run{i + 1}" if args.parallel == 1 else f"run{i + 1}-{slot}"
				if content is None:
					print(f"{name}: 失敗")
					continue
				# 1トークンあたりのミリ秒から、1秒あたりのトークン数（tok/s）にする
				prompt_tps = 1000 / prompt_per_token_ms if prompt_per_token_ms else 0
				predicted_tps = 1000 / predicted_per_token_ms if predicted_per_token_ms else 0
				total_s = (prompt_ms + predicted_ms) / 1000
				ok_tokens += predicted_n
				score = score_max = json_ok = ""
				if args.quiz:
					score, score_max, check, json_ok = score_answer(content, answer)
					wrong = [k for k, v in check.items() if not v]
					shown = f"{score}/{score_max} 点" + (f"  ×: {'、'.join(wrong)}" if wrong else "") + ("" if json_ok else "  （JSON なし）")
				else:
					check = check_answer(content, answer)
					shown = str(check)
				print(f"{name}: 入力 {prompt_n} tok {prompt_tps:7.1f} tok/s | 生成 {predicted_n} tok {predicted_tps:5.1f} tok/s"
					f" | 計 {total_s:6.1f} s | {finish_reason} | {shown}")
				if not content.strip():
					print(f"  ! 回答が空です（finish_reason={finish_reason}、推論 {reasoning_chars} 字）。"
						"推論だけで上限を使い切った可能性があります。--max-tokens を増やすか、推論を切ってください")
				elif args.quiz and finish_reason == "length":
					print("  ! 生成が上限で打ち切られています。--max-tokens を増やしてください")
				rows.append({
					"datetime": datetime.datetime.now().isoformat(timespec="seconds"),
					"label": args.label,
					"model": model_name,
					"log": log_path,
					"run": i + 1,
					"prompt_n": prompt_n,
					"prompt_ms": round(prompt_ms, 1),
					"prompt_tps": round(prompt_tps, 2),
					"predicted_n": predicted_n,
					"predicted_ms": round(predicted_ms, 1),
					"predicted_tps": round(predicted_tps, 2),
					"total_s": round(total_s, 2),
					"check": json.dumps(check, ensure_ascii=False),
					"content": content,
					"parallel": args.parallel,
					"slot": slot,
					"wall_s": round(wall_s, 2),  # 同時に投げた全員が終わるまでの時間（待ち時間を含む）
					"finish_reason": finish_reason,
					"reasoning_chars": reasoning_chars,
					"mode": "quiz" if args.quiz else "summary",
					"think": THINK,
					"temperature": TEMPERATURE,
					"score": score,
					"score_max": score_max,
					"json_ok": json_ok,
				})
			if args.parallel > 1 and ok_tokens:
				print(f"  → 全員が終わるまで {wall_s:.1f} s、全体の生成量 {ok_tokens / wall_s:.1f} tok/s（入力処理の時間を含む）")

	if not rows:
		print("成功した測定がありません")
		sys.exit(1)

	print("\n===== 結果（中央値）")
	print(f"入力処理: {statistics.median(r['prompt_tps'] for r in rows):.1f} tok/s")
	print(f"生成:     {statistics.median(r['predicted_tps'] for r in rows):.1f} tok/s（1人あたり。最小 {min(r['predicted_tps'] for r in rows):.1f}）")
	print(f"1回の時間: {statistics.median(r['total_s'] for r in rows):.1f} s")
	if args.parallel > 1:
		print(f"{args.parallel} 人全員が終わるまで: {statistics.median(r['wall_s'] for r in rows):.1f} s")

	if args.quiz:
		print("\n===== 精度")
		for log_path in args.log:
			rs = [r for r in rows if r["log"] == log_path]
			if rs:
				print(f"{log_path}: {sum(r['score'] for r in rs)}/{sum(r['score_max'] for r in rs)} 点（{len(rs)} 回）")
		total, total_max = sum(r["score"] for r in rows), sum(r["score_max"] for r in rows)
		print(f"合計: {total}/{total_max} 点（{100 * total / total_max:.1f}%）  JSON を出力できた回: {sum(1 for r in rows if r['json_ok'])}/{len(rows)}")
		# 項目ごとの正答率（どこで間違えやすいか）
		items = {}
		for r in rows:
			for k, v in json.loads(r["check"]).items():
				items.setdefault(k, []).append(v)
		for k, v in items.items():
			print(f"  {k}: {sum(v)}/{len(v)}")
	else:
		print("\n----- 回答（最後の回）")
		print(rows[-1]["content"])

	save_csv(args.csv, rows)
	print(f"\nsaved: {args.csv}（{len(rows)} 行追記）")


if "__main__" == __name__:
	main()
