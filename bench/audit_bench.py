import argparse
import csv
import datetime
import json
import os
import statistics
import sys

import requests

BASE_URL = "http://127.0.0.1:8080/"  # llama-server は http（https にすると SSL エラーで繋がらない）
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


def chat(model_name, prompt):
	url = f"{BASE_URL}v1/chat/completions"
	headers = {"Content-Type": "application/json"}
	data = {
		"model": model_name,
		"messages": [
			{
				"role": "system",
				"content": "you are log analyser. you will be given a auditd log and you will analyse it and give a summary of the log in a few sentences."
			},
			{
				"role": "user",
				"content": "This is the auditd log: " + prompt
			}
		],
		"temperature": 0.7,
		"stream": False,
		"max_tokens": 1024,
		"cache_prompt": False,  # 毎回入力を処理し直す（2回目以降だけ速く見えるのを防ぐ）
		"chat_template_kwargs": {"enable_thinking": False},  # Qwen 系の思考オフ（対応しないモデルでは無視される）
	}
	try:
		res = requests.post(url, headers=headers, json=data, timeout=TIMEOUT)
	except requests.exceptions.RequestException as e:
		print(f"Error: {e}")
		return None, None, None, None, None, None, None
	if res.status_code == 200:
		body = res.json()
		content = body["choices"][0]["message"]["content"]
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
		return content, prompt_n, prompt_ms, prompt_per_token_ms, predicted_n, predicted_ms, predicted_per_token_ms
	else:
		print(f"Error: {res.status_code} - {res.text}")
		return None, None, None, None, None, None, None


def get_model_name():
	"""llama-server が読み込んでいるモデル名を取る（記録用）"""
	try:
		res = requests.get(BASE_URL + "v1/models", timeout=10)
		return res.json()["data"][0]["id"]
	except Exception:
		return "unknown"


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


def main():
	global BASE_URL
	parser = argparse.ArgumentParser(description="auditd ログの要約で入力処理・生成の速さを測る")
	parser.add_argument("log", help="分析させる audit.log（gen_audit_log.py の出力など）")
	parser.add_argument("--runs", type=int, default=3, help="測定回数（このほかにウォームアップ1回）")
	parser.add_argument("--label", default="", help="記録用の名前（例: 調査1-gpt-oss-120b）")
	parser.add_argument("--url", default=BASE_URL)
	parser.add_argument("--csv", default="audit_bench_results.csv")
	args = parser.parse_args()
	BASE_URL = args.url.rstrip("/") + "/"

	print("Starting benchmark...")
	print("Health Check")
	if health_check():
		print("Health check passed")
	else:
		print("Health check failed")
		sys.exit(1)

	with open(args.log, encoding="utf-8") as f:
		log_text = f.read()
	answer = load_answer(args.log)
	model_name = get_model_name()
	print(f"model: {model_name}")
	print(f"log: {args.log}（{len(log_text.splitlines())} 行、{len(log_text):,} 文字）")

	# ウォームアップ（1回目は GPU の準備などで遅くなりやすいので捨てる）
	print("warm-up ...")
	chat(model_name, "type=DAEMON_START msg=audit(0.000:1): op=start res=success")

	rows = []
	for i in range(args.runs):
		content, prompt_n, prompt_ms, prompt_per_token_ms, predicted_n, predicted_ms, predicted_per_token_ms = chat(model_name, log_text)
		if content is None:
			print(f"run{i + 1}: 失敗")
			continue
		# 1トークンあたりのミリ秒から、1秒あたりのトークン数（tok/s）にする
		prompt_tps = 1000 / prompt_per_token_ms if prompt_per_token_ms else 0
		predicted_tps = 1000 / predicted_per_token_ms if predicted_per_token_ms else 0
		total_s = (prompt_ms + predicted_ms) / 1000
		check = check_answer(content, answer)
		print(f"run{i + 1}: 入力 {prompt_n} tok {prompt_tps:7.1f} tok/s | 生成 {predicted_n} tok {predicted_tps:5.1f} tok/s"
			f" | 計 {total_s:6.1f} s | {check}")
		rows.append({
			"datetime": datetime.datetime.now().isoformat(timespec="seconds"),
			"label": args.label,
			"model": model_name,
			"log": args.log,
			"run": i + 1,
			"prompt_n": prompt_n,
			"prompt_ms": round(prompt_ms, 1),
			"prompt_tps": round(prompt_tps, 2),
			"predicted_n": predicted_n,
			"predicted_ms": round(predicted_ms, 1),
			"predicted_tps": round(predicted_tps, 2),
			"total_s": round(total_s, 2),
			"check": json.dumps(check),
			"content": content,
		})

	if not rows:
		print("成功した測定がありません")
		sys.exit(1)

	print("\n===== 結果（中央値）")
	print(f"入力処理: {statistics.median(r['prompt_tps'] for r in rows):.1f} tok/s")
	print(f"生成:     {statistics.median(r['predicted_tps'] for r in rows):.1f} tok/s")
	print(f"1回の時間: {statistics.median(r['total_s'] for r in rows):.1f} s")
	print("\n----- 回答（最後の回）")
	print(rows[-1]["content"])

	new = not os.path.exists(args.csv)
	with open(args.csv, "a", newline="", encoding="utf-8") as f:
		w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
		if new:
			w.writeheader()
		w.writerows(rows)
	print(f"\nsaved: {args.csv}（{len(rows)} 行追記）")


if "__main__" == __name__:
	main()
