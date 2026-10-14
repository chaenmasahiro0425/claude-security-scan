"""このMac本体の設定チェック（sudo不要の範囲）。"""
from __future__ import annotations

import json
import os
import plistlib
import re
import stat
from pathlib import Path

from .common import Result, run, short_err

M = "mac"
HOME = Path.home()


def scan(cfg: dict) -> Result:
    r = Result()
    _filevault(r)
    _firewall(r)
    _gatekeeper_sip(r)
    _autologin_screenlock(r)
    if cfg.get("mac", {}).get("check_updates", True):
        _updates(r)
    _listening(r)
    _ssh(r)
    _secret_files(r)
    _launch_items(r)
    return r


def _filevault(r: Result):
    rc, out, err = run(["fdesetup", "status"])
    if rc != 0 or "FileVault is" not in out:
        r.cov(M, "FileVault", "error", short_err(err or out))
    elif "FileVault is On" in out:
        r.cov(M, "FileVault", "ok")
    else:
        r.add(M, "critical", "ディスク暗号化（FileVault）がオフ", "このMac",
              out.strip() or err.strip(),
              "システム設定 → プライバシーとセキュリティ → FileVault をオンにする。盗難・紛失時に全データが読まれるのを防ぐ")


def _firewall(r: Result):
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    _, out, _ = run([fw, "--getglobalstate"])
    if "State =" not in out:
        r.cov(M, "ファイアウォール", "error", short_err(out))
    elif "enabled" in out.lower() and "disabled" not in out.lower():
        r.cov(M, "ファイアウォール", "ok")
    else:
        r.add(M, "high", "ファイアウォールがオフ", "このMac", out.strip(),
              "システム設定 → ネットワーク → ファイアウォール をオンにする")
    _, out, _ = run([fw, "--getstealthmode"])
    if "off" in out.lower() or "disabled" in out.lower():
        r.add(M, "low", "ステルスモードがオフ", "このMac", out.strip(),
              "ファイアウォールのオプションで「ステルスモード」をオンにすると、公衆Wi-Fiでポートスキャンに応答しなくなる")


def _gatekeeper_sip(r: Result):
    rc, out, err = run(["spctl", "--status"])
    if "assessments" not in out:
        r.cov(M, "Gatekeeper", "error", short_err(err or out))
    elif "enabled" in out:
        r.cov(M, "Gatekeeper", "ok")
    else:
        r.add(M, "high", "Gatekeeperが無効（未署名アプリが無警告で動く）", "このMac", out.strip(),
              "ターミナルで sudo spctl --master-enable を本人が実行する")
    rc, out, err = run(["csrutil", "status"])
    if "System Integrity Protection status" not in out:
        r.cov(M, "SIP", "error", short_err(err or out))
    elif "enabled" in out:
        r.cov(M, "SIP", "ok")
    else:
        r.add(M, "high", "システム整合性保護（SIP）が無効", "このMac", out.strip(),
              "リカバリーモードで csrutil enable を実行する")


def _autologin_screenlock(r: Result):
    rc, out, _ = run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    if rc == 0 and out.strip():
        r.add(M, "high", "自動ログインが有効", "このMac", f"ユーザー: {out.strip()}",
              "システム設定 → ユーザとグループ → 自動ログインを「オフ」にする")
    rc, out, err = run(["sysadminctl", "-screenLock", "status"])
    text = (out + err).lower()
    if "off" in text or "disabled" in text:
        r.add(M, "medium", "スリープ・スクリーンセーバー後のパスワード要求がオフ", "このMac", (out + err).strip()[-200:],
              "システム設定 → ロック画面 →「スクリーンセーバ開始後またはディスプレイがオフになった後にパスワードを要求」を「すぐに」にする")
    elif "immediate" in text or "delay" in text or "enabled" in text:
        r.cov(M, "画面ロック", "ok", (out + err).strip()[-120:])
    else:
        r.cov(M, "画面ロック", "error", "状態を判定できない")


def _updates(r: Result):
    rc, out, err = run(["softwareupdate", "-l"], timeout=180)
    text = out + err
    if "No new software available" in text:
        r.cov(M, "macOSアップデート", "ok")
        return
    labels = re.findall(r"\* Label: (.+)", text)
    if not labels:
        r.cov(M, "macOSアップデート", "error", text.strip()[-200:])
        return
    sec = [l for l in labels if re.search(r"macOS|Security|Rapid|XProtect|Background Security", l, re.I)]
    sev = "high" if sec else "medium"
    r.add(M, sev, "未適用のソフトウェアアップデートがある", "このMac", "\n".join(labels),
          "システム設定 → 一般 → ソフトウェアアップデート から適用する（再起動が必要なものは作業の区切りで）")


def _listening(r: Result):
    """外部から接続を受け付けているTCPポート（127.0.0.1 以外で LISTEN）。"""
    _, out, _ = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    exposed: dict[str, set[str]] = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        cmd, addr = parts[0], parts[8]
        host, _, port = addr.rpartition(":")
        if host in ("127.0.0.1", "[::1]", "localhost"):
            continue
        exposed.setdefault(port, set()).add(cmd.replace("\\x20", " "))
    risky = {"22": "SSH", "5900": "画面共有", "445": "ファイル共有(SMB)", "548": "AFP", "3283": "Remote Desktop", "88": "Kerberos"}
    for port, cmds in sorted(exposed.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        name = risky.get(port)
        sev = "medium" if name else "low"
        r.add(M, sev, f"外部から接続を受け付けるポート {port}" + (f"（{name}）" if name else ""), f"tcp/{port}",
              "プロセス: " + ", ".join(sorted(cmds)),
              "使っていない共有機能・開発サーバーなら止めるか 127.0.0.1 にバインドする。公衆Wi-Fiでは特に注意")


def _ssh(r: Result):
    d = HOME / ".ssh"
    if not d.is_dir():
        return
    if stat.S_IMODE(d.stat().st_mode) & 0o077:
        r.add(M, "medium", "~/.ssh フォルダの権限が緩い", str(d), oct(stat.S_IMODE(d.stat().st_mode)), "chmod 700 ~/.ssh")
    for f in d.iterdir():
        if not f.is_file() or f.suffix == ".pub" or f.name in ("known_hosts", "known_hosts.old", "config", "authorized_keys"):
            continue
        mode = stat.S_IMODE(f.stat().st_mode)
        if mode & 0o077:
            r.add(M, "high", "SSH秘密鍵が他ユーザーから読める権限", str(f), oct(mode), f"chmod 600 {f}")
    ak = d / "authorized_keys"
    if ak.exists() and ak.stat().st_size > 0:
        n = sum(1 for l in ak.read_text(errors="ignore").splitlines() if l.strip() and not l.startswith("#"))
        r.add(M, "info", "このMacへSSHログインできる公開鍵が登録されている", str(ak), f"{n}件",
              "心当たりのない鍵があれば削除する（リモートログインがオフなら影響なし）")


SECRET_NAME = re.compile(r"^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_]*)\s*=", re.M)


def _secret_files(r: Result):
    """秘密値を含む設定ファイルの権限だけを見る。値は読み出さない（名前の件数だけ数える）。"""
    for name in [".zshenv", ".zshrc", ".zprofile", ".bash_profile", ".bashrc", ".netrc", ".npmrc", ".pypirc"]:
        f = HOME / name
        if not f.is_file():
            continue
        mode = stat.S_IMODE(f.stat().st_mode)
        n = len(SECRET_NAME.findall(f.read_text(errors="ignore")))
        if name in (".netrc", ".npmrc", ".pypirc"):
            n = max(n, 1)
        if n and mode & 0o044:
            r.add(M, "medium", "秘密情報を含むファイルが他ユーザーから読める権限", str(f),
                  f"権限 {oct(mode)} / 秘密っぽい変数 {n}件（値は表示しない）", f"chmod 600 {f}")
    for p in [HOME / ".aws" / "credentials"]:
        if p.is_file():
            r.add(M, "medium", "AWSの長期アクセスキーファイルが存在する", str(p), "SSOを使っている環境では通常不要",
                  "中身のキーが使われていないかIAMで確認し、不要なら無効化→ファイル削除。SSO(aws sso login)へ寄せる")


def _load_plist(p: Path):
    try:
        data = plistlib.loads(p.read_bytes())
    except Exception:  # noqa: BLE001  plistlib が受け付けない書式でも plutil なら読めることがある
        rc, out, _ = run(["plutil", "-convert", "json", "-o", "-", str(p)])
        if rc != 0:
            return None
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


def _user_writable(path: str) -> bool:
    """本人（root以外）がファイル自体か置き場のフォルダを書き換えられるか。"""
    p = Path(path)
    return p.exists() and (os.access(p, os.W_OK) or os.access(p.parent, os.W_OK))


def _unsigned(path: str) -> bool:
    rc, out, err = run(["codesign", "-dv", path], 20)
    text = out + err
    return rc != 0 or "Signature=adhoc" in text or "not signed" in text


def _launch_items(r: Result):
    """常駐（LaunchAgents/Daemons）の棚卸し。新しく増えたものはレポートで NEW 表示になる。"""
    dirs = [HOME / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
    suspicious_dirs = ("/tmp/", "/private/tmp/", "/var/tmp/", str(HOME / "Downloads"), "/Users/Shared/")
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.plist")):
            data = _load_plist(p)
            if data is None:
                r.cov(M, f"常駐 {p.name}", "error", "plistを読めない")
                continue
            prog = data.get("Program") or (data.get("ProgramArguments") or [""])[0]
            label = data.get("Label", p.stem)
            sev, note = "info", ""
            target_paths = [str(prog)] + [str(a) for a in (data.get("ProgramArguments") or [])]
            if any(s in tp for tp in target_paths for s in suspicious_dirs):
                sev, note = "high", "一時フォルダ・Downloads から起動している常駐。マルウェアの典型パターン"
            elif any(Path(tp).name.startswith(".") for tp in target_paths if tp.startswith("/")):
                sev, note = "medium", "隠しファイルを起動している常駐"
            elif d.name == "LaunchDaemons" and prog.startswith("/") and _user_writable(prog):
                sev, note = "high", "root権限で動く常駐なのに、起動するプログラムがユーザー権限で書き換えられる場所にある（すり替えでroot権限を取られる）"
            elif d.name == "LaunchDaemons" and prog.startswith("/") and Path(prog).exists() and _unsigned(prog):
                sev, note = "medium", "root権限で動く常駐が正式な署名のないプログラムを起動している"
            elif prog and prog.startswith("/") and not Path(prog).exists():
                sev, note = "low", "起動先のファイルが存在しない（残骸）"
            r.add(M, sev, f"常駐プログラム: {label}", str(p),
                  (note + "\n" if note else "") + f"起動: {prog}（引数は秘密が入りうるので記録しない）",
                  "心当たりがなければ launchctl bootout で止めてから plist を隔離する" if sev != "info" else "",
                  key="launch|" + str(p))
