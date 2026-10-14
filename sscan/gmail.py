"""Gmail / Googleアカウント: 乗っ取り時に仕込まれやすい設定と、届いているセキュリティ通知。

gog は必ず --readonly で呼ぶ（設定を書き換えない）。メール本文は読まない。件名と日時だけ使う。
"""
from __future__ import annotations

import re

from .common import Result, run, run_json, short_err, tool

M = "gmail"
ALERT_WORDS = re.compile(r"(ログイン|サインイン|sign-?in|新しいデバイス|new device|パスワード|password|アクセス|access|"
                         r"復元|recovery|2段階|2-Step|不審|suspicious|セキュリティ通知|security alert|アプリ|app)", re.I)


# 警告メールの送信元・件名に限定する（google.com 全体などに広げると普段の整理フィルタまで拾う）
SECURITY_SENDER = re.compile(r"(accounts\.google\.com|security|セキュリティ|password|パスワード|sign-?in|ログイン|signin\.aws|"
                             r"awsapps|aws-security|account-security|verify|認証コード|2段階|two-factor|2fa)", re.I)


DEFAULT_QUERIES = [
    "from:no-reply@accounts.google.com",
    'from:noreply@github.com subject:(security OR token OR "SSH key" OR OAuth OR sign-in)',
    "from:(no-reply@signin.aws OR no-reply@login.awsapps.com OR aws-security@amazon.com)",
    "from:(security@vercel.com OR notifications@vercel.com) subject:(login OR token OR security)",
]


def _gog_accounts() -> list[str]:
    """gog auth list から gmail を許可済みのアカウントを拾う。"""
    _, out, _ = run(["gog", "auth", "list", "--plain"], 20)
    accts = []
    for line in out.splitlines():
        cols = line.split("\t")
        if cols and "@" in cols[0] and (len(cols) < 3 or "gmail" in cols[2]):
            accts.append(cols[0].strip())
    return accts


def _gog(acct: str, *args, timeout: int = 60):
    return run_json(["gog", "--readonly", "--no-input", "-a", acct, "-j", *args], timeout)


def scan(cfg: dict) -> Result:
    r = Result()
    c = cfg.get("gmail", {})
    if not tool("gog"):
        r.cov(M, "Gmail", "skip", "gog CLI が無い（https://github.com/steipete/gogcli）")
        return r
    accounts = c.get("accounts") or _gog_accounts()
    if not accounts:
        r.cov(M, "Gmail", "skip", "gog にGmailで認証済みのアカウントが無い（gog auth add <メール>）")
        return r
    allowed_fwd = {a.lower() for a in c.get("allowed_forwarding", [])}
    for acct in accounts:
        ok = _settings(r, acct, allowed_fwd)
        if ok:
            _alerts(r, acct, c.get("alert_queries") or DEFAULT_QUERIES, c.get("alert_days", 14))
            r.cov(M, acct, "ok")
    admins = c.get("workspace_admin_accounts")
    if admins is None:
        admins = sorted({a for a in accounts if a.split("@")[-1].lower() not in ("gmail.com", "googlemail.com")})[:1]
    for acct in admins:
        data, err = _gog(acct, "admin", "users", "list", "--max", "1")
        if data is None:
            r.cov(M, f"Workspace管理 ({acct.split('@')[-1]})", "skip",
                  "Admin APIはドメイン全体の委任が必要。2段階認証の強制状況・外部共有・連携アプリは "
                  "https://admin.google.com/ac/security/health （セキュリティの状況ページ）で手動確認")
    return r


def _settings(r: Result, acct: str, allowed: set[str]) -> bool:
    af, err = _gog(acct, "gmail", "settings", "autoforward", "get")
    if af is None:
        r.cov(M, acct, "error", short_err(err) + "（gog auth add で再認証が必要な可能性）")
        return False
    a = af.get("autoForwarding", {})
    if a.get("enabled"):
        dest = a.get("emailAddress", "?")
        sev = "info" if dest.lower() in allowed else "high"
        r.add(M, sev, "全メールの自動転送がオン", acct, f"転送先: {dest}（処理: {a.get('disposition', '')}）",
              "自分で設定した覚えがなければ即オフにしてパスワード変更。乗っ取り後に仕込まれる典型設定")

    fw, err = _gog(acct, "gmail", "settings", "forwarding", "list")
    if fw is None:
        r.cov(M, f"{acct} 転送先", "error", short_err(err))
    for f in (fw or {}).get("forwardingAddresses", []):
        dest = f.get("forwardingEmail", "")
        if dest.lower() not in allowed:
            r.add(M, "medium", "転送先アドレスが登録されている", acct, f"{dest}（{f.get('verificationStatus')}）",
                  "使っていなければ Gmail設定 → メール転送 から削除", key=f"fwd|{acct}|{dest}")

    flt, err = _gog(acct, "gmail", "settings", "filters", "list")
    if flt is None:
        r.cov(M, f"{acct} フィルタ", "error", short_err(err))
    for f in (flt or {}).get("filters", []):
        act, crit = f.get("action", {}), f.get("criteria", {})
        crit_s = " ".join(f"{k}:{v}" for k, v in crit.items())
        if act.get("forward"):
            dest = act["forward"]
            r.add(M, "info" if dest.lower() in allowed else "high", "条件付きでメールを転送するフィルタ", acct,
                  f"条件 {crit_s} → 転送先 {dest}", "覚えがなければ削除。請求書・パスワード再設定メールを抜く手口がある", key=f"filter-fwd|{acct}|{f.get('id')}")
        trashes = "TRASH" in act.get("addLabelIds", []) or ("INBOX" in act.get("removeLabelIds", []) and "UNREAD" in act.get("removeLabelIds", []))
        if not trashes:
            continue
        if not crit_s.strip() or SECURITY_SENDER.search(crit_s):
            r.add(M, "high", "セキュリティ通知を見えなくするフィルタ", acct, f"条件 {crit_s} → ゴミ箱/既読アーカイブ",
                  "攻撃者が警告メールを隠すために仕込む手口。自分で作ったものか確認", key=f"filter|{acct}|{f.get('id')}")
        else:
            # 普段の整理用フィルタ。棚卸しとして残し、新しく増えたときにNEWで気付けるようにする
            r.add(M, "info", "メールを自動でゴミ箱/既読アーカイブするフィルタ", acct, f"条件 {crit_s}",
                  "覚えがなければ削除", key=f"filter|{acct}|{f.get('id')}")

    sa, _ = _gog(acct, "gmail", "settings", "sendas", "list")
    for s in (sa or {}).get("sendAs", []):
        if not s.get("isPrimary"):
            r.add(M, "info", "このアカウントから送信できる別アドレス（Send As）", acct,
                  f"{s.get('sendAsEmail')}（{(s.get('smtpMsa') or {}).get('host', 'Gmail経由')}）",
                  "使っていないものは削除", key=f"sendas|{acct}|{s.get('sendAsEmail')}")
    dl, _ = _gog(acct, "gmail", "settings", "delegates", "list")
    for d in (dl or {}).get("delegates", []):
        r.add(M, "medium", "メールボックスへの委任アクセス", acct, d.get("delegateEmail", ""), "覚えがなければ削除",
              key=f"delegate|{acct}|{d.get('delegateEmail')}")
    return True


def _alerts(r: Result, acct: str, queries: list[str], days: int):
    for q in queries:
        data, err = _gog(acct, "gmail", "search", f"{q} newer_than:{days}d", "--max", "30")
        if data is None:
            continue
        for t in data.get("threads", []):
            subj = t.get("subject", "")
            if not ALERT_WORDS.search(subj):
                continue
            unread = "UNREAD" in t.get("labels", [])
            r.add(M, "medium" if unread else "low", "最近のセキュリティ通知メール" + ("（未読）" if unread else ""), acct,
                  f"{t.get('date')}  {t.get('from', '')}\n件名: {subj}",
                  "自分の操作なら問題なし。覚えのないログイン・パスワード変更・アプリ連携なら即パスワード変更とセッション失効",
                  key=f"alert|{acct}|{t.get('id')}")
