"""公開Webサイト（外からの非破壊チェック）と Vercel プロジェクト設定。

外部サイトへは GET/HEAD を数回送るだけ。攻撃的なスキャン（総当たり・ファジング）はしない。
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .common import WHOLE, Result, run_json, short_err, tool

M = "web"
UA = "Mozilla/5.0 (security-scan; owner self-check)"
SECRETISH = re.compile(r"(SECRET|PRIVATE|PASSWORD|TOKEN|SERVICE_ROLE|API_KEY|ACCESS_KEY)", re.I)
ALWAYS_SECRET = re.compile(r"(SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|PERSONAL)", re.I)
PUBLIC_OK = re.compile(r"(ANON|PUBLISHABLE|PUBLIC_KEY|SITE_KEY|MEASUREMENT|GA_|GTM|POSTHOG|SENTRY_DSN|MAPS_API_KEY|FIREBASE_API_KEY)", re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _get(url: str, follow: bool = True, limit: int = 4096, timeout: int = 15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read(limit), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(limit) if e.fp else b"", url
    except Exception as e:  # noqa: BLE001
        return None, None, str(e).encode(), url


def _vercel(path: str, team: str):
    sep = "&" if "?" in path else "?"
    return run_json(["vercel", "api", f"{path}{sep}teamId={team}"], 90)


def scan(cfg: dict) -> Result:
    r = Result()
    c = cfg.get("web", {})
    hosts: set[str] = set(c.get("urls", []))
    if c.get("vercel", True) and tool("vercel"):
        hosts |= _vercel_scan(r, c)
    elif c.get("vercel", True):
        r.cov(M, "Vercel", "skip", "vercel CLI が無い。公開サイトは config の urls だけを見る", blocks=WHOLE)
    hosts = {h.replace("https://", "").replace("http://", "").strip("/") for h in hosts}
    hosts = {h for h in hosts if h and not any(x in h for x in c.get("exclude", []))}
    hosts = sorted(hosts)[: c.get("max_sites", 120)]
    r.cov(M, "対象サイト", "ok", f"{len(hosts)}件")
    with ThreadPoolExecutor(max_workers=6) as ex:
        for sub in ex.map(_safe_site, hosts):
            r.extend(sub)
    return r


# ---------------- Vercel ----------------

def _vercel_scan(r: Result, c: dict) -> set[str]:
    hosts: set[str] = set()
    teams, err = run_json(["vercel", "api", "/v2/teams"], 60)
    if not teams:
        r.cov(M, "Vercel", "error", short_err(err) + "（vercel login が必要）", blocks=WHOLE)
        return hosts
    for t in teams.get("teams", []):
        tid, slug = t["id"], t["slug"]
        projects, nxt = [], None
        while True:
            data, err = _vercel(f"/v9/projects?limit=100" + (f"&until={nxt}" if nxt else ""), tid)
            if not data:
                r.cov(M, f"Vercel {slug}", "error", short_err(err), blocks=WHOLE)
                break
            projects += data.get("projects", [])
            nxt = (data.get("pagination") or {}).get("next")
            if not nxt:
                break
        r.cov(M, f"Vercel {slug}", "ok", f"{len(projects)}プロジェクト")
        unprotected = []
        for p in projects:
            name = p["name"]
            prod = ((p.get("targets") or {}).get("production") or {})
            for a in prod.get("alias") or []:
                if not a.endswith(".vercel.app") or c.get("include_vercel_app", False):
                    hosts.add(a)
            if not p.get("ssoProtection") and not p.get("passwordProtection"):
                unprotected.append(name)
            for e in p.get("env") or []:
                _env_check(r, slug, name, e)
        if unprotected:
            r.add(M, "low", "プレビューURLに保護（Vercel認証）がかかっていないプロジェクト", f"Vercel {slug}",
                  f"{len(unprotected)}件: " + ", ".join(sorted(unprotected)[:40]),
                  "Project Settings → Deployment Protection → Vercel Authentication を「Standard Protection」に。開発中の画面やAPIが推測URLで見られるのを防ぐ",
                  key=f"vercel-unprotected|{slug}")
        if c.get("vercel_env_detail", True):
            with ThreadPoolExecutor(max_workers=6) as ex:
                for sub in ex.map(lambda p: _env_detail(slug, tid, p), [p for p in projects if not p.get("env")]):
                    r.extend(sub)
    return hosts


def _env_check(r: Result, team: str, project: str, e: dict):
    key, typ = e.get("key", ""), e.get("type", "")
    tgt = f"Vercel {team} / {project} / {key}"
    if key.startswith(("NEXT_PUBLIC_", "VITE_", "PUBLIC_", "EXPO_PUBLIC_")) and SECRETISH.search(key) and (ALWAYS_SECRET.search(key) or not PUBLIC_OK.search(key)):
        r.add(M, "high", "ブラウザに配信される環境変数に秘密っぽい名前", tgt,
              "NEXT_PUBLIC_ / VITE_ 付きの変数はJSに埋め込まれ、誰でも読める",
              "サーバー側だけで使う変数名に変え、キーはローテーション。公開前提の値なら無視してよい")
    elif typ == "plain" and SECRETISH.search(key) and not PUBLIC_OK.search(key):
        r.add(M, "medium", "秘密っぽい環境変数が平文(plain)で保存されている", tgt, "",
              "Sensitive 型で登録し直す（チームメンバーやログから値が見えなくなる）")


def _env_detail(team: str, tid: str, p: dict) -> Result:
    r = Result()
    data, err = _vercel(f"/v10/projects/{p['id']}/env", tid)
    if data is None:
        r.cov(M, f"Vercel {team}/{p['name']} env", "error", err, blocks=[("環境変数", f"Vercel {team} / {p['name']} /")])
    for e in (data or {}).get("envs", []):
        _env_check(r, team, p["name"], e)
    return r


# ---------------- サイト ----------------

def _safe_site(host: str) -> Result:
    try:
        return _site(host)
    except Exception as e:  # noqa: BLE001  1サイトの失敗で全体を止めない
        r = Result()
        r.cov(M, host, "error", type(e).__name__)
        return r


def _site(host: str) -> Result:
    r = Result()
    base = f"https://{host}"
    # 証明書（ページ取得が失敗しても独立に見る）
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock, ctx.wrap_socket(sock, server_hostname=host) as ss:
            cert = ss.getpeercert()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 14:
            r.add(M, "high", "SSL証明書の期限が近い", host, f"残り{days}日", "証明書を更新（自動更新が止まっていないか確認）")
        elif days < 30:
            r.add(M, "low", "SSL証明書の期限が30日以内", host, f"残り{days}日", "自動更新されるか確認")
    except ssl.SSLCertVerificationError as e:
        r.add(M, "high", "SSL証明書が不正（期限切れ・ドメイン不一致など）", host, str(e)[:200], "証明書を正しく発行し直す")
    except Exception as e:  # noqa: BLE001
        r.cov(M, f"{host} 証明書", "error", str(e)[:150], blocks=[("SSL証明書", host)])

    status, headers, body, final = _get(base)
    if status is None:
        r.cov(M, host, "error", body.decode(errors="ignore")[:150])
        return r
    if status >= 500 or status in (401, 403, 404):
        r.cov(M, host, "skip", f"HTTP {status}")

    # HTTP → HTTPS
    s2, h2, _, _ = _get(f"http://{host}", follow=False)
    loc = (h2 or {}).get("Location", "") if h2 else ""
    if s2 and not (300 <= s2 < 400 and loc.startswith("https://")):
        r.add(M, "medium", "http:// で開いたとき https:// に転送されない", host, f"HTTP {s2}", "HTTPSへの強制リダイレクトを設定")

    if headers is not None and status < 400:
        h = {k.lower(): v for k, v in headers.items()}
        missing = []
        if "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security")
        csp = h.get("content-security-policy", "")
        if not csp:
            missing.append("Content-Security-Policy")
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            missing.append("X-Frame-Options（クリックジャッキング対策）")
        if "x-content-type-options" not in h:
            missing.append("X-Content-Type-Options")
        if missing:
            r.add(M, "low", "セキュリティヘッダーが不足", host, "不足: " + ", ".join(missing),
                  "vercel.json / next.config の headers に追加（LPならCSPは report-only から始める）", key=f"hdr|{host}")
        for k in ("server", "x-powered-by"):
            if re.search(r"\d+\.\d+", h.get(k, "")):
                r.add(M, "low", f"{k} ヘッダーでソフトウェアのバージョンが見える", host, h[k], "バージョン表記を消す")
        for ck in headers.get_all("Set-Cookie") or []:
            name = ck.split("=", 1)[0]
            attrs = {a.strip().split("=", 1)[0].lower() for a in ck.split(";")[1:]}
            lack = [f for f in ("secure", "httponly") if f not in attrs]
            if lack and not name.startswith(("_ga", "_gcl", "_fbp")):
                r.add(M, "low", f"Cookie {name} に {'/'.join(lack)} 属性がない", host, "", "セッション系Cookieは Secure; HttpOnly; SameSite=Lax を付ける")

    # 露出してはいけないファイル（SPAは何にでも200を返すので中身で判定する）
    probes = {
        "/.git/HEAD": lambda b: b.startswith(b"ref:") or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None,
        "/.git/config": lambda b: b"[core]" in b,
        "/.env": lambda b: _looks_env(b),
        "/.env.local": lambda b: _looks_env(b),
        "/.env.production": lambda b: _looks_env(b),
        "/.DS_Store": lambda b: b[:8] == b"\x00\x00\x00\x01Bud1",
    }
    for path, test in probes.items():
        st, _, b, _ = _get(base + path, follow=False, limit=2048)
        if st == 200 and test(b):
            sev = "medium" if path == "/.DS_Store" else "critical"
            r.add(M, sev, f"公開してはいけないファイルが見える: {path}", host, base + path,
                  "デプロイ対象から除外（.vercelignore 等）し、.env/.git なら中のキーをすぐローテーション")
    return r


def _looks_env(b: bytes) -> bool:
    if b.lstrip()[:1] in (b"<", b"{"):
        return False
    lines = [l for l in b.decode(errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
    return bool(lines) and sum(bool(re.match(r"^[A-Z0-9_]+=", l)) for l in lines) >= max(1, len(lines) // 2)
