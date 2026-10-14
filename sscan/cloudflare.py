"""Cloudflare: ゾーンのTLS設定・DNSSEC・アカウントメンバーの2FA（API の GET のみ）。

CLOUDFLARE_API_TOKEN（読み取り権限: Zone:Read / Zone Settings:Read / DNS:Read / Account Settings:Read）を使う。
トークンの値はどこにも出さない。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .common import WHOLE, Result, short_err

M = "cloudflare"
API = "https://api.cloudflare.com/client/v4"


def _get(path: str, token: str):
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__
    if not isinstance(body, dict):
        return None, "想定外の応答"
    if not body.get("success"):
        codes = ",".join(str(x.get("code", "?")) for x in body.get("errors", []) if isinstance(x, dict))
        return None, f"APIエラー（code {codes or '?'}）"  # 応答の文面は記録しない
    return body.get("result"), ""


def _all(path: str, token: str):
    out, page = [], 1
    while True:
        sep = "&" if "?" in path else "?"
        res, err = _get(f"{path}{sep}per_page=50&page={page}", token)
        if res is None:  # 途中のページで失敗したら、部分的な一覧を正常として扱わない
            return None, err
        out += res
        if len(res) < 50:
            return out, ""
        page += 1


def scan(cfg: dict) -> Result:
    r = Result()
    c = cfg.get("cloudflare", {})
    token = os.environ.get(c.get("token_env", "CLOUDFLARE_API_TOKEN"), "")
    if not token:
        r.cov(M, "Cloudflare", "skip", "環境変数 CLOUDFLARE_API_TOKEN が無い（読み取り専用トークンを作って export）", blocks=WHOLE)
        return r
    zones, err = _all("/zones", token)
    if zones is None:
        r.cov(M, "Cloudflare", "error", err + "（トークンの権限を確認）", blocks=WHOLE)
        return r
    r.cov(M, "対象ゾーン", "ok", f"{len(zones)}件")
    for z in zones:
        if not isinstance(z, dict) or not z.get("id"):
            continue
        zid, name = z["id"], z.get("name", z["id"])
        ssl, e1 = _get(f"/zones/{zid}/settings/ssl", token)
        if ssl is None:
            r.cov(M, f"{name} SSL設定", "error", short_err(e1), blocks=[("", name)])
            continue
        mode = ssl.get("value")
        if mode == "off":
            r.add(M, "high", "SSL/TLS がオフ", name, "訪問者との通信が暗号化されない", "SSL/TLS を Full (strict) に", key=f"cf-ssl|{name}")
        elif mode == "flexible":
            r.add(M, "medium", "SSL/TLS が Flexible（Cloudflare→サーバー間が暗号化されない）", name, "",
                  "サーバー側に証明書を入れて Full (strict) に", key=f"cf-ssl|{name}")
        https, e2 = _get(f"/zones/{zid}/settings/always_use_https", token)
        if https is None:
            r.cov(M, f"{name} Always Use HTTPS", "error", e2, blocks=[("Always Use HTTPS", name)])
        elif https.get("value") == "off":
            r.add(M, "low", "Always Use HTTPS がオフ", name, "", "オンにして http を https へ転送", key=f"cf-https|{name}")
        tls, e3 = _get(f"/zones/{zid}/settings/min_tls_version", token)
        if tls is None:
            r.cov(M, f"{name} 最小TLS", "error", e3, blocks=[("TLS", name)])
        elif tls.get("value") in ("1.0", "1.1"):
            r.add(M, "low", "古いTLSを許可", name, f"最小TLS {tls.get('value')}", "最小TLSを1.2に", key=f"cf-tls|{name}")
        dnssec, e4 = _get(f"/zones/{zid}/dnssec", token)
        if dnssec is None:
            r.cov(M, f"{name} DNSSEC", "error", e4, blocks=[("DNSSEC", name)])
        elif dnssec.get("status") == "disabled":
            r.add(M, "low", "DNSSEC が無効", name, "", "レジストラ側の設定とあわせて有効化を検討", key=f"cf-dnssec|{name}")

    accounts, err = _all("/accounts", token)
    if accounts is None:
        r.cov(M, "アカウント一覧", "skip", f"{err}（Account Settings:Read 権限が必要）", blocks=[("2段階認証", "")])
    for a in accounts or []:
        if not isinstance(a, dict) or not a.get("id"):
            continue
        members, err = _all(f"/accounts/{a['id']}/members", token)
        if members is None:
            r.cov(M, f"{a.get('name')} メンバー", "skip", f"{err}（Account Settings:Read 権限が必要）", blocks=[("2段階認証", a.get("name", ""))])
            continue
        for m in members:
            u = (m.get("user") if isinstance(m, dict) else None) or {}
            if u.get("two_factor_authentication_enabled") is False:
                r.add(M, "high", "2段階認証を設定していないメンバー", f"{a.get('name')} / {u.get('email', '?')}", "",
                      "本人に2FA設定を依頼。アカウント設定で2FA必須化も検討", key=f"cf-2fa|{a['id']}|{u.get('id')}")
    return r
