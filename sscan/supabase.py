"""Supabase: 公式の Security Advisor（RLS未設定のテーブル・公開されたビュー等）を読む。

SUPABASE_ACCESS_TOKEN（Management API の個人トークン）があれば全プロジェクトの advisor を取得する。
無ければ supabase CLI でプロジェクト一覧だけ確認し、トークンの作り方を案内する。トークンの値はどこにも出さない。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .common import WHOLE, Result, run_json, short_err, tool

M = "supabase"
API = "https://api.supabase.com/v1"
LEVEL = {"ERROR": "high", "WARN": "medium", "INFO": "low"}
# 誰でもデータを読める・書ける状態につながる lint は1段重くする
CRITICAL = {"rls_disabled_in_public", "policy_exists_rls_disabled", "security_definer_view", "rls_references_user_metadata"}


def _get(path: str, token: str):
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read()), ""
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def scan(cfg: dict) -> Result:
    r = Result()
    c = cfg.get("supabase", {})
    token = os.environ.get(c.get("token_env", "SUPABASE_ACCESS_TOKEN"), "")
    if token:
        projects, err = _get("/projects", token)
    elif tool("supabase"):
        projects, err = run_json(["supabase", "projects", "list", "-o", "json"], 60)
    else:
        r.cov(M, "Supabase", "skip", "supabase CLI も SUPABASE_ACCESS_TOKEN も無い", blocks=WHOLE)
        return r
    if projects is None:
        r.cov(M, "Supabase", "error", short_err(err) + "（supabase login か トークンを確認）", blocks=WHOLE)
        return r
    active = [p for p in projects if str(p.get("status", "")).startswith("ACTIVE")]
    r.cov(M, "対象プロジェクト", "ok", f"稼働中 {len(active)}件（停止中 {len(projects) - len(active)}件）")
    if not token:
        r.cov(M, "Security Advisor", "skip",
              "RLS等の診断には SUPABASE_ACCESS_TOKEN が必要（ダッシュボード → Account → Access Tokens で作成し export）", blocks=WHOLE)
        return r
    for p in active:
        ref, name = p.get("ref") or p.get("id"), p.get("name")
        data, err = _get(f"/projects/{ref}/advisors/security", token)
        if data is None:
            r.cov(M, f"{name} advisor", "error", err, blocks=[("", name)])
            continue
        for lint in data.get("lints", []):
            sev = "critical" if lint.get("name") in CRITICAL and lint.get("level") == "ERROR" else LEVEL.get(lint.get("level"), "low")
            meta = lint.get("metadata") or {}
            obj = ".".join(x for x in (meta.get("schema"), meta.get("name")) if x)
            r.add(M, sev, f"Security Advisor: {lint.get('title') or lint.get('name')}", f"{name} / {obj or lint.get('name')}",
                  (lint.get("detail") or lint.get("description") or "")[:300],
                  (lint.get("remediation") or "ダッシュボードの Advisors → Security で確認"),
                  key=f"sb|{ref}|{lint.get('cache_key') or lint.get('name') + obj}")
        r.cov(M, name, "ok")
    return r
