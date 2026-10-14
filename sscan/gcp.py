"""Google Cloud: 各プロジェクトの公開設定・鍵・ファイアウォール（gcloud の list / get のみ）。"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import json

from .common import WHOLE, Result, run, short_err, tool

M = "gcp"
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
PUBLIC = ("allUsers", "allAuthenticatedUsers")
# API が有効になっていないだけのプロジェクトは「未使用」として静かに飛ばす
NOT_ENABLED = ("has not been used", "is disabled", "SERVICE_DISABLED", "not enabled")


def _g(c: dict, *args, timeout: int = 90):
    """(データ, エラーの理由) を返す。エラーは切り詰める前の全文で分類して、短い日本語にする。"""
    cmd = ["gcloud", *args, "--format=json", "--quiet"]
    if c.get("account"):
        cmd.append(f"--account={c['account']}")
    rc, out, err = run(cmd, timeout)
    if rc == 0:
        try:
            return json.loads(out or "null"), ""
        except json.JSONDecodeError:
            return None, "JSON parse error（応答本文は記録しない）"
    if any(s in err for s in NOT_ENABLED):
        return None, "API_NOT_ENABLED"
    if "PERMISSION_DENIED" in err or "403" in err or "does not have" in err:
        return None, "権限不足（閲覧者 roles/viewer 相当の権限が必要）"
    if "reauth" in err.lower() or "auth tokens" in err.lower():
        return None, "ログインの期限切れ（gcloud auth login で再ログイン）"
    return None, short_err(err[-300:])


def scan(cfg: dict) -> Result:
    r = Result()
    c = cfg.get("gcp", {})
    if not tool("gcloud"):
        r.cov(M, "Google Cloud", "skip", "gcloud CLI が無い", blocks=WHOLE)
        return r
    if c.get("projects"):
        ids = list(c["projects"])
    else:
        projects, err = _g(c, "projects", "list")
        if projects is None:
            if err == "API_NOT_ENABLED":
                msg = "プロジェクト一覧の取得に Cloud Resource Manager API が必要（有効化するか、設定の [gcp] projects で指定）"
            else:
                msg = err
            r.cov(M, "Google Cloud", "error", msg, blocks=WHOLE)
            return r
        ids = [p["projectId"] for p in projects if p.get("lifecycleState", "ACTIVE") == "ACTIVE"]
    ids = [i for i in ids if i not in c.get("exclude_projects", [])]
    r.cov(M, "対象プロジェクト", "ok", f"{len(ids)}件")
    with ThreadPoolExecutor(max_workers=c.get("workers", 4)) as ex:
        for sub in ex.map(lambda pid: _project(c, pid), ids):
            r.extend(sub)
    return r


def _skip_or_error(r: Result, item: str, err: str, blocks: list, needed: bool = False):
    if err == "API_NOT_ENABLED":
        if needed:  # IAM は「使っていない」ではなく「読めない」
            r.cov(M, item, "skip", "Cloud Resource Manager API が無効で読めない", blocks=blocks)
        return  # そのサービスを使っていないだけ
    r.cov(M, item, "skip" if err.startswith("権限不足") else "error", err, blocks=blocks)


def _project(c: dict, pid: str) -> Result:
    r = Result()
    # プロジェクトのIAM：誰でも（allUsers）に権限が付いていないか
    pol, err = _g(c, "projects", "get-iam-policy", pid)
    if pol is None:
        _skip_or_error(r, f"{pid} IAM", err, [("権限", pid)], needed=True)
    else:
        for b in pol.get("bindings", []):
            pub = [m for m in b.get("members", []) if m in PUBLIC]
            if pub:
                r.add(M, "critical", "プロジェクト全体の権限がインターネット全体に付与されている", f"{pid}",
                      f"{b.get('role')} → {', '.join(pub)}", "allUsers / allAuthenticatedUsers の付与を外す", key=f"gcp-iam-public|{pid}|{b.get('role')}")
            if b.get("role") in ("roles/owner", "roles/editor"):
                outsiders = [m for m in b.get("members", []) if m.startswith("user:") and m.endswith(("@gmail.com", "@googlemail.com"))]
                for m in outsiders:
                    r.add(M, "medium", "個人のGmailアカウントにオーナー/編集者権限", f"{pid} / {m.split(':', 1)[1]}", b["role"],
                          "会社のアカウントへ移すか、必要な最小限のロールに下げる", key=f"gcp-gmail|{pid}|{m}")

    # サービスアカウントの鍵（ユーザー管理の鍵は漏れると長期間使われる）
    sas, err = _g(c, "iam", "service-accounts", "list", f"--project={pid}")
    if sas is None:
        _skip_or_error(r, f"{pid} サービスアカウント", err, [("サービスアカウント", pid)])
    now = datetime.now(timezone.utc)
    for sa in sas or []:
        keys, _ = _g(c, "iam", "service-accounts", "keys", "list", f"--iam-account={sa['email']}", "--managed-by=user", f"--project={pid}")
        for k in keys or []:
            created = k.get("validAfterTime", "")
            try:
                age = (now - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
            except ValueError:
                age = -1
            sev = "medium" if age > 90 else "low"
            r.add(M, sev, "サービスアカウントにダウンロード可能な鍵がある", f"{pid} / {sa['email']}",
                  f"作成 {age}日前（鍵IDは伏せる: …{k.get('name', '')[-4:]}）",
                  "可能なら Workload Identity 連携に切り替え、不要な鍵は削除", key=f"gcp-sakey|{pid}|{k.get('name', '')[-12:]}")

    # Cloud Storage：誰でも読めるバケット
    buckets, err = _g(c, "storage", "buckets", "list", f"--project={pid}")
    if buckets is None:
        _skip_or_error(r, f"{pid} Cloud Storage", err, [("バケット", pid)])
    for bk in buckets or []:
        name = bk.get("name", "")
        if bk.get("public_access_prevention") == "enforced":
            continue
        bp, _ = _g(c, "storage", "buckets", "get-iam-policy", f"gs://{name}")
        for b in (bp or {}).get("bindings", []):
            if any(m in PUBLIC for m in b.get("members", [])):
                r.add(M, "critical", "誰でも読めるCloud Storageバケット", f"{pid} / gs://{name}", b.get("role", ""),
                      "公開が意図通りか確認。不要なら allUsers を外し、公開アクセス防止を有効に", key=f"gcp-bucket|{name}")

    # VPCファイアウォール：インターネット全体に開いた管理/DBポート
    fws, err = _g(c, "compute", "firewall-rules", "list", f"--project={pid}")
    if fws is None:
        _skip_or_error(r, f"{pid} ファイアウォール", err, [("ポート", pid)])
    for fw in fws or []:
        if fw.get("direction") != "INGRESS" or fw.get("disabled") or "0.0.0.0/0" not in fw.get("sourceRanges", []):
            continue
        hits = []
        for a in fw.get("allowed", []):
            ports = a.get("ports") or ["0-65535"]
            if a.get("IPProtocol") not in ("tcp", "all"):
                continue
            for pr in ports:
                lo, _, hi = pr.partition("-")
                lo, hi = int(lo), int(hi or lo)
                hits += [f"{p}({n})" for p, n in RISKY_PORTS.items() if lo <= p <= hi]
        if hits:
            r.add(M, "high", "インターネット全体に開いた管理/DBポート", f"{pid} / {fw.get('name')}", ", ".join(sorted(set(hits))),
                  "送信元を絞るか、IAP経由の接続に切り替える", key=f"gcp-fw|{pid}|{fw.get('name')}")

    # Cloud SQL：公開IPに全開放の許可ネットワーク
    sqls, err = _g(c, "sql", "instances", "list", f"--project={pid}")
    if sqls is None:
        _skip_or_error(r, f"{pid} Cloud SQL", err, [("Cloud SQL", pid)])
    for s in sqls or []:
        ip = (s.get("settings") or {}).get("ipConfiguration") or {}
        nets = [n.get("value") for n in ip.get("authorizedNetworks", [])]
        if ip.get("ipv4Enabled") and "0.0.0.0/0" in nets:
            r.add(M, "high", "Cloud SQL がインターネット全体から接続を受け付ける", f"{pid} / {s.get('name')}", "authorizedNetworks に 0.0.0.0/0",
                  "許可ネットワークを絞るか、Cloud SQL Auth Proxy / 非公開IPに切り替える", key=f"gcp-sql|{pid}|{s.get('name')}")
        if ip.get("ipv4Enabled") and not ip.get("requireSsl") and ip.get("sslMode") in (None, "ALLOW_UNENCRYPTED_AND_ENCRYPTED"):
            r.add(M, "low", "Cloud SQL が暗号化なしの接続も受け付ける", f"{pid} / {s.get('name')}", "",
                  "sslMode を ENCRYPTED_ONLY 以上に", key=f"gcp-sqlssl|{pid}|{s.get('name')}")
    r.cov(M, pid, "ok")
    return r
