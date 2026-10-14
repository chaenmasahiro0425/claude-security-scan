"""Azure: 各サブスクリプションのストレージ・ネットワーク・SQL の公開設定（az の list / show のみ）。"""
from __future__ import annotations

from .common import WHOLE, Result, run_json, short_err, tool

M = "azure"
RISKY_PORTS = {22: "SSH", 3389: "RDP", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
ANY_SRC = ("*", "0.0.0.0/0", "Internet", "Any")


def _az(*args, sub: str | None = None, timeout: int = 120):
    cmd = ["az", *args, "-o", "json", "--only-show-errors"]
    if sub:
        cmd += ["--subscription", sub]
    return run_json(cmd, timeout)


def _ports(rule: dict) -> list[tuple[int, int]]:
    out = []
    for pr in [rule.get("destinationPortRange")] + (rule.get("destinationPortRanges") or []):
        if not pr:
            continue
        if pr == "*":
            out.append((0, 65535))
            continue
        lo, _, hi = str(pr).partition("-")
        try:
            out.append((int(lo), int(hi or lo)))
        except ValueError:
            pass
    return out


def scan(cfg: dict) -> Result:
    r = Result()
    c = cfg.get("azure", {})
    if not tool("az"):
        r.cov(M, "Azure", "skip", "az CLI が無い", blocks=WHOLE)
        return r
    subs, err = _az("account", "list")
    if subs is None:
        r.cov(M, "Azure", "error", short_err(err) + "（az login が必要）", blocks=WHOLE)
        return r
    subs = [s for s in subs if s.get("state") == "Enabled" and s["id"] not in c.get("exclude_subscriptions", [])]
    for s in subs:
        _sub(r, s["id"], s.get("name", s["id"]))
    if not subs:
        r.cov(M, "Azure", "skip", "有効なサブスクリプションが無い", blocks=WHOLE)
    return r


def _sub(r: Result, sid: str, name: str):
    tgt = name
    # ストレージアカウント
    sts, err = _az("storage", "account", "list", sub=sid)
    if sts is None:
        r.cov(M, f"{name} ストレージ", "error", short_err(err), blocks=[("ストレージ", tgt)])
    for a in sts or []:
        an = a.get("name")
        if a.get("allowBlobPublicAccess"):
            r.add(M, "medium", "ストレージアカウントで匿名の公開アクセスが許可されている", f"{tgt} / {an}", "allowBlobPublicAccess = true",
                  "公開が要らなければ「BLOBの匿名アクセスを許可」をオフに", key=f"az-blobpub|{an}")
        if a.get("enableHttpsTrafficOnly") is False:
            r.add(M, "high", "ストレージアカウントが暗号化なし（HTTP）の通信を受け付ける", f"{tgt} / {an}", "",
                  "「安全な転送が必須」をオンに", key=f"az-http|{an}")
        if a.get("minimumTlsVersion") in ("TLS1_0", "TLS1_1"):
            r.add(M, "low", "ストレージアカウントが古いTLSを許可", f"{tgt} / {an}", a.get("minimumTlsVersion"), "最小TLSを1.2に", key=f"az-tls|{an}")

    # ネットワークセキュリティグループ：インターネット全体に開いた管理/DBポート
    nsgs, err = _az("network", "nsg", "list", sub=sid)
    if nsgs is None:
        r.cov(M, f"{name} NSG", "error", short_err(err), blocks=[("ポート", tgt)])
    for g in nsgs or []:
        for rule in g.get("securityRules", []):
            if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
                continue
            srcs = [rule.get("sourceAddressPrefix")] + (rule.get("sourceAddressPrefixes") or [])
            if not any(s in ANY_SRC for s in srcs if s):
                continue
            hits = [f"{p}({n})" for lo, hi in _ports(rule) for p, n in RISKY_PORTS.items() if lo <= p <= hi]
            if hits:
                r.add(M, "high", "インターネット全体に開いた管理/DBポート", f"{tgt} / {g.get('name')} / {rule.get('name')}",
                      ", ".join(sorted(set(hits))), "送信元を絞るか、Azure Bastion / Just-In-Time アクセスに切り替える",
                      key=f"az-nsg|{g.get('id')}|{rule.get('name')}")

    # Azure SQL：全開放のファイアウォール規則
    sqls, err = _az("sql", "server", "list", sub=sid)
    if sqls is None:
        r.cov(M, f"{name} SQL", "error", short_err(err), blocks=[("SQL", tgt)])
    for s in sqls or []:
        rules, _ = _az("sql", "server", "firewall-rule", "list", "--server", s["name"], "--resource-group", s["resourceGroup"], sub=sid)
        for fr in rules or []:
            if fr.get("startIpAddress") == "0.0.0.0" and fr.get("endIpAddress") == "255.255.255.255":
                r.add(M, "high", "Azure SQL がインターネット全体から接続を受け付ける", f"{tgt} / {s['name']}", fr.get("name", ""),
                      "許可範囲を自社のIPに絞るか、プライベートエンドポイントへ", key=f"az-sql|{s['name']}|{fr.get('name')}")
        if s.get("publicNetworkAccess") == "Enabled" and s.get("minimalTlsVersion") in ("1.0", "1.1"):
            r.add(M, "low", "Azure SQL が古いTLSを許可", f"{tgt} / {s['name']}", s.get("minimalTlsVersion"), "最小TLSを1.2に", key=f"az-sqltls|{s['name']}")

    # Microsoft Defender for Cloud：主要な保護が無料プランのまま
    prices, _ = _az("security", "pricing", "list", sub=sid)
    items = (prices or {}).get("value", prices) if isinstance(prices, dict) else prices
    free = [p.get("name") for p in items or [] if p.get("pricingTier") == "Free" and p.get("name") in ("VirtualMachines", "StorageAccounts", "SqlServers", "KeyVaults", "AppServices")]
    if free:
        r.add(M, "low", "Microsoft Defender for Cloud の保護が無料プランのまま", tgt, "無料: " + ", ".join(free),
              "使っているリソースの種類だけでも有効化を検討（費用を確認のうえ）", key=f"az-defender|{sid}")
    r.cov(M, name, "ok")
