"""AWS: 各アカウントの基本的なセキュリティ設定（describe/list/get のみ）。"""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .common import Result, run, run_json, short_err, tool

M = "aws"
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}


def _aws(profile: str, *args, region: str | None = None, timeout: int = 90):
    cmd = ["aws", *args, "--profile", profile, "--output", "json"]
    if region:
        cmd += ["--region", region]
    return run_json(cmd, timeout)


def scan(cfg: dict) -> Result:
    r = Result()
    c = cfg.get("aws", {})
    if not tool("aws"):
        r.cov(M, "AWS", "skip", "aws CLI が無い")
        return r
    _, out, _ = run(["aws", "configure", "list-profiles"])
    profiles = [p for p in out.split() if p not in c.get("exclude_profiles", [])]
    accounts: dict[str, str] = {}
    for p in profiles:
        ident, err = _aws(p, "sts", "get-caller-identity")
        if not ident:
            msg = "SSOの期限切れ（aws sso login --profile <名前> で再ログイン）" if "expired" in err.lower() or "sso" in err.lower() else short_err(err)
            r.cov(M, p, "error", msg)
            continue
        accounts.setdefault(ident["Account"], p)
    regions = c.get("regions", ["ap-northeast-1", "us-east-1"])

    def one(item):
        acct, p = item
        sub = Result()
        _account(sub, p, acct, regions)
        sub.cov(M, f"{p} ({acct})", "ok")
        return sub

    with ThreadPoolExecutor(max_workers=c.get("workers", 6)) as ex:
        for sub in ex.map(one, accounts.items()):
            r.extend(sub)
    return r


def _account(r: Result, p: str, acct: str, regions: list[str]):
    tgt = f"{p} ({acct})"
    summ, err = _aws(p, "iam", "get-account-summary")
    if summ:
        s = summ["SummaryMap"]
        if s.get("AccountMFAEnabled") == 0:
            r.add(M, "critical", "ルートユーザーにMFAがない", tgt,
                  "Organizationsのメンバーアカウントで、ルート認証情報を一元管理機能で削除済みなら実害なし（その場合は管理アカウント側で確認）",
                  "ルートでログインしMFA（できればハードウェアキー）を登録。またはOrganizationsの『ルートアクセスの一元管理』でルート認証情報を削除")
        if s.get("AccountAccessKeysPresent"):
            r.add(M, "critical", "ルートユーザーのアクセスキーが存在する", tgt, "", "IAM → セキュリティ認証情報 からルートのアクセスキーを削除")
    else:
        r.cov(M, f"{tgt} IAM", "skip", short_err(err))

    users, _ = _aws(p, "iam", "list-users")
    now = datetime.now(timezone.utc)
    for u in (users or {}).get("Users", []):
        name = u["UserName"]
        keys, _ = _aws(p, "iam", "list-access-keys", "--user-name", name)
        for k in (keys or {}).get("AccessKeyMetadata", []):
            if k["Status"] != "Active":
                continue
            age = (now - datetime.fromisoformat(k["CreateDate"].replace("Z", "+00:00"))).days
            last, lerr = _aws(p, "iam", "get-access-key-last-used", "--access-key-id", k["AccessKeyId"])
            if last is None:
                r.cov(M, f"{tgt} / {name} キー最終使用", "error", lerr)
                continue
            used = ((last or {}).get("AccessKeyLastUsed") or {}).get("LastUsedDate")
            unused_days = (now - datetime.fromisoformat(used.replace("Z", "+00:00"))).days if used else None
            if unused_days is None or unused_days > 90:
                r.add(M, "medium", "使われていない有効なアクセスキー", f"{tgt} / {name}",
                      f"作成{age}日前・最終使用 {'なし' if unused_days is None else f'{unused_days}日前'}（キーIDは伏せる: …{k['AccessKeyId'][-4:]}）",
                      "不要なら無効化→削除", key="key|" + hashlib.sha1(k["AccessKeyId"].encode()).hexdigest()[:12])
            elif age > 365:
                r.add(M, "medium", "1年以上ローテーションしていないアクセスキー", f"{tgt} / {name}",
                      f"作成{age}日前（…{k['AccessKeyId'][-4:]}）", "新しいキーを発行して差し替え→旧キー削除。可能ならIAMロール/SSOへ",
                      key="key|" + hashlib.sha1(k["AccessKeyId"].encode()).hexdigest()[:12])
        login, _ = _aws(p, "iam", "get-login-profile", "--user-name", name)
        if login:
            mfa, merr = _aws(p, "iam", "list-mfa-devices", "--user-name", name)
            if mfa is None:
                r.cov(M, f"{tgt} / {name} MFA", "error", merr)
            elif not mfa.get("MFADevices"):
                r.add(M, "high", "コンソールログインできるのにMFAがないIAMユーザー", f"{tgt} / {name}", "", "MFAを登録させるか、コンソールパスワードを削除")

    # S3
    pab, err = _aws(p, "s3control", "get-public-access-block", "--account-id", acct)
    cfgp = (pab or {}).get("PublicAccessBlockConfiguration", {})
    if not cfgp or not all(cfgp.values()):
        r.add(M, "medium", "アカウント全体の「S3パブリックアクセスブロック」が有効になっていない", tgt,
              str(cfgp) if cfgp else "未設定", "意図して公開するバケットがなければ、アカウント単位で4項目すべてオンに")
    buckets, _ = _aws(p, "s3api", "list-buckets")
    for b in (buckets or {}).get("Buckets", []):
        st, _ = _aws(p, "s3api", "get-bucket-policy-status", "--bucket", b["Name"], timeout=30)
        if st and st.get("PolicyStatus", {}).get("IsPublic"):
            r.add(M, "critical", "誰でも読めるS3バケット", f"{tgt} / s3://{b['Name']}", "バケットポリシーが公開",
                  "公開が意図通りか確認。静的サイト配信ならCloudFront+OACに切り替えて非公開に", key=f"s3pub|{b['Name']}")
        acl, _ = _aws(p, "s3api", "get-bucket-acl", "--bucket", b["Name"], timeout=30)
        for g in (acl or {}).get("Grants", []):
            if "AllUsers" in str(g.get("Grantee", {}).get("URI", "")) or "AuthenticatedUsers" in str(g.get("Grantee", {}).get("URI", "")):
                r.add(M, "critical", "ACLで公開されているS3バケット", f"{tgt} / s3://{b['Name']}", str(g.get("Permission")),
                      "ACLを無効化（Object Ownership = BucketOwnerEnforced）", key=f"s3acl|{b['Name']}")

    # 監査ログ
    trails, _ = _aws(p, "cloudtrail", "describe-trails", region=regions[0])
    tl = (trails or {}).get("trailList", [])
    logging = False
    for t in tl:
        st, _ = _aws(p, "cloudtrail", "get-trail-status", "--name", t["TrailARN"], region=t.get("HomeRegion", regions[0]))
        logging |= bool((st or {}).get("IsLogging"))
    if trails is not None and not logging:
        r.add(M, "medium", "CloudTrail（操作ログ）が記録されていない", tgt, "", "全リージョンのマルチリージョン証跡を1本作る（侵害時の調査に必須）")

    for region in regions:
        gd, _ = _aws(p, "guardduty", "list-detectors", region=region)
        if gd is not None and not gd.get("DetectorIds"):
            r.add(M, "low", "GuardDuty（脅威検知）が無効", f"{tgt} / {region}", "", "コストを確認のうえ有効化を検討", key=f"gd|{acct}|{region}")
        sgs, _ = _aws(p, "ec2", "describe-security-groups", region=region)
        for sg in (sgs or {}).get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                open_world = any(x.get("CidrIp") == "0.0.0.0/0" for x in perm.get("IpRanges", [])) or \
                    any(x.get("CidrIpv6") == "::/0" for x in perm.get("Ipv6Ranges", []))
                if not open_world:
                    continue
                lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                if perm.get("IpProtocol") == "-1":
                    lo, hi = 0, 65535
                hits = [f"{port}({n})" for port, n in RISKY_PORTS.items() if lo <= port <= hi]
                if hits:
                    r.add(M, "high", "インターネット全体に開いた管理/DBポート", f"{tgt} / {region} / {sg['GroupId']} {sg.get('GroupName', '')}",
                          ", ".join(hits), "送信元を自社IPやVPNに絞るか、SSM Session Managerに切り替えて閉じる", key=f"sg|{sg['GroupId']}|{lo}-{hi}")
        dbs, _ = _aws(p, "rds", "describe-db-instances", region=region)
        for db in (dbs or {}).get("DBInstances", []):
            if db.get("PubliclyAccessible"):
                r.add(M, "high", "インターネットから到達可能なRDS", f"{tgt} / {region} / {db['DBInstanceIdentifier']}", "",
                      "PubliclyAccessible を false にしてVPC内からのみ接続")
            if not db.get("StorageEncrypted"):
                r.add(M, "medium", "暗号化されていないRDS", f"{tgt} / {region} / {db['DBInstanceIdentifier']}", "",
                      "暗号化スナップショット経由で暗号化インスタンスへ移行")
