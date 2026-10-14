"""GitHub: 本人アカウントと所属orgの設定・アラート（読み取りのみ）。"""
from __future__ import annotations

from urllib.parse import urlparse

from .common import Result, run_json, short_err, tool

M = "github"


def _api(path: str, paginate: bool = False):
    cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json", path]
    if paginate:
        cmd[2:2] = ["--paginate", "--slurp"]
    data, err = run_json(cmd, 120)
    if paginate and isinstance(data, list):
        flat = []
        for page in data:
            flat += page if isinstance(page, list) else [page]
        data = flat
    return data, err


def scan(cfg: dict) -> Result:
    r = Result()
    if not tool("gh"):
        r.cov(M, "GitHub", "skip", "gh CLI が無い（brew install gh → gh auth login）")
        return r
    me, err = _api("user")
    if not me:
        r.cov(M, "gh 認証", "error", short_err(err) + "（gh auth login が必要）")
        return r
    login = me["login"]
    if "two_factor_authentication" not in me:
        r.cov(M, f"{login} 2FA", "skip", "トークンの権限では取得できない")
    elif me.get("two_factor_authentication") is False:
        r.add(M, "critical", "GitHubアカウントの2段階認証がオフ", login, "", "Settings → Password and authentication で2FAを有効化")
    else:
        r.cov(M, f"{login} 2FA", "ok")

    pubs, _ = _api(f"user/repos?visibility=public&affiliation=owner&per_page=100", paginate=True)
    for repo in pubs or []:
        r.add(M, "info", "公開リポジトリ", repo["full_name"], repo.get("description") or "",
              "意図して公開しているか確認。秘密情報の混入チェックは repos モジュールで実施", key="public|" + repo["full_name"])
        _repo_secret_alerts(r, repo["full_name"])

    orgs, _ = _api("user/orgs")
    for o in orgs or []:
        _org(r, o["login"])
    return r


def _repo_secret_alerts(r: Result, full: str):
    alerts, err = _api(f"repos/{full}/secret-scanning/alerts?state=open&per_page=100", paginate=True)
    for a in alerts or []:
        r.add(M, "critical", f"GitHubが秘密情報の漏えいを検知: {a.get('secret_type_display_name') or a.get('secret_type')}",
              full, a.get("html_url", ""), "キーを発行元で無効化→再発行し、アラートを close する", key=f"ss|{full}|{a.get('number')}")


def _org(r: Result, org: str):
    info, err = _api(f"orgs/{org}")
    if not info:
        r.cov(M, f"org {org}", "error", short_err(err))
        return
    if info.get("two_factor_requirement_enabled") is False:
        r.add(M, "high", "組織で2段階認証が必須になっていない", org, "",
              f"https://github.com/organizations/{org}/settings/security で「Require two-factor authentication」をオン（未設定メンバーは外れるので事前周知）")
    elif info.get("two_factor_requirement_enabled") is None:
        r.cov(M, f"{org} 2FA必須設定", "skip", "owner権限がないため取得不可")
    if info.get("members_can_create_public_repositories"):
        r.add(M, "medium", "メンバーが公開リポジトリを自由に作れる", org, "うっかり社内コードを公開する事故の入口",
              f"https://github.com/organizations/{org}/settings/member_privileges で public repository 作成をオフ")
    if info.get("default_repository_permission") in ("write", "admin"):
        r.add(M, "medium", f"メンバーの既定権限が {info['default_repository_permission']}", org, "",
              "Base permissions を read か none に下げ、必要なリポだけチームで付与")

    no2fa, err = _api(f"orgs/{org}/members?filter=2fa_disabled&per_page=100", paginate=True)
    for m in no2fa or []:
        r.add(M, "high", "2段階認証を設定していないメンバー", f"{org} / {m['login']}", "", "本人に2FA設定を依頼する")
    outside, _ = _api(f"orgs/{org}/outside_collaborators?per_page=100", paginate=True)
    for m in outside or []:
        r.add(M, "info", "外部コラボレーター（組織外のアカウント）", f"{org} / {m['login']}", "",
              "契約が終わった人なら削除する", key=f"outside|{org}|{m['login']}")
    hooks, _ = _api(f"orgs/{org}/hooks")
    for h in hooks or []:
        host = urlparse(h.get("config", {}).get("url", "")).hostname or "?"
        r.add(M, "info", "組織Webhook", f"{org} / {host}（ID {h.get('id')}）", f"events: {', '.join(h.get('events', []))}",
              "心当たりのない送信先なら削除", key=f"hook|{org}|{h.get('id')}")
    perms, _ = _api(f"orgs/{org}/actions/permissions")
    if perms and perms.get("allowed_actions") == "all":
        r.add(M, "low", "GitHub Actionsで任意の外部Actionが使える", org, "",
              "Settings → Actions → Allow select actions にし、GitHub製・認証済み作者に限定")

    # Dependabot（orgまとめ取得）
    alerts, err = _api(f"orgs/{org}/dependabot/alerts?state=open&per_page=100", paginate=True)
    if alerts is None:
        r.cov(M, f"{org} Dependabot", "skip", short_err(err))
    else:
        by_repo: dict[str, dict[str, int]] = {}
        for a in alerts:
            repo = a["repository"]["full_name"]
            s = (a.get("security_advisory") or {}).get("severity", "low")
            s = {"moderate": "medium"}.get(s, s)
            by_repo.setdefault(repo, {}).setdefault(s, 0)
            by_repo[repo][s] += 1
        for repo, cnt in by_repo.items():
            worst = next((s for s in ("critical", "high", "medium", "low") if cnt.get(s)), "low")
            r.add(M, worst, "Dependabotの未対応アラート", repo, " / ".join(f"{k}:{v}" for k, v in cnt.items()),
                  f"https://github.com/{repo}/security/dependabot で確認し、自動PRをマージ", key=f"dep|{repo}")
        r.cov(M, f"{org} Dependabot", "ok", f"未対応 {len(alerts)}件")

    ss, err = _api(f"orgs/{org}/secret-scanning/alerts?state=open&per_page=100", paginate=True)
    if ss is None:
        r.cov(M, f"{org} Secret scanning", "skip", "非公開リポはGitHub Advanced Security未契約だと使えない（ローカルのgitleaksで代替済み）")
    else:
        for a in ss:
            full = a["repository"]["full_name"]
            r.add(M, "critical", f"GitHubが秘密情報の漏えいを検知: {a.get('secret_type_display_name') or a.get('secret_type')}",
                  full, a.get("html_url", ""), "キーを発行元で無効化→再発行し、アラートを close する", key=f"ss|{full}|{a.get('number')}")
