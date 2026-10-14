"""ローカルのgitリポジトリ: コミット履歴の秘密情報（gitleaks）・.env の追跡・依存の既知脆弱性（osv-scanner）。"""
from __future__ import annotations

import json
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .common import WHOLE, ROOT, Result, run, run_json, short_err, tool

GITLEAKS = OSV = None

M = "repos"
SKIP_DIRS = {"node_modules", ".venv", "venv", ".next", "dist", "build", ".git", "__pycache__", ".cache", "vendor", "Pods"}
ENV_TRACKED = re.compile(r"(^|/)\.env(\.[\w-]+)?$")
ENV_OK = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)


def discover(roots: list[str], exclude: list[str], max_depth: int) -> list[Path]:
    found = []
    for root in roots:
        root = Path(os.path.expanduser(root))
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            p = Path(dirpath)
            if ".git" in dirnames or ".git" in filenames:
                found.append(p)
            if len(p.parts) - base_depth >= max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not any(x in str(p / d) for x in exclude)]
    # worktree は本体と履歴を共有するので、git の共通ディレクトリごとに1つ（パスが最も短いもの）だけ残す
    by_common: dict[str, Path] = {}
    for repo in sorted(set(found), key=lambda x: (len(x.parts), str(x))):
        _, out, _ = run(["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"], 10)
        by_common.setdefault(out.strip() or str(repo), repo)
    return sorted(by_common.values())


def _remote(repo: Path) -> str:
    _, out, _ = run(["git", "-C", str(repo), "remote", "get-url", "origin"], 10)
    m = re.search(r"github\.com[:/]([^/]+/[^/\s]+?)(?:\.git)?$", out.strip())
    return m.group(1).lower() if m else ""


def _owners_and_public() -> tuple[set[str], set[str]]:
    """自分と所属orgのアカウント名、そこが持つ public リポジトリ。"""
    pub = set()
    me, _ = run_json(["gh", "api", "user", "--jq", "{login: .login}"])
    orgs, _ = run_json(["gh", "api", "user/orgs", "--jq", "[.[].login]"])
    owners = ([me["login"]] if me else []) + (orgs or [])
    for o in owners:
        data, _ = run_json(["gh", "repo", "list", o, "--visibility", "public", "--limit", "1000", "--json", "nameWithOwner"], 60)
        pub |= {d["nameWithOwner"].lower() for d in data or []}
    return {o.lower() for o in owners}, pub


DEFAULT_ROOTS = ["~/dev", "~/work", "~/projects", "~/src", "~/code", "~/Developer", "~/repos", "~/git", "~/Documents/GitHub"]


def scan(cfg: dict) -> Result:
    global GITLEAKS, OSV
    c = cfg.get("repos", {})
    r = Result()
    GITLEAKS, OSV = tool("gitleaks"), tool("osv-scanner")
    if not GITLEAKS:
        c = {**c, "gitleaks": False, "secret_dirs": []}
        r.cov(M, "gitleaks", "skip", "未インストール（scripts/install-tools.sh で入る）。秘密情報の検査を省略", blocks=[("秘密情報", "")])
    if not OSV:
        c = {**c, "osv": False}
        r.cov(M, "osv-scanner", "skip", "未インストール（scripts/install-tools.sh で入る）。依存の脆弱性検査を省略", blocks=[("依存パッケージ", "")])
    roots = c.get("roots") or [d for d in DEFAULT_ROOTS if Path(os.path.expanduser(d)).is_dir()]
    repos = discover(roots, c.get("exclude", ["/_archive/", "/node_modules/"]), c.get("max_depth", 6))
    owners, public = _owners_and_public()
    # 他者のリポジトリを手元にcloneしただけのもの（llama.cpp 等）は自分の漏えい・脆弱性ではないので外す
    theirs = [p for p in repos if owners and (rm := _remote(p)) and rm.split("/")[0] not in owners]
    repos = [p for p in repos if p not in theirs]
    r.cov(M, "対象リポジトリ", "ok", f"{len(repos)}件（他者のリポジトリ {len(theirs)}件は対象外）")
    with ThreadPoolExecutor(max_workers=c.get("workers", 4)) as ex:
        for sub in ex.map(lambda p: _safe_repo(p, public, c), repos):
            r.extend(sub)
    for d in c.get("secret_dirs", ["~/.claude/skills"]):
        _scan_dir(r, Path(os.path.expanduser(d)))
    return r


def _scan_dir(r: Result, d: Path):
    """gitで管理していない置き場（スキル等）を作業ツリーのまま検査する。"""
    if not d.is_dir():
        return
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        rp = tf.name
    try:
        rc, _, err = run([GITLEAKS, "dir", str(d), "--redact", "--no-banner", "--log-level", "error",
                          "--max-target-megabytes", "2", "--report-format", "json", "--report-path", rp, "--exit-code", "0"], 600)
        if rc != 0:
            r.cov(M, f"gitleaks {_label(d)}", "error", short_err(err[-200:]), blocks=[("ローカルの置き場", _label(d))])
            return
        by_file: dict[str, list[str]] = {}
        own_reports = str(ROOT / "reports")
        for l in json.loads(Path(rp).read_text() or "[]"):
            if l.get("File", "").startswith(own_reports):  # このツール自身のレポート（差分キーのハッシュが誤検知される）
                continue
            by_file.setdefault(l.get("File", "?"), []).append(f'{l.get("RuleID")} 行{l.get("StartLine")}')
        for f, hits in by_file.items():
            r.add(M, "medium", "ファイルに秘密情報らしき文字列（ローカルの置き場）", _label(Path(f)),
                  "値は伏せ字\n" + "\n".join(hits[:10]),
                  "本物のキーなら環境変数（~/.zshenv）へ移し、共有・公開するスキルに含めない。偽値なら無視",
                  key=f"dirleak|{f}")
        r.cov(M, f"秘密情報検査 {_label(d)}", "ok", f"{len(by_file)}ファイル")
    finally:
        Path(rp).unlink(missing_ok=True)


def _safe_repo(repo: Path, public: set[str], c: dict) -> Result:
    try:
        return _scan_repo(repo, public, c)
    except Exception as e:  # noqa: BLE001  1リポの失敗で全体を止めない
        r = Result()
        r.cov(M, _label(repo), "error", type(e).__name__, blocks=[("", _label(repo) + "  ")])
        return r


def _label(repo: Path) -> str:
    return str(repo).replace(str(Path.home()), "~")


def _scan_repo(repo: Path, public: set[str], c: dict) -> Result:
    r = Result()
    remote = _remote(repo)
    is_public = remote in public
    inactive = any(x in str(repo) for x in ("/_archive/", "/_inactive/"))
    where = _label(repo) + (f"  ({remote}・公開)" if is_public else (f"  ({remote})" if remote else "  (リモートなし)"))

    # 1) .env の追跡
    _, out, _ = run(["git", "-C", str(repo), "ls-files"], 30)
    tracked = [f for f in out.splitlines() if ENV_TRACKED.search(f) and not ENV_OK.search(f)]
    if tracked:
        r.add(M, "critical" if is_public else "high", ".env ファイルがgitに登録されている", where,
              "\n".join(tracked[:20]),
              "git rm --cached で追跡を外し .gitignore に追加。中のキーは漏れた前提でローテーションする")

    # 2) コミット履歴の秘密情報（値は redact）
    if c.get("gitleaks", True):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            rp = tf.name
        try:
            rc, _, err = run([GITLEAKS, "git", str(repo), "--redact", "--no-banner", "--log-level", "error",
                              "--report-format", "json", "--report-path", rp, "--exit-code", "0"], timeout=c.get("gitleaks_timeout", 600))
            if rc == 0:
                leaks = json.loads(Path(rp).read_text() or "[]")
                by_rule: dict[str, list[str]] = {}
                for l in leaks:
                    by_rule.setdefault(l.get("RuleID", "?"), []).append(f'{l.get("File")}:{l.get("StartLine")} ({(l.get("Commit") or "")[:7]})')
                for rule, locs in by_rule.items():
                    sev = "critical" if is_public else ("medium" if inactive else "high")
                    r.add(M, sev, f"コミット履歴に秘密情報らしき文字列: {rule}", where,
                          f"{len(locs)}箇所（値は伏せ字）\n" + "\n".join(sorted(set(locs))[:15]),
                          "①そのキーを発行元で無効化・再発行 ②テスト用の偽値なら .gitleaksignore に登録 ③公開リポなら履歴からの除去も検討（git filter-repo）",
                          key=f"leak|{repo}|{rule}")
            else:
                r.cov(M, f"gitleaks {_label(repo)}", "error", short_err(err[-200:]), blocks=[("コミット履歴", _label(repo) + "  ")])
        finally:
            Path(rp).unlink(missing_ok=True)

    # 3) 依存の既知脆弱性
    if c.get("osv", True):
        # 脆弱性ありだと exit 1 になるので rc ではなく stdout の JSON で判定する
        rc, out, err = run([OSV, "scan", "source", "-r", "--format", "json", str(repo)], timeout=c.get("osv_timeout", 300))
        try:
            data = json.loads(out[out.find("{"):]) if "{" in out else None
        except json.JSONDecodeError:
            data = None
        if data is None and rc not in (0, 128) and "No package sources found" not in (err + out):
            r.cov(M, f"osv {_label(repo)}", "error", short_err(err[-200:]), blocks=[("依存パッケージ", _label(repo) + "  ")])
        if data:
            _osv(r, data, where, is_public, inactive)
    return r


def _sev_of(group: dict) -> str:
    try:
        score = float(group.get("max_severity") or 0)
    except ValueError:
        score = 0
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _osv(r: Result, data: dict, where: str, is_public: bool, inactive: bool):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    top: list[tuple[str, str]] = []
    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            name = f'{pkg["package"]["name"]}@{pkg["package"].get("version", "")}'
            for g in pkg.get("groups", []):
                s = _sev_of(g)
                counts[s] += 1
                if s in ("critical", "high"):
                    top.append((s, f'{name}: {", ".join(g.get("aliases", g.get("ids", []))[:2])}'))
    total = sum(counts.values())
    if not total:
        return
    worst = next(s for s in ("critical", "high", "medium", "low") if counts[s])
    # 依存の脆弱性は外から突ける状態か（本番で動いているか）が分からないので1段下げ、
    # 「緊急」は公開中の漏えいなど今すぐ悪用できるものに残す。休眠リポはさらに1段下げる
    worst = {"critical": "high", "high": "medium", "medium": "low"}.get(worst, "low")
    if inactive:
        worst = {"high": "medium", "medium": "low"}.get(worst, "low")
    summary = " / ".join(f"{k}:{v}" for k, v in counts.items() if v)
    r.add(M, worst, "依存パッケージに既知の脆弱性", where,
          f"{total}件（{summary}）\n" + "\n".join(t for _, t in sorted(top)[:12]),
          "npm audit fix / pip install -U <pkg> 等で更新し、動作確認してからPR。休眠中なら archive 化も検討",
          key=f"osv|{where}")
