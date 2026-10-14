"""共通部品: Finding / Coverage / コマンド実行。

このツールは読み取り専用。外部状態を変える API は呼ばない。
秘密値はどの出力にも載せない（gitleaks は --redact、env は名前だけ）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_JA = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}

# launchd から呼ばれても CLI が見つかるように PATH を補う
os.environ["PATH"] = ":".join([str(BIN), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", os.environ.get("PATH", "")])
os.environ.setdefault("USER", Path.home().name)
os.environ.setdefault("HOME", str(Path.home()))


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    target: str
    detail: str = ""
    fix: str = ""
    # 差分判定に使う安定キー。detail が毎回変わる項目（件数など）でも同一扱いにする
    key: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(self.severity)
        if not self.key:
            self.key = hashlib.sha1(f"{self.module}|{self.title}|{self.target}".encode()).hexdigest()[:16]

    def to_dict(self):
        return asdict(self)


WHOLE = [("*", "*")]  # モジュール全体が見えていない


@dataclass
class Coverage:
    module: str
    item: str
    status: str  # ok / skip / error
    message: str = ""
    # この確認が通らなかったときに「解消」「新規」の判定から外す指摘の範囲。
    # (タイトルに含む文字列, 対象に含む文字列) の組。省略時は対象に item を含む指摘。("*","*") はモジュール全体
    blocks: list = None

    def __post_init__(self):
        if self.blocks is None:
            self.blocks = [] if self.status == "ok" else [("", self.item)]

    def to_dict(self):
        return asdict(self)


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)

    def add(self, *a, **kw):
        self.findings.append(Finding(*a, **kw))

    def cov(self, *a, **kw):
        self.coverage.append(Coverage(*a, **kw))

    def extend(self, other: "Result"):
        self.findings += other.findings
        self.coverage += other.coverage


def tool(name: str) -> str | None:
    """同梱の bin/ を優先し、無ければ PATH から探す。見つからなければ None。"""
    local = BIN / name
    if local.exists():
        return str(local)
    return shutil.which(name)


def run(cmd: list[str], timeout: int = 120, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def run_json(cmd: list[str], timeout: int = 120, cwd: str | None = None):
    """JSON を返すコマンドを実行する。失敗時は (None, エラー文) を返す。"""
    rc, out, err = run(cmd, timeout, cwd)
    if rc != 0:
        return None, short_err((err.strip() or out.strip())[-400:])
    try:
        return json.loads(out), ""
    except json.JSONDecodeError:
        start = min([i for i in (out.find("{"), out.find("[")) if i >= 0], default=-1)
        if start >= 0:
            try:
                return json.loads(out[start:]), ""
            except json.JSONDecodeError:
                pass
        return None, "JSON parse error（応答本文は記録しない）"


_TOKENISH = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")
_ASSIGN = re.compile(r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH)[A-Z0-9_]*)\s*[=:]\s*\S+")
_URL_CRED = re.compile(r"(https?://)[^/@\s]+@")


def redact(msg: str) -> str:
    """エラー文に紛れ込んだ秘密値らしきものを伏せる（URLの認証情報・KEY=値・長いトークン列）。"""
    msg = _URL_CRED.sub(r"\1***@", msg)
    msg = _ASSIGN.sub(r"\1=***", msg)
    return _TOKENISH.sub(lambda m: m.group(0)[:4] + "***", msg)


def short_err(msg: str) -> str:
    return redact(" ".join(msg.split()))[:300]
