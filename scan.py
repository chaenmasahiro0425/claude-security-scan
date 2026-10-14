#!/usr/bin/env python3
"""security-scan: Mac・コード・GitHub・Web/Vercel・AWS・Gmail を読み取り専用で横断チェックする。

使い方:
  security-scan                    # 全部
  security-scan --only mac,web     # 一部だけ
  security-scan --skip repos       # 重いものを外す
  security-scan --notify --open    # 新しい高リスクがあれば通知、終わったらレポートを開く
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tomllib
import traceback
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sscan import aws, azure, cloudflare, gcp, github, gmail, mac, report, repos, supabase, web  # noqa: E402
from sscan.common import ROOT, WHOLE, Result, run  # noqa: E402

MODULES = {"mac": mac, "repos": repos, "github": github, "web": web, "aws": aws, "gcp": gcp, "azure": azure,
           "cloudflare": cloudflare, "supabase": supabase, "gmail": gmail}
REPORTS = Path(os.environ.get("SECURITY_SCAN_REPORTS", ROOT / "reports"))
CONFIG_CANDIDATES = [Path.home() / ".config/security-scan/config.toml", ROOT / "config.toml"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--skip", default="")
    ap.add_argument("--config", default="", help="既定は ~/.config/security-scan/config.toml → 同梱の config.toml。無くても自動検出で動く")
    ap.add_argument("--demo", action="store_true", help="見本データでレポートだけ作る（スクショ・動作確認用。何もスキャンしない）")
    ap.add_argument("--notify", action="store_true", help="新しい緊急/高があればmacOS通知")
    ap.add_argument("--open", action="store_true", help="終了後にレポートをブラウザで開く")
    a = ap.parse_args()

    cfg_path = Path(a.config) if a.config else next((p for p in CONFIG_CANDIDATES if p.exists()), None)
    cfg = tomllib.loads(cfg_path.read_text()) if cfg_path else {}
    mods = [m for m in (a.only.split(",") if a.only else MODULES) if m and m not in a.skip.split(",")]
    if sys.platform != "darwin" and "mac" in mods and not a.only:
        mods.remove("mac")
    started = datetime.now()
    os.umask(0o077)  # レポートには弱点の一覧が入るので本人以外読めないようにする
    outdir = REPORTS / (started.strftime("%Y-%m-%d_%H%M%S") + ("_demo" if a.demo else ""))
    outdir.mkdir(parents=True, exist_ok=False)

    total = Result()
    if a.demo:
        from sscan import demo
        total = demo.result()
        mods = sorted({f.module for f in total.findings})
    for m in ([] if a.demo else mods):
        t = time.time()
        print(f"▶ {m} ...", flush=True)
        try:
            res = MODULES[m].scan(cfg)
        except Exception as e:  # noqa: BLE001  1モジュールの失敗で全体を止めない
            res = Result()
            # 例外文に秘密が混ざりうるので型名と発生箇所だけ残す
            tb = traceback.extract_tb(e.__traceback__)[-1]
            res.cov(m, "モジュール全体", "error", f"{type(e).__name__} at {Path(tb.filename).name}:{tb.lineno}", blocks=WHOLE)
            print(f"  ERROR {type(e).__name__} at {Path(tb.filename).name}:{tb.lineno}", flush=True)
        total.extend(res)
        print(f"  {len(res.findings)}件 / {time.time() - t:.0f}秒", flush=True)

    findings = [f.to_dict() for f in total.findings]
    coverage = [c.to_dict() for c in total.coverage]
    prev, prev_cov = (demo.previous(), []) if a.demo else _previous(outdir, set(mods))
    # 確認できなかった範囲は「解消」「新規」と判定しない（見えなかっただけの可能性がある）
    new, resolved = report.diff(findings, prev, coverage, prev_cov)
    meta = {"demo": a.demo, "started": started.strftime("%Y-%m-%d %H:%M"), "elapsed": int((datetime.now() - started).total_seconds()), "modules": mods}
    report.write(outdir, meta, findings, coverage, new, resolved)

    latest = REPORTS / "latest"
    if not a.demo:  # 見本は latest を上書きしない（次回の差分が壊れるため）
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(outdir.name)

    hot = [f for f in findings if f["key"] in new and f["severity"] in ("critical", "high")]
    print((outdir / "summary.md").read_text())
    print(f"レポート: {outdir / 'report.html'}")
    if a.notify and hot:
        msg = f"新しい緊急/高リスク {len(hot)}件: " + hot[0]["title"][:40]
        # 文言はスクリプトに埋め込まず argv で渡す（finding由来の文字列をAppleScriptとして解釈させない）
        run(["osascript", "-e", "on run argv", "-e", 'display notification (item 1 of argv) with title "セキュリティスキャン" sound name "Basso"',
             "-e", "end run", msg])
    if a.open:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        rc, _, err = run([opener, str(outdir / "report.html")])
        if rc != 0:
            print(f"ブラウザで開けませんでした（{opener}）: {outdir / 'report.html'}")


def _previous(current: Path, mods: set[str]):
    """同じモジュール構成で回した直近のレポートを前回とみなす（部分実行で差分が壊れないように）。"""
    for d in sorted(REPORTS.glob("20*"), reverse=True):
        if d == current or d.name.endswith("_demo") or not (d / "findings.json").exists():
            continue
        try:
            data = json.loads((d / "findings.json").read_text())
            if set(data["meta"]["modules"]) >= mods:
                return ([f for f in data["findings"] if f["module"] in mods and {"key", "severity", "title", "target"} <= f.keys()],
                        data.get("coverage", []))
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return None, []


if __name__ == "__main__":
    main()
