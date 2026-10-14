"""findings.json / report.html / summary.md の生成と前回との差分。"""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from .common import SEV_JA, SEVERITIES

MOD_JA = {"mac": "Mac本体", "repos": "コード・リポジトリ", "github": "GitHub", "web": "Webサイト・Vercel", "aws": "AWS", "gmail": "メール・Googleアカウント"}
COLORS = {"critical": "#c62828", "high": "#ef6c00", "medium": "#f9a825", "low": "#1e88e5", "info": "#78909c"}


def diff(findings: list[dict], prev: list[dict] | None, failed_modules: set[str] = frozenset(),
         prev_failed: set[str] = frozenset()):
    """新規＝前回に無いキー、または重要度が上がったもの。解消＝今回消えたもの。
    取得に失敗した側のモジュールは比較しない（前回失敗→NEWにしない／今回失敗→解消にしない）。"""
    if prev is None:
        return set(), []
    order = {s: i for i, s in enumerate(SEVERITIES)}
    prev_sev = {f["key"]: f["severity"] for f in prev}
    cur_keys = {f["key"] for f in findings}
    new = {f["key"] for f in findings if f["module"] not in prev_failed and (
           f["key"] not in prev_sev or order[f["severity"]] < order.get(prev_sev[f["key"]], 99))}
    resolved = [f for f in prev if f["key"] not in cur_keys and f["severity"] != "info" and f["module"] not in failed_modules]
    return new, resolved


def write(outdir: Path, meta: dict, findings: list[dict], coverage: list[dict], new: set[str], resolved: list[dict]):
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["module"], f["title"], f["target"]))
    (outdir / "findings.json").write_text(json.dumps({"meta": meta, "findings": findings, "coverage": coverage,
                                                       "new": sorted(new), "resolved": resolved}, ensure_ascii=False, indent=1))
    (outdir / "summary.md").write_text(_md(meta, findings, coverage, new, resolved))
    (outdir / "report.html").write_text(_html(meta, findings, coverage, new, resolved))


def _counts(findings):
    return Counter(f["severity"] for f in findings)


def _md(meta, findings, coverage, new, resolved) -> str:
    c = _counts(findings)
    lines = [f"# セキュリティスキャン {meta['started']}", "",
             "■ 件数: " + " / ".join(f"{SEV_JA[s]} {c.get(s, 0)}" for s in SEVERITIES),
             f"■ 前回から新規: {len(new)}件 / 解消: {len(resolved)}件", ""]
    for s in ("critical", "high", "medium"):
        items = [f for f in findings if f["severity"] == s]
        if not items:
            continue
        lines.append(f"## {SEV_JA[s]}（{len(items)}）")
        for f in items:
            lines.append(f"- {'【NEW】' if f['key'] in new else ''}[{MOD_JA.get(f['module'], f['module'])}] {f['title']} — {f['target']}")
        lines.append("")
    errs = [x for x in coverage if x["status"] != "ok"]
    if errs:
        lines.append("## 確認できなかった項目")
        lines += [f"- [{x['module']}] {x['item']}: {x['status']} {x['message']}" for x in errs]
    return "\n".join(lines) + "\n"


def _html(meta, findings, coverage, new, resolved) -> str:
    e = html.escape
    c = _counts(findings)
    cards = "".join(
        f'<button class="card" data-sev="{s}" style="--c:{COLORS[s]}"><b>{c.get(s, 0)}</b><span>{SEV_JA[s]}</span></button>'
        for s in SEVERITIES)
    mods = sorted({f["module"] for f in findings})
    mod_btns = "".join(f'<button class="mod" data-mod="{m}">{e(MOD_JA.get(m, m))}</button>' for m in mods)
    rows = []
    for f in findings:
        badge = '<span class="new">NEW</span>' if f["key"] in new else ""
        rows.append(f'''<details class="f" data-sev="{f['severity']}" data-mod="{f['module']}" data-new="{int(f['key'] in new)}" {'open' if f['severity'] == 'critical' else ''}>
<summary><span class="sev" style="background:{COLORS[f['severity']]}">{SEV_JA[f['severity']]}</span>{badge}
<span class="mtag">{e(MOD_JA.get(f['module'], f['module']))}</span><span class="t">{e(f['title'])}</span><span class="tg">{e(f['target'])}</span></summary>
{'<pre>' + e(f['detail']) + '</pre>' if f['detail'] else ''}{'<p class="fix">対処: ' + e(f['fix']) + '</p>' if f['fix'] else ''}</details>''')
    cov_rows = "".join(
        f"<tr class='{x['status']}'><td>{e(MOD_JA.get(x['module'], x['module']))}</td><td>{e(x['item'])}</td><td>{e(x['status'])}</td><td>{e(x['message'])}</td></tr>"
        for x in sorted(coverage, key=lambda x: (x["status"] == "ok", x["module"])))
    res = "".join(f"<li>[{e(SEV_JA[f['severity']])}] {e(f['title'])} — {e(f['target'])}</li>" for f in resolved)
    return f'''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>セキュリティスキャン {e(meta['started'])}</title><style>
body{{font-family:"Hiragino Sans","Noto Sans JP",sans-serif;background:#fff;color:#1a1a1a;margin:0;padding:24px 16px;max-width:1100px;margin:auto}}
h1{{font-size:24px;margin:0 0 4px}} .demo{{font-size:12px;background:#6a1b9a;color:#fff;border-radius:6px;padding:2px 8px;margin-left:10px;vertical-align:middle}} .sub{{color:#666;font-size:13px;margin-bottom:20px}}
.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:12px}}
.card{{border:2px solid var(--c);border-radius:12px;background:#fff;padding:12px;cursor:pointer;display:flex;flex-direction:column;align-items:center;font:inherit}}
.card b{{font-size:30px;color:var(--c)}} .card span{{font-size:13px;color:#444}} .card.on{{background:var(--c)}} .card.on b,.card.on span{{color:#fff}}
.bar{{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 16px}} .mod,.tgl{{border:1px solid #ccc;background:#fafafa;border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit;font-size:13px}}
.mod.on,.tgl.on{{background:#1a1a1a;color:#fff;border-color:#1a1a1a}}
.f{{border:1px solid #e3e3e3;border-radius:10px;margin:6px 0;padding:8px 12px}} .f summary{{cursor:pointer;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}}
.sev{{color:#fff;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:700}} .new{{background:#d81b60;color:#fff;border-radius:6px;padding:1px 6px;font-size:11px;font-weight:700}}
.mtag{{font-size:12px;color:#666}} .t{{font-weight:700}} .tg{{color:#555;font-size:13px;word-break:break-all}}
pre{{background:#f6f6f6;border-radius:8px;padding:8px;white-space:pre-wrap;word-break:break-all;font-size:12px}} .fix{{font-size:13px;color:#1b5e20;margin:6px 0 2px}}
table{{border-collapse:collapse;width:100%;font-size:12px}} td{{border-bottom:1px solid #eee;padding:4px 6px;vertical-align:top}} tr.error td{{color:#c62828}} tr.skip td{{color:#8d6e00}}
h2{{font-size:18px;margin-top:28px}} @media(max-width:600px){{.cards{{grid-template-columns:repeat(3,1fr)}}}}
</style></head><body>
<h1>セキュリティスキャン結果{'<span class="demo">見本データ</span>' if meta.get('demo') else ''}</h1>
<div class="sub">実行 {e(meta['started'])}（{meta['elapsed']}秒）・対象 {e(', '.join(MOD_JA.get(m, m) for m in meta['modules']))}・前回から新規 {len(new)}件 / 解消 {len(resolved)}件</div>
<div class="cards">{cards}</div>
<div class="bar"><button class="tgl" id="onlynew">NEWだけ</button><button class="tgl on" id="hideinfo">「情報」を隠す</button>{mod_btns}</div>
<div id="list">{''.join(rows) or '<p>指摘はありません</p>'}</div>
{'<h2>前回から解消した項目</h2><ul>' + res + '</ul>' if res else ''}
<h2>確認範囲（ok / skip / error）</h2><table>{cov_rows}</table>
<script>
const st={{sev:null,mod:null,onlynew:false,hideinfo:true}};
function apply(){{document.querySelectorAll('.f').forEach(d=>{{const s=d.dataset.sev;let v=true;
if(st.sev&&s!==st.sev)v=false; if(st.mod&&d.dataset.mod!==st.mod)v=false; if(st.onlynew&&d.dataset.new!=='1')v=false;
if(st.hideinfo&&!st.sev&&s==='info')v=false; d.style.display=v?'':'none'}})}}
document.querySelectorAll('.card').forEach(b=>b.onclick=()=>{{st.sev=st.sev===b.dataset.sev?null:b.dataset.sev;document.querySelectorAll('.card').forEach(x=>x.classList.toggle('on',x.dataset.sev===st.sev));apply()}});
document.querySelectorAll('.mod').forEach(b=>b.onclick=()=>{{st.mod=st.mod===b.dataset.mod?null:b.dataset.mod;document.querySelectorAll('.mod').forEach(x=>x.classList.toggle('on',x.dataset.mod===st.mod));apply()}});
onlynew.onclick=()=>{{st.onlynew=!st.onlynew;onlynew.classList.toggle('on');apply()}};
hideinfo.onclick=()=>{{st.hideinfo=!st.hideinfo;hideinfo.classList.toggle('on');apply()}};apply();
</script></body></html>'''
