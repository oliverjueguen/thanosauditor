"""HTML rendering for the panel (dark theme, no template dependencies).

Keeps the look of the "Thanos Panel" from Practice 1 (P1): dark background, purple
accent and a table of aggregated artifacts with a SCORE column.
"""

from __future__ import annotations

from html import escape
from typing import Any

_STYLE = """
:root{
  --bg:#0b0d12; --panel:#12151c; --panel2:#171b24; --border:#232838;
  --fg:#e6e9ef; --muted:#8b93a7; --accent:#7c5cff; --accent2:#9d7bff;
  --p1:#ff5c7a; --p2:#ff9f45; --p3:#ffd34d; --p4:#5bd6a6;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent2);text-decoration:none} a:hover{text-decoration:underline}
header{display:flex;align-items:center;justify-content:space-between;
  padding:14px 22px;border-bottom:1px solid var(--border);background:var(--panel)}
.brand{display:flex;align-items:center;gap:10px;font-weight:700}
.dot{width:14px;height:14px;border-radius:50%;
  background:radial-gradient(circle at 30% 30%,var(--accent2),var(--accent))}
.nav a{margin-left:18px;color:var(--muted)}
main{max-width:1400px;margin:0 auto;padding:26px 22px}
h1{font-size:24px;margin:.2em 0}.sub{color:var(--muted);margin:0 0 20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;
  padding:18px 20px;margin-bottom:18px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:18px 0}
details.names{margin-top:4px;font-size:13px;color:var(--muted)}
.tag{display:inline-block;padding:1px 7px;border-radius:6px;font-size:12px;background:var(--panel2);
  color:var(--muted);border:1px solid var(--border)}
h2{font-size:19px;margin:.2em 0 .5em}
@media (min-width:900px){.scroll-hint{display:none}}
details.names summary{cursor:pointer;color:var(--accent2)}
details.names div{margin-top:4px;word-break:break-all}
.card{overflow-x:auto}
.kpi{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.kpi .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.kpi .val{font-size:28px;font-weight:700;margin-top:4px}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);font-size:14px}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
tbody tr:hover{background:var(--panel2)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.pos{color:var(--p4)} .neg{color:var(--p1)} .zero{color:var(--muted)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
.P1{background:rgba(255,92,122,.16);color:var(--p1)}
.P2{background:rgba(255,159,69,.16);color:var(--p2)}
.P3{background:rgba(255,211,77,.16);color:var(--p3)}
.P4{background:rgba(91,214,166,.16);color:var(--p4)}
.score{font-weight:700}
.drop{border:2px dashed var(--border);border-radius:12px;padding:30px;text-align:center;color:var(--muted)}
.btn{display:inline-block;background:#5b3fd6;color:#fff;border:none;border-radius:8px;
  padding:9px 16px;font-weight:600;cursor:pointer;margin-top:12px}
input[type=file]{color:var(--muted)}
.empty{color:var(--muted);padding:20px;text-align:center}
footer{color:var(--muted);text-align:center;padding:24px;font-size:12px}
"""


def _layout(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · Thanos Panel</title><style>{_STYLE}</style></head>
<body>
<header>
  <div class="brand"><span class="dot"></span> Thanos Panel</div>
  <nav class="nav"><a href="/">Cycles</a><a href="/#upload">Upload</a></nav>
</header>
<main>{body}</main>
<footer>Thanos: Windows Server 2022 patch triage · Practice 3 (P3)</footer>
</body></html>"""


def _delta(n: Any) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return '<span class="zero">-</span>'
    if n > 0:
        return f'<span class="pos">+{n}</span>'
    if n < 0:
        return f'<span class="neg">{n}</span>'
    return '<span class="zero">0</span>'


def render_error(status: int, title: str, detail: str) -> str:
    """Error page in English, without internal tracebacks."""
    body = f"""
    <div class="card" role="alert" style="border-color:var(--p1)">
      <h1>{escape(title)}</h1>
      <p class="sub">{escape(detail)}</p>
      <p><a href="/">← Back to cycles</a></p>
    </div>"""
    return _layout(f"Error {status}", body)


def render_home(
    cycles: list[dict[str, Any]],
    message: str | None = None,
    *,
    token_required: bool = False,
    is_error: bool = False,
) -> str:
    rows = ""
    for c in cycles:
        k = c["kpis"]
        rows += f"""<tr>
          <td><a href="/cycle/{escape(c['id'])}">{escape(c['patch_cycle'])}</a></td>
          <td class="mono">{escape(c.get('target_build',''))}</td>
          <td class="mono">{escape(' + '.join(c.get('kb_ids', [])))}</td>
          <td>{k['bundles']}</td>
          <td>{k['artifacts']}</td>
        </tr>"""
    if not rows:
        table = '<div class="empty">No cycles yet. Upload one or more <code>*.bundle.json</code> files.</div>'
    else:
        table = f"""<table><thead><tr>
          <th>Patch cycle</th><th>Target build</th><th>KBs</th>
          <th>Bundles</th><th>Artifacts</th></tr></thead><tbody>{rows}</tbody></table>"""

    msg = ""
    if message:
        role, color = ("alert", "var(--p1)") if is_error else ("status", "var(--accent)")
        msg = f'<div class="card" role="{role}" style="border-color:{color}">{escape(message)}</div>'
    token_field = (
        '<label for="token">Upload token</label> '
        '<input id="token" type="password" name="token" autocomplete="off" required>'
        if token_required else ""
    )

    body = f"""
    {msg}
    <h1>Patch Tuesday cycles</h1>
    <p class="sub">Aggregated bundles uploaded by the team. Choose a cycle to inspect the changed binaries.</p>
    <div class="card">{table}</div>

    <h1 id="upload">Upload bundles</h1>
    <p class="sub">Select one or more <code>*.bundle.json</code> files. The cycle is inferred from each bundle; uploading a person's bundle again replaces the previous one (a copy is kept). Only bundles that pass schema and type validation are accepted.</p>
    <div class="card">
      <form action="/upload" method="post" enctype="multipart/form-data">
        <div class="drop">
          <label for="files"><code>.bundle.json</code> files</label><br>
          <input id="files" type="file" name="files" accept=".json,application/json" multiple required>
        </div>
        {token_field}
        <button class="btn" type="submit">Upload</button>
      </form>
    </div>
    """
    return _layout("Cycles", body)


def _analysis_cell(a: dict[str, Any], source: str) -> str:
    an = a.get("analysis")
    if not an:
        return '<span class="zero">-</span>'
    title = escape(f"{source}: {an.get('rationale', '')}"[:600])
    return (f'<span class="badge {escape(an["priority"])}" title="{title}">{escape(an["priority"])}</span> '
            f'<span class="tag">{escape(an["severity"])} · conf. {escape(an["confidence"])}</span>')


def _cve_cell(a: dict[str, Any]) -> str:
    cands = a.get("cve_candidates") or []
    if not cands:
        return '<span class="zero">-</span>'
    top = max(cands, key=lambda x: x.get("cvss") or 0)
    items = "".join(
        f"<div>{escape(x['cve'])} · {escape(x.get('severity') or '')} · CVSS {escape(str(x.get('cvss')))} · "
        f"{escape(x['title'])} <span class='tag'>conf. {escape(x['confidence'])}</span></div>"
        for x in cands
    )
    return (f'<details class="names"><summary>{len(cands)} CVE · max CVSS {escape(str(top.get("cvss")))}</summary>'
            f'<div class="sub">Hypothesis based on the component name: Microsoft does not publish CVE→file.</div>{items}</details>')


def render_cycle(c: dict[str, Any], prio: str | None = None) -> str:
    k = c["kpis"]
    source = c.get("analysis_source") or ""
    counts = {p: sum(1 for a in c["artifacts"] if a["priority"] == p) for p in ("P1", "P2", "P3", "P4")}
    shown = [a for a in c["artifacts"] if not prio or a["priority"] == prio]
    bundles = "".join(
        f'<tr><td>{escape(b["person"])}</td><td class="mono">{escape(b.get("run_id",""))}</td>'
        f'<td>{b["artifact_count"]}</td><td class="mono">{escape(b.get("created_at",""))}</td></tr>'
        for b in c["bundles"]
    )
    arts = ""
    for a in shown:
        arts += f"""<tr id="{escape(a['logical_name'])}">
          <td class="mono">{escape(a['logical_name'])}{_arch_tag(a.get('arch', ''))}{_names_detail(a)}</td>
          <td><span class="badge {escape(a['priority'])}">{escape(a['priority'])}</span></td>
          <td class="score" title="P1 formula (|FN+|+|FN−|): {a.get('p1_score', '-')}">{a['score']}</td>
          <td>{_analysis_cell(a, source)}</td>
          <td>{_cve_cell(a)}</td>
          <td>{_delta(a['size_delta'])}</td>
          <td>{_added_removed(a.get('fn_added', []), a.get('fn_removed', []), a['fn_delta'], a.get('has_name_diff'))}</td>
          <td>{_delta(a['fn_delta'])}</td>
          <td>{_added_removed(a.get('exp_added', []), a.get('exp_removed', []), a['exp_delta'], a.get('has_name_diff'))}</td>
          <td>{escape(a['person'])}</td>
          <td class="mono">{escape(_short_version(a.get('version_before','')))} → {escape(_short_version(a.get('version_after','')))}</td>
        </tr>"""
    cid = escape(c.get("id", ""))
    filters = " · ".join(
        [f'<a href="/cycle/{cid}">all ({len(c["artifacts"])})</a>']
        + [f'<a href="/cycle/{cid}?prio={p}">{p} ({n})</a>' for p, n in counts.items()]
    )
    summary = escape(c.get("analysis_summary") or "")
    analysis_note = (f'<div class="card" role="status"><b>Thanos Auditor report</b> '
                     f'<span class="tag">{escape(source)}</span><p>{summary}</p></div>') if source else (
        '<div class="card" role="status">No Thanos Auditor report for this cycle: generate one with '
        '<code>python -m thanos.auditor.cli analyze … -o output/report.json</code>.</div>')

    body = f"""
    <p class="sub"><a href="/">← All cycles</a></p>
    <h1>{escape(c['patch_cycle'])}</h1>
    <p class="sub">{escape(c.get('target_product',''))} {escape(c.get('target_build',''))} ·
       KBs {escape(' + '.join(c.get('kb_ids', [])))} · {escape(c.get('provenance', ''))}</p>

    <div class="kpis">
      <div class="kpi"><div class="label">Changed binaries</div><div class="val">{k['artifacts']}</div></div>
      <div class="kpi"><div class="label">Priority P1 / P2</div><div class="val">{counts['P1']} / {counts['P2']}</div></div>
      <div class="kpi"><div class="label">With function changes</div><div class="val">{k['with_fn_diff']}</div></div>
      <div class="kpi"><div class="label">With export changes</div><div class="val">{k['with_exp_diff']}</div></div>
      <div class="kpi"><div class="label">Ghidra noise filtered</div><div class="val">{k.get('noise_filtered', 0)}</div></div>
      <div class="kpi"><div class="label">Cycle CVEs (MSRC)</div><div class="val">{k.get('cves_cycle', '-')}</div></div>
    </div>

    {analysis_note}

    <div class="card">
      <h2>Changed binaries</h2>
      <p class="sub">Filter: {filters}</p>
      <p class="sub"><b>Priority P1-P4</b> based on the heuristic <b>score</b>: P1 ≥ 200, P2 ≥ 80, P3 ≥ 20.
        Weights: export ×10, import ×3, named function ×2, change in function count ×1,
        string ×1. Ghidra auto-generated names (Unwind@, Catch@, FUN_…) are discarded.
        <b>Auditor</b>: priority, severity and confidence from the report ({escape(source or 'no report')}).
        <b>CVE</b>: MSRC bulletin candidates by component name (hypothesis), looked up in
        {escape(c.get('cve_source', ''))}.</p>
      <p class="sub scroll-hint">The table scrolls horizontally on narrow screens.</p>
      <table><thead><tr>
        <th>Binary</th><th>Priority</th><th>Score</th><th>Auditor</th><th>CVE (hypothesis)</th>
        <th>Δ size</th><th>Functions +/−</th><th>Δ functions</th><th>Exports +/−</th>
        <th>Person</th><th>Versions</th>
      </tr></thead><tbody>{arts}</tbody></table>
    </div>

    <div class="card">
      <h2>Received bundles</h2>
      <table><thead><tr><th>Person</th><th>Run id</th><th>Binaries</th><th>Created</th></tr></thead>
      <tbody>{bundles}</tbody></table>
    </div>
    """
    return _layout(c["patch_cycle"], body)


def _arch_tag(arch: str) -> str:
    """Architecture tag; highlighted when it is not the native one (amd64)."""
    if not arch or arch == "amd64":
        return ""
    return f' <span class="tag" title="package {escape(arch)}">{escape(arch)}</span>'


def _short_version(v: str) -> str:
    """'10.0.20348.4647 (WinBuild.160101.0800)' → '10.0.20348.4647'."""
    return (v or "").split(" ")[0]


def _added_removed(added: list[str], removed: list[str], net: int, has_names: bool | None) -> str:
    if not has_names:
        return _delta(net)
    if not added and not removed:
        return '<span class="zero">0</span>'
    parts = []
    if added:
        parts.append(f'<span class="pos">+{len(added)}</span>')
    if removed:
        parts.append(f'<span class="neg">−{len(removed)}</span>')
    return " ".join(parts)


def _names_detail(a: dict[str, Any]) -> str:
    """Collapsible list with the real names added/removed."""
    rows = []
    for label, key in (("+ fn", "fn_added"), ("− fn", "fn_removed"),
                       ("+ exp", "exp_added"), ("− exp", "exp_removed")):
        names = a.get(key) or []
        if names:
            shown = ", ".join(escape(n) for n in names[:40])
            more = f" … (+{len(names) - 40})" if len(names) > 40 else ""
            rows.append(f"<div><b>{label}</b> {shown}{more}</div>")
    if not rows:
        return ""
    return f'<details class="names"><summary>show names</summary>{"".join(rows)}</details>'
