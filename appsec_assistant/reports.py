from __future__ import annotations

import base64
import hashlib
import html
import json
import unicodedata
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .models import LIMITATIONS, REVIEW_CHECKLIST, ScanResult
from .rules import RULES
from .navigation import GUIDANCE


def plain(value):
    """Prevent filenames and metadata from injecting terminal control sequences."""
    return "".join(c if c in "\n\t" or not unicodedata.category(c).startswith("C") else "?" for c in str(value))


def text_report(result: ScanResult):
    data = result.to_dict()
    summary = data["summary"]
    lines = [f"APPSEC ASSISTANT {__version__}", f"Target: {result.target}",
             f"Scan: {'completed within supported scope' if result.complete else 'INCOMPLETE — see diagnostics'}",
             f"Files analyzed: {result.files_scanned}; files skipped: {result.files_skipped}",
             f"New: {summary['new']} | Existing: {summary['existing']} | Suppressed: {summary['suppressed']} | Filtered: {result.filtered_findings}",
             "Severity (new): " + ", ".join(f"{s}={n}" for s, n in summary["by_severity"].items()),
             f"Likely vulnerabilities: {summary['likely_vulnerabilities']} | Review hotspots (medium+ confidence): {summary['review_findings_medium_plus']} | Low-confidence hotspots: {summary['low_confidence_hotspots']}", ""]
    lines += ["WHERE TO START (up to 20 scopes; ordering is a triage aid, not a risk score)"]
    for item in result.review_queue[:20]:
        lines += [f"  {item['path']}:{item['line']}  {item['function']}", f"    {item['reason']}"]
    if len(result.review_queue) > 20:
        lines.append(f"  +{len(result.review_queue) - 20} more scopes (available in JSON, HTML and SARIF)")
    lines += ["", "FINDINGS"]
    for group in result.finding_groups:
        f = group.primary
        lines += [f"[{f.classification} / {f.severity.upper()} / {f.confidence} confidence / {f.status}] {f.rule_id}: {f.title}",
                  f"  {f.path}:{f.line}:{f.column}  {f.cwe}  ({f.engine})", f"  Evidence: {f.message}",
                  f"  Scope: {f.function}",
                  f"  Fix: {f.remediation}", f"  Verify: {f.review}"]
        lines.append("  Locations: " + ", ".join(f"{v.line}:{v.column}" for v in group.locations))
        if f.trace:
            lines.append("  Flow: " + " → ".join(f"line {t.line}: {t.label}" for t in f.trace))
        if f.suppression_reason:
            lines.append(f"  Suppression: {f.suppression_reason}")
        lines += [f"  Fingerprint: {f.fingerprint}", f"  Reference: {f.reference}", ""]
    if not result.findings:
        lines.append("No findings under the selected rules and filters. This is not a security assurance.\n")
    lines += ["CODE MAP (first 100 entries; JSON/HTML include the full map)"]
    for m in result.code_map[:100]:
        lines.append(f"  [{m['kind']}] {m['path']}:{m['line']}  {m['category']} · {m['name']}  ({m['function']})")
    lines += ["", "FILE INVENTORY"]
    lines.extend(f"  {f['path']} — {f['language']} — {f['analysis']}" for f in result.file_inventory)
    if result.diagnostics:
        lines.append("DIAGNOSTICS")
        lines.extend(f"  {'INCOMPLETE' if d['incomplete'] else 'INFO'} {d['path']}: {d['reason']}" for d in result.diagnostics)
    lines += ["", f"DEPENDENCY INVENTORY: {len(result.inventory)} declarations; advisory status NOT CHECKED"]
    lines.extend(f"  {d['ecosystem']} {d['name']} {d['specifier']} ({d['path']}; {d['group']})" for d in result.inventory)
    lines += ["", "MANUAL REVIEW"] + [f"  • {s}" for s in REVIEW_CHECKLIST]
    lines += ["", "LIMITATIONS"] + [f"  • {s}" for s in LIMITATIONS]
    return plain("\n".join(lines)) + "\n"


def sarif_report(result: ScanResult):
    ids = sorted({f.rule_id for f in result.findings})
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules = []
    for id in ids:
        r = RULES[id]
        rules.append({"id": id, "name": id, "shortDescription": {"text": r.title},
                      "helpUri": r.reference, "help": {"text": r.remediation + " " + r.review},
                      "defaultConfiguration": {"level": level[r.severity]},
                      "properties": {"tags": ["security", f"CWE-{r.cwe}"]}})
    results = []
    for group in result.finding_groups:
        f = group.primary
        def loc(line, column=1, message=None):
            item = {"physicalLocation": {"artifactLocation": {"uri": quote(f.path, safe="/"), "uriBaseId": "%SRCROOT%"},
                                         "region": {"startLine": line, "startColumn": column}}}
            if message:
                item["message"] = {"text": message}
            return item
        item = {"ruleId": f.rule_id, "ruleIndex": ids.index(f.rule_id), "level": level[f.severity],
                "message": {"text": f.message + " Remediation: " + f.remediation},
                "rank": group.rank,
                "locations": [loc(v.line, v.column) for v in group.locations],
                "partialFingerprints": {"appsecAssistant/v1": f.fingerprint},
                "baselineState": "unchanged" if f.status == "existing" else "new",
                "properties": {"severity": f.severity, "confidence": f.confidence, "engine": f.engine, "review": f.review,
                               "classification": f.classification, "function": f.function,
                               "occurrenceFingerprints": [v.fingerprint for v in group.locations]}}
        flows = [{"threadFlows": [{"locations": [{"location": loc(t.line, message=t.label)} for t in v.trace]}]} for v in group.locations if v.trace]
        if flows:
            item["codeFlows"] = flows
        if f.status == "suppressed":
            item["suppressions"] = [{"kind": "external", "status": "accepted", "justification": f.suppression_reason}]
        results.append(item)
    invocation = {"executionSuccessful": result.complete, "toolExecutionNotifications": [
        {"level": "error" if d["incomplete"] else "note", "message": {"text": f"{d['path']}: {d['reason']}"}}
        for d in result.diagnostics
    ]}
    run = {"tool": {"driver": {"name": "AppSec Assistant", "version": __version__, "rules": rules}},
           "columnKind": "unicodeCodePoints", "results": results, "invocations": [invocation],
           "properties": {"coverage": result.coverage, "limitations": LIMITATIONS, "policy": result.policy,
                          "filteredFindings": result.filtered_findings, "manualReview": REVIEW_CHECKLIST,
                          "codeMap": result.code_map, "reviewQueue": result.review_queue,
                          "fileInventory": result.file_inventory, "dependencyInventory": result.inventory}}
    if result.target != "standard input":
        target = Path(result.target)
        root = target if target.is_dir() else target.parent
        run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": root.as_uri().rstrip("/") + "/"}}
    return json.dumps({"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
                       "version": "2.1.0", "runs": [run]}, indent=2) + "\n"


SCRIPT = """const q=document.querySelector('#search'),s=document.querySelector('#severity'),t=document.querySelector('#status');
function filter(){let n=0;document.querySelectorAll('.finding').forEach(el=>{const ok=(!s.value||el.dataset.severity===s.value)&&(!t.value||el.dataset.status===t.value)&&el.textContent.toLowerCase().includes(q.value.toLowerCase());el.hidden=!ok;if(ok)n++;});document.querySelector('#visible').textContent=n+' findings shown';}
[q,s,t].forEach(el=>el.addEventListener('input',filter));filter();
const mq=document.querySelector('#map-search'),mc=document.querySelector('#map-category');
function mapFilter(){document.querySelector('#map-inputs').open=!!mq.value||mc.value==='input'||mc.value==='state';document.querySelectorAll('.map-row').forEach(el=>{el.hidden=!(el.textContent.toLowerCase().includes(mq.value.toLowerCase())&&(!mc.value||el.dataset.category===mc.value));});}
[mq,mc].forEach(el=>el.addEventListener('input',mapFilter));"""
CSS = """*{box-sizing:border-box}body{margin:0;background:#f3f5f8;color:#19243a;font:15px/1.6 system-ui,-apple-system,sans-serif}header{background:#122139;color:#fff;padding:42px max(24px,calc((100vw - 1120px)/2))}header small{color:#83d9cd;letter-spacing:.16em;font-weight:700}h1{font-size:36px;letter-spacing:-.035em;margin:10px 0}h2{font-size:21px;letter-spacing:-.02em}h3{margin:9px 0}p{margin:8px 0}.subtitle{color:#c5cfde;overflow-wrap:anywhere}.wrap{max-width:1168px;padding:26px 24px 70px;margin:auto}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px}.stat,.panel,.finding{background:#fff;border:1px solid #dfe4ec;border-radius:12px;padding:20px}.stat strong{display:block;font-size:30px}.stat span{color:#59677b}.notice{padding:15px 20px;margin:20px 0;background:#e8eef7;border-left:4px solid #5476a5;border-radius:4px}.incomplete{background:#fff0db;border-color:#b96d0a}.toolbar{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0 10px}input,select{font:inherit;padding:11px;border:1px solid #b5c1d1;border-radius:7px;background:white;max-width:100%}input{flex:1;min-width:220px}.finding{margin:14px 0;border-left:5px solid #75869c;overflow-wrap:anywhere}.finding[data-severity=high],.finding[data-severity=critical]{border-left-color:#c34646}.finding[data-severity=medium]{border-left-color:#c28c2c}.badges{display:flex;gap:8px;flex-wrap:wrap}.badge{font-size:11px;text-transform:uppercase;font-weight:750;letter-spacing:.07em;padding:3px 8px;background:#edf1f6;border-radius:4px}.high,.critical{background:#fce6e4;color:#a92d2d}.medium{background:#fff1d9;color:#865700}.meta,.muted{color:#66748a;font-size:13px}a{color:#235d96}dl{display:grid;grid-template-columns:90px 1fr;gap:10px}dt{font-weight:700}dd{margin:0}.flow{padding:12px 20px;background:#f5f7fa;border-radius:6px}code{font-size:12px;word-break:break-all}.panel{margin:24px 0}summary{cursor:pointer;font-weight:650}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:10px;border-bottom:1px solid #e3e8ef;overflow-wrap:anywhere}.scroll{overflow:auto}footer{color:#66748a;font-size:12px;margin-top:32px}[hidden]{display:none!important}:focus-visible{outline:3px solid #458ab8;outline-offset:3px}@media(max-width:650px){.stats{grid-template-columns:repeat(2,1fr)}header{padding:28px 24px}h1{font-size:30px}dl{grid-template-columns:1fr;gap:4px}dd{margin-bottom:10px}}@media print{header{background:#fff;color:#19243a}.toolbar{display:none}.finding{break-inside:avoid}.wrap{padding:0}.panel{break-inside:avoid}}"""


def html_report(result: ScanResult):
    def esc(v):
        return html.escape(plain(v), quote=True)
    def scope_label(item):
        return "<file>" if item["function"] == f"<file: {item['path']}>" else item["function"]
    data = result.to_dict()
    summary = data["summary"]
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    cards = []
    for group in result.finding_groups:
        f = group.primary
        flow = ""
        if f.trace:
            flow = '<ol class="flow">' + "".join(f"<li><strong>Line {t.line}</strong> · {esc(t.label)}</li>" for t in f.trace) + "</ol>"
        locations = ", ".join(f"{v.line}:{v.column}" for v in group.locations)
        identities = "".join(f"<li>Line {v.line}:{v.column} · {esc(v.confidence)} confidence · <code>{v.fingerprint}</code></li>" for v in group.locations)
        suppression = f"<p><strong>Suppression reason:</strong> {esc(f.suppression_reason)}</p>" if f.suppression_reason else ""
        cards.append(f'''<article class="finding" data-severity="{f.severity}" data-status="{f.status}">
<div class="badges"><span class="badge {f.severity}">{f.severity}</span><span class="badge">{f.classification}</span><span class="badge">{f.confidence} confidence</span><span class="badge">{f.status}</span><span class="badge">{f.rule_id}</span></div>
<h3>{esc(f.title)}</h3><p class="meta">{esc(f.path)} : {f.line} : {f.column} · {esc(f.function)} · {f.engine} · <a href="{f.reference}" rel="noreferrer">{f.cwe}</a></p>
<p class="meta">{len(group.locations)} location(s): {locations} · Triage rank {group.rank:.2f}</p><dl><dt>Evidence</dt><dd>{esc(f.message)}</dd><dt>Remediation</dt><dd>{esc(f.remediation)}</dd><dt>Verify</dt><dd>{esc(f.review)}</dd></dl>{flow}{suppression}
<details><summary class="muted">Location identities</summary><ul>{identities}</ul></details></article>''')
    diagnostics = "".join(f"<li><strong>{'Incomplete' if d['incomplete'] else 'Info'}</strong> · {esc(d['path'])}: {esc(d['reason'])}</li>" for d in result.diagnostics)
    inventory = "".join(f"<tr><td>{esc(d['ecosystem'])}</td><td>{esc(d['name'])}</td><td>{esc(d['specifier'])}</td><td>{esc(d['group'])}</td><td>{esc(d['path'])}</td></tr>" for d in result.inventory)
    # Fold repeated symbols into line lists; show review guidance once per category.
    mapped = {}
    for m in result.code_map:
        key = (m["path"], m["function"], m.get("scope_start", 0), m["category"], m["name"])
        row = mapped.setdefault(key, {**m, "lines": set()})
        row["lines"].add(m["line"])
    def map_table(rows):
        body = "".join(f'<tr class="map-row" data-category="{esc(m["category"])}"><td>{esc(m["path"])}:{", ".join(map(str, sorted(m["lines"])))}</td><td>{esc(m["category"])}</td><td>{esc(m["name"])}</td><td>{esc(scope_label(m))}</td></tr>' for m in rows)
        return '<div class="scroll"><table><thead><tr><th>Location(s)</th><th>Category</th><th>Symbol</th><th>Scope</th></tr></thead><tbody>' + body + '</tbody></table></div>'
    collapsed = {"input", "state"}
    map_rows = map_table([m for m in mapped.values() if m["category"] not in collapsed])
    inputs = [m for m in mapped.values() if m["category"] in collapsed]
    map_rows += f'<details id="map-inputs"><summary>Input and state locations ({sum(len(m["lines"]) for m in inputs)})</summary>{map_table(inputs)}</details>'
    guidance = "".join(f'<li><strong>{esc(c)}:</strong> {esc(GUIDANCE[c])}</li>' for c in sorted({m["category"] for m in result.code_map}))
    map_rows += f'<details><summary>Review guidance by category</summary><ul>{guidance}</ul></details>'
    map_options = "".join(f'<option>{esc(c)}</option>' for c in sorted({m["category"] for m in result.code_map}))
    file_rows = "".join(f'<tr><td>{esc(f["path"])}</td><td>{esc(f["language"])}</td><td>{esc(f["analysis"])}</td></tr>' for f in result.file_inventory)
    queue_items = [f'<li><strong>{esc(m["path"])}:{m["line"]} · {esc(scope_label(m))}</strong><p>{esc(m["reason"])}</p></li>' for m in result.review_queue]
    queue = "".join(queue_items[:20])
    more_scopes = (f'<details><summary>+{len(queue_items) - 20} more scopes</summary><ol start="21">' + "".join(queue_items[20:]) + "</ol></details>") if len(queue_items) > 20 else ""
    coverage = ", ".join(f"{esc(k)}: {v}" for k, v in result.coverage.items()) or "No supported files analyzed"
    outcome = "Completed within supported scope" if result.complete else "Incomplete scan — review diagnostics before using these results"
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; base-uri 'none'; form-action 'none'">
<title>AppSec Assistant · Security review</title><style>{CSS}</style></head><body>
<header><small>APPSEC ASSISTANT / LOCAL CODE REVIEW</small><h1>Security review workspace</h1><p class="subtitle">{esc(result.target)}</p><p class="subtitle">Evidence, remediation and questions for the analyst.</p></header>
<main class="wrap"><div class="stats"><div class="stat"><strong>{summary['new']}</strong><span>New findings</span></div><div class="stat"><strong>{summary['likely_vulnerabilities']}</strong><span>Likely vulnerabilities</span></div><div class="stat"><strong>{summary['review_findings_medium_plus']}</strong><span>Review hotspots (medium+ confidence)</span></div><div class="stat"><strong>{summary['low_confidence_hotspots']}</strong><span>Low-confidence hotspots</span></div><div class="stat"><strong>{result.files_scanned}</strong><span>Files analyzed</span></div><div class="stat"><strong>{summary['existing'] + summary['suppressed']}</strong><span>Existing / suppressed</span></div></div>
<div class="notice {'incomplete' if not result.complete else ''}"><strong>{outcome}</strong><p>{coverage}. {result.files_skipped} files skipped; {result.test_files_excluded} test files excluded; {result.vendored_files_excluded} vendored/generated/minified files excluded; {result.filtered_findings} findings excluded by severity/confidence filters.</p><p>Findings require validation. A clean report is not evidence that an application is secure.</p></div>
<section class="panel"><h2>Where to start</h2><p>{summary['entry_points']} entry points · {summary['navigation_hotspots']} navigation hotspots · {summary['functions']} function declarations. The order below is a review aid, not a risk score.</p><ol>{queue or '<li>No review locations identified by the supported checks.</li>'}</ol>{more_scopes}</section>
<section class="panel"><h2>Reading the labels</h2><p><strong>Likely vulnerability:</strong> a rule has stronger evidence, such as traced input or an explicit verification bypass; validate the context. <strong>Review hotspot:</strong> a suspicious pattern or sensitive API needs inspection. <strong>Note:</strong> a function declaration or potential mitigation; mitigation notes do not establish safety. No label means confirmed exploitability.</p></section>
<h2>Findings</h2><div class="toolbar"><input id="search" type="search" placeholder="Search findings, paths, or CWE…" aria-label="Search findings"><select id="severity" aria-label="Filter severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="status" aria-label="Filter status"><option value="">All statuses</option><option>new</option><option>existing</option><option>suppressed</option></select></div><p class="muted" id="visible" aria-live="polite">{len(cards)} findings</p>
{''.join(cards) or '<div class="panel">No findings under the selected rules and filters.</div>'}
<section class="panel"><h2>Code map</h2><p>Sensitive APIs can be used safely. These locations help you navigate; their presence does not establish a vulnerability. Non-Python locations and scopes are approximate.</p><div class="toolbar"><input id="map-search" type="search" placeholder="Search function, API, or file…" aria-label="Search code map"><select id="map-category" aria-label="Filter code map category"><option value="">All categories</option>{map_options}</select></div>{map_rows}</section>
<section class="panel"><details><summary>File inventory ({len(result.file_inventory)})</summary><div class="scroll"><table><thead><tr><th>File</th><th>Language</th><th>Analysis</th></tr></thead><tbody>{file_rows}</tbody></table></div></details></section>
<section class="panel"><h2>Manual review agenda</h2><ul>{''.join('<li>'+esc(s)+'</li>' for s in REVIEW_CHECKLIST)}</ul></section>
<section class="panel"><h2>Dependency inventory</h2><p>Declared dependencies only. Vulnerability advisories, resolved versions and transitive dependencies were not checked.</p><div class="scroll"><table><thead><tr><th>Ecosystem</th><th>Package</th><th>Specifier</th><th>Group</th><th>Manifest</th></tr></thead><tbody>{inventory}</tbody></table></div>{'<p class="muted">No supported dependency declarations found.</p>' if not inventory else ''}</section>
<section class="panel"><details {'open' if not result.complete else ''}><summary>Diagnostics ({len(result.diagnostics)})</summary><ul>{diagnostics or '<li>No read or parser diagnostics.</li>'}</ul></details></section>
<section class="panel"><h2>Scope and limitations</h2><ul>{''.join('<li>'+esc(s)+'</li>' for s in LIMITATIONS)}</ul><details><summary>Applied scan policy</summary><pre>{esc(json.dumps(result.policy, indent=2))}</pre></details></section>
<footer>AppSec Assistant {__version__} · {result.elapsed_seconds:.3f}s · Offline analysis · Source snippets and detected credential values are omitted.</footer></main><script>{SCRIPT}</script></body></html>'''


def render(result: ScanResult, format: str):
    if format == "json":
        return json.dumps(result.to_dict(), indent=2) + "\n"
    if format == "sarif":
        return sarif_report(result)
    if format == "html":
        return html_report(result)
    return text_report(result)
