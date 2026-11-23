"""
Milestone 3: Advanced Exporters
================================
Provides render functions for Markdown, HTML, SARIF, and JSON output formats.
All formats share the same redaction guarantee: sensitive fields that have
already been redacted by ``explorer.replay._redact`` remain ``<redacted>``
throughout every export path, so no secondary redaction sweep is required here.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Hidden API Attack-Surface Explorer"
TOOL_VERSION = "0.1.0"
TOOL_URI = "https://github.com/example/vapt-el"

SEVERITY_SARIF = {
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Badge colours used in the HTML report
BADGE_COLOUR = {
    "high": "#d93f0b",
    "medium": "#e4a200",
    "low": "#0075ca",
    "info": "#0075ca",
}


# ---------------------------------------------------------------------------
# JSON (passthrough)
# ---------------------------------------------------------------------------


def to_json(report: dict[str, Any], *, indent: int = 2) -> str:
    """Serialise *report* to a pretty-printed JSON string."""
    return json.dumps(report, indent=indent, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_severity_badge(severity: str) -> str:
    return f"**[{severity.upper()}]**"


def _md_table_row(*cells: str) -> str:
    return "| " + " | ".join(cells) + " |"


def to_markdown(report: dict[str, Any]) -> str:
    """Return a Markdown string summarising *report*."""
    meta = report.get("metadata", {})
    summary = report.get("summary", {})
    endpoints = report.get("endpoints", [])
    findings = report.get("findings", [])

    lines: list[str] = []

    # Header ----------------------------------------------------------------
    lines += [
        f"# {TOOL_NAME} – Security Report",
        "",
        f"**Target:** `{meta.get('target', 'N/A')}`  ",
        f"**Generated:** {meta.get('generated_at', 'N/A')}  ",
        f"**Safety mode:** {meta.get('safety_mode', 'N/A')}  ",
        f"**Tool version:** {meta.get('version', TOOL_VERSION)}",
        "",
    ]

    # Summary ---------------------------------------------------------------
    lines += [
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        _md_table_row("Endpoints discovered", str(summary.get("endpoint_count", 0))),
        _md_table_row("Undocumented endpoints", str(summary.get("undocumented_count", 0))),
        _md_table_row("Endpoints tested", str(summary.get("tested_count", 0))),
        _md_table_row("Findings", str(summary.get("finding_count", 0))),
        "",
    ]

    # Findings --------------------------------------------------------------
    if findings:
        lines += ["## Findings", ""]
        for finding in findings:
            sev = finding.get("severity", "medium")
            lines += [
                f"### {finding['id']} – {finding['title']}",
                "",
                f"- **Severity:** {_md_severity_badge(sev)}",
                f"- **Category:** {finding.get('category', 'N/A')}",
                f"- **Endpoint:** `{finding.get('endpoint', 'N/A')}`",
                f"- **Unexpected identities:** {', '.join(f'`{i}`' for i in finding.get('unexpected_identities', []))}",
                f"- **Confidence:** {finding.get('confidence', 'N/A')}",
                "",
                f"**Remediation:** {finding.get('remediation', '')}",
                "",
                "#### Evidence",
                "",
                "| Identity | HTTP status | Body SHA-256 |",
                "|----------|-------------|--------------|",
            ]
            for ev in finding.get("evidence", []):
                lines.append(
                    _md_table_row(
                        f"`{ev.get('identity', '')}`",
                        str(ev.get("status", "")),
                        f"`{ev.get('body_sha256', '')}`",
                    )
                )
            lines.append("")
    else:
        lines += ["## Findings", "", "_No findings – all tested policies passed._", ""]

    # Endpoints inventory ---------------------------------------------------
    lines += [
        "## Endpoint Inventory",
        "",
        "| Key | Sources | Undocumented | Policy |",
        "|-----|---------|--------------|--------|",
    ]
    for ep in endpoints:
        sources = ", ".join(ep.get("sources", []))
        undoc = "⚠️ Yes" if ep.get("undocumented") else "No"
        policy = ep.get("policy")
        policy_cell = (
            f"{policy['permission']} on `{policy['object']}`" if policy else "_none_"
        )
        lines.append(
            _md_table_row(f"`{ep['key']}`", sources, undoc, policy_cell)
        )

    lines.append("")

    # Observations detail ---------------------------------------------------
    obs_sections: list[str] = []
    for ep in endpoints:
        obs_list = ep.get("observations", [])
        if not obs_list:
            continue
        obs_sections += [
            f"### `{ep['key']}` – Observation Detail",
            "",
            "| Identity | Role | Status | Expected | Body (redacted) |",
            "|----------|------|--------|----------|-----------------|",
        ]
        for obs in obs_list:
            body_preview = json.dumps(obs.get("body", ""), ensure_ascii=False)
            if len(body_preview) > 120:
                body_preview = body_preview[:120] + "…"
            obs_sections.append(
                _md_table_row(
                    f"`{obs.get('identity', '')}`",
                    obs.get("role", ""),
                    str(obs.get("status", obs.get("error", ""))),
                    obs.get("expected", ""),
                    body_preview,
                )
            )
        obs_sections.append("")

    if obs_sections:
        lines += ["## Observation Details", ""] + obs_sections

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
  :root { --red: #d93f0b; --amber: #e4a200; --blue: #0075ca; --green: #2ea043;
          --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9;
          --text-muted: #8b949e; --text-heading: #f0f6fc; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background: var(--bg); color: var(--text); padding: 2rem 1rem; }
  h1,h2,h3 { color: var(--text-heading); margin-bottom: .5rem; }
  h1 { font-size: 1.75rem; border-bottom: 1px solid var(--border); padding-bottom: .5rem; }
  h2 { font-size: 1.25rem; margin-top: 2rem; }
  h3 { font-size: 1rem; margin-top: 1.5rem; }
  .meta { color: var(--text-muted); font-size: .85rem; margin-top: .25rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit,minmax(170px,1fr));
           gap: 1rem; margin: 1rem 0; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
          padding: 1rem; text-align: center; }
  .card .num { font-size: 2rem; font-weight: 700; color: var(--text-heading); }
  .card .label { color: var(--text-muted); font-size: .8rem; margin-top: .25rem; }
  table { width: 100%; border-collapse: collapse; margin-top: .75rem; font-size: .875rem; }
  th,td { text-align: left; padding: .5rem .75rem; border: 1px solid var(--border); }
  th { background: var(--surface); color: var(--text-heading); }
  tr:nth-child(even) { background: rgba(255,255,255,.025); }
  code { background: rgba(255,255,255,.07); border-radius: 4px; padding: .1em .35em;
         font-family: 'SFMono-Regular',Consolas,monospace; font-size: .85em; }
  .badge { display: inline-block; border-radius: 4px; padding: .2em .55em;
           font-size: .75rem; font-weight: 700; color: #fff; }
  .sev-high    { background: var(--red); }
  .sev-medium  { background: var(--amber); }
  .sev-low,.sev-info { background: var(--blue); }
  .finding-card { background: var(--surface); border: 1px solid var(--border);
                  border-radius: 8px; padding: 1.25rem; margin-top: 1rem; }
  .finding-card h3 { margin-top: 0; }
  .finding-meta { display: flex; gap: 1rem; flex-wrap: wrap; margin: .5rem 0;
                  font-size: .85rem; color: var(--text-muted); }
  .undoc-yes { color: var(--amber); font-weight: 600; }
  .undoc-no  { color: var(--green); }
  .remediation { background: rgba(0,117,202,.12); border-left: 3px solid var(--blue);
                 padding: .6rem 1rem; border-radius: 0 4px 4px 0; margin-top: .75rem;
                 font-size: .875rem; }
  details summary { cursor: pointer; color: var(--text-muted); font-size: .85rem;
                    margin-top: .5rem; }
"""

_JS = """
  document.querySelectorAll('.finding-card').forEach(c => {
    c.addEventListener('click', e => {
      if (e.target.tagName === 'A') return;
      c.querySelector('details').toggleAttribute('open');
    });
  });
"""


def _h(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text))


def _badge(severity: str) -> str:
    css = f"sev-{severity.lower()}"
    return f'<span class="badge {css}">{_h(severity.upper())}</span>'


def to_html(report: dict[str, Any]) -> str:
    """Return a standalone single-page HTML string for *report*."""
    meta = report.get("metadata", {})
    summary = report.get("summary", {})
    endpoints = report.get("endpoints", [])
    findings = report.get("findings", [])

    target = _h(meta.get("target", "N/A"))
    generated = _h(meta.get("generated_at", "N/A"))
    safety = _h(meta.get("safety_mode", "N/A"))
    version = _h(meta.get("version", TOOL_VERSION))

    # Summary cards
    cards_html = "".join(
        f'<div class="card"><div class="num">{n}</div><div class="label">{label}</div></div>'
        for n, label in [
            (summary.get("endpoint_count", 0), "Endpoints"),
            (summary.get("undocumented_count", 0), "Undocumented"),
            (summary.get("tested_count", 0), "Tested"),
            (summary.get("finding_count", 0), "Findings"),
        ]
    )

    # Findings
    if findings:
        findings_html_parts: list[str] = []
        for f in findings:
            sev = f.get("severity", "medium")
            identities = ", ".join(f'<code>{_h(i)}</code>' for i in f.get("unexpected_identities", []))
            evidence_rows = "".join(
                f"<tr><td><code>{_h(ev.get('identity',''))}</code></td>"
                f"<td>{_h(str(ev.get('status','')))}</td>"
                f"<td><code>{_h(ev.get('body_sha256',''))}</code></td></tr>"
                for ev in f.get("evidence", [])
            )
            findings_html_parts.append(f"""
  <div class="finding-card">
    <h3>{_h(f['id'])} &mdash; {_h(f['title'])}</h3>
    <div class="finding-meta">
      <span>{_badge(sev)}</span>
      <span>Endpoint: <code>{_h(f.get('endpoint',''))}</code></span>
      <span>Category: {_h(f.get('category',''))}</span>
      <span>Confidence: {_h(f.get('confidence',''))}</span>
    </div>
    <p>Unexpected access by: {identities}</p>
    <details>
      <summary>Show evidence</summary>
      <table>
        <thead><tr><th>Identity</th><th>Status</th><th>Body SHA-256</th></tr></thead>
        <tbody>{evidence_rows}</tbody>
      </table>
    </details>
    <div class="remediation">{_h(f.get('remediation',''))}</div>
  </div>""")
        findings_section = "\n".join(findings_html_parts)
    else:
        findings_section = "<p><em>No findings – all tested policies passed.</em></p>"

    # Endpoints table + per-endpoint observation details
    endpoint_rows = []
    obs_detail_parts: list[str] = []
    for ep in endpoints:
        sources = ", ".join(ep.get("sources", []))
        undoc = ep.get("undocumented", False)
        undoc_cell = (
            '<span class="undoc-yes">⚠ Yes</span>'
            if undoc
            else '<span class="undoc-no">No</span>'
        )
        policy = ep.get("policy")
        policy_cell = (
            f"{_h(policy['permission'])} on <code>{_h(policy['object'])}</code>"
            if policy
            else "<em>none</em>"
        )
        endpoint_rows.append(
            f"<tr><td><code>{_h(ep['key'])}</code></td><td>{_h(sources)}</td>"
            f"<td>{undoc_cell}</td><td>{policy_cell}</td></tr>"
        )
        obs_list = ep.get("observations", [])
        if obs_list:
            obs_rows = []
            for obs in obs_list:
                body_json = json.dumps(obs.get("body", ""), ensure_ascii=False)
                if len(body_json) > 200:
                    body_json = body_json[:200] + "…"
                obs_rows.append(
                    f"<tr>"
                    f"<td><code>{_h(obs.get('identity',''))}</code></td>"
                    f"<td>{_h(obs.get('role',''))}</td>"
                    f"<td>{_h(str(obs.get('status', obs.get('error',''))))}</td>"
                    f"<td>{_h(obs.get('expected',''))}</td>"
                    f"<td><code>{_h(body_json)}</code></td>"
                    f"</tr>"
                )
            obs_detail_parts.append(
                f"<h3><code>{_h(ep['key'])}</code> – Observations</h3>"
                f"<table><thead><tr><th>Identity</th><th>Role</th><th>Status</th>"
                f"<th>Expected</th><th>Body (redacted)</th></tr></thead>"
                f"<tbody>{''.join(obs_rows)}</tbody></table>"
            )
    endpoint_table = "\n".join(endpoint_rows)
    obs_details_html = "\n".join(obs_detail_parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{_h(TOOL_NAME)} – Security Report</title>
  <style>{_CSS}</style>
</head>
<body>
<div class="container">
  <h1>{_h(TOOL_NAME)} – Security Report</h1>
  <p class="meta">
    Target: <code>{target}</code> &nbsp;|&nbsp;
    Generated: {generated} &nbsp;|&nbsp;
    Safety: {safety} &nbsp;|&nbsp;
    Version: {version}
  </p>

  <h2>Summary</h2>
  <div class="cards">{cards_html}</div>

  <h2>Findings</h2>
  {findings_section}

  <h2>Endpoint Inventory</h2>
  <table>
    <thead>
      <tr><th>Key</th><th>Sources</th><th>Undocumented</th><th>Policy</th></tr>
    </thead>
    <tbody>
{endpoint_table}
    </tbody>
  </table>

  <h2>Observation Details</h2>
  {obs_details_html if obs_details_html else "<p><em>No observations recorded.</em></p>"}
</div>
<script>{_JS}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def _sarif_rule(finding: dict[str, Any]) -> dict[str, Any]:
    fid = finding.get("id", "AUTHZ-000")
    category = finding.get("category", "Access-control policy mismatch")
    return {
        "id": fid,
        "name": re.sub(r"[^A-Za-z0-9]", "", finding.get("title", fid)),
        "shortDescription": {"text": finding.get("title", fid)},
        "fullDescription": {"text": f"{category}. {finding.get('remediation', '')}"},
        "helpUri": TOOL_URI,
        "properties": {
            "category": category,
            "confidence": finding.get("confidence", "high"),
            "tags": ["security", "authorization"],
        },
        "defaultConfiguration": {
            "level": SEVERITY_SARIF.get(finding.get("severity", "medium"), "warning")
        },
    }


def _sarif_result(finding: dict[str, Any], rule_index: int, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    endpoint = finding.get("endpoint", "")
    sev = finding.get("severity", "medium")
    identities = ", ".join(finding.get("unexpected_identities", []))
    message = (
        f"Unexpected access to {endpoint} by {identities}. "
        f"Category: {finding.get('category', '')}. "
        f"Remediation: {finding.get('remediation', '')}"
    )
    # Attach redacted observation bodies from the matching endpoint so that
    # the <redacted> placeholder is faithfully preserved in SARIF output.
    obs_bodies: list[dict[str, Any]] = []
    for ep in endpoints:
        if ep.get("key") == endpoint:
            for obs in ep.get("observations", []):
                obs_bodies.append(
                    {
                        "identity": obs.get("identity"),
                        "status": obs.get("status"),
                        "body": obs.get("body"),
                    }
                )
            break
    return {
        "ruleId": finding.get("id", "AUTHZ-000"),
        "ruleIndex": rule_index,
        "level": SEVERITY_SARIF.get(sev, "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": endpoint, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": finding.get("id", "AUTHZ-000"),
        },
        "properties": {
            "severity": sev,
            "unexpectedIdentities": finding.get("unexpected_identities", []),
            "evidence": finding.get("evidence", []),
            "observationBodies": obs_bodies,
        },
    }


def to_sarif(report: dict[str, Any]) -> str:
    """Return a SARIF 2.1.0 JSON string for *report*."""
    meta = report.get("metadata", {})
    findings = report.get("findings", [])

    rules = [_sarif_rule(f) for f in findings]
    results = [_sarif_result(f, i, report.get("endpoints", [])) for i, f in enumerate(findings)]

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": meta.get("version", TOOL_VERSION),
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"explorer --base-url {meta.get('target', '')}",
                        "properties": {
                            "safetyMode": meta.get("safety_mode", ""),
                            "authorizationAttested": meta.get("authorization_attested", False),
                            "generatedAt": meta.get("generated_at", ""),
                        },
                    }
                ],
                "results": results,
                "artifacts": [
                    {
                        "location": {"uri": ep["key"], "uriBaseId": "%SRCROOT%"},
                        "description": {"text": ep["key"]},
                        "properties": {
                            "undocumented": ep.get("undocumented", False),
                            "sources": ep.get("sources", []),
                        },
                    }
                    for ep in report.get("endpoints", [])
                ],
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

FORMATS = ("json", "markdown", "html", "sarif")


def render(report: dict[str, Any], fmt: str) -> str:
    """Render *report* in the requested *fmt* and return a string."""
    fmt = fmt.lower()
    if fmt == "json":
        return to_json(report)
    if fmt in {"markdown", "md"}:
        return to_markdown(report)
    if fmt == "html":
        return to_html(report)
    if fmt == "sarif":
        return to_sarif(report)
    raise ValueError(f"Unknown format {fmt!r}. Choose from: {', '.join(FORMATS)}")
