"""Render an AnalysisResult as colored terminal text, JSON, or an HTML report."""

from __future__ import annotations

import html
import json

from .analyzer import AnalysisResult

# ANSI colors — kept tiny so we avoid a dependency just for output.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLORS = {
    "pass": "\033[32m",   # green
    "warn": "\033[33m",   # yellow
    "fail": "\033[31m",   # red
}
_GRADE_COLOR = {
    "A": "\033[32m",
    "B": "\033[32m",
    "C": "\033[33m",
    "D": "\033[33m",
    "F": "\033[31m",
}
_ICON = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}


def to_json(result: AnalysisResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def to_terminal(result: AnalysisResult, use_color: bool = True) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if use_color else text

    lines = []
    lines.append("")
    lines.append(c(f"  Security Header Report", _BOLD))
    lines.append(f"  Target:  {result.url}")
    if result.final_url != result.url:
        lines.append(f"  Final:   {result.final_url}")
    lines.append(f"  Status:  HTTP {result.status_code}")

    grade_code = _GRADE_COLOR.get(result.grade, "")
    lines.append(
        "  Grade:   "
        + c(f"{result.grade}", grade_code + _BOLD if use_color else "")
        + f"  ({result.score}/100)"
    )
    counts = result.counts
    lines.append(
        f"  Summary: {counts['pass']} passed, "
        f"{counts['warn']} warnings, {counts['fail']} failed"
    )
    lines.append("  " + "-" * 60)

    for f in result.findings:
        code = _COLORS[f.status] if use_color else ""
        badge = c(f"[{_ICON[f.status]}]", code)
        lines.append(f"  {badge} {c(f.name, _BOLD)}  ({f.severity})")
        if f.value:
            lines.append(f"        value: {f.value}")
        if f.detail:
            lines.append(f"        {f.detail}")
        if f.remediation and f.status != "pass":
            lines.append(f"        fix: {c(f.remediation, code)}")
        lines.append("")

    return "\n".join(lines)


def to_html(result: AnalysisResult) -> str:
    e = html.escape
    rows = []
    for f in result.findings:
        rows.append(
            f"""
        <tr class="{f.status}">
          <td><span class="badge {f.status}">{f.status.upper()}</span></td>
          <td class="name">{e(f.name)}</td>
          <td>{e(f.severity)}</td>
          <td>
            <div class="detail">{e(f.detail)}</div>
            {f'<div class="value"><code>{e(f.value)}</code></div>' if f.value else ''}
            {f'<div class="fix">Fix: {e(f.remediation)}</div>' if f.remediation and f.status != "pass" else ''}
          </td>
        </tr>"""
        )

    grade_class = "good" if result.grade in ("A", "B") else (
        "mid" if result.grade in ("C", "D") else "bad"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Header Report — {e(result.url)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; padding: 2rem; line-height: 1.5;
         background: #0f172a; color: #e2e8f0; }}
  .card {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
  .meta {{ color: #94a3b8; font-size: .9rem; margin-bottom: 1.5rem;
          word-break: break-all; }}
  .grade {{ display: inline-flex; align-items: center; justify-content: center;
           width: 84px; height: 84px; border-radius: 50%; font-size: 2.4rem;
           font-weight: 700; margin-right: 1rem; }}
  .grade.good {{ background: #14532d; color: #86efac; }}
  .grade.mid  {{ background: #713f12; color: #fde047; }}
  .grade.bad  {{ background: #7f1d1d; color: #fca5a5; }}
  .header-row {{ display: flex; align-items: center; margin-bottom: 1.5rem; }}
  .score {{ font-size: .95rem; color: #cbd5e1; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
  th, td {{ text-align: left; padding: .6rem .5rem; vertical-align: top;
           border-bottom: 1px solid #1e293b; }}
  th {{ color: #94a3b8; font-weight: 600; }}
  .name {{ font-weight: 600; white-space: nowrap; }}
  .badge {{ display: inline-block; padding: .1rem .5rem; border-radius: 4px;
           font-size: .72rem; font-weight: 700; }}
  .badge.pass {{ background: #14532d; color: #86efac; }}
  .badge.warn {{ background: #713f12; color: #fde047; }}
  .badge.fail {{ background: #7f1d1d; color: #fca5a5; }}
  .detail {{ color: #cbd5e1; }}
  .value code {{ background: #1e293b; padding: .1rem .3rem; border-radius: 3px;
               font-size: .82rem; word-break: break-all; }}
  .fix {{ color: #7dd3fc; margin-top: .3rem; }}
  footer {{ margin-top: 2rem; color: #64748b; font-size: .8rem; }}
</style>
</head>
<body>
  <div class="card">
    <div class="header-row">
      <div class="grade {grade_class}">{result.grade}</div>
      <div>
        <h1>Security Header Report</h1>
        <div class="score">{result.score}/100 &middot;
          {result.counts['pass']} passed,
          {result.counts['warn']} warnings,
          {result.counts['fail']} failed</div>
      </div>
    </div>
    <div class="meta">
      Target: {e(result.url)}<br>
      Final URL: {e(result.final_url)} &middot; HTTP {result.status_code}
    </div>
    <table>
      <thead>
        <tr><th>Status</th><th>Control</th><th>Severity</th><th>Details</th></tr>
      </thead>
      <tbody>{''.join(rows)}
      </tbody>
    </table>
    <footer>Generated by header-analyzer &middot; For authorized testing and
      educational use only.</footer>
  </div>
</body>
</html>
"""
