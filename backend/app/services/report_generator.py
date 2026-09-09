"""Report generation: JSON, Markdown and HTML.

The README advertises shareable audit summaries. PDF is intentionally *not*
claimed here -- it needs a heavy layout dependency, and promising it without
shipping it would be worse than not mentioning it.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models.audit import AuditResult, Severity

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
    Severity.OPTIMIZATION,
]


def _env() -> Environment:
    # autoescape is set unconditionally rather than via select_autoescape:
    # that helper keys off the final filename extension, and this template is
    # `report.html.j2`, so it would resolve to "j2" and leave escaping off --
    # an XSS hole fed straight from audited source text.
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def to_json(result: AuditResult, *, indent: int = 2) -> str:
    """Machine-readable report, stable enough to diff between runs."""
    payload = result.model_dump(mode="json")
    payload["counts"] = result.counts_by_severity()
    return json.dumps(payload, indent=indent, sort_keys=False)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------
_SEVERITY_BADGE = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Informational": "⚪",
    "Optimization": "⚙️",
}


def to_markdown(result: AuditResult) -> str:
    """Human-readable report suitable for a GitHub issue or PR comment."""
    from app.services.risk import headline, score_findings

    breakdown = score_findings(result.findings)
    counts = result.counts_by_severity()

    lines: list[str] = []
    lines.append(f"# Smart Contract Audit Report")
    lines.append("")
    lines.append(f"**Score:** {result.score}/100 &nbsp;·&nbsp; **Grade:** {result.grade}")
    lines.append("")
    lines.append(f"> {breakdown.summary}")
    lines.append("")
    lines.append(headline(result.findings, result.score, result.grade))
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for severity in SEVERITY_ORDER:
        label = severity.label
        lines.append(f"| {_SEVERITY_BADGE.get(label, '')} {label} | {counts.get(label, 0)} |")
    lines.append("")

    lines.append("## Analysis context")
    lines.append("")
    lines.append(f"- Compiled: **{'yes' if result.compiled else 'no'}** (solc {result.solc_version or 'n/a'})")
    lines.append(f"- Files: {len(result.sources)}")
    lines.append(f"- Contracts: {len(result.contracts)}")
    lines.append(f"- Duration: {result.duration_ms} ms")
    if result.contracts:
        lines.append("")
        lines.append("| Contract | File | Kind | Functions | State vars | Bytecode (bytes) |")
        lines.append("|---|---|---|---:|---:|---:|")
        for c in result.contracts:
            lines.append(
                f"| `{c.name}` | `{c.file}` | {c.kind} | {c.functions} | "
                f"{c.state_variables} | {c.bytecode_size} |"
            )
    if result.tools:
        lines.append("")
        lines.append("### External analysers")
        lines.append("")
        for tool in result.tools:
            state = (
                f"ran, {len(tool.findings)} finding(s) in {tool.duration_ms} ms"
                if tool.ran
                else ("installed but did not complete" if tool.available else "not installed")
            )
            lines.append(f"- **{tool.name}**: {state}")
            if tool.note:
                lines.append(f"  - {tool.note}")
    lines.append("")

    if not result.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("_No issues were reported by the enabled checks._")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    grouped: dict[str, list] = {}
    for finding in result.findings:
        grouped.setdefault(finding.severity.label, []).append(finding)

    index = 0
    for severity in SEVERITY_ORDER:
        bucket = grouped.get(severity.label)
        if not bucket:
            continue
        lines.append(f"### {_SEVERITY_BADGE.get(severity.label, '')} {severity.label}")
        lines.append("")
        for finding in sorted(bucket, key=lambda f: (f.location.file, f.location.line)):
            index += 1
            where = finding.location.file or "<unknown>"
            if finding.location.line:
                where += f":{finding.location.line}"
            if finding.location.column:
                where += f":{finding.location.column}"
            scope = " · ".join(x for x in (finding.contract, finding.function) if x)
            lines.append(f"#### {index}. {finding.title}")
            lines.append("")
            meta = [f"`{where}`", f"confidence: {finding.confidence}"]
            if scope:
                meta.append(f"`{scope}`")
            ids = [i for i in (finding.swc, finding.cwe) if i]
            if ids:
                meta.append(" · ".join(ids))
            lines.append("*" + " — ".join(meta) + "*")
            lines.append("")
            lines.append(finding.description)
            lines.append("")
            if finding.location.snippet:
                lines.append("```solidity")
                lines.append(finding.location.snippet)
                lines.append("```")
                lines.append("")
            lines.append(f"**Recommendation:** {finding.recommendation}")
            lines.append("")
            if finding.references:
                for ref in finding.references:
                    lines.append(f"- <{ref}>")
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Static analysis cannot prove the absence of bugs. Treat this report as a "
        "prioritised starting point, not a guarantee._"
    )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------
def to_html(result: AuditResult) -> str:
    """Self-contained HTML report (no external assets)."""
    template = _env().get_template("report.html.j2")
    return template.render(
        result=result,
        counts=result.counts_by_severity(),
        severity_order=SEVERITY_ORDER,
        findings=result.sorted_findings(),
    )


# --------------------------------------------------------------------------
# Writing to disk
# --------------------------------------------------------------------------
def write_reports(
    result: AuditResult,
    directory: str | Path,
    *,
    formats: tuple[str, ...] = ("json", "md", "html"),
) -> dict[str, Path]:
    """Write the requested formats and return ``{format: path}``."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    renderers = {"json": (to_json, "json"), "md": (to_markdown, "md"), "html": (to_html, "html")}

    for fmt in formats:
        if fmt not in renderers:
            raise ValueError(f"unknown report format: {fmt}")
        render, ext = renderers[fmt]
        path = out_dir / f"{result.id}.{ext}"
        path.write_text(render(result), encoding="utf-8")
        written[fmt] = path
    return written
