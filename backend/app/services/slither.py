"""Optional Slither integration.

Slither is *not* required: it needs a native ``solc`` binary, which is not
always installable (the upstream binary host is frequently unreachable from
sandboxed environments). When it is present its findings are merged into the
report; when it is not, the run says so plainly instead of pretending.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from app.models.audit import CodeLocation, Finding, Severity, ToolRun

#: Slither impact -> our severity
IMPACT_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Optimization": Severity.OPTIMIZATION,
}

NAME = "slither"


def is_available(binary: str = "slither") -> bool:
    return shutil.which(binary) is not None


def run(
    sources: dict[str, str],
    binary: str = "slither",
    timeout: int = 300,
) -> ToolRun:
    """Run Slither over the sources, writing them to a temp project first."""
    start = time.time()
    if not is_available(binary):
        return ToolRun(
            name=NAME,
            available=False,
            note=(
                "slither is not installed. Install with `pip install slither-analyzer` "
                "(it also needs a native solc). Built-in detectors still ran."
            ),
        )

    import tempfile

    with tempfile.TemporaryDirectory(prefix="auditor-slither-") as tmp:
        base = Path(tmp)
        for name, text in sources.items():
            target = base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        entry = next(iter(sources))
        try:
            proc = subprocess.run(
                [binary, str(base / entry), "--json", "-"],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(base),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolRun(
                name=NAME, available=True, ran=False,
                note=f"slither failed to run: {exc}",
                duration_ms=int((time.time() - start) * 1000),
            )

    try:
        payload = json.loads(proc.stdout[proc.stdout.find("{") :])
    except (ValueError, json.JSONDecodeError):
        return ToolRun(
            name=NAME, available=True, ran=False,
            note=f"could not parse slither output: {proc.stderr[:200]}",
            duration_ms=int((time.time() - start) * 1000),
        )

    findings: list[Finding] = []
    for entry in ((payload.get("results") or {}).get("detectors")) or []:
        elements = (entry.get("elements") or [{}])
        first = elements[0] if elements else {}
        source_mapping = first.get("source_mapping") or {}
        findings.append(
            Finding(
                check_id=f"slither:{entry.get('check', 'unknown')}",
                title=entry.get("check", "slither finding").replace("-", " ").title(),
                severity=IMPACT_MAP.get(entry.get("impact", ""), Severity.INFORMATIONAL),
                confidence=str(entry.get("confidence", "medium")).lower(),
                description=entry.get("description", "").strip(),
                recommendation=entry.get("description", "").strip() or "See Slither output.",
                location=CodeLocation(
                    file=source_mapping.get("filename_relative", ""),
                    line=int(source_mapping.get("lines", [0])[0]) if source_mapping.get("lines") else 0,
                    column=int(source_mapping.get("start", 0) or 0),
                ),
                contract=first.get("name", ""),
                swc=",".join(str(s) for s in entry.get("additional_fields", {}).get("swc", []) or []),
                extra={"tool": NAME, "impact": entry.get("impact")},
            )
        )

    return ToolRun(
        name=NAME,
        available=True,
        ran=True,
        duration_ms=int((time.time() - start) * 1000),
        findings=findings,
    )
