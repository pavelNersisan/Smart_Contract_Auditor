"""Optional Mythril integration.

Mythril adds symbolic execution on top of the built-in static checks. Like
Slither it is strictly optional; the engine reports its absence rather than
substituting a weaker analysis silently.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from app.models.audit import CodeLocation, Finding, Severity, ToolRun

SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}

NAME = "mythril"


def is_available(binary: str = "myth") -> bool:
    return shutil.which(binary) is not None


def run(
    sources: dict[str, str],
    binary: str = "myth",
    timeout: int = 600,
    execution_timeout: int = 60,
) -> ToolRun:
    start = time.time()
    if not is_available(binary):
        return ToolRun(
            name=NAME,
            available=False,
            note=(
                "mythril is not installed. Install with `pip install mythril` for "
                "symbolic execution; built-in detectors still ran."
            ),
        )

    import tempfile

    with tempfile.TemporaryDirectory(prefix="auditor-myth-") as tmp:
        base = Path(tmp)
        for name, text in sources.items():
            target = base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        entry = base / next(iter(sources))
        try:
            proc = subprocess.run(
                [
                    binary, "analyze", str(entry),
                    "-o", "json",
                    "--execution-timeout", str(execution_timeout),
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(base),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolRun(
                name=NAME, available=True, ran=False,
                note=f"mythril failed to run: {exc}",
                duration_ms=int((time.time() - start) * 1000),
            )

    try:
        payload = json.loads(proc.stdout[proc.stdout.find("{") :])
    except (ValueError, json.JSONDecodeError):
        return ToolRun(
            name=NAME, available=True, ran=False,
            note=f"could not parse mythril output: {proc.stderr[:200]}",
            duration_ms=int((time.time() - start) * 1000),
        )

    findings = [
        Finding(
            check_id=f"mythril:{issue.get('swc-id', 'unknown')}",
            title=issue.get("title", "mythril finding"),
            severity=SEVERITY_MAP.get(issue.get("severity", ""), Severity.INFORMATIONAL),
            confidence=str(issue.get("confidence", "medium")).lower(),
            description=issue.get("description", "").strip(),
            recommendation="Review the transaction trace reported by Mythril.",
            location=CodeLocation(
                file=issue.get("filename", ""),
                line=int(issue.get("lineno", 0) or 0),
                column=int(issue.get("column", 0) or 0),
            ),
            extra={"tool": NAME, "swc": issue.get("swc-id")},
        )
        for issue in (payload.get("issues") or [])
    ]

    return ToolRun(
        name=NAME,
        available=True,
        ran=True,
        duration_ms=int((time.time() - start) * 1000),
        findings=findings,
    )
