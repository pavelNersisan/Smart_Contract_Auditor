"""Risk scoring.

A 100-point scale, as promised in the README, derived from the finding set with
two properties worth stating explicitly:

* It is **monotonic** -- adding a finding never raises the score.
* Repeats **decay** (geometrically at 0.85) so a contract with 40 informational
  notes is not scored the same as one with 40 criticals, and the score cannot be
  gamed by splitting one issue into many.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from app.models.audit import SEVERITY_WEIGHT, Finding, Severity

DECAY = 0.85

#: Inclusive lower bound -> letter grade.
GRADE_BANDS: tuple[tuple[int, str, str], ...] = (
    (90, "A", "Production-ready from a static-analysis standpoint."),
    (75, "B", "No critical issues; address the high/medium findings before launch."),
    (60, "C", "Material issues present. Do not deploy without remediation."),
    (40, "D", "Serious exposure. Treat as unsafe until re-audited."),
    (0, "F", "Critical exposure. Do not deploy."),
)


@dataclass
class ScoreBreakdown:
    score: int
    grade: str
    summary: str
    penalties: dict[str, float]
    total_penalty: float


def grade_for(score: int) -> tuple[str, str]:
    for threshold, letter, summary in GRADE_BANDS:
        if score >= threshold:
            return letter, summary
    return "F", GRADE_BANDS[-1][2]


def score_findings(findings: list[Finding]) -> ScoreBreakdown:
    """Compute the 1-100 score and its letter grade."""
    penalties: dict[str, float] = {}
    seen: Counter[Severity] = Counter()
    total = 0.0

    for finding in sorted(findings, key=lambda f: -int(f.severity)):
        weight = SEVERITY_WEIGHT.get(finding.severity, 1.0)
        decayed = weight * (DECAY ** seen[finding.severity])
        seen[finding.severity] += 1
        total += decayed
        penalties[finding.severity.name.title()] = round(
            penalties.get(finding.severity.name.title(), 0.0) + decayed, 2
        )

    score = max(1, min(100, round(100 - total)))
    grade, summary = grade_for(score)
    return ScoreBreakdown(
        score=score,
        grade=grade,
        summary=summary,
        penalties=penalties,
        total_penalty=round(total, 2),
    )


def headline(findings: list[Finding], score: int, grade: str) -> str:
    """One-sentence verdict for the top of a report."""
    counts = Counter(f.severity for f in findings)
    parts = [
        f"{counts[s]} {s.name.lower()}"
        for s in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFORMATIONAL,
            Severity.OPTIMIZATION,
        )
        if counts[s]
    ]
    if not parts:
        return f"No issues found across the enabled checks (score {score}/100, grade {grade})."
    joined = ", ".join(parts)
    return f"Found {len(findings)} issue(s) -- {joined} (score {score}/100, grade {grade})."
