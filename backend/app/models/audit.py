"""Domain models for an audit run.

These are the single source of truth shared by the engine, the REST API, the
CLI and the report generator, so a finding always renders identically
everywhere.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(IntEnum):
    """Finding severity, ordered so ``sorted()`` puts the worst first.

    An ``IntEnum`` (not a ``str`` mix-in) because ordering matters more than
    JSON aesthetics: severity comparisons drive scoring and sorting. Reports
    render the human label via :attr:`label`.
    """

    OPTIMIZATION = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        """Title-cased display name, e.g. ``CRITICAL`` -> ``Critical``."""
        return self.name.capitalize()

    def __str__(self) -> str:
        return self.label


#: Points deducted from the 100-point score, per first finding of a severity.
#: Calibrated so one critical drops a contract to ~45 (grade D) and repeated
#: findings of the same severity decay rather than pinning the score at zero.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 55.0,
    Severity.HIGH: 30.0,
    Severity.MEDIUM: 14.0,
    Severity.LOW: 5.0,
    Severity.INFORMATIONAL: 1.0,
    Severity.OPTIMIZATION: 0.5,
}


class CodeLocation(BaseModel):
    file: str = ""
    line: int = 0
    column: int = 0
    snippet: str = ""


class Finding(BaseModel):
    """A single issue reported by a detector."""

    check_id: str
    title: str
    severity: Severity
    confidence: str = "medium"  # high | medium | low
    description: str
    recommendation: str
    location: CodeLocation = Field(default_factory=CodeLocation)
    contract: str = ""
    function: str = ""
    swc: str = ""
    cwe: str = ""
    references: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable id so repeated audits of the same code dedupe cleanly."""
        loc = self.location
        raw = f"{self.check_id}|{self.contract}|{self.function}|{loc.file}|{loc.line}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]


class CompilerDiagnostic(BaseModel):
    severity: str
    type: str
    message: str
    formatted: str = ""
    file: str = ""
    line: int = 0
    column: int = 0


class ToolRun(BaseModel):
    """Outcome of an optional external analyser (Slither, Mythril, ...)."""

    name: str
    available: bool
    ran: bool = False
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    note: str = ""


class ContractSummary(BaseModel):
    name: str
    file: str
    kind: str = "contract"
    functions: int = 0
    state_variables: int = 0
    has_receive: bool = False
    has_fallback: bool = False
    bytecode_size: int = 0


class AuditResult(BaseModel):
    """Everything produced by one audit run."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = Field(default_factory=time.time)
    status: str = "completed"  # completed | failed
    sources: dict[str, str] = Field(default_factory=dict)

    compiled: bool = False
    solc_version: str = ""
    compiler_diagnostics: list[CompilerDiagnostic] = Field(default_factory=list)

    findings: list[Finding] = Field(default_factory=list)
    contracts: list[ContractSummary] = Field(default_factory=list)
    tools: list[ToolRun] = Field(default_factory=list)

    score: int = 100
    grade: str = "A"
    duration_ms: int = 0
    error: str = ""

    # -- convenience views -------------------------------------------------
    def counts_by_severity(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.location.file, f.location.line),
        )


class AuditRequest(BaseModel):
    """JSON body accepted by ``POST /audit``.

    Either ``source`` (single contract) or ``sources`` (multi-file project
    keyed by path) must be supplied.
    """

    source: str | None = None
    sources: dict[str, str] | None = None
    filename: str = "Contract.sol"
    include_optimizations: bool = True
    run_external_tools: bool = True
