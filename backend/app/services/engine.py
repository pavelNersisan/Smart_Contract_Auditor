"""Audit orchestration.

``audit_sources`` is the single entry point used by the CLI, the REST API and
the test suite, so all three always produce identical results.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from app.core.config import Settings, get_settings
from app.models.audit import (
    AuditResult,
    CompilerDiagnostic,
    ContractSummary,
    Finding,
    Severity,
)

from . import mythril as mythril_adapter
from . import slither as slither_adapter
from .detectors import AnalysisContext, AstDetector, build_default_registry
from .detectors.ast_utils import function_name, walk
from .risk import score_findings
from .solc import Compilation, CompilerUnavailable, compile_sources, discover_solc

logger = logging.getLogger("auditor.engine")

__all__ = ["audit_sources", "audit_file", "audit_directory", "AuditEngine"]


class AuditEngine:
    """Reusable engine holding configuration between runs."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._solc: str | None = None

    @property
    def solc_binary(self) -> str | None:
        if self._solc is None:
            self._solc = discover_solc(self.settings.solc_bin)
        return self._solc

    def compile(self, sources: dict[str, str]) -> Compilation:
        """Compile, degrading to an AST-less result if no compiler exists."""
        try:
            return compile_sources(
                sources, self.solc_binary, timeout=self.settings.solc_timeout
            )
        except CompilerUnavailable as exc:
            logger.warning("compiler unavailable, running source-level checks only: %s", exc)
            from .solc import build_line_index

            return Compilation(
                ok=False,
                solc_version="unavailable",
                sources=dict(sources),
                line_indexes={n: build_line_index(t) for n, t in sources.items()},
                messages=[],
            )

    def audit(
        self,
        sources: dict[str, str],
        *,
        include_optimizations: bool = True,
        run_external_tools: bool = True,
        disabled_checks: set[str] | None = None,
    ) -> AuditResult:
        started = time.time()
        result = AuditResult(sources=dict(sources))

        compilation = self.compile(sources)
        result.compiled = compilation.ok and compilation.has_ast
        result.solc_version = compilation.solc_version
        result.compiler_diagnostics = [
            CompilerDiagnostic(
                severity=m.severity,
                type=m.type,
                message=m.message,
                formatted=m.formatted,
                file=m.file,
                line=m.line,
                column=m.column,
            )
            for m in compilation.messages
        ]

        ctx = AnalysisContext.build(compilation)
        result.contracts = _summarize_contracts(ctx, compilation)

        registry = build_default_registry(
            include_optimizations=include_optimizations, disabled=disabled_checks
        )

        findings: list[Finding] = []
        for detector in registry.enabled():
            if detector.requires_ast and not compilation.has_ast:
                continue
            try:
                findings.extend(list(detector.run(ctx)))
            except Exception:  # a broken detector must not sink the audit
                logger.exception("detector %s failed", detector.check_id)

        if run_external_tools:
            for tool_run in self._run_external_tools(sources):
                result.tools.append(tool_run)
                findings.extend(tool_run.findings)

        result.findings = _dedupe(findings)
        breakdown = score_findings(result.findings)
        result.score = breakdown.score
        result.grade = breakdown.grade
        result.duration_ms = int((time.time() - started) * 1000)
        return result

    def _run_external_tools(self, sources: dict[str, str]) -> list:
        runs = []
        if self.settings.enable_slither:
            runs.append(slither_adapter.run(sources, self.settings.slither_bin))
        if self.settings.enable_mythril:
            runs.append(mythril_adapter.run(sources, self.settings.mythril_bin))
        return runs


def _summarize_contracts(ctx: AnalysisContext, compilation: Compilation) -> list[ContractSummary]:
    summaries = []
    for contract in ctx.contracts:
        kinds = {fn.get("kind") for fn in contract.functions}
        qualified = f"{contract.file}:{contract.name}"
        bytecode = (compilation.contracts.get(qualified) or None)
        summaries.append(
            ContractSummary(
                name=contract.name,
                file=contract.file,
                kind=contract.kind,
                functions=len([f for f in contract.functions if f.get("kind") == "function"]),
                state_variables=len(contract.state_vars),
                has_receive="receive" in kinds,
                has_fallback="fallback" in kinds,
                bytecode_size=(len(bytecode.bytecode) // 2) if bytecode else 0,
            )
        )
    return summaries


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop repeats of the same check at the same location, worst severity wins."""
    best: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        current = best.get(key)
        if current is None or int(finding.severity) > int(current.severity):
            best[key] = finding
    return sorted(
        best.values(),
        key=lambda f: (-int(f.severity), f.location.file, f.location.line, f.check_id),
    )


# --------------------------------------------------------------------------
# Convenience helpers
# --------------------------------------------------------------------------
def audit_sources(
    sources: dict[str, str],
    *,
    settings: Settings | None = None,
    include_optimizations: bool = True,
    run_external_tools: bool = True,
    disabled_checks: set[str] | None = None,
) -> AuditResult:
    """Audit an in-memory ``{path: source}`` mapping."""
    if not sources:
        raise ValueError("no sources supplied")
    engine = AuditEngine(settings)
    return engine.audit(
        sources,
        include_optimizations=include_optimizations,
        run_external_tools=run_external_tools,
        disabled_checks=disabled_checks,
    )


def audit_file(
    path: str | Path,
    *,
    settings: Settings | None = None,
    include_optimizations: bool = True,
    run_external_tools: bool = True,
) -> AuditResult:
    """Audit a single ``.sol`` file."""
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    return audit_sources(
        {file_path.name: text},
        settings=settings,
        include_optimizations=include_optimizations,
        run_external_tools=run_external_tools,
    )


def audit_directory(
    root: str | Path,
    *,
    settings: Settings | None = None,
    include_optimizations: bool = True,
    run_external_tools: bool = True,
) -> AuditResult:
    """Audit every ``.sol`` file under ``root`` as one compilation unit."""
    base = Path(root)
    sources = {
        str(p.relative_to(base)): p.read_text(encoding="utf-8")
        for p in sorted(base.rglob("*.sol"))
    }
    if not sources:
        raise ValueError(f"no .sol files found under {base}")
    return audit_sources(
        sources,
        settings=settings,
        include_optimizations=include_optimizations,
        run_external_tools=run_external_tools,
    )
