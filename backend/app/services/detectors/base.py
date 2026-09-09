"""Detector base classes and the shared analysis context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from app.models.audit import Finding, Severity
from app.services.solc import Compilation

from . import ast_utils
from .ast_utils import AnalysisContext, ContractInfo

__all__ = [
    "Detector",
    "AnalysisContext",
    "ContractInfo",
    "Finding",
    "Severity",
    "ast_utils",
]


class Detector(ABC):
    """Base class for every check.

    Subclasses set ``check_id``/``title`` metadata and implement ``run``.
    Detectors that need a compiled AST should subclass :class:`AstDetector`;
    they are skipped automatically when compilation failed.

    Deliberately *not* a dataclass: a dataclass field declared here (e.g.
    ``check_id: str = ""``) makes the generated ``__init__`` assign the empty
    default onto every subclass instance, silently erasing the subclass's own
    class attribute.
    """

    check_id: str = ""
    title: str = ""
    #: Human-readable one-liner shown in ``GET /detectors``.
    blurb: str = ""
    swc: str = ""
    cwe: str = ""

    requires_ast: bool = False
    enabled: bool = True

    @abstractmethod
    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        """Yield findings for this check."""

    # -- helpers -----------------------------------------------------------
    def finding(
        self,
        ctx: AnalysisContext,
        node: dict | None,
        *,
        severity: Severity,
        description: str,
        recommendation: str,
        confidence: str = "medium",
        contract: str = "",
        function: str = "",
        file: str = "",
        line: int = 0,
        column: int = 0,
        snippet: str = "",
        references: list[str] | None = None,
        extra: dict | None = None,
    ) -> Finding:
        """Build a Finding, filling location from ``node`` when available."""
        from app.models.audit import CodeLocation

        loc_file, loc_line, loc_col, loc_snippet = file, line, column, snippet
        if node is not None:
            f, l, c, s = ctx.locate(node)
            loc_file = loc_file or f
            loc_line = loc_line or l
            loc_col = loc_col or c
            loc_snippet = loc_snippet or s

        return Finding(
            check_id=self.check_id,
            title=self.title,
            severity=severity,
            confidence=confidence,
            description=description,
            recommendation=recommendation,
            location=CodeLocation(
                file=loc_file, line=loc_line, column=loc_col, snippet=loc_snippet
            ),
            contract=contract,
            function=function,
            swc=self.swc,
            cwe=self.cwe,
            references=references or [],
            extra=extra or {},
        )


class AstDetector(Detector):
    """Detector that needs a successfully compiled AST."""

    requires_ast = True


class DetectorRegistry:
    """Holds the enabled detector set."""

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors: list[Detector] = list(detectors or [])

    def register(self, detector: Detector) -> Detector:
        self.detectors.append(detector)
        return detector

    def all(self) -> list[Detector]:
        return list(self.detectors)

    def enabled(self) -> list[Detector]:
        return [d for d in self.detectors if d.enabled]

    def by_id(self, check_id: str) -> Detector | None:
        for d in self.detectors:
            if d.check_id == check_id:
                return d
        return None
