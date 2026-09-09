"""Checks that need only the source text.

These run even when compilation fails, so a broken contract still produces a
useful report instead of an empty one.
"""

from __future__ import annotations

import re
from typing import Iterable

from app.models.audit import CodeLocation, Finding, Severity

from .ast_utils import AnalysisContext
from .base import Detector

LICENSE_RE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")
TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|BUG)\b\s*:?\s*(.*)", re.I)
PRIVATE_KEY_RE = re.compile(
    r"\b0x[0-9a-fA-F]{64}\b"
)
#: Textual markers of legacy call syntax, which no longer compiles but shows up
#: in copied snippets.
LEGACY_CALL_RE = re.compile(r"\.call\.value\s*\(|\.call\.gas\s*\(")

UNLICENSED_SEVERITY = Severity.INFORMATIONAL


class MissingLicenseHeader(Detector):
    """No SPDX identifier in the file."""

    check_id = "missing-license"
    title = "Missing SPDX license identifier"
    blurb = "Required for verifiable builds and dependency tooling."
    swc = ""
    cwe = ""

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for file_name, text in ctx.compilation.sources.items():
            if not text:
                continue
            if LICENSE_RE.search(text):
                continue
            yield Finding(
                check_id=self.check_id,
                title=self.title,
                severity=UNLICENSED_SEVERITY,
                confidence="high",
                description=(
                    f"`{file_name}` has no `SPDX-License-Identifier` comment. Solidity "
                    "warns about this, and package/verification tooling relies on it."
                ),
                recommendation=(
                    "Add `// SPDX-License-Identifier: MIT` (or your chosen license) as "
                    "the first line."
                ),
                location=CodeLocation(file=file_name, line=1, column=1),
            )


class TodoComments(Detector):
    """Unfinished-work markers left in shipped code."""

    check_id = "todo-comment"
    title = "Unresolved TODO/FIXME comment"
    blurb = "Marked-unfinished code in a deployed contract."
    swc = ""
    cwe = ""

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for file_name, text in ctx.compilation.sources.items():
            if not text:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = TODO_RE.search(line)
                if not match:
                    continue
                yield Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.INFORMATIONAL,
                    confidence="high",
                    description=(
                        f"{file_name}:{line_number} carries an unfinished-work marker: "
                        f"`{line.strip()[:120]}`."
                    ),
                    recommendation="Resolve or remove before deployment.",
                    location=CodeLocation(
                        file=file_name, line=line_number, column=match.start() + 1,
                        snippet=line.strip()[:200],
                    ),
                )


class LegacyCallSyntax(Detector):
    """`.call.value(...)` / `.call.gas(...)` pre-0.5 syntax."""

    check_id = "legacy-call-syntax"
    title = "Legacy low-level call syntax"
    blurb = "call.value()/call.gas() were removed in 0.5.0."
    swc = ""
    cwe = "CWE-477"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for file_name, text in ctx.compilation.sources.items():
            if not text:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not LEGACY_CALL_RE.search(line):
                    continue
                yield Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.LOW,
                    confidence="high",
                    description=(
                        f"{file_name}:{line_number} uses pre-0.5 call syntax, which "
                        "suggests code copied from a very old source."
                    ),
                    recommendation="Rewrite as `addr.call{value: x, gas: g}(data)`.",
                    location=CodeLocation(
                        file=file_name, line=line_number, column=1,
                        snippet=line.strip()[:200],
                    ),
                )


class HardcodedSecret(Detector):
    """32-byte hex constants that look like a private key."""

    check_id = "hardcoded-secret"
    title = "Possible hardcoded secret"
    blurb = "A 32-byte hex literal is indistinguishable from a private key."
    swc = "SWC-136"
    cwe = "CWE-798"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for file_name, text in ctx.compilation.sources.items():
            if not text:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = PRIVATE_KEY_RE.search(line)
                if not match:
                    continue
                # Constants like keccak slots are usually named; a key-looking
                # literal assigned to something called key/secret is the signal.
                if not re.search(r"key|secret|priv|seed|mnemonic", line, re.I):
                    continue
                yield Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    confidence="medium",
                    description=(
                        f"{file_name}:{line_number} embeds a 32-byte hex value in code "
                        "that mentions a key or secret. Anyone can read deployed "
                        "bytecode, so this must be treated as public."
                    ),
                    recommendation=(
                        "Remove the literal. Keys never belong in a contract; use "
                        "off-chain signing or a threshold/escrow scheme."
                    ),
                    references=["https://swcregistry.io/docs/SWC-136"],
                    location=CodeLocation(
                        file=file_name, line=line_number, column=match.start() + 1,
                        snippet="<redacted>",
                    ),
                )


class UncompilableSource(Detector):
    """Explicitly flags when AST-based analysis could not run."""

    check_id = "uncompilable-source"
    title = "Source did not compile"
    blurb = "AST detectors are skipped when solc rejects the source."
    swc = ""
    cwe = ""

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        if ctx.compilation.ok:
            return
        errors = ctx.compilation.errors
        if not errors:
            return
        first = errors[0]
        yield Finding(
            check_id=self.check_id,
            title=self.title,
            severity=Severity.MEDIUM,
            confidence="high",
            description=(
                f"solc reported {len(errors)} error(s); the first is "
                f"{first.type}: {first.message[:200]}. Deep AST checks were skipped for "
                "the affected units, so this report is necessarily incomplete."
            ),
            recommendation=(
                "Fix the compile errors and re-run. If the contract relies on external "
                "imports, supply those files too so the compiler can resolve them."
            ),
            location=CodeLocation(file=first.file, line=first.line, column=first.column),
            extra={"error_count": len(errors)},
        )
