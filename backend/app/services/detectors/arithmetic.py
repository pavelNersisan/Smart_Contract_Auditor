"""Arithmetic checks: pre-0.8 overflow exposure and division ordering."""

from __future__ import annotations

from typing import Iterable

from app.models.audit import Finding, Severity

from .ast_utils import (
    AnalysisContext,
    ContractInfo,
    function_name,
    identifier_name,
    root_identifier,
    type_string,
    unwrap_tuple,
    walk,
)
from .base import AstDetector

OVERFLOWING_OPS = {"+", "-", "*", "**"}
#: ``using SafeMath for ...`` neutralises these on old compilers.
SAFEMATH_RE = ("safemath",)


def _uses_safemath(contract: ContractInfo) -> bool:
    for directive in contract.using_for:
        lib = directive.get("libraryName") or {}
        if identifier_name(lib).lower() in SAFEMATH_RE:
            return True
    return False


def _is_integer_expression(node: dict) -> bool:
    text = type_string(node)
    return text.startswith("uint") or text.startswith("int")


def _inside_unchecked(node: dict, ctx: AnalysisContext) -> bool:
    """Walk up parent links looking for an ``unchecked { }`` block."""
    current = node
    while current is not None:
        if current.get("nodeType") == "UncheckedBlock":
            return True
        current = ctx.parents.get(int(current.get("id", -1)))
    return False


class IntegerOverflow(AstDetector):
    """Unchecked arithmetic on a compiler older than 0.8.0."""

    check_id = "integer-overflow"
    title = "Unchecked arithmetic on pre-0.8 compiler"
    blurb = "Solidity < 0.8.0 wraps on overflow instead of reverting."
    swc = "SWC-101"
    cwe = "CWE-190"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            version = contract.version
            if version is None or version >= (0, 8, 0):
                continue
            if _uses_safemath(contract):
                continue
            if contract.kind in ("library", "interface"):
                continue

            reported: set[str] = set()
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if node.get("nodeType") != "BinaryOperation":
                        continue
                    if node.get("operator") not in OVERFLOWING_OPS:
                        continue
                    if not _is_integer_expression(node):
                        continue
                    key = f"{function_name(fn)}:{node.get('id')}"
                    if key in reported:
                        continue
                    reported.add(key)
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.HIGH,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` uses `{node.get('operator')}` on "
                            f"integers while the pragma allows "
                            f"{'.'.join(map(str, version))}. Before 0.8.0 Solidity wraps "
                            "on overflow/underflow, so a balance can wrap to a huge "
                            "number or a subtraction to near-zero."
                        ),
                        recommendation=(
                            "Upgrade the pragma to ^0.8.0 (arithmetic then reverts by "
                            "default), or use OpenZeppelin SafeMath / explicit bound "
                            "checks if the old compiler is mandatory."
                        ),
                        references=["https://swcregistry.io/docs/SWC-101"],
                        extra={"operator": node.get("operator")},
                    )


class UncheckedArithmeticBlock(AstDetector):
    """``unchecked { }`` on 0.8+ -- intentional, but worth a second look."""

    check_id = "unchecked-arithmetic"
    title = "Explicitly unchecked arithmetic"
    blurb = "unchecked { } re-enables wrapping arithmetic."
    swc = "SWC-101"
    cwe = "CWE-190"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            if (contract.version or (0, 8, 0)) < (0, 8, 0):
                continue
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if node.get("nodeType") != "BinaryOperation":
                        continue
                    if node.get("operator") not in OVERFLOWING_OPS:
                        continue
                    if not _inside_unchecked(node, ctx):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.INFORMATIONAL,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` performs "
                            f"`{node.get('operator')}` inside an `unchecked` block, which "
                            "deliberately opts out of 0.8.x overflow protection."
                        ),
                        recommendation=(
                            "Confirm the inputs are provably bounded and add a comment "
                            "explaining why wrapping is safe, since this is the single "
                            "easiest place for a later edit to introduce an overflow."
                        ),
                    )


class DivideBeforeMultiply(AstDetector):
    """``(a / b) * c`` loses precision."""

    check_id = "divide-before-multiply"
    title = "Division before multiplication"
    blurb = "Integer division truncates and loses precision."
    swc = ""
    cwe = "CWE-682"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if node.get("nodeType") != "BinaryOperation":
                        continue
                    if node.get("operator") != "*":
                        continue
                    left = unwrap_tuple(node.get("leftExpression"))
                    right = unwrap_tuple(node.get("rightExpression"))
                    division_side = None
                    for side, label in ((left, "left"), (right, "right")):
                        if side and side.get("nodeType") == "BinaryOperation":
                            if side.get("operator") == "/":
                                division_side = label
                                break
                    if not division_side:
                        continue
                    if not _is_integer_expression(node):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.LOW,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` divides before multiplying on the "
                            f"{division_side}-hand side. Solidity integer division "
                            "truncates, so the result can be zero or materially "
                            "inaccurate for small numerators."
                        ),
                        recommendation=(
                            "Multiply first and divide last "
                            "(`(a * c) / b`), checking for overflow, or use a fixed-point "
                            "library."
                        ),
                    )


class UnvalidatedDivisor(AstDetector):
    """Division or modulo by a value that is not proven non-zero."""

    check_id = "unvalidated-divisor"
    title = "Division by a possibly zero divisor"
    blurb = "Divide-by-zero reverts and can block a code path."
    swc = ""
    cwe = "CWE-369"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                params = ((fn.get("parameters") or {}).get("parameters")) or []
                param_ids = {int(p["id"]) for p in params if "id" in p}
                for node in walk(body):
                    if node.get("nodeType") != "BinaryOperation":
                        continue
                    if node.get("operator") not in {"/", "%"}:
                        continue
                    divisor = node.get("rightExpression") or {}
                    root = root_identifier(divisor)
                    ref = root.get("referencedDeclaration") if root else None
                    if ref is None or int(ref) not in param_ids:
                        continue
                    if self._guarded(node, ctx, int(ref)):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.MEDIUM,
                        confidence="low",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` divides by "
                            f"`{(root or {}).get('name', '?')}`, a caller-supplied "
                            "parameter, with no visible non-zero check. A zero divisor "
                            "reverts the transaction."
                        ),
                        recommendation=(
                            "Add `require(divisor != 0)` before the division, or use a "
                            "SafeMath-style helper that documents the revert."
                        ),
                    )

    @staticmethod
    def _guarded(node: dict, ctx: AnalysisContext, param_id: int) -> bool:
        """True if a `require`/`if` comparing the divisor to zero appears earlier."""
        fn_id = None
        current = node
        while current is not None:
            if current.get("nodeType") == "FunctionDefinition":
                fn_id = current
                break
            current = ctx.parents.get(int(current.get("id", -1)))
        if fn_id is None:
            return False
        target_start = int((node.get("src") or "0").split(":")[0])
        for candidate in walk(fn_id):
            if candidate.get("nodeType") != "FunctionCall":
                continue
            if identifier_name(candidate) not in {"require", "assert"}:
                continue
            start = int((candidate.get("src") or "0").split(":")[0])
            if start > target_start:
                continue
            for arg in walk(candidate):
                if (
                    arg.get("nodeType") == "Identifier"
                    and arg.get("referencedDeclaration") == param_id
                ):
                    return True
        return False
