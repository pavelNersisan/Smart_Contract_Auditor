"""Hygiene, best-practice and gas checks."""

from __future__ import annotations

import re
from typing import Iterable

from app.models.audit import CompilerDiagnostic, Finding, Severity

from .ast_utils import (
    AnalysisContext,
    ContractInfo,
    function_name,
    function_signature,
    identifier_name,
    is_zero_address_literal,
    pragma_texts,
    root_identifier,
    type_string,
    walk,
)
from .base import AstDetector, Detector

RANDOMISH_NAMES = re.compile(r"random|rand|seed|nonce|lottery|salt|entropy|jackpot", re.I)
BLOCK_ENTROPY_MEMBERS = {
    "blockhash",
    "timestamp",
    "difficulty",
    "prevrandao",
    "coinbase",
    "number",
    "gaslimit",
}
#: `block.blockhash()` is deprecated; the global `blockhash(n)` is not.
DEPRECATED_IDENTIFIERS = {"suicide", "sha3", "throw", "now"}
class FloatingPragma(AstDetector):
    """``pragma solidity ^x.y.z`` compiles against a moving target."""

    check_id = "floating-pragma"
    title = "Floating pragma"
    blurb = "A caret pragma lets any newer patch version compile the code."
    swc = "SWC-103"
    cwe = "CWE-1104"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for file_name, source_unit in ctx.compilation.asts.items():
            for node in source_unit.get("nodes") or []:
                if node.get("nodeType") != "PragmaDirective":
                    continue
                literals = node.get("literals") or []
                if not literals or literals[0] != "solidity":
                    continue
                spec = "".join(literals[1:])
                if spec.startswith("^") or spec.startswith(">=") or "||" in spec:
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.INFORMATIONAL,
                        confidence="high",
                        file=file_name,
                        description=(
                            f"The pragma `{spec}` accepts a range of compiler versions. "
                            "Deployed bytecode then depends on which version happened to "
                            "be current at build time."
                        ),
                        recommendation=(
                            "Pin an exact version (`pragma solidity 0.8.24;`) for "
                            "deployable contracts; ranges are acceptable for libraries "
                            "meant to be consumed by others."
                        ),
                        references=["https://swcregistry.io/docs/SWC-103"],
                        extra={"pragma": spec},
                    )


class AncientSolcVersion(AstDetector):
    """Compiler version with known miscompilations or missing safety."""

    check_id = "old-solc-version"
    title = "Outdated compiler version"
    blurb = "Versions before 0.8.0 lack built-in overflow checks."
    swc = ""
    cwe = "CWE-1104"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        seen: set[tuple[str, str]] = set()
        for contract in ctx.contracts:
            version = contract.version
            if version is None or version >= (0, 8, 0):
                continue
            key = (contract.file, ".".join(map(str, version)))
            if key in seen:
                continue
            seen.add(key)
            yield self.finding(
                ctx,
                contract.ast,
                severity=Severity.MEDIUM,
                confidence="high",
                contract=contract.name,
                description=(
                    f"`{contract.name}` targets Solidity "
                    f"{'.'.join(map(str, version))}, which predates built-in overflow "
                    "checks (0.8.0) and, below 0.8.0, also lacks free `revert` with "
                    "custom errors."
                ),
                recommendation=(
                    "Migrate to 0.8.24 or newer and re-run the suite; the overflow "
                    "protection alone removes an entire class of accounting bugs."
                ),
            )


class TimestampDependency(AstDetector):
    """Logic keyed to ``block.timestamp``."""

    check_id = "timestamp-dependence"
    title = "Dependence on block.timestamp"
    blurb = "Miners/validators can shift the timestamp by seconds."
    swc = "SWC-116"
    cwe = "CWE-829"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if not self._is_block_timestamp(node):
                        continue
                    parent = ctx.parents.get(int(node.get("id", -1)))
                    if parent is None or parent.get("nodeType") != "BinaryOperation":
                        continue
                    if parent.get("operator") not in {"<", ">", "<=", ">=", "==", "!="}:
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.LOW,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` branches on a `block.timestamp` "
                            "comparison. The block producer chooses the timestamp within "
                            "a small window, so anything with a tight deadline or a "
                            "lottery cutoff can be nudged."
                        ),
                        recommendation=(
                            "Avoid tight time windows; use block numbers for coarse "
                            "ordering, or an oracle/commit-reveal scheme when the exact "
                            "time is security-relevant."
                        ),
                        references=["https://swcregistry.io/docs/SWC-116"],
                    )

    @staticmethod
    def _is_block_timestamp(node: dict) -> bool:
        return (
            node.get("nodeType") == "MemberAccess"
            and node.get("memberName") == "timestamp"
            and identifier_name(node.get("expression")) == "block"
        )


class WeakRandomness(AstDetector):
    """On-chain values used as an entropy source."""

    check_id = "weak-randomness"
    title = "Predictable on-chain randomness"
    blurb = "blockhash/timestamp-derived values are attacker-predictable."
    swc = "SWC-120"
    cwe = "CWE-330"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if not self._is_entropy(node):
                        continue
                    if not self._feeds_random_context(node, ctx):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.HIGH,
                        confidence="high",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` derives a value that looks random "
                            f"from `{self._describe(node)}`. Every one of these inputs is "
                            "known to, or chosen by, the block producer before the "
                            "transaction is included, so the outcome can be computed "
                            "and gamed in advance."
                        ),
                        recommendation=(
                            "Use a commit-reveal scheme or a verifiable randomness "
                            "source (e.g. Chainlink VRF). Never derive prizes, draws or "
                            "secrets from block properties."
                        ),
                        references=["https://swcregistry.io/docs/SWC-120"],
                    )

    @staticmethod
    def _is_entropy(node: dict) -> bool:
        kind = node.get("nodeType")
        if kind == "MemberAccess":
            if identifier_name(node.get("expression")) != "block":
                return False
            return node.get("memberName") in BLOCK_ENTROPY_MEMBERS
        if kind == "FunctionCall":
            return identifier_name(node) == "blockhash"
        return False

    @staticmethod
    def _describe(node: dict) -> str:
        if node.get("nodeType") == "FunctionCall":
            return "blockhash()"
        return f"block.{node.get('memberName')}"

    def _feeds_random_context(self, node: dict, ctx: AnalysisContext) -> bool:
        """Entropy counts when it reaches a modulo, a hash, or a random-ish name."""
        current = node
        for _ in range(6):
            parent = ctx.parents.get(int(current.get("id", -1)))
            if parent is None:
                return False
            kind = parent.get("nodeType")
            if kind == "BinaryOperation" and parent.get("operator") in {"%", "^", "|", "&"}:
                return True
            if kind == "FunctionCall" and identifier_name(parent) in {
                "keccak256",
                "sha256",
                "ripemd160",
            }:
                return True
            if kind == "VariableDeclarationStatement":
                for decl in parent.get("declarations") or []:
                    if decl and RANDOMISH_NAMES.search(decl.get("name") or ""):
                        return True
            if kind == "Assignment":
                left = parent.get("leftHandSide")
                if left and RANDOMISH_NAMES.search(identifier_name(left)):
                    return True
            current = parent
        return False


class AssemblyUsage(AstDetector):
    """Inline assembly bypasses Solidity's safety checks."""

    check_id = "inline-assembly"
    title = "Use of inline assembly"
    blurb = "Assembly disables type and bounds checking."
    swc = "SWC-127"
    cwe = "CWE-1104"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for node in walk(contract.ast):
                if node.get("nodeType") != "InlineAssembly":
                    continue
                owner_contract, fn = ctx.enclosing_function(node)
                yield self.finding(
                    ctx,
                    node,
                    severity=Severity.INFORMATIONAL,
                    confidence="high",
                    contract=contract.name,
                    function=function_name(fn) if fn else "",
                    description=(
                        "Inline assembly is used here. It sidesteps the compiler's type, "
                        "bounds and overflow checking, so a small mistake can corrupt "
                        "storage silently."
                    ),
                    recommendation=(
                        "Keep assembly minimal and well-tested (fuzz it), and prefer "
                        "Solidity constructs unless the gas saving is measured and "
                        "material."
                    ),
                )


class HardcodedAddress(AstDetector):
    """Non-zero address literals baked into bytecode."""

    check_id = "hardcoded-address"
    title = "Hardcoded address literal"
    blurb = "An embedded address cannot be changed after deployment."
    swc = ""
    cwe = "CWE-1104"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if node.get("nodeType") != "Literal":
                        continue
                    if not type_string(node).startswith("address"):
                        continue
                    if is_zero_address_literal(node):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.LOW,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` embeds the address literal "
                            f"`{node.get('value')}`. If that contract is upgraded, "
                            "migrated or compromised, this one cannot follow."
                        ),
                        recommendation=(
                            "Pass the address through the constructor into an immutable, "
                            "or store it in a state variable behind an admin-only setter."
                        ),
                    )


class MissingZeroAddressCheck(AstDetector):
    """Address parameters stored without a ``!= address(0)`` guard."""

    check_id = "missing-zero-address-check"
    title = "Missing zero-address validation"
    blurb = "An address(0) owner or token bricks the contract."
    swc = ""
    cwe = "CWE-20"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            if contract.kind in ("library", "interface"):
                continue
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                params = ((fn.get("parameters") or {}).get("parameters")) or []
                address_params = {
                    int(p["id"]): p.get("name", "")
                    for p in params
                    if p.get("id") is not None
                    and type_string(p.get("typeName")).startswith("address")
                }
                if not address_params:
                    continue
                is_constructor = fn.get("kind") == "constructor"
                if is_constructor:
                    candidates = set(address_params)
                else:
                    # Outside a constructor, only flag parameters assigned
                    # straight to a scalar state variable (`owner = to`).
                    # Standard ERC-20 `approve(spender, ...)` writes a mapping
                    # keyed by the parameter and is not the same mistake.
                    candidates = self._assigned_to_scalar(fn, contract, address_params)
                if not candidates:
                    continue
                guarded = self._zero_checked(fn, candidates)
                for param_id, param_name in address_params.items():
                    if param_id not in candidates or param_id in guarded:
                        continue
                    yield self.finding(
                        ctx,
                        fn,
                        severity=Severity.MEDIUM,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` stores the address parameter "
                            f"`{param_name}` without checking it against `address(0)`. A "
                            "zero owner, token or target address usually makes the "
                            "contract permanently unusable."
                        ),
                        recommendation=(
                            f"Add `require({param_name} != address(0))` at the top of the "
                            "function."
                        ),
                        extra={"parameter": param_name},
                    )

    @staticmethod
    def _assigned_to_scalar(
        fn: dict, contract: ContractInfo, address_params: dict[int, str]
    ) -> set[int]:
        """Address params assigned directly to a non-mapping state variable."""
        from .ast_utils import references_declaration, root_identifier

        found: set[int] = set()
        body = fn.get("body")
        if not body:
            return found
        for node in walk(body):
            if node.get("nodeType") != "Assignment":
                continue
            left = node.get("leftHandSide") or {}
            if left.get("nodeType") != "Identifier":
                continue  # mapping/array writes are excluded by design
            if not contract.is_state_var(references_declaration(left)):
                continue
            right = node.get("rightHandSide")
            root = root_identifier(right)
            ref = references_declaration(root)
            if ref is not None and int(ref) in address_params:
                found.add(int(ref))
        return found

    @staticmethod
    def _zero_checked(fn: dict, param_ids: set[int]) -> set[int]:
        """Parameter ids that appear in a require alongside address(0)."""
        found: set[int] = set()
        body = fn.get("body")
        if not body:
            return found
        for node in walk(body):
            if node.get("nodeType") != "FunctionCall":
                continue
            if identifier_name(node) not in {"require", "assert"}:
                continue
            args = node.get("arguments") or []
            if not args:
                continue
            condition = args[0]
            mentions_zero = any(
                is_zero_address_literal(n) for n in walk(condition)
            )
            if not mentions_zero:
                continue
            for n in walk(condition):
                ref = n.get("referencedDeclaration")
                if n.get("nodeType") == "Identifier" and ref is not None:
                    if int(ref) in param_ids:
                        found.add(int(ref))
        return found


class Erc20ApproveRace(AstDetector):
    """Direct ``allowance`` overwrite in ``approve``."""

    check_id = "erc20-approve-race"
    title = "ERC-20 approve front-running"
    blurb = "The classic allowance race condition."
    swc = "SWC-114"
    cwe = "CWE-362"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            fn = contract.function_by_name("approve")
            if fn is None:
                continue
            body = fn.get("body")
            if not body:
                continue
            from .ast_utils import state_write_info

            writes = [state_write_info(n, contract) for n in walk(body)]
            if not any(w for w in writes if w):
                continue
            has_safe_path = (
                contract.function_by_name("increaseAllowance") is not None
                or contract.function_by_name("decreaseAllowance") is not None
                or any(
                    identifier_name(n) in {"increaseAllowance", "decreaseAllowance"}
                    for n in walk(body)
                )
                # The "must reset to zero first" mitigation.
                or any(is_zero_address_literal(n) for n in walk(body))
            )
            if has_safe_path:
                continue
            # A zero-then-set sequence is the standard mitigation.
            yield self.finding(
                ctx,
                fn,
                severity=Severity.MEDIUM,
                confidence="medium",
                contract=contract.name,
                function=function_signature(fn),
                description=(
                    "`approve` overwrites the allowance directly. A spender watching the "
                    "mempool can spend the old allowance, then the new one, in that "
                    "order, taking both."
                ),
                recommendation=(
                    "Provide `increaseAllowance`/`decreaseAllowance`, or require the "
                    "caller to reset the allowance to zero first."
                ),
                references=["https://swcregistry.io/docs/SWC-114"],
            )


class DeprecatedUsage(AstDetector):
    """``now``, ``sha3``, ``suicide``, ``throw`` and friends."""

    check_id = "deprecated-usage"
    title = "Deprecated Solidity construct"
    blurb = "Removed or renamed in modern compilers."
    swc = "SWC-111"
    cwe = "CWE-477"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for node in walk(contract.ast):
                if node.get("nodeType") not in {"Identifier", "MemberAccess"}:
                    continue
                name = identifier_name(node)
                if name not in DEPRECATED_IDENTIFIERS:
                    continue
                yield self.finding(
                    ctx,
                    node,
                    severity=Severity.INFORMATIONAL,
                    confidence="high",
                    contract=contract.name,
                    description=(
                        f"`{name}` is deprecated or removed in current Solidity "
                        "versions."
                    ),
                    recommendation={
                        "now": "Use `block.timestamp`.",
                        "sha3": "Use `keccak256`.",
                        "suicide": "Use `selfdestruct` (and reconsider using it at all).",
                        "throw": "Use `revert()` or `require(...)`.",
                    }.get(name, "Replace with the modern equivalent."),
                    references=["https://swcregistry.io/docs/SWC-111"],
                    extra={"identifier": name},
                )


class ExternalFunction(AstDetector):
    """``public`` functions never called internally cost more gas."""

    check_id = "external-function"
    title = "Public function could be external"
    blurb = "external avoids copying arguments to memory."
    swc = ""
    cwe = ""

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            if contract.is_abstract or contract.kind in ("interface", "library"):
                continue
            internal_refs: set[str] = set()
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if node.get("nodeType") == "Identifier":
                        internal_refs.add(node.get("name", ""))
            for fn in contract.functions:
                if fn.get("visibility") != "public":
                    continue
                name = fn.get("name")
                if not name or name in internal_refs:
                    continue
                if fn.get("kind") in ("constructor", "receive", "fallback"):
                    continue
                yield self.finding(
                    ctx,
                    fn,
                    severity=Severity.OPTIMIZATION,
                    confidence="low",
                    contract=contract.name,
                    function=function_signature(fn),
                    description=(
                        f"`{name}` is `public` but is never called from inside "
                        f"`{contract.name}`."
                    ),
                    recommendation="Declare it `external` to skip the memory copy of arguments.",
                )


class LongFunction(AstDetector):
    """Very long function bodies are hard to audit and reason about."""

    check_id = "long-function"
    title = "Overlong function"
    blurb = "Large bodies hide invariants and raise audit cost."
    swc = ""
    cwe = "CWE-1080"

    MAX_LINES = 60

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                _, start_line, _, _ = ctx.locate(fn)
                _, end_line, _ = ctx.end_location(body)
                if not start_line or not end_line:
                    continue
                length = end_line - start_line
                if length <= self.MAX_LINES:
                    continue
                yield self.finding(
                    ctx,
                    fn,
                    severity=Severity.OPTIMIZATION,
                    confidence="high",
                    contract=contract.name,
                    function=function_name(fn),
                    description=(
                        f"`{function_name(fn)}` spans roughly {length} lines. Long "
                        "functions are harder to audit, easier to get wrong on edit, "
                        "and may push the deployment over the contract size limit."
                    ),
                    recommendation="Split into smaller internal helpers with single responsibilities.",
                    extra={"approx_lines": length},
                )


class CompilerDiagnostics(Detector):
    """Surfaces solc's own warnings as findings.

    Does not require an AST: even a failed compile yields useful messages, and
    the user needs to see *why* the deeper checks could not run.
    """

    check_id = "compiler-diagnostic"
    title = "Compiler diagnostic"
    blurb = "Warnings and errors reported by solc itself."
    swc = ""
    cwe = ""

    #: solc warning type -> severity
    SEVERITY_BY_TYPE: dict[str, Severity] = {
        "UninitializedStoragePointer": Severity.HIGH,
        "TxOrigin": Severity.HIGH,
        "PayableNoReceive": Severity.MEDIUM,
        "ShadowingStateVariables": Severity.LOW,
        "ShadowingLocalVariables": Severity.LOW,
        "Visibility": Severity.LOW,
        "Return": Severity.LOW,
        "Deprecated": Severity.LOW,
        "UnusedLocalVariable": Severity.INFORMATIONAL,
        "FuncMutability": Severity.INFORMATIONAL,
        "InlineAssembly": Severity.INFORMATIONAL,
        "DataLocation": Severity.INFORMATIONAL,
        "UnnamedReturnVariable": Severity.INFORMATIONAL,
    }

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for message in ctx.compilation.messages:
            severity = (
                Severity.LOW
                if message.severity == "error"
                else self.SEVERITY_BY_TYPE.get(message.type, Severity.INFORMATIONAL)
            )
            yield Finding(
                check_id=f"compiler-{message.severity}",
                title=(
                    "Compiler error" if message.severity == "error" else "Compiler warning"
                ),
                severity=severity,
                confidence="high",
                description=message.message.strip(),
                recommendation=(
                    "Resolve this compiler diagnostic before relying on the rest of the "
                    "audit: parse errors stop the AST-based detectors from running."
                    if message.severity == "error"
                    else "Review the compiler's own diagnosis."
                ),
                location={
                    "file": message.file,
                    "line": message.line,
                    "column": message.column,
                    "snippet": "",
                },
                extra={"compiler_type": message.type},
            )
