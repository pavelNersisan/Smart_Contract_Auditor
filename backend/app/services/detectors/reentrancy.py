"""Reentrancy detection (SWC-107).

The classic check: a function performs an external call and *then* writes
contract state, violating checks-effects-interactions. Ordering is derived from
byte offsets in ``src``, which is why ``child_nodes`` sorts by offset.

Known limitation, stated plainly: this is intra-procedural. A call into another
function of the same contract that itself reaches out is not followed, and no
call graph is built. That is what keeps the analysis fast and precise; a
symbolic engine (Mythril) is the right tool for cross-function paths and is
wired in as an optional accelerator.
"""

from __future__ import annotations

from typing import Iterable

from app.models.audit import Finding, Severity

from .ast_utils import (
    AnalysisContext,
    ContractInfo,
    find_external_calls,
    function_name,
    has_reentrancy_guard,
    state_write_info,
    walk,
)
from .base import AstDetector


def _offset(node: dict) -> int:
    src = (node.get("src") or "").split(":")
    return int(src[0]) if src and src[0].lstrip("-").isdigit() else 0


class ReentrancyEth(AstDetector):
    """Ether leaves the contract before state is updated."""

    check_id = "reentrancy-eth"
    title = "Reentrancy: ether sent before state update"
    blurb = "External value transfer followed by a state write (CEI violation)."
    swc = "SWC-107"
    cwe = "CWE-841"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                yield from self._check_function(ctx, contract, fn)

    def _check_function(
        self, ctx: AnalysisContext, contract: ContractInfo, fn: dict
    ) -> Iterable[Finding]:
        body = fn.get("body")
        if not body:
            return
        if has_reentrancy_guard(fn, contract):
            # A mutex is present; the pattern is handled, not a finding.
            return

        calls = find_external_calls(body, ctx)
        eth_calls = [c for c in calls if c["sends_eth"]]
        if not eth_calls:
            return

        reported: set[tuple[str, int]] = set()
        for node in walk(body):
            write = state_write_info(node, contract)
            if not write:
                continue
            write_at = _offset(node)
            # Only calls that happen *before* this write create the window.
            preceding = [c for c in eth_calls if _offset(c["call_node"]) < write_at]
            if not preceding:
                continue
            key = (write["name"], _offset(preceding[0]["call_node"]))
            if key in reported:
                continue
            reported.add(key)

            call_node = preceding[0]["call_node"]
            call_line = ctx.locate(call_node)[1]
            member = preceding[0]["member"]
            yield self.finding(
                ctx,
                node,
                severity=Severity.HIGH,
                confidence="high",
                contract=contract.name,
                function=function_name(fn),
                description=(
                    f"`{function_name(fn)}` sends ether via `{member}` on line "
                    f"{call_line} and only afterwards writes state variable "
                    f"`{write['name']}`. The receiving contract can re-enter "
                    f"before that write lands and repeat the withdrawal with a "
                    f"stale balance."
                ),
                recommendation=(
                    "Apply checks-effects-interactions: validate, update "
                    f"`{write['name']}` (or delete the balance entry), and only "
                    "then transfer. Add a `nonReentrant` mutex as defence in "
                    "depth, and prefer a pull-payment pattern over pushing ether."
                ),
                references=[
                    "https://swcregistry.io/docs/SWC-107",
                    "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
                ],
                extra={
                    "call_line": call_line,
                    "call_member": member,
                    "state_variable": write["name"],
                    "write_via": write["via"],
                },
            )


class ReentrancyNoEth(AstDetector):
    """State is written after a non-value external call."""

    check_id = "reentrancy-no-eth"
    title = "Reentrancy: state written after external call"
    blurb = "External call (no ether) followed by a state write."
    swc = "SWC-107"
    cwe = "CWE-841"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body or has_reentrancy_guard(fn, contract):
                    continue
                calls = find_external_calls(body, ctx)
                non_eth = [c for c in calls if not c["sends_eth"]]
                if not non_eth:
                    continue
                seen: set[str] = set()
                for node in walk(body):
                    write = state_write_info(node, contract)
                    if not write:
                        continue
                    write_at = _offset(node)
                    preceding = [c for c in non_eth if _offset(c["call_node"]) < write_at]
                    if not preceding or write["name"] in seen:
                        continue
                    seen.add(write["name"])
                    call_line = ctx.locate(preceding[0]["call_node"])[1]
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.MEDIUM,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` writes `{write['name']}` after an "
                            f"external call on line {call_line}. No ether moves in "
                            "this call, but the callee can still re-enter and observe "
                            "or exploit the not-yet-updated state."
                        ),
                        recommendation=(
                            "Move the state update above the external call, or mark the "
                            "function `nonReentrant`."
                        ),
                        references=["https://swcregistry.io/docs/SWC-107"],
                        extra={
                            "call_line": call_line,
                            "state_variable": write["name"],
                        },
                    )
