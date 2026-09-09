"""Low-level call handling: unchecked returns, loops, delegatecall."""

from __future__ import annotations

from typing import Iterable

from app.models.audit import Finding, Severity

from .ast_utils import (
    AnalysisContext,
    ContractInfo,
    external_call_info,
    find_external_calls,
    function_name,
    identifier_name,
    is_msg_value,
    is_result_discarded,
    root_identifier,
    walk,
)
from .base import AstDetector


def _src_range(node: dict) -> tuple[int, int]:
    parts = (node.get("src") or "0:0:0").split(":")
    try:
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return 0, 0


def _contains(outer: dict, inner: dict) -> bool:
    o_start, o_len = _src_range(outer)
    i_start, _ = _src_range(inner)
    return o_start <= i_start < o_start + o_len


def _loop_nodes(body: dict) -> list[dict]:
    return [
        n
        for n in walk(body)
        if n.get("nodeType") in {"ForStatement", "WhileStatement", "DoWhileStatement"}
    ]


def _parameter_ids(fn: dict) -> set[int]:
    params = ((fn.get("parameters") or {}).get("parameters")) or []
    return {int(p["id"]) for p in params if "id" in p}



class UncheckedSend(AstDetector):
    """``address.send()`` return value ignored."""

    check_id = "unchecked-send"
    title = "Unchecked send() return value"
    blurb = "send() returns false on failure instead of reverting."
    swc = "SWC-104"
    cwe = "CWE-252"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for info in find_external_calls(body, ctx):
                    if info["member"] != "send":
                        continue
                    if not is_result_discarded(ctx.parents, info["call_node"]):
                        continue
                    yield self.finding(
                        ctx,
                        info["call_node"],
                        severity=Severity.HIGH,
                        confidence="high",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` ignores the boolean returned by "
                            "`send()`. `send` forwards a fixed 2300 gas stipend and "
                            "returns false rather than reverting when the recipient "
                            "cannot accept ether, so the contract continues as though "
                            "the transfer succeeded."
                        ),
                        recommendation=(
                            "Check the result (`require(addr.send(x), \"send failed\")`) "
                            "or switch to `call{value: x}(\"\")` with the boolean "
                            "checked. If the failure should abort the transaction, "
                            "`transfer` gives that behaviour directly."
                        ),
                        references=["https://swcregistry.io/docs/SWC-104"],
                    )


class UncheckedLowLevelCall(AstDetector):
    """``address.call()`` / ``delegatecall`` result ignored."""

    check_id = "unchecked-lowlevel-call"
    title = "Unchecked low-level call"
    blurb = "call()/delegatecall() success flag discarded."
    swc = "SWC-104"
    cwe = "CWE-252"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for info in find_external_calls(body, ctx):
                    if info["member"] not in {"call", "delegatecall", "callcode"}:
                        continue
                    if not is_result_discarded(ctx.parents, info["call_node"]):
                        continue
                    yield self.finding(
                        ctx,
                        info["call_node"],
                        severity=Severity.HIGH,
                        confidence="high",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` discards the `(bool success, bytes "
                            f"data)` returned by `{info['member']}`. A silently failed "
                            "call leaves the caller believing the interaction happened."
                        ),
                        recommendation=(
                            "Bind and check the result: "
                            "`(bool ok, ) = target.call(data); require(ok, \"call failed\");`"
                        ),
                        references=["https://swcregistry.io/docs/SWC-104"],
                    )


class CallsInsideLoop(AstDetector):
    """External calls inside a loop (gas griefing / DoS)."""

    check_id = "calls-inside-loop"
    title = "External call inside a loop"
    blurb = "Unbounded iteration over callees enables gas-limit DoS."
    swc = "SWC-113"
    cwe = "CWE-400"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                loops = _loop_nodes(body)
                if not loops:
                    continue
                reported: set[int] = set()
                for info in find_external_calls(body, ctx):
                    node = info["call_node"]
                    if id(node) in reported:
                        continue
                    if not any(_contains(loop, node) for loop in loops):
                        continue
                    reported.add(id(node))
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.MEDIUM,
                        confidence="medium",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` performs an external call inside a "
                            "loop. If the iteration count is attacker-influenced, or a "
                            "single callee reverts, the whole batch becomes impossible "
                            "to execute within the block gas limit."
                        ),
                        recommendation=(
                            "Batch with an explicit index/limit, or use a pull pattern "
                            "so each recipient claims individually. Never make one "
                            "failing callee block the entire operation."
                        ),
                        references=["https://swcregistry.io/docs/SWC-113"],
                    )


class MsgValueInLoop(AstDetector):
    """``msg.value`` reused inside a loop."""

    check_id = "msg-value-in-loop"
    title = "msg.value used inside a loop"
    blurb = "A single deposit gets counted once per iteration."
    swc = "SWC-101"
    cwe = "CWE-841"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                loops = _loop_nodes(body)
                if not loops:
                    continue
                for node in walk(body):
                    if not is_msg_value(node):
                        continue
                    if not any(_contains(loop, node) for loop in loops):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.HIGH,
                        confidence="high",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` reads `msg.value` inside a loop. "
                            "`msg.value` is the total attached to the transaction, not "
                            "a per-iteration amount, so crediting it each pass mints "
                            "value out of thin air."
                        ),
                        recommendation=(
                            "Compute the per-iteration amount once before the loop "
                            "(`uint each = msg.value / n;`) and validate it against the "
                            "expected total."
                        ),
                    )


class DelegatecallToUntrustedInput(AstDetector):
    """``delegatecall`` whose target comes from a parameter or storage."""

    check_id = "delegatecall-to-untrusted-input"
    title = "delegatecall target controlled by caller or storage"
    blurb = "Arbitrary code execution in the caller's storage context."
    swc = "SWC-112"
    cwe = "CWE-829"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                param_ids = _parameter_ids(fn)
                for info in find_external_calls(body, ctx):
                    if info["member"] != "delegatecall":
                        continue
                    target = info.get("address_expression")
                    root = root_identifier(target)
                    ref = int(root["referencedDeclaration"]) if root and root.get(
                        "referencedDeclaration"
                    ) is not None else None
                    if ref is not None and ref in param_ids:
                        severity, confidence, why = (
                            Severity.CRITICAL,
                            "high",
                            "comes straight from a function parameter",
                        )
                    elif contract.is_state_var(ref):
                        severity, confidence, why = (
                            Severity.HIGH,
                            "medium",
                            f"is read from the state variable `{contract.state_var_name(ref)}`",
                        )
                    else:
                        continue
                    yield self.finding(
                        ctx,
                        info["call_node"],
                        severity=severity,
                        confidence=confidence,
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` performs a `delegatecall` whose "
                            f"target {why}. Code executed via delegatecall runs against "
                            "this contract's storage, so whoever controls the target "
                            "controls the contract."
                        ),
                        recommendation=(
                            "Restrict delegatecall targets to an immutable allowlist or "
                            "a value only an admin can set, and verify the target's code "
                            "is audited. If this is a proxy, use a vetted proxy "
                            "implementation rather than hand-rolled delegatecall."
                        ),
                        references=["https://swcregistry.io/docs/SWC-112"],
                        extra={"target_source": why},
                    )
