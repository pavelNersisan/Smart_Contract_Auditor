"""Access-control checks: selfdestruct, withdrawals, initializers, tx.origin."""

from __future__ import annotations

import re
from typing import Iterable

from app.models.audit import Finding, Severity

from .ast_utils import (
    ACCESS_CONTROL_MODIFIER_RE,
    INITIALIZER_NAME_RE,
    AnalysisContext,
    ContractInfo,
    external_call_info,
    find_all,
    function_name,
    has_access_control,
    identifier_name,
    is_msg_sender,
    is_msg_value,
    is_tx_origin,
    root_identifier,
    value_arguments,
    visibility_is_public,
    walk,
)
from .base import AstDetector


def _is_msg_sender_indexed(write: dict) -> bool:
    """True for ``mapping[msg.sender] = ...`` style self-service writes."""
    if write["via"] not in {"index", "delete-index"}:
        return False
    node = write["node"]
    if node.get("nodeType") == "Assignment":
        left = node.get("leftHandSide")
    else:  # delete balances[x]
        left = node.get("subExpression")
    if not left or left.get("nodeType") != "IndexAccess":
        return False
    return any(is_msg_sender(n) for n in walk(left.get("indexExpression") or {}))


class Suicidal(AstDetector):
    """``selfdestruct`` reachable by anyone."""

    check_id = "suicidal"
    title = "Unprotected selfdestruct"
    blurb = "selfdestruct callable without access control."
    swc = "SWC-106"
    cwe = "CWE-284"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            if contract.kind in ("library", "interface"):
                continue
            for fn in contract.functions:
                if not visibility_is_public(fn):
                    continue
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    name = identifier_name(node)
                    if name not in {"selfdestruct", "suicide"}:
                        continue
                    if has_access_control(fn, contract):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.CRITICAL,
                        confidence="high",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` is {fn.get('visibility')} and calls "
                            "`selfdestruct` with no caller check. Anyone can destroy the "
                            "contract and force its remaining balance to an address of "
                            "their choosing, permanently bricking the system."
                        ),
                        recommendation=(
                            "Guard the function with an owner/role modifier "
                            "(`onlyOwner`, `onlyRole(DEFAULT_ADMIN_ROLE)`), or remove "
                            "`selfdestruct` entirely -- on post-Dencun chains destroyed "
                            "code can be redeployed at the same address, which makes "
                            "selfdestruct actively dangerous in proxies."
                        ),
                        references=["https://swcregistry.io/docs/SWC-106"],
                    )


class UnprotectedEtherWithdrawal(AstDetector):
    """Public function pushes ether to a caller-chosen address."""

    check_id = "unprotected-ether-withdrawal"
    title = "Unprotected ether withdrawal"
    blurb = "Anyone can drain the contract balance."
    swc = "SWC-105"
    cwe = "CWE-284"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            if contract.kind in ("library", "interface"):
                continue
            for fn in contract.functions:
                if fn.get("kind") in ("receive", "fallback"):
                    continue
                if not visibility_is_public(fn):
                    continue
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    info = external_call_info(node, ctx)
                    if not info or not info["sends_eth"]:
                        continue
                    if has_access_control(fn, contract):
                        continue
                    if self._pays_caller_own_balance(info, fn):
                        # Ordinary `withdraw()` of the caller's own balance;
                        # the real risk there is reentrancy, reported separately.
                        continue
                    if self._forwards_caller_value(info, fn):
                        # A payable function forwarding the caller's own
                        # msg.value is not draining the contract.
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.CRITICAL,
                        confidence="high",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` is "
                            f"{fn.get('visibility') or 'public'} and sends ether without "
                            "restricting the caller or the destination. Any account can "
                            "drain the contract."
                        ),
                        recommendation=(
                            "Add an access-control modifier, or restrict the destination "
                            "to `msg.sender` with a balance accounting check."
                        ),
                        references=["https://swcregistry.io/docs/SWC-105"],
                    )

    @staticmethod
    def _pays_caller_own_balance(info: dict, fn: dict) -> bool:
        """Heuristic: destination is msg.sender and it is paid from a mapping."""
        dest = info.get("address_expression")
        if not is_msg_sender(dest):
            return False
        params = ((fn.get("parameters") or {}).get("parameters")) or []
        # `withdraw(address to)` that happens to receive msg.sender is not a
        # self-payment pattern; require no address parameter.
        return not any(
            (p.get("typeName") or {}).get("name") == "address" for p in params
        )

    @staticmethod
    def _forwards_caller_value(info: dict, fn: dict) -> bool:
        """True when a payable function forwards the caller's own ``msg.value``.

        ``function tip(address payable to) external payable { to.send(msg.value); }``
        moves the caller's money, not the contract's, so it is not a drain.
        """
        if (fn.get("stateMutability") or "") != "payable":
            return False
        return any(
            is_msg_value(node)
            for value in value_arguments(info["call_node"])
            for node in walk(value)
        )


class UnprotectedInitializer(AstDetector):
    """Public ``initialize()`` with no owner set and no guard flag."""

    check_id = "unprotected-initializer"
    title = "Unprotected initializer"
    blurb = "initialize() can be called by anyone, including on a proxy."
    swc = "SWC-118"
    cwe = "CWE-306"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            if contract.kind in ("library", "interface"):
                continue
            for fn in contract.functions:
                name = fn.get("name") or ""
                if not INITIALIZER_NAME_RE.match(name):
                    continue
                if not visibility_is_public(fn):
                    continue
                if has_access_control(fn, contract):
                    continue
                if self._has_initialized_guard(fn):
                    continue
                yield self.finding(
                    ctx,
                    fn,
                    severity=Severity.HIGH,
                    confidence="medium",
                    contract=contract.name,
                    function=name,
                    description=(
                        f"`{name}` is callable by anyone and has neither a caller "
                        "check nor an `initialized` guard. Behind a proxy the first "
                        "caller becomes owner and controls every privileged function."
                    ),
                    recommendation=(
                        "Set the owner inside the initializer and guard it with a "
                        "one-shot flag (`if (initialized) revert();` or OpenZeppelin's "
                        "`initializer` modifier). Call the initializer in the same "
                        "transaction as deployment."
                    ),
                    references=[
                        "https://swcregistry.io/docs/SWC-118",
                        "https://docs.openzeppelin.com/upgrades-plugins/",
                    ],
                )

    @staticmethod
    def _has_initialized_guard(fn: dict) -> bool:
        body = fn.get("body")
        if not body:
            return False
        for node in walk(body):
            if node.get("nodeType") == "Identifier" and re.search(
                r"initialized|_initialized|isInitialized", node.get("name", ""), re.I
            ):
                return True
        return False


class MissingAccessControlOnSetter(AstDetector):
    """Public state writer in a contract that clearly does use access control.

    The precondition (some *other* function in the contract is protected) is
    what keeps this from firing on plain public-setter designs.
    """

    check_id = "missing-access-control-setter"
    title = "Privileged setter without access control"
    blurb = "Public state writer in a contract that protects other functions."
    swc = "SWC-105"
    cwe = "CWE-862"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            if contract.kind in ("library", "interface"):
                continue
            protected = [
                fn for fn in contract.functions if has_access_control(fn, contract)
            ]
            if not protected:
                continue
            for fn in contract.functions:
                if not visibility_is_public(fn):
                    continue
                if has_access_control(fn, contract):
                    continue
                if fn.get("kind") in ("constructor", "receive", "fallback"):
                    continue
                # `initialize()` is already covered by UnprotectedInitializer.
                if INITIALIZER_NAME_RE.match(fn.get("name") or ""):
                    continue
                body = fn.get("body")
                if not body:
                    continue
                from .ast_utils import state_write_info

                writes = [w for w in (state_write_info(n, contract) for n in walk(body)) if w]
                written = sorted({w["name"] for w in writes if w["name"]})
                if not written:
                    continue
                # A public function that only touches the caller's own ledger
                # entry (deposit/withdraw/claim) is self-service by design.
                if all(_is_msg_sender_indexed(w) for w in writes):
                    continue
                if any(ACCESS_CONTROL_MODIFIER_RE.search(name) for name in [fn.get("name", "")]):
                    continue
                yield self.finding(
                    ctx,
                    fn,
                    severity=Severity.MEDIUM,
                    confidence="low",
                    contract=contract.name,
                    function=function_name(fn),
                    description=(
                        f"`{function_name(fn)}` writes {', '.join(written)} but has no "
                        "caller restriction, while other functions in "
                        f"`{contract.name}` are protected. This is often an oversight."
                    ),
                    recommendation=(
                        "If only privileged roles should call it, add the same modifier "
                        "used elsewhere in this contract; otherwise document that it is "
                        "intentionally permissionless."
                    ),
                    extra={"state_variables": written},
                )


class TxOriginAuth(AstDetector):
    """Authorization based on ``tx.origin``."""

    check_id = "tx-origin-auth"
    title = "Authorization uses tx.origin"
    blurb = "tx.origin comparison is phishable (SWC-115)."
    swc = "SWC-115"
    cwe = "CWE-477"

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:
        for contract in ctx.contracts:
            for fn in contract.functions:
                body = fn.get("body")
                if not body:
                    continue
                for node in walk(body):
                    if not is_tx_origin(node):
                        continue
                    if not self._used_in_comparison(ctx, node):
                        continue
                    yield self.finding(
                        ctx,
                        node,
                        severity=Severity.HIGH,
                        confidence="high",
                        contract=contract.name,
                        function=function_name(fn),
                        description=(
                            f"`{function_name(fn)}` authorizes using `tx.origin`, which "
                            "is the original externally-owned account rather than the "
                            "immediate caller. A malicious contract the victim interacts "
                            "with can relay the call and pass this check, letting it act "
                            "as the victim."
                        ),
                        recommendation=(
                            "Use `msg.sender` for authorization and signature-based "
                            "delegation (EIP-712 + EIP-1271) where an EOA identity is "
                            "really required."
                        ),
                        references=["https://swcregistry.io/docs/SWC-115"],
                    )

    @staticmethod
    def _used_in_comparison(ctx: AnalysisContext, node: dict) -> bool:
        parent = ctx.parents.get(int(node.get("id", -1)))
        return bool(parent) and parent.get("nodeType") in {
            "BinaryOperation",
            "UnaryOperation",
        }
