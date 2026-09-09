"""Helpers for navigating solc's standard-JSON AST.

Solidity AST nodes carry a ``src`` attribute of the form
``"<byteOffset>:<length>:<fileIndex>"``. Everything here turns those raw
offsets into the file/line/column a human needs.

Ordering note: solc serialises node fields alphabetically, so iterating a
node's values does *not* yield children in source order (``arguments`` sorts
before ``expression`` on a ``FunctionCall``). ``child_nodes`` therefore sorts
children by their ``src`` start offset to recover true document order, which
the ordering-sensitive detectors (CEI / reentrancy) depend on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.services.solc import Compilation, offset_to_line_column

HUGE = 1 << 62

#: Members of ``address`` that move ether or jump to another contract.
ETH_SENDING_MEMBERS = {"send", "transfer"}
LOW_LEVEL_CALL_MEMBERS = {"call", "delegatecall", "staticcall", "callcode"}


# --------------------------------------------------------------------------
# Traversal
# --------------------------------------------------------------------------
def _src_start(node: dict) -> int:
    src = node.get("src") or ""
    parts = src.split(":")
    if parts and parts[0].lstrip("-").isdigit():
        return int(parts[0])
    return HUGE


def child_nodes(node: dict) -> list[dict]:
    """Direct AST children, in true source order."""
    out: list[dict] = []
    for value in node.values():
        if isinstance(value, dict) and "nodeType" in value:
            out.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "nodeType" in item:
                    out.append(item)
    out.sort(key=_src_start)
    return out


def walk(node: dict):
    """Pre-order traversal in source order (yields ``node`` itself first)."""
    yield node
    for child in child_nodes(node):
        yield from walk(child)


def find_all(node: dict, node_type: str) -> list[dict]:
    return [n for n in walk(node) if n.get("nodeType") == node_type]


def find_first(node: dict, node_type: str) -> dict | None:
    for n in walk(node):
        if n.get("nodeType") == node_type:
            return n
    return None


# --------------------------------------------------------------------------
# Small predicates
# --------------------------------------------------------------------------
def type_string(node: dict | None) -> str:
    if not node:
        return ""
    return ((node.get("typeDescriptions") or {}).get("typeString") or "").strip()


def identifier_name(node: dict | None) -> str:
    """Best-effort name of an expression (``a.b`` -> ``b``, ``a`` -> ``a``)."""
    if not node:
        return ""
    kind = node.get("nodeType")
    if kind == "Identifier":
        return node.get("name", "")
    if kind == "MemberAccess":
        return node.get("memberName", "")
    if kind in ("FunctionCall", "FunctionCallOptions"):
        return identifier_name(node.get("expression"))
    if kind == "IndexAccess":
        return identifier_name(node.get("baseExpression"))
    return ""


def unwrap_tuple(node: dict | None) -> dict | None:
    """Strip single-component ``TupleExpression`` wrappers.

    ``(a / b)`` parses to a TupleExpression around the division, which would
    otherwise hide the operator from operator-level checks.
    """
    while node is not None and node.get("nodeType") == "TupleExpression":
        components = [c for c in (node.get("components") or []) if c]
        if len(components) != 1:
            return node
        node = components[0]
    return node


def root_identifier(node: dict | None) -> dict | None:
    """Left-most Identifier of an expression chain (``a.b[c].d`` -> ``a``)."""
    cur = node
    while cur:
        kind = cur.get("nodeType")
        if kind == "Identifier":
            return cur
        if kind in ("MemberAccess", "IndexAccess"):
            cur = cur.get("baseExpression") or cur.get("expression")
        elif kind == "FunctionCall":
            cur = cur.get("expression")
        else:
            return None
    return None


def references_declaration(node: dict | None) -> int | None:
    if not node:
        return None
    ref = node.get("referencedDeclaration")
    return int(ref) if ref is not None else None


def is_msg_sender(node: dict | None) -> bool:
    """True for the ``msg.sender`` member access."""
    return (
        bool(node)
        and node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "sender"
        and identifier_name(node.get("expression")) == "msg"
    )


def is_tx_origin(node: dict | None) -> bool:
    return (
        bool(node)
        and node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "origin"
        and identifier_name(node.get("expression")) == "tx"
    )


def is_msg_value(node: dict | None) -> bool:
    """True for the ``msg.value`` member access."""
    return (
        bool(node)
        and node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "value"
        and identifier_name(node.get("expression")) == "msg"
    )


def value_arguments(call_node: dict) -> list[dict]:
    """The ether-value expressions of a call, for either call style."""
    callee = call_node.get("expression") or {}
    if callee.get("nodeType") == "FunctionCallOptions":
        return [o for o in (callee.get("options") or []) if o]
    return [a for a in (call_node.get("arguments") or []) if a]


def is_zero_address_literal(node: dict | None) -> bool:
    """True for ``address(0)`` / ``address(0x0)``.

    solc encodes ``address(0)`` as a ``typeConversion`` FunctionCall whose
    expression is an ``ElementaryTypeNameExpression`` (not an Identifier), so
    the type name has to be read off ``typeName.name``.
    """
    if not node or node.get("nodeType") != "FunctionCall":
        return False
    expression = node.get("expression") or {}
    if expression.get("nodeType") == "ElementaryTypeNameExpression":
        is_address = (expression.get("typeName") or {}).get("name") == "address"
    else:
        is_address = identifier_name(expression) == "address"
    if not is_address:
        return False
    args = node.get("arguments") or []
    if len(args) != 1:
        return False
    lit = args[0]
    if lit.get("nodeType") != "Literal":
        return False
    value = str(lit.get("value") or "")
    hex_value = str(lit.get("hexValue") or "")
    return value == "0" or (bool(hex_value) and set(hex_value) <= {"0"})


def function_signature(fn: dict) -> str:
    """``name(type,type)`` for a FunctionDefinition."""
    name = fn.get("name") or fn.get("kind") or "<anonymous>"
    params = ((fn.get("parameters") or {}).get("parameters")) or []
    types = [type_string(p.get("typeName")) for p in params]
    return f"{name}({','.join(types)})"


def _index_parents(node: dict, parents: dict[int, dict]) -> None:
    """Populate ``parents`` for every node below ``node``."""
    for child in child_nodes(node):
        if "id" in child:
            parents[int(child["id"])] = node
        _index_parents(child, parents)


def parent_of(ctx_parents: dict[int, dict], node: dict) -> dict | None:
    if "id" not in node:
        return None
    return ctx_parents.get(int(node["id"]))


def is_result_discarded(ctx_parents: dict[int, dict], node: dict) -> bool:
    """True when a call's return value is not bound, tested or returned.

    ``addr.call(...);`` as a bare statement discards the ``(bool, bytes)``
    result; binding it in a declaration, tuple, assignment, ``require`` or
    ``if`` condition counts as checked.
    """
    parent = parent_of(ctx_parents, node)
    if parent is None:
        return False
    kind = parent.get("nodeType")
    if kind == "ExpressionStatement":
        return parent.get("expression") is node or (
            "id" in node and parent.get("expression", {}).get("id") == node.get("id")
        )
    return False


def function_name(fn: dict) -> str:
    return fn.get("name") or fn.get("kind") or "<anonymous>"


# --------------------------------------------------------------------------
# Version handling
# --------------------------------------------------------------------------
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(text or "")
    if not match:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


def pragma_texts(source_unit: dict) -> list[str]:
    """Raw pragma strings from a SourceUnit, e.g. ``["^0.8.0"]``."""
    out = []
    for node in source_unit.get("nodes") or []:
        if node.get("nodeType") == "PragmaDirective":
            literals = node.get("literals") or []
            if literals and literals[0] == "solidity":
                out.append("".join(literals[1:]))
    return out


def max_pragma_version(source_unit: dict) -> tuple[int, int, int] | None:
    versions = [v for v in (parse_version(t) for t in pragma_texts(source_unit)) if v]
    return max(versions) if versions else None


# --------------------------------------------------------------------------
# Analysis context
# --------------------------------------------------------------------------
@dataclass
class ContractInfo:
    """Per-contract view built once and shared by all detectors."""

    name: str
    file: str
    ast: dict
    kind: str = "contract"
    is_abstract: bool = False
    state_vars: dict[int, str] = field(default_factory=dict)  # id -> name
    functions: list[dict] = field(default_factory=list)
    modifiers: dict[str, dict] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    base_contract_ids: list[int] = field(default_factory=list)
    using_for: list[dict] = field(default_factory=list)
    version: tuple[int, int, int] | None = None

    #: Populated after all contracts are known: state vars including inherited.
    all_state_var_ids: set[int] = field(default_factory=set)

    def function_by_name(self, name: str) -> dict | None:
        for fn in self.functions:
            if fn.get("name") == name:
                return fn
        return None

    def is_state_var(self, node_id: int | None) -> bool:
        return node_id is not None and node_id in self.all_state_var_ids

    def state_var_name(self, node_id: int | None) -> str:
        return self.state_vars.get(node_id or -1, "")


@dataclass
class AnalysisContext:
    """Everything a detector may need."""

    compilation: Compilation
    contracts: list[ContractInfo]
    #: AST node id -> node, across every parsed file.
    nodes_by_id: dict[int, dict] = field(default_factory=dict)
    #: AST node id -> owning ContractInfo (for nodes inside a contract).
    owner_by_id: dict[int, ContractInfo] = field(default_factory=dict)
    #: Function node id -> (contract, function) for quick attribution.
    function_owner: dict[int, tuple[ContractInfo, dict]] = field(default_factory=dict)
    #: AST node id -> parent node. solc omits parent links; we rebuild them so
    #: detectors can ask whether a call's return value is consumed.
    parents: dict[int, dict] = field(default_factory=dict)

    # -- location ----------------------------------------------------------
    def locate(self, node: dict) -> tuple[str, int, int, str]:
        """Resolve a node's ``src`` to (file, line, column, snippet)."""
        src = node.get("src") or ""
        parts = src.split(":")
        if len(parts) < 3:
            return ("", 0, 0, "")
        try:
            start = int(parts[0])
            file_index = int(parts[2])
        except ValueError:
            return ("", 0, 0, "")
        name = self.compilation.file_index_to_name.get(file_index, "")
        if not name:
            return ("", 0, 0, "")
        offsets = self.compilation.line_indexes.get(name)
        if not offsets:
            return (name, 0, 0, "")
        line, column = offset_to_line_column(offsets, start)
        text = self.compilation.sources.get(name, "")
        snippet = ""
        if text:
            lines = text.splitlines()
            if 0 < line <= len(lines):
                snippet = lines[line - 1].strip()[:200]
        return (name, line, column, snippet)

    def end_location(self, node: dict) -> tuple[str, int, int]:
        """(file, line, column) of the *end* of a node, from ``start + length``."""
        parts = (node.get("src") or "").split(":")
        if len(parts) < 3:
            return ("", 0, 0)
        try:
            start, length, file_index = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            return ("", 0, 0)
        name = self.compilation.file_index_to_name.get(file_index, "")
        offsets = self.compilation.line_indexes.get(name)
        if not name or not offsets:
            return (name, 0, 0)
        line, column = offset_to_line_column(offsets, start + max(length - 1, 0))
        return (name, line, column)

    def enclosing_function(self, node: dict) -> tuple[ContractInfo | None, dict | None]:
        """Find the function containing ``node`` by AST-offset containment."""
        start = _src_start(node)
        best: tuple[ContractInfo | None, dict | None] = (None, None)
        best_span = HUGE
        for contract, fn in self.function_owner.values():
            fstart = _src_start(fn)
            fsrc = (fn.get("src") or "0:0:0").split(":")
            try:
                flen = int(fsrc[1])
            except (ValueError, IndexError):
                flen = 0
            if fstart <= start < fstart + flen:
                span = flen
                if span < best_span:
                    best_span = span
                    best = (contract, fn)
        return best

    # -- build -------------------------------------------------------------
    @classmethod
    def build(cls, compilation: Compilation) -> "AnalysisContext":
        nodes_by_id: dict[int, dict] = {}
        contracts: list[ContractInfo] = []
        owner_by_id: dict[int, ContractInfo] = {}
        parents: dict[int, dict] = {}

        for file_name, source_unit in compilation.asts.items():
            for node in walk(source_unit):
                if "id" in node:
                    nodes_by_id[int(node["id"])] = node

            for contract_ast in source_unit.get("nodes") or []:
                if contract_ast.get("nodeType") != "ContractDefinition":
                    continue
                info = ContractInfo(
                    name=contract_ast.get("name", ""),
                    file=file_name,
                    ast=contract_ast,
                    kind=contract_ast.get("kind", "contract"),
                    is_abstract=bool(contract_ast.get("abstract")),
                    base_contract_ids=[
                        int(b) for b in contract_ast.get("linearizedBaseContracts") or []
                    ],
                    version=max_pragma_version(source_unit),
                )
                for member in contract_ast.get("nodes") or []:
                    mtype = member.get("nodeType")
                    if mtype == "VariableDeclaration" and member.get("stateVariable"):
                        info.state_vars[int(member["id"])] = member.get("name", "")
                    elif mtype == "FunctionDefinition":
                        info.functions.append(member)
                    elif mtype == "ModifierDefinition":
                        info.modifiers[member.get("name", "")] = member
                    elif mtype == "EventDefinition":
                        info.events.append(member)
                    elif mtype == "UsingForDirective":
                        info.using_for.append(member)
                contracts.append(info)
                for node in walk(contract_ast):
                    if "id" in node:
                        owner_by_id[int(node["id"])] = info
                _index_parents(contract_ast, parents)

        ctx = cls(
            compilation=compilation,
            contracts=contracts,
            nodes_by_id=nodes_by_id,
            owner_by_id=owner_by_id,
            parents=parents,
        )

        # Resolve inheritance so inherited state vars count as writes too.
        by_node_id = {
            int(c.ast["id"]): c for c in contracts if "id" in c.ast
        }
        for info in contracts:
            ids = set(info.state_vars)
            for base_id in info.base_contract_ids:
                base = by_node_id.get(base_id)
                if base is not None and base is not info:
                    ids |= set(base.state_vars)
            info.all_state_var_ids = ids

        for info in contracts:
            for fn in info.functions:
                ctx.function_owner[int(fn["id"])] = (info, fn)
        return ctx


# --------------------------------------------------------------------------
# Semantic helpers used by several detectors
# --------------------------------------------------------------------------
def external_call_info(node: dict, ctx: AnalysisContext) -> dict | None:
    """Classify an expression as an external call, or return ``None``.

    Returns ``{"member", "sends_eth", "target_type", "call_node"}``.
    """
    if node.get("nodeType") != "FunctionCall":
        return None

    callee = node.get("expression")

    # `addr.call{value: x}(data)` wraps the callee in a FunctionCallOptions
    # node on modern solc (verified on 0.8.24). Older compilers modelled the
    # same syntax as a nested FunctionCall, so both shapes are accepted.
    option_value = False
    if callee and callee.get("nodeType") == "FunctionCallOptions":
        if "value" in (callee.get("names") or []):
            option_value = True
        callee = callee.get("expression")
    elif (
        callee
        and callee.get("nodeType") == "FunctionCall"
        and callee.get("kind") == "functionCall"
        and callee.get("names")
    ):
        if "value" in (callee.get("names") or []):
            option_value = True
        callee = callee.get("expression")

    if not callee or callee.get("nodeType") != "MemberAccess":
        return None
    member = callee.get("memberName")
    if member not in ETH_SENDING_MEMBERS | LOW_LEVEL_CALL_MEMBERS:
        return None

    base_type = type_string(callee.get("expression"))
    if not base_type.startswith("address") and not base_type.startswith("contract "):
        # e.g. an ERC-20 `transfer(address,uint256)` on an interface type.
        if member == "transfer" and base_type.startswith("contract "):
            return None
        if not base_type.startswith("address"):
            return None

    sends_eth = (
        member == "send"
        or option_value
        or (member == "transfer" and base_type.startswith("address"))
    )
    return {
        "member": member,
        "sends_eth": sends_eth,
        "target_type": base_type,
        "call_node": node,
        "address_expression": callee.get("expression"),
        "has_value_option": option_value,
    }


def find_external_calls(body: dict, ctx: AnalysisContext) -> list[dict]:
    """All external calls in a function body, in source order."""
    out = []
    for node in walk(body):
        info = external_call_info(node, ctx)
        if info:
            out.append(info)
    return out


def state_write_info(node: dict, contract: ContractInfo) -> dict | None:
    """Describe a state-variable write, or return ``None``."""
    kind = node.get("nodeType")

    if kind == "Assignment":
        left = node.get("leftHandSide")
        ref = references_declaration(root_identifier(left))
        if contract.is_state_var(ref):
            return {"name": contract.state_var_name(ref), "node": node, "via": "assign"}
        # Mapping / array element write: `balances[x] = y`
        if left and left.get("nodeType") == "IndexAccess":
            base_ref = references_declaration(root_identifier(left.get("baseExpression")))
            if contract.is_state_var(base_ref):
                return {
                    "name": contract.state_var_name(base_ref),
                    "node": node,
                    "via": "index",
                }
        return None

    if kind == "UnaryOperation" and node.get("operator") in {"++", "--"}:
        ref = references_declaration(root_identifier(node.get("subExpression")))
        if contract.is_state_var(ref):
            return {"name": contract.state_var_name(ref), "node": node, "via": "increment"}
        return None

    if kind == "UnaryOperation" and node.get("operator") == "delete":
        ref = references_declaration(node.get("subExpression"))
        if contract.is_state_var(ref):
            return {"name": contract.state_var_name(ref), "node": node, "via": "delete"}
        # delete balances[x]
        sub = node.get("subExpression")
        if sub and sub.get("nodeType") == "IndexAccess":
            base_ref = references_declaration(root_identifier(sub.get("baseExpression")))
            if contract.is_state_var(base_ref):
                return {
                    "name": contract.state_var_name(base_ref),
                    "node": node,
                    "via": "delete-index",
                }
        return None

    if kind == "FunctionCall" and identifier_name(node) == "push":
        base_ref = references_declaration(
            root_identifier((node.get("expression") or {}).get("expression"))
        )
        if contract.is_state_var(base_ref):
            return {"name": contract.state_var_name(base_ref), "node": node, "via": "push"}

    return None


#: Modifiers that conventionally implement access control.
ACCESS_CONTROL_MODIFIER_RE = re.compile(
    r"(only|auth|restrict|admin|owner|governance|guard|permission|require)", re.I
)
#: Modifiers that are *not* access control despite matching loosely.
NON_ACCESS_MODIFIERS = {"whenNotPaused", "nonReentrant", "noDelegateCall"}

INITIALIZER_NAME_RE = re.compile(r"^(initialize|init|setup|setUp|__\w*init\w*)", re.I)


OWNER_LIKE_IDENTIFIERS = {"owner", "_owner", "admin", "_admin", "governance", "manager"}
ROLE_CHECK_FUNCTIONS = {
    "_checkRole",
    "_checkOwner",
    "checkOwner",
    "_requireOwner",
    "requireOwner",
    "hasRole",
    "onlyOwner",
    "auth",
    "_authorize",
    "_requireAuth",
}


def _mentions_caller_or_owner(node: dict | None) -> bool:
    """True if an expression refers to the caller or an owner-like identity."""
    if not node:
        return False
    for n in walk(node):
        if is_msg_sender(n) or is_tx_origin(n):
            return True
        if n.get("nodeType") == "BinaryOperation" and n.get("operator") in {"==", "!="}:
            for side in (n.get("leftExpression"), n.get("rightExpression")):
                if identifier_name(side) in OWNER_LIKE_IDENTIFIERS:
                    return True
    return False


def _contains_revert(node: dict | None) -> bool:
    """True if a body reverts (``revert()``, ``require``-less guard, etc.)."""
    if not node:
        return False
    for n in walk(node):
        if n.get("nodeType") == "FunctionCall" and identifier_name(n) in {
            "revert",
            "require",
            "assert",
        }:
            return True
    return False


def _body_enforces_caller(node: dict) -> bool:
    """True if a body *enforces* a caller restriction.

    Mere mention of ``msg.sender`` is not enough -- ``owner = msg.sender`` is an
    assignment, not a guard. A restriction counts only when it appears in a
    ``require``/``assert`` or in an ``if`` that reverts.
    """
    for n in walk(node):
        kind = n.get("nodeType")
        if kind != "FunctionCall":
            if kind == "IfStatement":
                guarded = _contains_revert(n.get("trueBody")) or _contains_revert(
                    n.get("falseBody")
                )
                if guarded and _mentions_caller_or_owner(n.get("condition")):
                    return True
            continue

        name = identifier_name(n)
        if name in ROLE_CHECK_FUNCTIONS:
            return True
        if name in {"require", "assert"} and _mentions_caller_or_owner(n):
            return True
    return False


def has_access_control(fn: dict, contract: ContractInfo) -> bool:
    """Conservative check: does this function restrict who may call it?"""
    visibility = fn.get("visibility")
    if visibility in ("private", "internal"):
        return True

    for invocation in fn.get("modifiers") or []:
        name = identifier_name(invocation.get("modifierName"))
        if not name or name in NON_ACCESS_MODIFIERS:
            continue
        definition = contract.modifiers.get(name)
        if definition is not None:
            if _body_enforces_caller(definition.get("body") or definition):
                return True
        elif ACCESS_CONTROL_MODIFIER_RE.search(name):
            # Inherited (e.g. OpenZeppelin `onlyOwner`); trust the convention.
            return True

    body = fn.get("body")
    if body and _body_enforces_caller(body):
        return True

    # A function that only forwards to an access-controlled internal helper is
    # still protected in practice; approximate by scanning internal calls.
    return False


def has_reentrancy_guard(fn: dict, contract: ContractInfo) -> bool:
    """True when a nonReentrant-style guard is applied."""
    for invocation in fn.get("modifiers") or []:
        name = identifier_name(invocation.get("modifierName"))
        if name and re.search(r"reentran|nonreentrant|lock", name, re.I):
            return True
    for node in walk(fn.get("body") or {}):
        if node.get("nodeType") == "VariableDeclaration" and re.search(
            r"lock", node.get("name", ""), re.I
        ):
            return True
    return False


def is_payable(fn: dict) -> bool:
    return fn.get("stateMutability") == "payable"


def visibility_is_public(fn: dict) -> bool:
    return fn.get("visibility") in ("public", "external", None)
