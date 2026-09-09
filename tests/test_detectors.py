"""Detector behaviour tests.

Each test asserts a *specific* check fires on a *specific* line of a fixture,
and that the clean fixtures stay clean. That combination is what distinguishes
a working analyser from one that merely runs.
"""

from __future__ import annotations

import pytest


def check_ids(result) -> set[str]:
    return {f.check_id for f in result.findings}


def findings_for(result, check_id):
    return [f for f in result.findings if f.check_id == check_id]


class TestReentrancy:
    def test_eth_reentrancy_detected(self, audit_cache):
        result = audit_cache("vulnerable/ReentrantVault.sol")
        hits = findings_for(result, "reentrancy-eth")
        assert len(hits) == 1
        assert hits[0].contract == "ReentrantVault"
        assert hits[0].function == "withdraw"
        assert hits[0].location.line == 21
        assert hits[0].severity.name == "HIGH"
        assert hits[0].swc == "SWC-107"

    def test_non_eth_reentrancy_detected(self, audit_cache):
        result = audit_cache("vulnerable/ReentrantVault.sol")
        hits = findings_for(result, "reentrancy-no-eth")
        assert len(hits) == 1
        assert hits[0].function == "sync"

    def test_cei_and_mutex_do_not_trigger(self, audit_cache):
        result = audit_cache("safe/SafeVault.sol")
        assert "reentrancy-eth" not in check_ids(result)
        assert "reentrancy-no-eth" not in check_ids(result)


class TestAccessControl:
    def test_unprotected_selfdestruct(self, audit_cache):
        result = audit_cache("vulnerable/AccessControlFail.sol")
        hits = findings_for(result, "suicidal")
        assert len(hits) == 1
        assert hits[0].function == "kill"
        assert hits[0].severity.name == "CRITICAL"

    def test_unprotected_withdrawal(self, audit_cache):
        result = audit_cache("vulnerable/AccessControlFail.sol")
        hits = findings_for(result, "unprotected-ether-withdrawal")
        assert any(h.function == "sweep" for h in hits)

    def test_unprotected_initializer(self, audit_cache):
        result = audit_cache("vulnerable/AccessControlFail.sol")
        hits = findings_for(result, "unprotected-initializer")
        assert len(hits) == 1
        assert hits[0].function == "initialize"

    def test_tx_origin_authorization(self, audit_cache):
        result = audit_cache("vulnerable/AccessControlFail.sol")
        hits = findings_for(result, "tx-origin-auth")
        assert len(hits) == 1
        assert hits[0].function == "setFee"
        assert hits[0].swc == "SWC-115"

    def test_only_owner_modifier_counts_as_control(self, audit_cache):
        result = audit_cache("safe/SafeVault.sol")
        assert "suicidal" not in check_ids(result)
        assert "unprotected-ether-withdrawal" not in check_ids(result)

    def test_assignment_of_msg_sender_is_not_access_control(self, source_of):
        """`owner = msg.sender` is an assignment, not a guard."""
        from app.services.engine import audit_sources

        source = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Sneaky {
    address public owner;
    function initialize() external { owner = msg.sender; }
}
"""
        result = audit_sources({"Sneaky.sol": source}, run_external_tools=False)
        assert "unprotected-initializer" in check_ids(result)


class TestExternalCalls:
    def test_unchecked_send(self, audit_cache):
        result = audit_cache("vulnerable/ExternalCallIssues.sol")
        hits = findings_for(result, "unchecked-send")
        assert len(hits) == 1
        assert hits[0].function == "tip"
        assert hits[0].swc == "SWC-104"

    def test_unchecked_low_level_call(self, audit_cache):
        result = audit_cache("vulnerable/ExternalCallIssues.sol")
        assert "unchecked-lowlevel-call" in check_ids(result)

    def test_checked_call_is_not_flagged(self, source_of):
        from app.services.engine import audit_sources

        source = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Careful {
    function poke(address target) external {
        (bool ok, ) = target.call(abi.encodeWithSignature("ping()"));
        require(ok, "call failed");
    }
}
"""
        result = audit_sources({"Careful.sol": source}, run_external_tools=False)
        assert "unchecked-lowlevel-call" not in check_ids(result)

    def test_calls_inside_loop(self, audit_cache):
        result = audit_cache("vulnerable/ExternalCallIssues.sol")
        hits = findings_for(result, "calls-inside-loop")
        assert hits and hits[0].function == "flush"

    def test_msg_value_in_loop(self, audit_cache):
        result = audit_cache("vulnerable/ExternalCallIssues.sol")
        hits = findings_for(result, "msg-value-in-loop")
        assert hits and hits[0].function == "spread"

    def test_delegatecall_to_parameter_is_critical(self, audit_cache):
        result = audit_cache("vulnerable/ExternalCallIssues.sol")
        hits = findings_for(result, "delegatecall-to-untrusted-input")
        assert len(hits) == 1
        assert hits[0].severity.name == "CRITICAL"
        assert hits[0].function == "upgradeAndRun"

    def test_payable_forwarding_is_not_a_drain(self, audit_cache):
        """`to.send(msg.value)` in a payable function moves the caller's funds."""
        result = audit_cache("vulnerable/ExternalCallIssues.sol")
        withdrawal_functions = {
            h.function for h in findings_for(result, "unprotected-ether-withdrawal")
        }
        assert "tip" not in withdrawal_functions


class TestArithmetic:
    def test_pre_08_arithmetic_flagged(self, audit_cache):
        result = audit_cache("vulnerable/OldArithmetic.sol")
        hits = findings_for(result, "integer-overflow")
        assert len(hits) >= 2
        assert all(h.severity.name == "HIGH" for h in hits)

    def test_old_compiler_version_flagged(self, audit_cache):
        result = audit_cache("vulnerable/OldArithmetic.sol")
        assert "old-solc-version" in check_ids(result)

    def test_08_arithmetic_is_clean(self, audit_cache):
        result = audit_cache("safe/SafeToken.sol")
        assert "integer-overflow" not in check_ids(result)

    def test_divide_before_multiply(self, audit_cache):
        result = audit_cache("vulnerable/OldArithmetic.sol")
        hits = findings_for(result, "divide-before-multiply")
        assert hits, "parenthesised (a / b) * c must still be detected"
        assert hits[0].function == "share"

    def test_unvalidated_divisor(self, audit_cache):
        result = audit_cache("vulnerable/OldArithmetic.sol")
        hits = findings_for(result, "unvalidated-divisor")
        assert [h.function for h in hits] == ["split"]

    def test_guarded_divisor_is_clean(self, audit_cache):
        """`share` has require(b != 0) so it must not be reported."""
        result = audit_cache("vulnerable/OldArithmetic.sol")
        functions = {h.function for h in findings_for(result, "unvalidated-divisor")}
        assert "share" not in functions


class TestHygiene:
    def test_weak_randomness(self, audit_cache):
        result = audit_cache("vulnerable/WeakRandom.sol")
        hits = findings_for(result, "weak-randomness")
        assert hits and hits[0].severity.name == "HIGH"
        assert hits[0].swc == "SWC-120"

    def test_timestamp_dependence(self, audit_cache):
        result = audit_cache("vulnerable/WeakRandom.sol")
        assert "timestamp-dependence" in check_ids(result)

    def test_floating_pragma(self, audit_cache):
        assert "floating-pragma" in check_ids(audit_cache("vulnerable/ReentrantVault.sol"))

    def test_pinned_pragma_is_clean(self, audit_cache):
        assert "floating-pragma" not in check_ids(audit_cache("safe/SafeVault.sol"))

    def test_missing_zero_address_check(self, audit_cache):
        result = audit_cache("vulnerable/BadToken.sol")
        hits = findings_for(result, "missing-zero-address-check")
        assert hits and hits[0].function == "constructor"

    def test_zero_address_check_is_recognised(self, audit_cache):
        """SafeVault requires `!= address(0)`; address(0) is a typeConversion."""
        result = audit_cache("safe/SafeVault.sol")
        assert "missing-zero-address-check" not in check_ids(result)

    def test_erc20_approve_race(self, audit_cache):
        assert "erc20-approve-race" in check_ids(audit_cache("vulnerable/BadToken.sol"))

    def test_allowance_helpers_clear_the_race(self, audit_cache):
        assert "erc20-approve-race" not in check_ids(audit_cache("safe/SafeToken.sol"))

    def test_standard_erc20_approve_is_not_a_zero_address_bug(self, audit_cache):
        """approve(spender, ...) writes a mapping; that is not the same mistake."""
        assert "missing-zero-address-check" not in check_ids(audit_cache("safe/SafeToken.sol"))


class TestSourceLevelChecks:
    def test_todo_comments_are_surfaced(self, audit_cache):
        assert "todo-comment" in check_ids(audit_cache("vulnerable/ReentrantVault.sol"))

    def test_hardcoded_secret_detected(self):
        from app.services.engine import audit_sources

        source = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity 0.8.24;\n"
            "contract Leaky {\n"
            "    bytes32 private constant ADMIN_KEY = "
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318;\n"
            "}\n"
        )
        result = audit_sources({"Leaky.sol": source}, run_external_tools=False)
        hits = findings_for(result, "hardcoded-secret")
        assert hits and hits[0].severity.name == "CRITICAL"
        assert hits[0].location.snippet == "<redacted>"

    def test_missing_license_detected(self):
        from app.services.engine import audit_sources

        source = "pragma solidity 0.8.24;\ncontract NoLicense {}\n"
        result = audit_sources({"NoLicense.sol": source}, run_external_tools=False)
        assert "missing-license" in check_ids(result)

    def test_broken_source_still_reports(self):
        """A parse error must produce a finding, not an empty report."""
        from app.services.engine import audit_sources

        result = audit_sources(
            {"Broken.sol": "pragma solidity ^0.8.0;\ncontract B { function f( {} }\n"},
            run_external_tools=False,
        )
        assert result.compiled is False
        assert "uncompilable-source" in check_ids(result)
        assert any(f.check_id == "compiler-error" for f in result.findings)


class TestRegistry:
    def test_every_registered_detector_has_metadata(self):
        from app.services.detectors import build_default_registry

        for detector in build_default_registry().all():
            assert detector.check_id, f"{detector.__name__} has no check_id"
            assert detector.title, f"{detector.check_id} has no title"

    def test_optimizations_can_be_disabled(self):
        from app.services.detectors import build_default_registry

        full = {d.check_id for d in build_default_registry(include_optimizations=True).all()}
        lean = {d.check_id for d in build_default_registry(include_optimizations=False).all()}
        assert "external-function" in full
        assert "external-function" not in lean

    def test_checks_can_be_disabled_by_id(self):
        from app.services.detectors import build_default_registry

        registry = build_default_registry(disabled={"floating-pragma"})
        assert registry.by_id("floating-pragma") is None
        assert registry.by_id("suicidal") is not None
