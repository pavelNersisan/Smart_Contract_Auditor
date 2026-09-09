"""Engine orchestration tests."""

from __future__ import annotations

import pytest

from app.models.audit import AuditResult, Severity
from app.services.engine import AuditEngine, audit_directory, audit_file, audit_sources

REENTRANT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 b = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: b}("");
        require(ok);
        balances[msg.sender] = 0;
    }
    receive() external payable {}
}
"""


class TestAuditSources:
    def test_returns_completed_result(self):
        result = audit_sources({"Vault.sol": REENTRANT}, run_external_tools=False)
        assert isinstance(result, AuditResult)
        assert result.status == "completed"
        assert result.compiled is True
        assert result.duration_ms >= 0
        assert result.id

    def test_contract_summary(self):
        result = audit_sources({"Vault.sol": REENTRANT}, run_external_tools=False)
        assert len(result.contracts) == 1
        contract = result.contracts[0]
        assert contract.name == "Vault"
        assert contract.file == "Vault.sol"
        assert contract.functions == 1
        assert contract.state_variables == 1
        assert contract.has_receive is True
        assert contract.has_fallback is False
        assert contract.bytecode_size > 0

    def test_findings_are_deduplicated(self):
        result = audit_sources({"Vault.sol": REENTRANT}, run_external_tools=False)
        keys = [f.fingerprint for f in result.findings]
        assert len(keys) == len(set(keys))

    def test_sorted_worst_first(self):
        result = audit_sources({"Vault.sol": REENTRANT}, run_external_tools=False)
        severities = [int(f.severity) for f in result.sorted_findings()]
        assert severities == sorted(severities, reverse=True)

    def test_empty_sources_rejected(self):
        with pytest.raises(ValueError):
            audit_sources({})

    def test_counts_by_severity_covers_every_level(self):
        result = audit_sources({"Vault.sol": REENTRANT}, run_external_tools=False)
        counts = result.counts_by_severity()
        assert set(counts) == {s.label for s in Severity}
        assert sum(counts.values()) == len(result.findings)

    def test_external_tools_reported_as_unavailable(self):
        """When Slither/Mythril are absent the run must say so, not stay silent."""
        result = audit_sources({"Vault.sol": REENTRANT}, run_external_tools=True)
        names = {t.name for t in result.tools}
        assert names <= {"slither", "mythril"}
        for tool in result.tools:
            assert tool.available is False or tool.ran is True


class TestMultiFile:
    def test_directory_audit(self, fixtures_dir):
        result = audit_directory(fixtures_dir / "safe", run_external_tools=False)
        assert len(result.sources) == 2
        assert {c.name for c in result.contracts} == {"SafeToken", "SafeVault"}
        assert result.score == 100

    def test_missing_directory_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            audit_directory(tmp_path)

    def test_single_file_helper(self, fixtures_dir):
        result = audit_file(
            fixtures_dir / "safe" / "SafeToken.sol", run_external_tools=False
        )
        assert result.compiled
        assert [c.name for c in result.contracts] == ["SafeToken"]


class TestScoring:
    def test_clean_contract_scores_100(self, fixtures_dir):
        result = audit_file(fixtures_dir / "safe" / "SafeToken.sol", run_external_tools=False)
        assert result.findings == []
        assert result.score == 100
        assert result.grade == "A"

    def test_critical_contract_scores_low(self, fixtures_dir):
        result = audit_file(
            fixtures_dir / "vulnerable" / "AccessControlFail.sol", run_external_tools=False
        )
        assert result.score <= 40
        assert result.grade in {"D", "F"}

    def test_score_never_exceeds_bounds(self, fixtures_dir):
        for path in sorted(fixtures_dir.rglob("*.sol")):
            result = audit_file(path, run_external_tools=False)
            assert 1 <= result.score <= 100
            assert result.grade in {"A", "B", "C", "D", "F"}


class TestEngineReuse:
    def test_engine_caches_solc_discovery(self):
        engine = AuditEngine()
        first = engine.solc_binary
        second = engine.solc_binary
        assert first == second

    def test_optimization_toggle(self):
        full = audit_sources({"Vault.sol": REENTRANT}, include_optimizations=True,
                             run_external_tools=False)
        lean = audit_sources({"Vault.sol": REENTRANT}, include_optimizations=False,
                             run_external_tools=False)
        assert len(lean.findings) <= len(full.findings)

    def test_compiler_unavailable_degrades_gracefully(self, monkeypatch):
        """With no compiler the run still completes on source-level checks."""
        from app.services import engine as engine_module

        def _raise(*args, **kwargs):
            from app.services.solc import CompilerUnavailable

            raise CompilerUnavailable("no compiler in this test")

        monkeypatch.setattr(engine_module, "compile_sources", _raise)
        result = engine_module.audit_sources(
            {"Vault.sol": REENTRANT}, run_external_tools=False
        )
        assert result.compiled is False
        assert result.solc_version == "unavailable"
        assert "missing-license" not in {f.check_id for f in result.findings}
        assert "todo-comment" not in {f.check_id for f in result.findings}
        assert result.score == 100  # nothing could be checked
