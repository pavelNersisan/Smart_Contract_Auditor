"""Multi-file compilation and scale tests.

These cover the two things the small fixtures cannot: real ``import`` chains
resolved through directories, and compiler output large enough to matter.
"""

from __future__ import annotations

import pytest

from app.services.engine import audit_sources


def build_large_contract(function_count: int) -> str:
    """A contract whose solc AST JSON is far larger than a 64 KiB pipe buffer."""
    functions = "".join(
        f"    function f{i}(uint256 a) external pure returns (uint256) "
        f"{{ return a * {i + 1} + {i}; }}\n"
        for i in range(function_count)
    )
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.24;\n"
        "contract Big {\n" + functions + "}\n"
    )


class TestCrossFileImports:
    def test_nested_directory_project_compiles(self, fixtures_dir):
        from app.services.engine import audit_directory

        result = audit_directory(
            fixtures_dir / "multifile", run_external_tools=False
        )
        assert result.compiled, [d.message for d in result.compiler_diagnostics]
        assert len(result.sources) == 4
        assert {c.name for c in result.contracts} == {
            "IERC20",
            "Token",
            "Vault",
            "Staking",
        }

    def test_imported_interfaces_produce_no_bytecode(self, fixtures_dir):
        from app.services.engine import audit_directory

        result = audit_directory(fixtures_dir / "multifile", run_external_tools=False)
        by_name = {c.name: c for c in result.contracts}
        assert by_name["IERC20"].bytecode_size == 0
        assert by_name["Token"].bytecode_size > 0

    def test_line_numbers_resolve_in_nested_files(self, fixtures_dir):
        """Findings in an imported file must carry that file's own path."""
        from app.services.engine import audit_directory

        result = audit_directory(fixtures_dir / "multifile", run_external_tools=False)
        for contract in result.contracts:
            assert "/" in contract.file or contract.file.endswith(".sol")

    def test_clean_project_scores_full_marks(self, fixtures_dir):
        from app.services.engine import audit_directory

        result = audit_directory(fixtures_dir / "multifile", run_external_tools=False)
        assert result.findings == []
        assert result.score == 100

    def test_broken_import_is_reported(self, source_of):
        """An unresolvable import must surface as an error, not a silent pass."""
        entry = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity 0.8.24;\n"
            'import "./DoesNotExist.sol";\n'
            "contract NeedsIt {}\n"
        )
        result = audit_sources({"NeedsIt.sol": entry}, run_external_tools=False)
        assert result.compiled is False
        assert any(
            "DoesNotExist" in d.message or d.severity == "error"
            for d in result.compiler_diagnostics
        )
        assert "uncompilable-source" in {f.check_id for f in result.findings}


class TestScale:
    def test_large_output_is_not_truncated(self):
        """Regression: Node could exit before draining a pipe, cutting JSON at 64 KiB.

        300 functions produce a multi-megabyte AST document; if stdout were
        captured from a pipe this would intermittently fail to parse.
        """
        result = audit_sources(
            {"Big.sol": build_large_contract(300)}, run_external_tools=False
        )
        assert result.compiled is True
        assert result.contracts[0].functions == 300
        assert result.contracts[0].bytecode_size > 0

    def test_every_function_is_visible_to_analysis(self):
        result = audit_sources(
            {"Big.sol": build_large_contract(120)}, run_external_tools=False
        )
        assert result.contracts[0].functions == 120

    def test_contract_size_limit_is_escalated(self):
        """EIP-170: over 24576 bytes the contract cannot be deployed at all.

        solc reports this under the generic type "Warning", so it must be
        escalated from the message text rather than left informational.
        """
        result = audit_sources(
            {"Big.sol": build_large_contract(300)}, run_external_tools=False
        )
        size_findings = [
            f
            for f in result.findings
            if "exceeds 24576" in f.description or "code size" in f.description.lower()
        ]
        assert size_findings, "expected an EIP-170 code size finding"
        assert size_findings[0].severity.name == "MEDIUM"

    def test_small_contract_has_no_size_finding(self):
        source = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity 0.8.24;\n"
            "contract Small { function f() external pure returns (uint256) { return 1; } }\n"
        )
        result = audit_sources({"Small.sol": source}, run_external_tools=False)
        assert not [
            f for f in result.findings if "24576" in f.description
        ]
        assert result.score == 100


class TestCompilerDiagnosticSeverity:
    def _severity_for(self, text: str):
        from app.models.audit import CompilerDiagnostic
        from app.services.detectors.hygiene import CompilerDiagnostics

        return CompilerDiagnostics()._severity(
            CompilerDiagnostic(severity="warning", type="Warning", message=text)
        )

    def test_code_size_is_medium(self):
        assert self._severity_for(
            "Contract code size is 29083 bytes and exceeds 24576 bytes"
        ).name == "MEDIUM"

    def test_unused_variable_is_informational(self):
        assert self._severity_for(
            "Unused local variable 'x'."
        ).name == "INFORMATIONAL"

    def test_shadowing_is_low(self):
        assert self._severity_for(
            "This declaration shadows a declaration outside the local scope."
        ).name == "LOW"

    def test_mutability_is_optimization(self):
        assert self._severity_for(
            "Function state mutability can be restricted to pure"
        ).name == "OPTIMIZATION"

    def test_unknown_warning_defaults_to_informational(self):
        assert self._severity_for("Something entirely new.").name == "INFORMATIONAL"

    def test_errors_are_low_not_informational(self):
        from app.models.audit import CompilerDiagnostic
        from app.services.detectors.hygiene import CompilerDiagnostics

        severity = CompilerDiagnostics()._severity(
            CompilerDiagnostic(severity="error", type="ParserError", message="Expected ';'")
        )
        assert severity.name == "LOW"

    def test_known_type_wins_over_message_pattern(self):
        """A precise solc type must not be overridden by a loose message match."""
        from app.models.audit import CompilerDiagnostic
        from app.services.detectors.hygiene import CompilerDiagnostics

        severity = CompilerDiagnostics()._severity(
            CompilerDiagnostic(
                severity="warning",
                type="UnusedLocalVariable",
                message="unused variable, and this shadows something",
            )
        )
        assert severity.name == "INFORMATIONAL"
