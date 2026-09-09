"""Compiler adapter tests.

These pin down the solcjs behaviours the whole engine depends on; if the
compiler interface changes, these fail first and loudly.
"""

from __future__ import annotations

import pytest

from app.services.solc import (
    CompilerUnavailable,
    build_line_index,
    compile_sources,
    discover_solc,
    offset_to_line_column,
    solc_version,
)

SIMPLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Simple {
    uint256 public value;
    function set(uint256 v) external { value = v; }
}
"""


class TestDiscovery:
    def test_finds_a_binary(self, solc_binary):
        assert solc_binary

    def test_version_is_parsable(self, solc_binary):
        version = solc_version(solc_binary)
        assert version != "unknown"
        assert any(ch.isdigit() for ch in version)

    def test_missing_binary_raises(self):
        with pytest.raises(CompilerUnavailable):
            compile_sources({"A.sol": SIMPLE}, binary="/nonexistent/solc")


class TestLineMapping:
    def test_offsets_are_line_starts(self):
        offsets = build_line_index("ab\ncd\nef")
        assert offsets == [0, 3, 6]

    def test_offset_to_line_column(self):
        offsets = build_line_index("ab\ncd\nef")
        assert offset_to_line_column(offsets, 0) == (1, 1)
        assert offset_to_line_column(offsets, 3) == (2, 1)
        assert offset_to_line_column(offsets, 7) == (3, 2)

    def test_empty_index_is_safe(self):
        assert offset_to_line_column([], 5) == (0, 0)


class TestCompilation:
    def test_produces_ast_and_bytecode(self, solc_binary):
        result = compile_sources({"Simple.sol": SIMPLE}, solc_binary)
        assert result.ok
        assert "Simple.sol" in result.asts
        assert result.asts["Simple.sol"]["nodeType"] == "SourceUnit"
        contract = result.contracts["Simple.sol:Simple"]
        assert contract.bytecode.startswith("60") or contract.bytecode.startswith("0x")
        assert len(contract.abi) > 0

    def test_file_index_maps_to_filename(self, solc_binary):
        """The third `src` component must resolve to a real filename.

        Regression guard: it is NOT the SourceUnit node id.
        """
        result = compile_sources({"Simple.sol": SIMPLE}, solc_binary)
        source_unit = result.asts["Simple.sol"]
        file_index = int(source_unit["src"].split(":")[2])
        assert result.file_index_to_name[file_index] == "Simple.sol"
        assert int(source_unit["id"]) != file_index

    def test_line_numbers_match_source(self, solc_binary):
        source = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract L {\n"
            "    function f() public pure returns (uint256) {\n"
            "        return 42;\n"
            "    }\n"
            "}\n"
        )
        result = compile_sources({"L.sol": source}, solc_binary)
        contract_ast = [
            n for n in result.asts["L.sol"]["nodes"] if n["nodeType"] == "ContractDefinition"
        ][0]
        assert contract_ast["name"] == "L"
        start = int(contract_ast["src"].split(":")[0])
        line, _ = offset_to_line_column(result.line_indexes["L.sol"], start)
        assert line == 3
        assert source.splitlines()[line - 1].strip().startswith("contract L")

    def test_imports_resolve_from_base_path(self, solc_binary):
        """Only the entry file is supplied; the import must still compile."""
        entry = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            'import "./Helper.sol";\n'
            "contract UsesHelper { function f() public pure returns (uint256) { return Helper.two(); } }\n"
        )
        helper = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "library Helper { function two() internal pure returns (uint256) { return 2; } }\n"
        )
        result = compile_sources(
            {"UsesHelper.sol": entry, "Helper.sol": helper}, solc_binary
        )
        assert result.ok, [m.message for m in result.errors]
        assert set(result.asts) == {"UsesHelper.sol", "Helper.sol"}

    def test_parse_error_is_reported_not_raised(self, solc_binary):
        broken = "pragma solidity ^0.8.0;\ncontract Broken { function f( {} }\n"
        result = compile_sources({"Broken.sol": broken}, solc_binary)
        assert not result.ok
        assert any(m.severity == "error" for m in result.messages)

    def test_empty_sources_rejected(self):
        with pytest.raises(ValueError):
            compile_sources({})

    def test_non_sol_extension_is_normalised(self, solc_binary):
        result = compile_sources({"contract.txt": SIMPLE}, solc_binary)
        assert result.ok
        assert "Contract.sol" in result.asts


class TestJsonExtraction:
    def test_banner_lines_are_skipped(self):
        from app.services.solc import _extract_json

        raw = '>>> Cannot retry compilation with SMT because there are no SMT solvers available.\n{"a": 1}'
        assert _extract_json(raw) == {"a": 1}

    def test_garbage_raises(self):
        from app.services.solc import _extract_json

        with pytest.raises(ValueError):
            _extract_json("no json here")
