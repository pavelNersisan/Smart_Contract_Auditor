"""CLI tests -- the entry point users actually run."""

from __future__ import annotations

import json

import pytest

from app.cli import main


class TestAuditCommand:
    def test_table_output(self, fixtures_dir, capsys):
        code = main(["audit", str(fixtures_dir / "vulnerable" / "ReentrantVault.sol"),
                     "--no-external-tools"])
        out = capsys.readouterr().out
        assert code == 0
        assert "reentrancy-eth" in out
        assert "ReentrantVault.sol:21" in out
        assert "score:" in out

    def test_json_output_is_parseable(self, fixtures_dir, capsys):
        code = main(["audit", str(fixtures_dir / "safe" / "SafeToken.sol"),
                     "-f", "json", "--no-external-tools"])
        out = capsys.readouterr().out
        assert code == 0
        payload = json.loads(out)
        assert payload["score"] == 100
        assert payload["compiled"] is True

    def test_markdown_output(self, fixtures_dir, capsys):
        main(["audit", str(fixtures_dir / "safe" / "SafeVault.sol"),
              "-f", "md", "--no-external-tools"])
        assert "# Smart Contract Audit Report" in capsys.readouterr().out

    def test_directory_input(self, fixtures_dir, capsys):
        code = main(["audit", str(fixtures_dir / "safe"), "--no-external-tools"])
        assert code == 0
        assert "SafeToken" in capsys.readouterr().out

    def test_writes_reports(self, fixtures_dir, tmp_path):
        main(["audit", str(fixtures_dir / "vulnerable" / "BadToken.sol"),
              "-o", str(tmp_path), "--no-external-tools"])
        produced = {p.suffix for p in tmp_path.iterdir()}
        assert produced == {".json", ".md", ".html"}

    def test_fail_under_threshold(self, fixtures_dir):
        code = main(["audit", str(fixtures_dir / "vulnerable" / "AccessControlFail.sol"),
                     "--fail-under", "80", "--no-external-tools"])
        assert code == 1

    def test_passes_threshold(self, fixtures_dir):
        code = main(["audit", str(fixtures_dir / "safe" / "SafeToken.sol"),
                     "--fail-under", "80", "--no-external-tools"])
        assert code == 0

    def test_fail_on_severity(self, fixtures_dir):
        code = main(["audit", str(fixtures_dir / "vulnerable" / "AccessControlFail.sol"),
                     "--fail-on", "critical", "--no-external-tools"])
        assert code == 1

    def test_missing_path_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["audit", str(tmp_path / "nope.sol")])

    def test_empty_directory_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["audit", str(tmp_path)])


class TestInfoCommands:
    def test_detectors_lists_checks(self, capsys):
        assert main(["detectors"]) == 0
        out = capsys.readouterr().out
        assert "reentrancy-eth" in out
        assert "checks available" in out

    def test_detectors_json(self, capsys):
        main(["detectors", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert isinstance(payload, list)
        assert all("check_id" in entry for entry in payload)

    def test_doctor_reports_environment(self, capsys, solc_binary):
        assert main(["doctor"]) == 0
        out = capsys.readouterr().out
        assert "solc binary" in out
        assert solc_binary in out

    def test_unknown_command_rejected(self):
        with pytest.raises(SystemExit):
            main(["bogus"])
