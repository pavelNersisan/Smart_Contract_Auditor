"""Report generation tests."""

from __future__ import annotations

import json

import pytest

from app.services.report_generator import (
    to_html,
    to_json,
    to_markdown,
    write_reports,
)


@pytest.fixture(scope="session")
def vulnerable_report(audit_cache):
    return audit_cache("vulnerable/ReentrantVault.sol")


@pytest.fixture(scope="session")
def clean_report(audit_cache):
    return audit_cache("safe/SafeToken.sol")


class TestJsonReport:
    def test_is_valid_json(self, vulnerable_report):
        payload = json.loads(to_json(vulnerable_report))
        assert payload["id"] == vulnerable_report.id
        assert payload["score"] == vulnerable_report.score
        assert payload["counts"] == vulnerable_report.counts_by_severity()

    def test_includes_locations(self, vulnerable_report):
        payload = json.loads(to_json(vulnerable_report))
        finding = payload["findings"][0]
        assert finding["location"]["file"] == "ReentrantVault.sol"
        assert finding["location"]["line"] > 0

    def test_severity_serialises_to_its_value(self, vulnerable_report):
        payload = json.loads(to_json(vulnerable_report))
        severities = {f["severity"] for f in payload["findings"]}
        assert severities <= {0, 1, 2, 3, 4, 5}


class TestMarkdownReport:
    def test_has_expected_sections(self, vulnerable_report):
        text = to_markdown(vulnerable_report)
        for heading in ("# Smart Contract Audit Report", "## Summary", "## Findings",
                        "## Analysis context"):
            assert heading in text

    def test_score_and_grade_present(self, vulnerable_report):
        text = to_markdown(vulnerable_report)
        assert f"{vulnerable_report.score}/100" in text
        assert f"**Grade:** {vulnerable_report.grade}" in text

    def test_finding_details_present(self, vulnerable_report):
        text = to_markdown(vulnerable_report)
        assert "reentrancy" in text.lower()
        assert "ReentrantVault.sol:21" in text
        assert "Recommendation" in text

    def test_clean_report_says_no_issues(self, clean_report):
        text = to_markdown(clean_report)
        assert "No issues were reported" in text

    def test_source_snippets_are_fenced(self, vulnerable_report):
        text = to_markdown(vulnerable_report)
        assert "```solidity" in text


class TestHtmlReport:
    def test_renders_score(self, vulnerable_report):
        html = to_html(vulnerable_report)
        assert str(vulnerable_report.score) in html
        assert vulnerable_report.grade in html

    def test_escapes_source_content(self):
        """Solidity source must not be able to inject markup."""
        from app.services.engine import audit_sources

        source = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity 0.8.24;\n"
            "contract X {\n"
            "    // TODO: <script>alert(1)</script>\n"
            "}\n"
        )
        result = audit_sources({"X.sol": source}, run_external_tools=False)
        html = to_html(result)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestWritingReports:
    def test_writes_all_formats(self, vulnerable_report, tmp_path):
        written = write_reports(vulnerable_report, tmp_path)
        assert set(written) == {"json", "md", "html"}
        for path in written.values():
            assert path.exists()
            assert path.stat().st_size > 0

    def test_subset_of_formats(self, vulnerable_report, tmp_path):
        written = write_reports(vulnerable_report, tmp_path, formats=("md",))
        assert list(written) == ["md"]

    def test_unknown_format_rejected(self, vulnerable_report, tmp_path):
        with pytest.raises(ValueError):
            write_reports(vulnerable_report, tmp_path, formats=("pdf",))

    def test_creates_missing_directory(self, vulnerable_report, tmp_path):
        target = tmp_path / "nested" / "reports"
        written = write_reports(vulnerable_report, target, formats=("json",))
        assert written["json"].exists()
