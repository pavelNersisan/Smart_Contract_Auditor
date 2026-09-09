"""Security primitive, risk-scoring and worker tests."""

from __future__ import annotations

import time

import pytest

from app.core.security import (
    SecurityError,
    TokenBucketRateLimiter,
    check_api_key,
    client_key,
    issue_token,
    verify_token,
)
from app.models.audit import Finding, Severity
from app.services.risk import DECAY, grade_for, headline, score_findings
from app.worker import ThreadTaskRunner, build_runner


def make_finding(severity: Severity, check_id: str = "test", line: int = 1) -> Finding:
    return Finding(
        check_id=check_id,
        title="t",
        severity=severity,
        description="d",
        recommendation="r",
        location={"file": "A.sol", "line": line},
    )


class TestTokens:
    def test_roundtrip(self):
        token = issue_token("secret", "alice", 60)
        payload = verify_token("secret", token)
        assert payload["sub"] == "alice"

    def test_wrong_secret_rejected(self):
        token = issue_token("secret", "alice", 60)
        with pytest.raises(SecurityError):
            verify_token("other", token)

    def test_expired_rejected(self):
        token = issue_token("secret", "alice", -1)
        with pytest.raises(SecurityError):
            verify_token("secret", token)

    def test_malformed_rejected(self):
        with pytest.raises(SecurityError):
            verify_token("secret", "not-a-token")

    def test_tampered_payload_rejected(self):
        token = issue_token("secret", "alice", 60)
        body, sig = token.rsplit(".", 1)
        with pytest.raises(SecurityError):
            verify_token("secret", body[:-1] + "X." + sig)


class TestApiKeys:
    def test_disabled_allows_everything(self):
        assert check_api_key([], None) is True

    def test_missing_key_rejected(self):
        assert check_api_key(["a"], None) is False

    def test_correct_key_accepted(self):
        assert check_api_key(["a", "b"], "b") is True

    def test_wrong_key_rejected(self):
        assert check_api_key(["a"], "z") is False


class TestRateLimiter:
    def test_allows_up_to_capacity(self):
        limiter = TokenBucketRateLimiter(3, 0.0)
        assert [limiter.allow("k") for _ in range(4)] == [True, True, True, False]

    def test_keys_are_independent(self):
        limiter = TokenBucketRateLimiter(1, 0.0)
        assert limiter.allow("a") is True
        assert limiter.allow("b") is True
        assert limiter.allow("a") is False

    def test_refills_over_time(self):
        limiter = TokenBucketRateLimiter(1, 50.0)
        assert limiter.allow("k") is True
        assert limiter.allow("k") is False
        time.sleep(0.05)
        assert limiter.allow("k") is True

    def test_reset(self):
        limiter = TokenBucketRateLimiter(1, 0.0)
        limiter.allow("k")
        limiter.reset()
        assert limiter.allow("k") is True

    def test_client_key_prefers_api_key(self):
        assert client_key({"x-api-key": "abc"}, "1.2.3.4").startswith("key:")
        assert client_key({}, "1.2.3.4") == "ip:1.2.3.4"


class TestRiskScoring:
    def test_no_findings_is_perfect(self):
        breakdown = score_findings([])
        assert breakdown.score == 100
        assert breakdown.grade == "A"

    def test_one_critical_drops_score(self):
        breakdown = score_findings([make_finding(Severity.CRITICAL)])
        assert breakdown.score < 60
        assert breakdown.grade in {"C", "D"}

    def test_monotonic_under_addition(self):
        one = score_findings([make_finding(Severity.HIGH, line=1)]).score
        two = score_findings(
            [make_finding(Severity.HIGH, line=1), make_finding(Severity.HIGH, line=2)]
        ).score
        three = score_findings(
            [make_finding(Severity.HIGH, line=i) for i in range(3)]
        ).score
        assert one > two > three

    def test_repeats_decay(self):
        single = score_findings([make_finding(Severity.MEDIUM, line=1)]).total_penalty
        double = score_findings(
            [make_finding(Severity.MEDIUM, line=i) for i in range(2)]
        ).total_penalty
        assert double < single * 2
        assert double == pytest.approx(single * (1 + DECAY), rel=1e-6)

    def test_score_never_leaves_bounds(self):
        many = [make_finding(Severity.CRITICAL, line=i) for i in range(50)]
        assert score_findings(many).score == 1

    def test_grade_bands(self):
        assert grade_for(100)[0] == "A"
        assert grade_for(90)[0] == "A"
        assert grade_for(89)[0] == "B"
        assert grade_for(75)[0] == "B"
        assert grade_for(74)[0] == "C"
        assert grade_for(45)[0] == "D"
        assert grade_for(1)[0] == "F"

    def test_informational_only_stays_high(self):
        findings = [make_finding(Severity.INFORMATIONAL, line=i) for i in range(10)]
        assert score_findings(findings).grade == "A"

    def test_headline_describes_findings(self):
        text = headline([make_finding(Severity.HIGH)], 70, "C")
        assert "1 high" in text
        assert "70/100" in text

    def test_headline_for_clean_audit(self):
        assert "No issues found" in headline([], 100, "A")


class TestWorker:
    def test_thread_runner_completes(self):
        runner = ThreadTaskRunner(max_workers=2)
        try:
            source = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\ncontract C {}\n"
            job = runner.submit({"C.sol": source}, run_external_tools=False)
            status = runner.wait(job, timeout=120)
            assert status.state == "completed"
            assert status.result is not None
            assert status.result.compiled is True
        finally:
            runner.shutdown()

    def test_unknown_job_is_none(self):
        runner = ThreadTaskRunner()
        try:
            assert runner.status("nope") is None
        finally:
            runner.shutdown()

    def test_default_backend_is_threads(self, monkeypatch):
        monkeypatch.delenv("AUDITOR_BROKER_URL", raising=False)
        runner = build_runner()
        assert isinstance(runner, ThreadTaskRunner)
        runner.shutdown()
