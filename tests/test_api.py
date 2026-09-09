"""REST API tests, exercising the real FastAPI app through its lifespan."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.core.security import TokenBucketRateLimiter, issue_token
from app.main import create_app

SOURCE = """// SPDX-License-Identifier: MIT
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


@pytest.fixture(scope="module")
def client():
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


class TestHealthAndMetadata:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["detectors"] > 20
        assert body["solc_version"] != "unknown"

    def test_detectors_listing(self, client):
        response = client.get("/detectors")
        assert response.status_code == 200
        body = response.json()
        ids = {d["check_id"] for d in body["detectors"]}
        assert "reentrancy-eth" in ids
        assert "suicidal" in ids
        assert body["count"] == len(body["detectors"])

    def test_openapi_is_served(self, client):
        assert client.get("/openapi.json").status_code == 200


class TestAuditEndpoint:
    def test_json_source(self, client):
        response = client.post("/audit", json={"source": SOURCE, "filename": "Vault.sol"})
        assert response.status_code == 200
        body = response.json()
        assert body["compiled"] is True
        assert body["score"] < 100
        ids = {f["check_id"] for f in body["findings"]}
        assert "reentrancy-eth" in ids

    def test_multipart_upload_matches_readme_contract(self, client):
        """The README documents `curl -F "contract=@file.sol" /audit`."""
        response = client.post(
            "/audit", files=[("files", ("Vault.sol", SOURCE, "text/plain"))]
        )
        assert response.status_code == 200
        assert response.json()["compiled"] is True

    def test_multi_file_json(self, client):
        response = client.post(
            "/audit",
            json={"sources": {"Vault.sol": SOURCE}},
        )
        assert response.status_code == 200

    def test_missing_source_is_400(self, client):
        response = client.post("/audit", json={})
        assert response.status_code == 400

    def test_binary_upload_is_400(self, client):
        response = client.post(
            "/audit", files=[("files", ("bad.sol", b"\xff\xfe\x00\x01", "application/octet-stream"))]
        )
        assert response.status_code == 400

    def test_run_external_tools_flag(self, client):
        response = client.post(
            "/audit", json={"source": SOURCE, "run_external_tools": False}
        )
        assert response.json()["tools"] == []


class TestPersistence:
    def test_audit_is_retrievable(self, client):
        created = client.post("/audit", json={"source": SOURCE}).json()
        fetched = client.get(f"/audits/{created['id']}")
        assert fetched.status_code == 200
        assert fetched.json()["id"] == created["id"]
        assert fetched.json()["score"] == created["score"]

    def test_listing_includes_run(self, client):
        created = client.post("/audit", json={"source": SOURCE}).json()
        listing = client.get("/audits").json()
        assert any(entry["id"] == created["id"] for entry in listing)

    def test_unknown_id_is_404(self, client):
        assert client.get("/audits/does-not-exist").status_code == 404


class TestReports:
    def test_json_report(self, client):
        created = client.post("/audit", json={"source": SOURCE}).json()
        response = client.get(f"/audits/{created['id']}/report.json")
        assert response.status_code == 200
        assert response.json()["id"] == created["id"]

    def test_markdown_report(self, client):
        created = client.post("/audit", json={"source": SOURCE}).json()
        response = client.get(f"/audits/{created['id']}/report.md")
        assert response.status_code == 200
        assert "Smart Contract Audit Report" in response.text

    def test_html_report(self, client):
        created = client.post("/audit", json={"source": SOURCE}).json()
        response = client.get(f"/audits/{created['id']}/report.html")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert "<html" in response.text

    def test_unknown_format_is_400(self, client):
        created = client.post("/audit", json={"source": SOURCE}).json()
        response = client.get(f"/audits/{created['id']}/report.pdf")
        assert response.status_code == 400


class TestAuthentication:
    @pytest.fixture()
    def secured_client(self):
        app = create_app()
        app.dependency_overrides[get_settings] = lambda: Settings(api_keys=("s3cret",))
        with TestClient(app) as test_client:
            yield test_client
        app.dependency_overrides.clear()

    def test_rejects_missing_key(self, secured_client):
        assert secured_client.post("/audit", json={"source": SOURCE}).status_code == 401

    def test_rejects_wrong_key(self, secured_client):
        response = secured_client.post(
            "/audit", json={"source": SOURCE}, headers={"X-API-Key": "wrong"}
        )
        assert response.status_code == 401

    def test_accepts_correct_key(self, secured_client):
        response = secured_client.post(
            "/audit", json={"source": SOURCE}, headers={"X-API-Key": "s3cret"}
        )
        assert response.status_code == 200

    def test_accepts_bearer_token(self, secured_client):
        settings = Settings(api_keys=("s3cret",))
        token = issue_token(settings.token_secret, "ci", settings.token_ttl_seconds)
        response = secured_client.post(
            "/audit", json={"source": SOURCE}, headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

    def test_health_needs_no_key(self, secured_client):
        assert secured_client.get("/health").status_code == 200


class TestRateLimiting:
    def test_returns_429_when_exhausted(self, client):
        limiter = client.app.state.auditor["limiter"]
        original = (limiter.capacity, limiter.refill_per_sec)
        client.app.state.auditor["limiter"] = TokenBucketRateLimiter(1, 0.0)
        try:
            first = client.post("/audit", json={"source": SOURCE})
            second = client.post("/audit", json={"source": SOURCE})
            assert first.status_code == 200
            assert second.status_code == 429
        finally:
            client.app.state.auditor["limiter"] = TokenBucketRateLimiter(*original)
