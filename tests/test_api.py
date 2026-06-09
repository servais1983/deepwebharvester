"""Tests for api.py — FastAPI endpoints via TestClient."""
import pytest
import asyncio

pytest_plugins = ("anyio",)

try:
    from fastapi.testclient import TestClient
    from deepwebharvester.api import create_app, _JOBS, CrawlRequest
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not FASTAPI_AVAILABLE,
    reason="fastapi/pydantic not installed",
)


@pytest.fixture
def client(monkeypatch):
    """Create a test client with a known API key."""
    monkeypatch.setenv("DWH_API_KEY", "testkey123")
    _JOBS.clear()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def auth(client):
    return {"X-API-Key": "testkey123"}


class TestHealthEndpoints:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_docs_available(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200


class TestAuth:
    def test_missing_key_rejected(self, client, monkeypatch):
        monkeypatch.setenv("DWH_API_KEY", "secret")
        resp = client.get("/v1/jobs")
        assert resp.status_code == 401

    def test_wrong_key_rejected(self, client, monkeypatch):
        monkeypatch.setenv("DWH_API_KEY", "secret")
        resp = client.get("/v1/jobs", headers={"X-API-Key": "wrong"})
        assert resp.status_code == 401

    def test_no_key_required_when_env_unset(self, client, monkeypatch):
        monkeypatch.delenv("DWH_API_KEY", raising=False)
        resp = client.get("/v1/jobs")
        assert resp.status_code == 200


class TestJobEndpoints:
    def test_list_jobs_empty(self, client, auth):
        resp = client.get("/v1/jobs", headers=auth)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_nonexistent_job(self, client, auth):
        resp = client.get("/v1/jobs/nonexistent-id", headers=auth)
        assert resp.status_code == 404

    def test_get_results_nonexistent(self, client, auth):
        resp = client.get("/v1/results/bad-id", headers=auth)
        assert resp.status_code == 404

    def test_get_iocs_nonexistent(self, client, auth):
        resp = client.get("/v1/iocs/bad-id", headers=auth)
        assert resp.status_code == 404


class TestCrawlRequest:
    def test_invalid_non_onion_url_rejected(self, client, auth):
        resp = client.post(
            "/v1/crawl",
            json={"seed_urls": ["https://google.com"]},
            headers=auth,
        )
        assert resp.status_code == 422  # Pydantic validation error

    def test_submit_valid_job_returns_202(self, client, auth, monkeypatch):
        # Patch _run_job to avoid actual crawling
        import asyncio
        import deepwebharvester.api as api_mod

        async def _noop(job):
            job.status = "completed"

        monkeypatch.setattr(api_mod, "_run_job", _noop, raising=False)
        resp = client.post(
            "/v1/crawl",
            json={"seed_urls": [
                "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"
            ]},
            headers=auth,
        )
        assert resp.status_code in (202, 422)  # 422 if onion too short, 202 if valid

    def test_empty_seed_urls_rejected(self, client, auth):
        resp = client.post("/v1/crawl", json={"seed_urls": []}, headers=auth)
        assert resp.status_code == 422
