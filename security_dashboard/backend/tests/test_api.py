from __future__ import annotations

import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.config import Settings, get_settings
from app.main import app as main_app
from app.main import create_app, get_repository


class FakeRepository:
    def __init__(self) -> None:
        self.runs = {}
        self.signatures = set()

    def claim_signature(self, signature: str) -> bool:
        if signature in self.signatures:
            return False
        self.signatures.add(signature)
        return True

    def upsert(self, report):
        run_id = str(report["github"]["run_id"])
        self.runs[run_id] = {**report, "run_id": run_id}
        return self.runs[run_id]

    def overview(self):
        latest = next(reversed(self.runs.values()), None) if self.runs else None
        return {"latest": latest, "last_success": latest, "status_counts": {"COMPLETED": len(self.runs), "BLOCKED": 0, "ERROR": 0}}

    def trends(self, days):
        return list(self.runs.values())

    def list_runs(self, page, limit, status=None, search=None):
        items = list(self.runs.values())
        return items, len(items)

    def get(self, run_id):
        return self.runs.get(run_id)


def report(run_id="100"):
    return {
        "schema_version": "1.0",
        "run_started_at": "2026-06-12T00:00:00+00:00",
        "run_finished_at": "2026-06-12T00:00:10+00:00",
        "duration_seconds": 10,
        "pipeline_status": "COMPLETED",
        "stages": {},
        "scanner_health": {},
        "findings_by_tool": {"gitleaks": 0},
        "findings_by_severity": {"HIGH": 0, "CRITICAL": 0},
        "findings": [],
        "findings_truncated": False,
        "policy_decision": "PASS",
        "llm_available": False,
        "llm_recommendation": "UNAVAILABLE",
        "final_decision": "PASS",
        "error": None,
        "git": {"commit_sha": "abc"},
        "github": {"run_id": run_id, "repository": "owner/repo"},
    }


def build_client():
    app = create_app()
    repository = FakeRepository()
    settings = Settings(
        mongodb_uri="mongodb+srv://test.example.mongodb.net/",
        security_monitor_secret="test-secret",
    )
    app.dependency_overrides[get_repository] = lambda: repository
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app), repository


def signed_headers(body: bytes, timestamp=None, secret="test-secret"):
    timestamp = str(timestamp or int(time.time()))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"X-Monitor-Timestamp": timestamp, "X-Monitor-Signature": signature}


def test_hmac_rejects_invalid_and_expired_requests():
    client, _ = build_client()
    body = json.dumps(report()).encode()
    assert client.post("/api/v1/runs", content=body, headers=signed_headers(body, secret="wrong")).status_code == 401
    assert client.post("/api/v1/runs", content=body, headers=signed_headers(body, timestamp=int(time.time()) - 600)).status_code == 401


def test_ingestion_is_replay_protected_and_run_id_is_upserted():
    client, repository = build_client()
    body = json.dumps(report()).encode()
    headers = signed_headers(body)
    assert client.post("/api/v1/runs", content=body, headers=headers).status_code == 202
    assert client.post("/api/v1/runs", content=body, headers=headers).status_code == 409

    updated = report()
    updated["duration_seconds"] = 12
    updated["raw_findings"] = [{"secret": "must-not-be-stored"}]
    updated["git"]["source"] = "must-not-be-stored"
    updated_body = json.dumps(updated).encode()
    assert client.post("/api/v1/runs", content=updated_body, headers=signed_headers(updated_body)).status_code == 202
    assert len(repository.runs) == 1
    assert repository.runs["100"]["duration_seconds"] == 12
    assert "raw_findings" not in repository.runs["100"]
    assert "source" not in repository.runs["100"]["git"]


def test_health_endpoint_is_public():
    client, _ = build_client()
    assert client.get("/health").json() == {"status": "ok"}


def test_vercel_entrypoint_exports_fastapi_app():
    from index import app as vercel_app
    from api.index import app as vercel_function_app

    assert vercel_app is main_app
    assert vercel_function_app is main_app


def test_required_settings_have_no_insecure_fallbacks(monkeypatch):
    monkeypatch.delenv("MONGODB_URI", raising=False)
    monkeypatch.delenv("SECURITY_MONITOR_SECRET", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_atlas_uri_is_accepted_and_invalid_scheme_is_rejected():
    settings = Settings(
        _env_file=None,
        mongodb_uri="mongodb+srv://user:password@cluster.example.mongodb.net/",
        security_monitor_secret="test-secret",
    )
    assert settings.mongodb_uri.startswith("mongodb+srv://")

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            mongodb_uri="https://cluster.example.mongodb.net/",
            security_monitor_secret="test-secret",
        )


def test_detailed_findings_are_validated_and_legacy_reports_are_accepted():
    client, repository = build_client()
    detailed = report("200")
    detailed["findings"] = [{
        "tool": "semgrep",
        "severity": "HIGH",
        "type": "python.lang.security.rule",
        "message": "Unsafe call detected",
        "file": "src/app.py",
        "line": 12,
    }]
    body = json.dumps(detailed).encode()
    assert client.post("/api/v1/runs", content=body, headers=signed_headers(body)).status_code == 202
    assert repository.runs["200"]["findings"][0]["file"] == "src/app.py"

    legacy = report("201")
    legacy.pop("findings")
    legacy.pop("findings_truncated")
    body = json.dumps(legacy).encode()
    assert client.post("/api/v1/runs", content=body, headers=signed_headers(body)).status_code == 202

    invalid = report("202")
    invalid["findings"] = [{
        "tool": "gitleaks",
        "severity": "HIGH",
        "type": "secret",
        "message": "Secret detected",
        "file": "../outside.env",
        "line": 1,
        "source": "not allowed",
    }]
    body = json.dumps(invalid).encode()
    assert client.post("/api/v1/runs", content=body, headers=signed_headers(body)).status_code == 422


def test_configured_finding_limit_is_enforced():
    client, _ = build_client()
    client.app.dependency_overrides[get_settings] = lambda: Settings(
        mongodb_uri="mongodb+srv://test.example.mongodb.net/",
        security_monitor_secret="test-secret",
        max_findings_per_run=1,
    )
    payload = report("203")
    finding = {"tool": "trivy", "severity": "HIGH", "type": "CVE-1", "message": "issue"}
    payload["findings"] = [finding, finding]
    body = json.dumps(payload).encode()
    assert client.post("/api/v1/runs", content=body, headers=signed_headers(body)).status_code == 422
