from __future__ import annotations

from datetime import datetime, timezone

from app.repository import MongoRunRepository


class FakeRuns:
    def find_one_and_update(self, query, update, **kwargs):
        return update["$set"]


class FakeFindings:
    def __init__(self):
        self.deleted = []
        self.inserted = []

    def delete_many(self, query):
        self.deleted.append(query)

    def insert_many(self, documents):
        self.inserted.extend(documents)


def test_upsert_replaces_findings_and_keeps_them_out_of_run_document():
    repository = MongoRunRepository.__new__(MongoRunRepository)
    repository.retention_days = 90
    repository.runs = FakeRuns()
    repository.findings = FakeFindings()
    report = {
        "github": {"run_id": "10"},
        "git": {"commit_sha": "abc"},
        "run_started_at": datetime.now(timezone.utc),
        "findings": [{"tool": "semgrep", "severity": "HIGH", "type": "rule", "message": "issue"}],
    }

    saved = repository.upsert(report)

    assert "findings" not in saved
    assert "findings" in report
    assert repository.findings.deleted == [{"run_id": "10"}]
    assert repository.findings.inserted[0]["run_id"] == "10"
    assert repository.findings.inserted[0]["commit"] == "abc"
    assert repository.findings.inserted[0]["expires_at"] > datetime.now(timezone.utc)
