from __future__ import annotations

import json

from security_system.application.monitoring import PipelineMonitor
from security_system.domain.parsers.gitleaks import GitleaksParser


def test_gitleaks_parser_never_preserves_secret_match(tmp_path):
    report = tmp_path / "gitleaks.json"
    secret = "super-secret-token-value"
    report.write_text(json.dumps([{
        "RuleID": "generic-api-key",
        "Match": secret,
        "File": "config/.env",
        "StartLine": 4,
        "Entropy": 5.0,
    }]), encoding="utf-8")

    issue = GitleaksParser().parse_file(report).issues[0]

    assert secret not in issue.message
    assert issue.type == "generic-api-key"


def test_monitor_sanitizes_paths_and_truncates_findings(monkeypatch):
    monkeypatch.setenv("MAX_FINDINGS_PER_RUN", "1")
    summary = GitleaksParser()._empty_summary()
    parsed = type("Issue", (), {
        "tool": "gitleaks",
        "severity": type("Severity", (), {"value": "HIGH"})(),
        "type": "rule",
        "message": "safe\nmessage",
        "file": "../outside.env",
        "line": 2,
    })()
    summary.issues = [parsed, parsed]
    summary.total_findings = 2
    summary.by_severity["HIGH"] = 2
    monitor = PipelineMonitor()

    monitor.record_findings({"gitleaks": summary})
    output = monitor.to_dict()

    assert len(output["findings"]) == 1
    assert output["findings"][0]["file"] is None
    assert output["findings"][0]["message"] == "safe message"
    assert output["findings_truncated"] is True
