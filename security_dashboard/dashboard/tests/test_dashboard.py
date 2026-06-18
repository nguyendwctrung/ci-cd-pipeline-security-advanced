from __future__ import annotations

from auth import hash_password, verify_password
from configuration import mongodb_configuration_error
from dashboard_data import (
    PIPELINE_STATUS_ORDER,
    SEVERITY_ORDER,
    build_overview,
    filter_findings,
    filter_runs,
    findings_frame,
    parse_timestamp,
    runs_frame,
    severity_rows,
    stage_frame,
)


def sample_run(run_id="1", status="COMPLETED"):
    return {
        "run_id": run_id,
        "run_started_at": "2026-06-12T00:00:00+00:00",
        "pipeline_status": status,
        "final_decision": "PASS",
        "policy_decision": "PASS",
        "duration_seconds": 12,
        "llm_available": True,
        "findings_by_tool": {"gitleaks": 0, "semgrep": 2, "trivy": 1},
        "findings_by_severity": {"HIGH": 2, "CRITICAL": 1},
        "github": {"repository": "owner/repo", "ref": "main", "run_id": run_id},
        "git": {"commit_sha": "abcdef123456"},
        "stages": {"trivy_scan": {"status": "COMPLETED", "duration_seconds": 3}},
    }


def test_password_hash_validation():
    encoded = hash_password("correct-password", salt=b"0123456789abcdef", iterations=1000)
    assert verify_password("correct-password", encoded)
    assert not verify_password("wrong-password", encoded)
    assert not verify_password("correct-password", "invalid-hash")


def test_overview_and_filters():
    runs = [sample_run("2", "ERROR"), sample_run("1", "COMPLETED")]
    overview = build_overview(runs)
    assert overview["latest"]["run_id"] == "2"
    assert overview["last_success"]["run_id"] == "1"
    assert overview["status_counts"]["ERROR"] == 1
    assert filter_runs(runs, status="COMPLETED")[0]["run_id"] == "1"
    assert filter_runs(runs, search="abcdef")[0]["run_id"] == "2"
    assert filter_runs(runs, search="missing") == []


def test_frames_handle_empty_and_nested_data():
    assert runs_frame([]).empty
    frame = runs_frame([sample_run()])
    assert frame.iloc[0]["findings"] == 3
    stages = stage_frame(sample_run())
    assert stages.iloc[0]["stage"] == "Trivy Scan"


def test_parse_timestamp_handles_valid_and_invalid_values():
    assert parse_timestamp("2026-06-12T00:00:00+00:00").isoformat() == "2026-06-12T00:00:00+00:00"
    assert parse_timestamp(None) is None


def test_severity_rows_use_risk_order_and_fill_missing_levels():
    rows = severity_rows({"LOW": 4, "CRITICAL": 1, "MEDIUM": 3})

    assert [row["severity"] for row in rows] == list(SEVERITY_ORDER)
    assert [row["findings"] for row in rows] == [1, 0, 3, 4]


def test_mongodb_configuration_requires_valid_uri():
    assert "not configured" in mongodb_configuration_error("")
    assert "must use" in mongodb_configuration_error("https://cluster.example.com")
    assert mongodb_configuration_error(
        "mongodb+srv://user:password@cluster.example.mongodb.net/"
    ) is None


def test_findings_frame_filters_and_missing_locations():
    frame = findings_frame([
        {"run_id": "1", "commit": "abc", "tool": "trivy", "severity": "CRITICAL", "type": "CVE-1", "message": "package issue", "file": "package-lock.json", "line": None},
        {"run_id": "2", "commit": "def", "tool": "semgrep", "severity": "HIGH", "type": "python.lang.rule", "message": "unsafe call", "file": "app.py", "line": 12},
    ])
    assert frame.iloc[0]["line"] == "N/A"
    assert len(filter_findings(frame, severity="HIGH")) == 1
    assert len(filter_findings(frame, tool="trivy", search="package")) == 1
    assert len(filter_findings(frame, run_id="2", file="app.py")) == 1


def test_pipeline_status_order_matches_chart_domain():
    assert PIPELINE_STATUS_ORDER == ("COMPLETED", "BLOCKED", "ERROR")
