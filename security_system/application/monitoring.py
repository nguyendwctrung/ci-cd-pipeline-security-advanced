"""Sanitized monitoring records for security pipeline executions."""

from __future__ import annotations

import os
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_error(error: BaseException | str) -> str:
    text = str(error).replace("\r", " ").replace("\n", " ").strip()
    return text[:500] or "Unknown error"


def _clean_text(value: object, limit: int) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return re.sub(r"\s+", " ", text)[:limit]


def _clean_path(value: object) -> Optional[str]:
    text = _clean_text(value, 500).replace("\\", "/")
    if not text:
        return None
    while text.startswith("./"):
        text = text[2:]
    if text.startswith("/") or re.match(r"^[A-Za-z]:/", text):
        return None
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)[:500]


class PipelineMonitor:
    """Collect stage health and sanitized metrics for one pipeline run."""

    def __init__(self) -> None:
        self._started_at = _utc_now()
        self._started_clock = time.monotonic()
        self._active: Dict[str, float] = {}
        self._stages: Dict[str, Dict[str, Any]] = {}
        self._scanner_health = {
            tool: {"status": "PENDING", "error": None}
            for tool in ("gitleaks", "semgrep", "trivy")
        }
        self._findings_by_tool = {tool: 0 for tool in self._scanner_health}
        self._findings_by_severity = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }
        self._findings: list[Dict[str, Any]] = []
        self._findings_truncated = False
        self._pipeline_status = "ERROR"
        self._policy_decision: Optional[str] = None
        self._llm_available: Optional[bool] = None
        self._llm_recommendation: Optional[str] = None
        self._final_decision: Optional[str] = None
        self._error: Optional[Dict[str, str]] = None
        self._git: Dict[str, Any] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        self.start_stage(name)
        try:
            yield
        except Exception as exc:
            self.finish_stage(name, "ERROR", exc)
            raise
        else:
            self.finish_stage(name, "COMPLETED")

    def start_stage(self, name: str) -> None:
        self._active[name] = time.monotonic()
        self._stages[name] = {"status": "RUNNING", "duration_seconds": 0.0, "error": None}

    def finish_stage(
        self,
        name: str,
        status: str,
        error: BaseException | str | None = None,
    ) -> None:
        started = self._active.pop(name, time.monotonic())
        self._stages[name] = {
            "status": status,
            "duration_seconds": round(time.monotonic() - started, 3),
            "error": _clean_error(error) if error else None,
        }

    def record_stage(
        self,
        name: str,
        status: str,
        duration_seconds: float,
        error: BaseException | str | None = None,
    ) -> None:
        """Record a stage completed by an external CI worker."""
        self._stages[name] = {
            "status": status,
            "duration_seconds": round(max(0.0, duration_seconds), 3),
            "error": _clean_error(error) if error else None,
        }

    def record_git(self, context: Any) -> None:
        self._git = {
            "commit_sha": context.commit_hash,
            "author": context.author,
        }

    def record_scanner(self, tool: str, status: str, error: str | None = None) -> None:
        self._scanner_health[tool] = {
            "status": status,
            "error": _clean_error(error) if error else None,
        }

    def record_findings(self, summaries: Dict[str, Any]) -> None:
        max_findings = max(1, int(os.getenv("MAX_FINDINGS_PER_RUN", "5000")))
        for tool, summary in summaries.items():
            self._findings_by_tool[tool] = summary.total_findings
            for severity, count in summary.by_severity.items():
                self._findings_by_severity[severity] = (
                    self._findings_by_severity.get(severity, 0) + count
                )
            for issue in summary.issues:
                if len(self._findings) >= max_findings:
                    self._findings_truncated = True
                    continue
                self._findings.append({
                    "tool": _clean_text(issue.tool, 50).lower(),
                    "severity": issue.severity.value,
                    "type": _clean_text(issue.type, 200) or "unknown",
                    "message": _clean_text(issue.message, 500) or "No description available",
                    "file": _clean_path(issue.file),
                    "line": issue.line if isinstance(issue.line, int) and issue.line > 0 else None,
                })

    def record_analysis(self, analysis: Any) -> None:
        self._llm_available = not analysis.errors
        self._llm_recommendation = (
            analysis.recommended_decision if self._llm_available else "UNAVAILABLE"
        )

    def record_decision(self, decision: Any) -> None:
        self._final_decision = decision.decision
        self._policy_decision = decision.metadata.get("policy_decision", decision.decision)
        if self._llm_available is None and "llm_available" in decision.metadata:
            self._llm_available = bool(decision.metadata["llm_available"])
            self._llm_recommendation = decision.metadata.get("llm_decision", "UNAVAILABLE")
        self._pipeline_status = "BLOCKED" if decision.decision == "FAIL" else "COMPLETED"

    def record_error(self, category: str, error: BaseException | str) -> None:
        self._pipeline_status = "ERROR"
        self._error = {"category": category, "message": _clean_error(error)}

    def to_dict(self) -> Dict[str, Any]:
        stages = {name: dict(value) for name, value in self._stages.items()}
        for name, started in self._active.items():
            stages[name] = {
                "status": "ERROR",
                "duration_seconds": round(time.monotonic() - started, 3),
                "error": "Stage interrupted before completion",
            }
        return {
            "schema_version": "1.1",
            "run_started_at": self._started_at,
            "run_finished_at": _utc_now(),
            "duration_seconds": round(time.monotonic() - self._started_clock, 3),
            "pipeline_status": self._pipeline_status,
            "stages": stages,
            "scanner_health": self._scanner_health,
            "findings_by_tool": self._findings_by_tool,
            "findings_by_severity": self._findings_by_severity,
            "findings": self._findings,
            "findings_truncated": self._findings_truncated,
            "policy_decision": self._policy_decision,
            "llm_available": self._llm_available,
            "llm_recommendation": self._llm_recommendation,
            "final_decision": self._final_decision,
            "error": self._error,
            "git": self._git,
            "github": {
                "run_id": os.getenv("GITHUB_RUN_ID", "local"),
                "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT", "1"),
                "run_url": _github_run_url(),
                "repository": os.getenv("GITHUB_REPOSITORY", "local"),
                "event": os.getenv("GITHUB_EVENT_NAME", "local"),
                "ref": os.getenv("GITHUB_REF_NAME", "local"),
                "sha": os.getenv("GITHUB_SHA", self._git.get("commit_sha", "unknown")),
            },
        }


def _github_run_url() -> Optional[str]:
    server = os.getenv("GITHUB_SERVER_URL")
    repository = os.getenv("GITHUB_REPOSITORY")
    run_id = os.getenv("GITHUB_RUN_ID")
    if not all((server, repository, run_id)):
        return None
    return f"{server}/{repository}/actions/runs/{run_id}"
