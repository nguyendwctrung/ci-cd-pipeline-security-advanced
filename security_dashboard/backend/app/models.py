from __future__ import annotations

from datetime import datetime
from typing import Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StageRecord(BaseModel):
    status: str
    duration_seconds: float = Field(ge=0)
    error: Optional[str] = Field(default=None, max_length=500)


class ScannerHealth(BaseModel):
    status: str
    error: Optional[str] = Field(default=None, max_length=500)


class ErrorRecord(BaseModel):
    category: str = Field(max_length=100)
    message: str = Field(max_length=500)


class FindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=50)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    type: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=500)
    file: Optional[str] = Field(default=None, max_length=500)
    line: Optional[int] = Field(default=None, ge=1)

    @field_validator("file")
    @classmethod
    def validate_relative_path(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ".." in normalized.split("/"):
            raise ValueError("finding file must be repository-relative")
        if len(normalized) >= 3 and normalized[1:3] == ":/":
            raise ValueError("finding file must be repository-relative")
        return normalized


class GitMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")
    commit_sha: str = Field(default="unknown", max_length=64)
    author: str = Field(default="unknown", max_length=200)


class GitHubMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")
    run_id: str | int
    run_attempt: str | int = "1"
    run_url: Optional[str] = Field(default=None, max_length=500)
    repository: str = Field(default="unknown", max_length=200)
    event: str = Field(default="unknown", max_length=100)
    ref: str = Field(default="unknown", max_length=300)
    sha: str = Field(default="unknown", max_length=64)


class MonitorReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str
    run_started_at: datetime
    run_finished_at: datetime
    duration_seconds: float = Field(ge=0)
    pipeline_status: Literal["COMPLETED", "BLOCKED", "ERROR"]
    stages: Dict[str, StageRecord] = Field(default_factory=dict)
    scanner_health: Dict[str, ScannerHealth] = Field(default_factory=dict)
    findings_by_tool: Dict[str, int] = Field(default_factory=dict)
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings: list[FindingRecord] = Field(default_factory=list)
    findings_truncated: bool = False
    policy_decision: Optional[str] = None
    llm_available: Optional[bool] = None
    llm_recommendation: Optional[str] = None
    final_decision: Optional[str] = None
    error: Optional[ErrorRecord] = None
    git: GitMetadata = Field(default_factory=GitMetadata)
    github: GitHubMetadata

    @property
    def run_id(self) -> str:
        return str(self.github.run_id or "")
