"""External baseline tool interfaces for future benchmark expansion."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from security_system.benchmark.models import RepoSpec


@dataclass(frozen=True)
class BaselineStatus:
    """Execution status for a baseline tool."""

    tool: str
    status: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"tool": self.tool, "status": self.status, "reason": self.reason}


BASELINE_TOOLS = ("codeql", "checkov", "trufflehog", "dependency-check")


def run_baseline_stubs(repo: RepoSpec, repo_path: Path) -> list[BaselineStatus]:
    """Return stable not-configured statuses without executing external tools."""
    return [
        BaselineStatus(
            tool=tool,
            status="not_configured",
            reason=f"{tool} adapter is defined but execution is outside the Benchmark MVP",
        )
        for tool in BASELINE_TOOLS
    ]

