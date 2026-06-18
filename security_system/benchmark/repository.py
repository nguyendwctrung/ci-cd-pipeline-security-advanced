"""Repository clone and checkout management for benchmark runs."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from security_system.benchmark.models import RepoSpec


@dataclass(frozen=True)
class CheckoutResult:
    """Outcome of preparing a benchmark repository."""

    repo: str
    path: Path
    status: str
    commit: str
    error: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "repo": self.repo,
            "path": str(self.path),
            "status": self.status,
            "commit": self.commit,
            "error": self.error,
        }


class RepositoryManager:
    """Clone benchmark repositories and check out their pinned commits."""

    def __init__(self, repo_workdir: Path) -> None:
        self.repo_workdir = repo_workdir
        self.repo_workdir.mkdir(parents=True, exist_ok=True)

    def prepare(self, repo: RepoSpec) -> CheckoutResult:
        target = self.repo_workdir / repo.name
        try:
            if not target.exists():
                self._run(["git", "clone", "--no-tags", repo.url, str(target)], cwd=self.repo_workdir)
            else:
                self._run(["git", "fetch", "--no-tags", "origin", repo.commit], cwd=target)
            self._run(["git", "checkout", "--detach", repo.commit], cwd=target)
            actual = self._run(["git", "rev-parse", "HEAD"], cwd=target).strip()
            if actual.lower() != repo.commit:
                raise RuntimeError(f"checked out {actual}, expected {repo.commit}")
            return CheckoutResult(repo=repo.name, path=target, status="READY", commit=actual)
        except Exception as exc:  # pylint: disable=broad-except
            return CheckoutResult(repo=repo.name, path=target, status="ERROR", commit=repo.commit, error=str(exc)[:500])

    @staticmethod
    def _run(cmd: list[str], cwd: Path) -> str:
        result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"{' '.join(cmd)} failed: {detail}")
        return result.stdout

