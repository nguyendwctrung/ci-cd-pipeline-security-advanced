"""Resolve repository files changed in the configured security diff."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


_GIT_TIMEOUT = 10
_INCLUDED_STATUSES = ("A", "C", "M", "R", "T")


@dataclass(frozen=True)
class ChangedFileScope:
    """Changed-file scan scope resolved from Git diff context."""

    mode: str
    base: str = ""
    head: str = ""
    changed_files: list[str] = field(default_factory=list)
    skipped_deleted_count: int = 0

    def to_manifest(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "base": self.base or None,
            "head": self.head or None,
            "changed_file_count": len(self.changed_files),
            "skipped_deleted_count": self.skipped_deleted_count,
        }


def resolve_changed_file_scope(
    repo_root: Path,
    *,
    base: Optional[str] = None,
    head: Optional[str] = None,
) -> ChangedFileScope:
    """Return changed, scan-eligible files for the configured diff range."""
    diff_base = (base if base is not None else os.getenv("SECURITY_DIFF_BASE", "")).strip()
    diff_head = (head if head is not None else os.getenv("SECURITY_DIFF_HEAD", "")).strip()

    mode = "diff"
    if diff_base and diff_head:
        diff_spec = f"{diff_base}..{diff_head}"
        cmd = ["git", "diff", "--name-status", diff_spec]
    else:
        mode = "working-tree"
        cmd = ["git", "diff", "--name-status", "--cached"]

    output = _run_git(cmd, repo_root)
    changed_files, deleted = _parse_name_status(output.splitlines() if output else ())
    existing_files = [
        path for path in changed_files
        if (repo_root / Path(path)).is_file()
    ]

    return ChangedFileScope(
        mode=mode,
        base=diff_base,
        head=diff_head,
        changed_files=existing_files,
        skipped_deleted_count=deleted + (len(changed_files) - len(existing_files)),
    )


def _parse_name_status(lines: Iterable[str]) -> tuple[list[str], int]:
    changed: list[str] = []
    skipped_deleted = 0
    for line in lines:
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        code = status[:1]
        if code == "D":
            skipped_deleted += 1
            continue
        if code not in _INCLUDED_STATUSES:
            continue
        path = parts[-1] if code in ("C", "R") and len(parts) >= 3 else parts[1]
        normalized = path.replace("\\", "/").strip("/")
        if normalized:
            changed.append(normalized)
    return changed, skipped_deleted


def _run_git(cmd: list[str], cwd: Path) -> str:
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=_GIT_TIMEOUT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git command failed: {' '.join(cmd)}: {result.stderr.strip()}")
    return result.stdout.strip()
