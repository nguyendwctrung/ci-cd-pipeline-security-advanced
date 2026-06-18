"""Gitleaks CLI wrapper."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence

logger = logging.getLogger(__name__)

_TIMEOUT = 60


def run_gitleaks(
    source: Path,
    *,
    staged_only: bool = False,
    output_path: Optional[Path] = None,
    timeout: int = _TIMEOUT,
    changed_files: Optional[Sequence[str]] = None,
) -> Optional[list[Any]]:
    """Execute Gitleaks and return raw findings."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_file = Path(tmp.name)
    mirror: Optional[tempfile.TemporaryDirectory[str]] = None

    try:
        scan_source = source
        command = "detect"
        if changed_files is not None:
            mirror = tempfile.TemporaryDirectory()
            scan_source = _copy_changed_files_to_mirror(source, changed_files, Path(mirror.name))
            command = "dir"

        cmd = ["gitleaks", command]
        if changed_files is None:
            cmd.extend(["--source", str(scan_source)])
        cmd.extend([
            "--report-format", "json",
            "--report-path", str(report_file),
            "--exit-code", "0",
            "--redact",
        ])
        if staged_only and changed_files is None:
            cmd.append("--staged")
        if changed_files is not None:
            cmd.append(str(scan_source))

        logger.info("Running Gitleaks: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        logger.debug("Gitleaks exit code: %d", result.returncode)
        if result.stderr:
            logger.debug("Gitleaks stderr: %s", result.stderr.strip())

        raw = _load_json(report_file)
        if raw is None:
            raw = []
        if changed_files is not None:
            raw = _normalize_report_paths(raw, scan_source)
            report_file.write_text(json.dumps(raw), encoding="utf-8")

        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(report_file.read_bytes())

        if isinstance(raw, list):
            return raw
        return raw.get("Leaks", [])

    except FileNotFoundError:
        logger.error("Gitleaks binary not found. Install: https://github.com/gitleaks/gitleaks")
        return None
    except subprocess.TimeoutExpired:
        logger.error("Gitleaks scan timed out after %ds", timeout)
        return None
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Gitleaks execution failed: %s", exc)
        return None
    finally:
        report_file.unlink(missing_ok=True)
        if mirror is not None:
            mirror.cleanup()


def _load_json(path: Path) -> Optional[Any]:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Gitleaks JSON output: %s", exc)
        return None


def _copy_changed_files_to_mirror(source: Path, changed_files: Sequence[str], mirror: Path) -> Path:
    source_root = source.resolve()
    for rel in changed_files:
        src = (source_root / rel).resolve()
        if not src.is_file() or not _is_relative_to(src, source_root):
            continue
        dst = mirror / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return mirror


def _normalize_report_paths(raw: Any, scan_source: Path) -> Any:
    leaks = raw if isinstance(raw, list) else raw.get("Leaks", []) if isinstance(raw, dict) else []
    for leak in leaks:
        if not isinstance(leak, dict):
            continue
        for key in ("File", "Path"):
            value = leak.get(key)
            if value:
                leak[key] = _normalize_path(str(value), scan_source)
    return raw


def _normalize_path(value: str, scan_source: Path) -> str:
    path = Path(value)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(scan_source.resolve()).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
