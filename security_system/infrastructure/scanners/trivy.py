"""Trivy CLI wrapper."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence

logger = logging.getLogger(__name__)

_TIMEOUT = 1800
_DEFAULT_SEVERITIES = "HIGH,CRITICAL"
_DEFAULT_SKIP_DIRS = (
    "node_modules",
    ".venv",
    "security_system/reports",
    "PokeMap/src/server/tempUploads",
)


def run_trivy(
    target: Path,
    *,
    severities: str = _DEFAULT_SEVERITIES,
    output_path: Optional[Path] = None,
    timeout: int = _TIMEOUT,
    changed_files: Optional[Sequence[str]] = None,
) -> Optional[list[Any]]:
    """Execute Trivy and return raw result groups."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_file = Path(tmp.name)
    mirror: Optional[tempfile.TemporaryDirectory[str]] = None

    try:
        scan_target = target
        if changed_files is not None:
            mirror = tempfile.TemporaryDirectory()
            scan_target = _copy_changed_files_to_mirror(target, changed_files, Path(mirror.name))

        cmd = [
            "trivy",
            "fs",
            "--severity", severities,
            "--format", "json",
            "--output", str(report_file),
        ]
        for skip_dir in _DEFAULT_SKIP_DIRS:
            cmd.extend(["--skip-dirs", skip_dir])
        cmd.append(str(scan_target))

        logger.info("Running Trivy: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        logger.debug("Trivy exit code: %d", result.returncode)
        if result.stderr:
            logger.debug("Trivy stderr: %s", result.stderr.strip())

        raw = _load_json(report_file)
        if raw is None:
            raw = {"Results": []}
            report_file.write_text(json.dumps(raw), encoding="utf-8")
        if changed_files is not None:
            raw = _normalize_report_paths(raw, scan_target)
            report_file.write_text(json.dumps(raw), encoding="utf-8")

        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(report_file.read_bytes())

        if isinstance(raw, dict):
            return raw.get("Results", [])
        return raw

    except FileNotFoundError:
        logger.error("Trivy binary not found. Install: https://trivy.dev/docs/getting-started/installation/")
        return None
    except subprocess.TimeoutExpired:
        logger.error("Trivy scan timed out after %ds", timeout)
        return None
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Trivy execution failed: %s", exc)
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
        logger.error("Failed to parse Trivy JSON output: %s", exc)
        return None


def _copy_changed_files_to_mirror(target: Path, changed_files: Sequence[str], mirror: Path) -> Path:
    repo_root = target.resolve()
    for rel in changed_files:
        src = (repo_root / rel).resolve()
        if not src.is_file() or not _is_relative_to(src, repo_root):
            continue
        dst = mirror / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return mirror


def _normalize_report_paths(raw: Any, scan_target: Path) -> Any:
    results = raw.get("Results", []) if isinstance(raw, dict) else []
    for result in results:
        if not isinstance(result, dict) or not result.get("Target"):
            continue
        path = Path(result["Target"])
        if path.is_absolute():
            try:
                result["Target"] = path.resolve().relative_to(scan_target.resolve()).as_posix()
            except ValueError:
                result["Target"] = path.as_posix()
        else:
            result["Target"] = path.as_posix()
    return raw


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
