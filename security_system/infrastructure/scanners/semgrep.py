"""Semgrep CLI wrapper."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence

logger = logging.getLogger(__name__)

_TIMEOUT = 120
_DEFAULT_CONFIG = "p/security-audit"
_DEFAULT_EXCLUDES = (
    "node_modules",
    ".venv",
    "security_system/reports",
    "PokeMap/src/server/tempUploads",
)


def run_semgrep(
    target: Path,
    *,
    config: str = _DEFAULT_CONFIG,
    output_path: Optional[Path] = None,
    timeout: int = _TIMEOUT,
    changed_files: Optional[Sequence[str]] = None,
) -> Optional[list[Any]]:
    """Execute Semgrep and return raw result entries."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_file = Path(tmp.name)

    try:
        cmd = [
            "semgrep",
            "--config", config,
            "--json",
            "--output", str(report_file),
        ]
        for exclude in _DEFAULT_EXCLUDES:
            cmd.extend(["--exclude", exclude])
        if changed_files is None:
            cmd.append(str(target))
        else:
            cmd.extend(str(target / path) for path in changed_files)

        logger.info("Running Semgrep: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        logger.debug("Semgrep exit code: %d", result.returncode)
        if result.stderr:
            logger.debug("Semgrep stderr: %s", result.stderr.strip())

        raw = _load_json(report_file)
        if raw is None:
            raw = {"results": []}
        if changed_files is not None:
            raw = _normalize_report_paths(raw, target)
            report_file.write_text(json.dumps(raw), encoding="utf-8")

        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(report_file.read_bytes())

        if isinstance(raw, dict):
            return raw.get("results", [])
        return raw

    except FileNotFoundError:
        logger.error("Semgrep binary not found. Install: https://semgrep.dev/docs/getting-started/")
        return None
    except subprocess.TimeoutExpired:
        logger.error("Semgrep scan timed out after %ds", timeout)
        return None
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Semgrep execution failed: %s", exc)
        return None
    finally:
        report_file.unlink(missing_ok=True)


def _load_json(path: Path) -> Optional[Any]:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Semgrep JSON output: %s", exc)
        return None


def _normalize_report_paths(raw: Any, target: Path) -> Any:
    repo_root = target.resolve()
    results = raw.get("results", []) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
    for result in results:
        if not isinstance(result, dict) or not result.get("path"):
            continue
        path = Path(result["path"])
        if path.is_absolute():
            try:
                result["path"] = path.resolve().relative_to(repo_root).as_posix()
            except ValueError:
                result["path"] = path.as_posix()
        else:
            result["path"] = path.as_posix()
    return raw
