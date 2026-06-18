"""Run one security scanner and emit a CI aggregation manifest."""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, Optional

from security_system.application.changed_files import ChangedFileScope, resolve_changed_file_scope
from security_system.application.use_cases.run_scan import REPORT_PATHS
from security_system.infrastructure.scanners import run_gitleaks, run_semgrep, run_trivy
from security_system.infrastructure.storage import ensure_dir
from security_system.infrastructure.storage.file_store import write_json


logger = logging.getLogger(__name__)
SCANNERS: dict[str, Callable[..., Optional[list[Any]]]] = {
    "gitleaks": run_gitleaks,
    "semgrep": run_semgrep,
    "trivy": run_trivy,
}


def run_scanner_job(
    tool: str,
    target: Path,
    output_dir: Path,
    *,
    installation_status: str = "success",
    changed_only: bool = False,
) -> dict[str, Any]:
    """Run one scanner, always writing a machine-readable manifest."""
    if tool not in SCANNERS:
        raise ValueError(f"Unsupported scanner: {tool}")

    ensure_dir(output_dir)
    report_path = output_dir / REPORT_PATHS[tool]
    manifest_path = output_dir / f"{tool}-manifest.json"
    started = time.monotonic()
    error: Optional[str] = None
    scan_scope: Optional[ChangedFileScope] = None

    if installation_status != "success":
        error = f"{tool} installation failed"
    else:
        try:
            if changed_only:
                scan_scope = resolve_changed_file_scope(target)
                if not scan_scope.changed_files:
                    _write_empty_report(tool, report_path)
                    findings = []
                else:
                    findings = SCANNERS[tool](
                        target,
                        output_path=report_path,
                        changed_files=scan_scope.changed_files,
                    )
            else:
                findings = SCANNERS[tool](target, output_path=report_path)
            if findings is None:
                error = f"{tool} scanner failed or is unavailable"
            else:
                _validate_or_normalize_report(tool, report_path, findings)
        except Exception as exc:  # pylint: disable=broad-except
            error = f"{tool} scanner failed: {str(exc)[:400]}"

    manifest = {
        "schema_version": "1.0",
        "tool": tool,
        "status": "ERROR" if error else "COMPLETED",
        "duration_seconds": round(time.monotonic() - started, 3),
        "report": REPORT_PATHS[tool],
        "error": error,
        "scan_scope": scan_scope.to_manifest() if scan_scope else {
            "mode": "full",
            "base": None,
            "head": None,
            "changed_file_count": None,
            "skipped_deleted_count": 0,
        },
    }
    write_json(manifest_path, manifest)
    if error:
        logger.error(error)
    else:
        logger.info("%s scan completed", tool)
    return manifest


def _validate_or_normalize_report(
    tool: str,
    report_path: Path,
    findings: list[Any],
) -> None:
    """Reject malformed output while normalizing a truly empty report."""
    if not report_path.exists() or report_path.stat().st_size == 0:
        empty: Any = [] if tool == "gitleaks" else {
            "semgrep": {"results": []},
            "trivy": {"Results": []},
        }[tool]
        write_json(report_path, empty)
        return
    with report_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if tool == "gitleaks" and not isinstance(data, (list, dict)):
        raise ValueError("Gitleaks report must be an array or object")
    if tool in ("semgrep", "trivy") and not isinstance(data, dict):
        raise ValueError(f"{tool} report must be an object")
    if not isinstance(findings, list):
        raise ValueError(f"{tool} scanner returned an invalid result")


def _write_empty_report(tool: str, report_path: Path) -> None:
    empty: Any = [] if tool == "gitleaks" else {
        "semgrep": {"results": []},
        "trivy": {"Results": []},
    }[tool]
    write_json(report_path, empty)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", choices=tuple(SCANNERS))
    parser.add_argument("--target", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--installation-status", default="success")
    parser.add_argument("--changed-only", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    run_scanner_job(
        args.tool,
        args.target,
        args.output_dir,
        installation_status=args.installation_status,
        changed_only=args.changed_only,
    )


if __name__ == "__main__":
    main()
