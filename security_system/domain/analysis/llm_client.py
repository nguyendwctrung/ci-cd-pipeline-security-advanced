"""
Helpers for parsing and validating LLM security analysis responses.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple


_VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_VALID_DECISIONS = {"FAIL", "WARN", "PASS"}
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def parse_llm_json_response(text: str) -> Optional[dict]:
    """
    Parse a JSON object returned by an LLM.

    Accepts clean JSON and tolerates a single markdown code fence if a provider
    ignores the requested JSON-only output.
    """
    cleaned = text.strip()
    fence_match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return None

    return parsed if isinstance(parsed, dict) else None


def normalize_analysis_payload(
    payload: dict,
    scan_data: Dict[str, Any],
) -> Tuple[Optional[dict], Optional[str]]:
    """
    Validate and normalize the LLM payload into the AnalysisResult schema.
    """
    required = {
        "recommended_decision",
        "risk_level",
        "is_malicious",
        "detected_patterns",
        "recommendations",
        "reasoning",
    }
    missing = sorted(required - set(payload))
    if missing:
        return None, f"LLM response missing required fields: {', '.join(missing)}"

    recommended_decision = str(payload["recommended_decision"]).upper()
    if recommended_decision not in _VALID_DECISIONS:
        return None, "recommended_decision must be FAIL, WARN, or PASS"
    if bool(payload["is_malicious"]):
        recommended_decision = "FAIL"

    risk_level = str(payload["risk_level"]).upper()
    if risk_level not in _VALID_RISK_LEVELS:
        return None, "risk_level must be LOW, MEDIUM, HIGH, or CRITICAL"

    max_severity = max_scanner_severity(scan_data)
    if (
        _SEVERITY_ORDER[risk_level] > _SEVERITY_ORDER[max_severity]
        and max_severity != "LOW"
    ):
        risk_level = max_severity

    detected_patterns = payload["detected_patterns"]
    recommendations = payload["recommendations"]
    if not isinstance(detected_patterns, list):
        return None, "detected_patterns must be a list"
    if not isinstance(recommendations, list):
        return None, "recommendations must be a list"

    return {
        "recommended_decision": recommended_decision,
        "risk_level": risk_level,
        "is_malicious": bool(payload["is_malicious"]),
        "detected_patterns": [str(item) for item in detected_patterns],
        "recommendations": [str(item) for item in recommendations],
        "reasoning": str(payload["reasoning"]),
    }, None


def max_scanner_severity(scan_data: Dict[str, Any]) -> str:
    """Return the maximum severity found in raw scanner data."""
    max_level = "LOW"

    if scan_data.get("gitleaks"):
        max_level = _max(max_level, "HIGH")

    for item in scan_data.get("semgrep", []):
        severity = str(item.get("extra", {}).get("severity") or item.get("severity", "")).upper()
        mapped = {"INFO": "LOW", "WARNING": "MEDIUM", "ERROR": "HIGH"}.get(
            severity,
            severity if severity in _VALID_RISK_LEVELS else "LOW",
        )
        max_level = _max(max_level, mapped)

    for group in scan_data.get("trivy", []):
        for vuln in group.get("Vulnerabilities", []):
            severity = str(vuln.get("Severity", "LOW")).upper()
            max_level = _max(max_level, severity if severity in _VALID_RISK_LEVELS else "LOW")
        for misconfig in group.get("Misconfigurations", []):
            severity = str(misconfig.get("Severity", "LOW")).upper()
            max_level = _max(max_level, severity if severity in _VALID_RISK_LEVELS else "LOW")

    return max_level


def _max(left: str, right: str) -> str:
    """Return the stricter severity."""
    return left if _SEVERITY_ORDER[left] >= _SEVERITY_ORDER[right] else right
