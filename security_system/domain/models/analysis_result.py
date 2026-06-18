"""
AnalysisResult data model.

Represents the output produced by the LLM security analysis step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal


DecisionRecommendation = Literal["FAIL", "WARN", "PASS"]


@dataclass
class AnalysisResult:
	"""
	Output of the LLM-based security analysis.

	Attributes:
		timestamp:         ISO 8601 time when the analysis was performed.
		recommended_decision: LLM's categorical recommendation.
		risk_level:        Human-readable risk label (LOW / MEDIUM / HIGH / CRITICAL).
		is_malicious:      True if the LLM flagged the commit as potentially malicious.
		detected_patterns: List of identified threat patterns (e.g. 'hardcoded secret').
		recommendations:   Suggested remediation actions.
		reasoning:         LLM's natural-language justification.
		scan_issues_count: Total number of issues from all scan tools.
		errors:            Non-fatal errors encountered during analysis.
	"""

	timestamp: str
	recommended_decision: DecisionRecommendation
	risk_level: str
	is_malicious: bool
	detected_patterns: List[str] = field(default_factory=list)
	recommendations: List[str] = field(default_factory=list)
	reasoning: str = ""
	scan_issues_count: int = 0
	errors: List[str] = field(default_factory=list)

	def to_dict(self) -> dict:
		return {
			"timestamp": self.timestamp,
			"recommended_decision": self.recommended_decision,
			"risk_level": self.risk_level,
			"is_malicious": self.is_malicious,
			"detected_patterns": self.detected_patterns,
			"recommendations": self.recommendations,
			"reasoning": self.reasoning,
			"scan_issues_count": self.scan_issues_count,
			"errors": self.errors,
		}

	@classmethod
	def fallback(cls, timestamp: str, error_message: str) -> "AnalysisResult":
		"""
		Creates a safe fallback result when LLM analysis fails.
		"""
		return cls(
			timestamp=timestamp,
			recommended_decision="WARN",
			risk_level="MEDIUM",
			is_malicious=False,
			detected_patterns=[],
			recommendations=["Manual review required — automated analysis failed."],
			reasoning="LLM analysis unavailable.",
			scan_issues_count=0,
			errors=[error_message],
		)
