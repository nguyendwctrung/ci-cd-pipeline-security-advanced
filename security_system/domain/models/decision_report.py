"""
DecisionReport data model.

Represents the final security decision produced by the decision engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal

# Allowed decision values — used as a type alias throughout the system
DecisionType = Literal["FAIL", "WARN", "PASS"]


@dataclass
class DecisionReport:
	"""
	Final security decision for a CI/CD pipeline run.

	Attributes:
		timestamp:         ISO 8601 time when the decision was made.
		decision:          One of FAIL / WARN / PASS.
		reason:            Short explanation of the decision.
		is_malicious:      Whether the LLM flagged the commit as malicious.
		detected_patterns: Threat patterns identified in the analysis.
		recommendations:   Suggested remediation actions.
		metadata:          Arbitrary additional context (commit SHA, author, etc.).
	"""

	timestamp: str
	decision: DecisionType
	reason: str
	is_malicious: bool
	detected_patterns: List[str] = field(default_factory=list)
	recommendations: List[str] = field(default_factory=list)
	metadata: Dict[str, Any] = field(default_factory=dict)

	@property
	def is_blocking(self) -> bool:
		"""Returns True if this decision blocks the pipeline."""
		return self.decision == "FAIL"

	def to_dict(self) -> dict:
		return {
			"timestamp": self.timestamp,
			"decision": self.decision,
			"reason": self.reason,
			"is_malicious": self.is_malicious,
			"detected_patterns": self.detected_patterns,
			"recommendations": self.recommendations,
			"metadata": self.metadata,
		}

	def exit_code(self) -> int:
		"""
		Returns the appropriate shell exit code for this decision.
			0 = PASS or WARN (pipeline continues)
			1 = FAIL (pipeline blocked)
		"""
		return 1 if self.is_blocking else 0
