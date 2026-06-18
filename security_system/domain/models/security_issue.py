"""
SecurityIssue data model.

Represents a single normalized security finding produced by any scan tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from enum import Enum


class Severity(str, Enum):
	"""Canonical severity levels used across the entire system."""

	LOW = "LOW"
	MEDIUM = "MEDIUM"
	HIGH = "HIGH"
	CRITICAL = "CRITICAL"

	@classmethod
	def from_string(cls, value: str) -> "Severity":
		"""
		Convert a raw severity string to a Severity enum value.
		Defaults to LOW for unknown values.
		"""
		try:
			return cls(value.upper())
		except ValueError:
			return cls.LOW


@dataclass
class SecurityIssue:
	"""
	A normalized security finding from any scan tool.

	Attributes:
		tool:     Name of the tool that produced this finding (e.g. 'semgrep').
		severity: Canonical severity level (LOW / MEDIUM / HIGH / CRITICAL).
		type:     Short category label (e.g. 'secret', 'sql-injection').
		message:  Human-readable description of the finding.
		file:     Path to the affected file, if available.
		line:     Line number of the finding, if available.
	"""

	tool: str
	severity: Severity
	type: str
	message: str
	file: Optional[str] = None
	line: Optional[int] = None

	def __post_init__(self) -> None:
		if isinstance(self.severity, str):
			self.severity = Severity.from_string(self.severity)

	def to_dict(self) -> dict:
		return {
			"tool": self.tool,
			"severity": self.severity.value,
			"type": self.type,
			"message": self.message,
			"file": self.file,
			"line": self.line,
		}
