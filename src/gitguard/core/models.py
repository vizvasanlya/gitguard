from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(Enum):
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    BAD_PRACTICE = "bad_practice"
    LICENSE_ISSUE = "license_issue"
    DEPENDENCY_VULN = "dependency_vuln"
    STYLE = "style"
    SECURITY = "security"


@dataclass
class Finding:
    finding_type: FindingType
    severity: Severity
    message: str
    file_path: Path
    line_number: int
    line_content: str
    rule_id: str = ""
    suggestion: str = ""
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.finding_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "file": str(self.file_path),
            "line": self.line_number,
            "content": self.line_content,
            "rule": self.rule_id,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    @property
    def has_high(self) -> bool:
        return self.high_count > 0

    def get_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_by_type(self, finding_type: FindingType) -> list[Finding]:
        return [f for f in self.findings if f.finding_type == finding_type]


@dataclass
class ReviewResult:
    summary: str = ""
    suggestions: list[str] = field(default_factory=list)
    issues: list[Finding] = field(default_factory=list)
    score: float = 0.0

    @property
    def has_issues(self) -> bool:
        return len(self.issues) > 0


@dataclass
class AuditResult:
    dependencies: list[DependencyInfo] = field(default_factory=list)
    vulnerabilities: list[Finding] = field(default_factory=list)
    total_deps: int = 0
    vulnerable_deps: int = 0


@dataclass
class DependencyInfo:
    name: str
    version: str
    ecosystem: str
    is_direct: bool = True
    vulnerabilities: list[str] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0
