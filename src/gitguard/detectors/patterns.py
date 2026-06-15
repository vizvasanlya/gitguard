from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class BadPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    rule_id: str
    description: str
    languages: list[str]


BAD_PATTERNS: list[BadPattern] = [
    BadPattern(
        name="Bare Except",
        pattern=re.compile(r"""except\s*:"""),
        severity=Severity.MEDIUM,
        rule_id="BP001",
        description="Bare except clause - catches all exceptions including SystemExit",
        languages=["python"],
    ),
    BadPattern(
        name="TODO/FIXME/HACK",
        pattern=re.compile(r"""(?i)#\s*(?:TODO|FIXME|HACK|XXX|BUG)"""),
        severity=Severity.LOW,
        rule_id="BP002",
        description="Unresolved TODO/FIXME comment",
        languages=[],
    ),
    BadPattern(
        name="Print Statement",
        pattern=re.compile(r"""(?<!\w)print\s*\("""),
        severity=Severity.INFO,
        rule_id="BP003",
        description="print() statement - consider using logging",
        languages=["python"],
    ),
    BadPattern(
        name="Console Log",
        pattern=re.compile(r"""console\.(?:log|warn|error|debug)\s*\("""),
        severity=Severity.INFO,
        rule_id="BP004",
        description="console.log() statement - remove before production",
        languages=["javascript", "typescript"],
    ),
    BadPattern(
        name="Magic Number",
        pattern=re.compile(r"""(?:if|while|return|==|!=|>=|<=|>|<)\s*(?:0x[0-9a-fA-F]{4,}|\d{4,})(?!\.\d)"""),
        severity=Severity.LOW,
        rule_id="BP005",
        description="Magic number - consider using a named constant",
        languages=[],
    ),
    BadPattern(
        name="Deep Nesting",
        pattern=re.compile(r"""^                \S"""),
        severity=Severity.LOW,
        rule_id="BP006",
        description="Deeply nested code (4+ levels) - consider refactoring",
        languages=[],
    ),
    BadPattern(
        name="Star Import",
        pattern=re.compile(r"""from\s+\S+\s+import\s+\*"""),
        severity=Severity.MEDIUM,
        rule_id="BP007",
        description="Wildcard import - may cause namespace pollution",
        languages=["python"],
    ),
    BadPattern(
        name="Mutable Default Argument",
        pattern=re.compile(r"""def\s+\w+\s*\(.*=\s*(?:\[\]|\{\}|set\(\))"""),
        severity=Severity.MEDIUM,
        rule_id="BP008",
        description="Mutable default argument - use None instead",
        languages=["python"],
    ),
    BadPattern(
        name="Global Variable",
        pattern=re.compile(r"""^global\s+\w+"""),
        severity=Severity.MEDIUM,
        rule_id="BP009",
        description="Global variable usage - consider refactoring",
        languages=["python"],
    ),
    BadPattern(
        name="Sleep in Loop",
        pattern=re.compile(r"""(?:time\.sleep|Thread\.sleep|setTimeout|\.sleep\()"""),
        severity=Severity.LOW,
        rule_id="BP010",
        description="Sleep in code - may indicate polling pattern",
        languages=[],
    ),
    BadPattern(
        name="Empty Except Block",
        pattern=re.compile(r"""except.*:\s*$"""),
        severity=Severity.MEDIUM,
        rule_id="BP011",
        description="Empty except block - exceptions are silently swallowed",
        languages=["python"],
    ),
    BadPattern(
        name="Type Check with Type",
        pattern=re.compile(r"""type\s*\(\w+\)\s*==\s*type\s*\("""),
        severity=Severity.LOW,
        rule_id="BP012",
        description="Use isinstance() instead of type() comparison",
        languages=["python"],
    ),
    BadPattern(
        name="Assert in Production",
        pattern=re.compile(r"""^assert\s+"""),
        severity=Severity.LOW,
        rule_id="BP013",
        description="assert statement - removed when running with -O flag",
        languages=["python"],
    ),
    BadPattern(
        name="Semicolon Usage",
        pattern=re.compile(r""";\s*$"""),
        severity=Severity.INFO,
        rule_id="BP014",
        description="Unnecessary semicolon",
        languages=["python"],
    ),
    BadPattern(
        name="Complex List Comprehension",
        pattern=re.compile(r"""for\s+.*\s+in\s+.*\s+for\s+.*\s+in"""),
        severity=Severity.LOW,
        rule_id="BP015",
        description="Nested list comprehension - consider simplifying",
        languages=["python"],
    ),
]


def scan_for_bad_patterns(file_path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    suffix = file_path.suffix.lstrip(".")

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for bad_pattern in BAD_PATTERNS:
            if bad_pattern.languages and suffix not in bad_pattern.languages:
                continue

            match = bad_pattern.pattern.search(stripped)
            if match:
                findings.append(
                    Finding(
                        finding_type=FindingType.BAD_PRACTICE,
                        severity=bad_pattern.severity,
                        message=bad_pattern.description,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=stripped[:120],
                        rule_id=bad_pattern.rule_id,
                        suggestion=f"Fix: {bad_pattern.name}",
                    )
                )

    return findings
