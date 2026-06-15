from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class CustomRule:
    id: str
    name: str
    pattern: str
    severity: str = "medium"
    message: str = ""
    languages: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    suggestion: str = ""
    enabled: bool = True

    def __post_init__(self) -> None:
        try:
            self._compiled = re.compile(self.pattern)
        except re.error:
            self._compiled = re.compile("NEVER_MATCH_PATTERN")

    def match(self, line: str) -> re.Match[str] | None:
        return self._compiled.search(line)


class RuleEngine:
    """Loads and applies custom security rules from YAML/JSON files."""

    DEFAULT_RULES_DIR = Path.home() / ".gitguard" / "rules"

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or self.DEFAULT_RULES_DIR
        self.rules: list[CustomRule] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_dir.exists():
            return

        for rule_file in self.rules_dir.glob("*.json"):
            try:
                data = json.loads(rule_file.read_text())
                if isinstance(data, list):
                    for rule_data in data:
                        self.rules.append(CustomRule(**rule_data))
                elif isinstance(data, dict) and "rules" in data:
                    for rule_data in data["rules"]:
                        self.rules.append(CustomRule(**rule_data))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                import yaml  # type: ignore[import-untyped]
                data = yaml.safe_load(rule_file.read_text())
                if isinstance(data, list):
                    for rule_data in data:
                        self.rules.append(CustomRule(**rule_data))
                elif isinstance(data, dict) and "rules" in data:
                    for rule_data in data["rules"]:
                        self.rules.append(CustomRule(**rule_data))
            except (ImportError, Exception):
                continue

    def load_rules_from_file(self, rule_file: Path) -> int:
        count = 0
        try:
            if rule_file.suffix == ".json":
                data = json.loads(rule_file.read_text())
                rules_data = data if isinstance(data, list) else data.get("rules", [])
                for rule_data in rules_data:
                    self.rules.append(CustomRule(**rule_data))
                    count += 1
            elif rule_file.suffix in (".yaml", ".yml"):
                import yaml  # type: ignore[import-untyped]
                data = yaml.safe_load(rule_file.read_text())
                rules_data = data if isinstance(data, list) else data.get("rules", [])
                for rule_data in rules_data:
                    self.rules.append(CustomRule(**rule_data))
                    count += 1
        except Exception:
            pass
        return count

    def scan(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        suffix = file_path.suffix.lstrip(".")

        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.languages and suffix not in rule.languages:
                continue

            if rule.file_patterns and not any(re.search(fp, str(file_path)) for fp in rule.file_patterns):
                continue

            for line_num, line in enumerate(lines, start=1):
                match = rule.match(line)
                if match:
                    findings.append(
                        Finding(
                            finding_type=FindingType.SECURITY,
                            severity=Severity(rule.severity),
                            message=rule.message or f"Custom rule {rule.id} matched",
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line.strip()[:120],
                            rule_id=rule.id,
                            suggestion=rule.suggestion,
                        )
                    )

        return findings

    def get_rules(self) -> list[CustomRule]:
        return self.rules

    def add_rule(self, rule: CustomRule) -> None:
        self.rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                return True
        return False
