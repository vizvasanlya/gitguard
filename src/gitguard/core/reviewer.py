from __future__ import annotations

from pathlib import Path

from gitguard.core.models import Finding, FindingType, ReviewResult, Severity


class CodeReviewer:
    """Reviews code quality and provides suggestions."""

    def review_file(self, file_path: Path, content: str) -> ReviewResult:
        issues: list[Finding] = []
        suggestions: list[str] = []
        lines = content.splitlines()

        issues.extend(self._check_complexity(file_path, lines))
        issues.extend(self._check_documentation(file_path, lines))
        issues.extend(self._check_naming(file_path, lines))
        issues.extend(self._check_structure(file_path, lines))

        suggestions.extend(self._generate_suggestions(file_path, lines, issues))

        score = self._calculate_score(lines, issues)

        summary = self._generate_summary(file_path, lines, issues, score)

        return ReviewResult(
            summary=summary,
            suggestions=suggestions,
            issues=issues,
            score=score,
        )

    def review_diff(self, diff_content: str) -> ReviewResult:
        issues: list[Finding] = []
        suggestions: list[str] = []
        current_file: Path | None = None
        added_lines: list[str] = []

        for line in diff_content.splitlines():
            if line.startswith("+++ b/"):
                if current_file and added_lines:
                    content = "\n".join(added_lines)
                    result = self.review_file(current_file, content)
                    issues.extend(result.issues)
                    suggestions.extend(result.suggestions)
                current_file = Path(line[6:])
                added_lines = []
            elif line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])

        if current_file and added_lines:
            content = "\n".join(added_lines)
            result = self.review_file(current_file, content)
            issues.extend(result.issues)
            suggestions.extend(result.suggestions)

        score = max(0, 100 - len(issues) * 5)

        return ReviewResult(
            summary=f"Reviewed changes with {len(issues)} issues found",
            suggestions=suggestions,
            issues=issues,
            score=float(score),
        )

    def _check_complexity(self, file_path: Path, lines: list[str]) -> list[Finding]:
        issues: list[Finding] = []
        max_line_length = 120

        for i, line in enumerate(lines, start=1):
            if len(line) > max_line_length:
                issues.append(
                    Finding(
                        finding_type=FindingType.STYLE,
                        severity=Severity.LOW,
                        message=f"Line exceeds {max_line_length} characters ({len(line)})",
                        file_path=file_path,
                        line_number=i,
                        line_content=line[:120],
                        rule_id="STYLE001",
                        suggestion="Break long lines for better readability",
                    )
                )

        if len(lines) > 500:
            issues.append(
                Finding(
                    finding_type=FindingType.STYLE,
                    severity=Severity.MEDIUM,
                    message=f"File is very long ({len(lines)} lines) - consider splitting",
                    file_path=file_path,
                    line_number=1,
                    line_content="",
                    rule_id="STYLE002",
                    suggestion="Split large files into smaller, focused modules",
                )
            )

        return issues

    def _check_documentation(self, file_path: Path, lines: list[str]) -> list[Finding]:
        issues: list[Finding] = []

        if file_path.suffix == ".py" and lines:
            first_line = lines[0].strip()
            if (not first_line.startswith('"""') and not first_line.startswith("'''") and
                not first_line.startswith("#") and not first_line.startswith("from")):
                    issues.append(
                        Finding(
                            finding_type=FindingType.STYLE,
                            severity=Severity.LOW,
                            message="Missing module docstring",
                            file_path=file_path,
                            line_number=1,
                            line_content=first_line[:120],
                            rule_id="STYLE003",
                            suggestion="Add a module docstring explaining the purpose",
                        )
                    )

        return issues

    def _check_naming(self, file_path: Path, lines: list[str]) -> list[Finding]:
        issues: list[Finding] = []

        if file_path.suffix == ".py":
            import re
            for i, line in enumerate(lines, start=1):
                match = re.match(r"^(?:class|def)\s+(\w+)", line)
                if match:
                    name = match.group(1)
                    if name.startswith("_") and not name.startswith("__"):
                        continue
                    if name.isupper() and len(name) > 2:
                        continue
                    if (not re.match(r"^[A-Z][a-zA-Z0-9]*$", name) and
                        not re.match(r"^[a-z][a-z0-9_]*$", name) and
                        not name.startswith("__")):
                            issues.append(
                                Finding(
                                    finding_type=FindingType.STYLE,
                                    severity=Severity.INFO,
                                    message=f"Non-standard naming: {name}",
                                    file_path=file_path,
                                    line_number=i,
                                    line_content=line.strip()[:120],
                                    rule_id="STYLE004",
                                    suggestion="Use snake_case for functions/variables, PascalCase for classes",
                                )
                            )

        return issues

    def _check_structure(self, file_path: Path, lines: list[str]) -> list[Finding]:
        issues: list[Finding] = []

        if file_path.suffix == ".py":
            has_main = False
            for line in lines:
                if 'if __name__ == "__main__"' in line:
                    has_main = True
                    break

            if has_main and len(lines) > 50:
                issues.append(
                    Finding(
                        finding_type=FindingType.STYLE,
                        severity=Severity.LOW,
                        message="Large file with main block - consider CLI entry point",
                        file_path=file_path,
                        line_number=1,
                        line_content="",
                        rule_id="STYLE005",
                        suggestion="Use click or argparse for CLI entry points",
                    )
                )

        return issues

    def _generate_suggestions(
        self, file_path: Path, lines: list[str], issues: list[Finding]
    ) -> list[str]:
        suggestions: list[str] = []

        if file_path.suffix == ".py":
            imports = [line for line in lines if line.strip().startswith("import") or line.strip().startswith("from")]
            if len(imports) > 15:
                suggestions.append("Consider organizing imports using isort")

        if any(i.rule_id == "STYLE002" for i in issues):
            suggestions.append("Break large files into smaller, focused modules")

        if any(i.rule_id == "STYLE001" for i in issues):
            suggestions.append("Use a formatter like black or ruff format")

        return suggestions

    def _calculate_score(self, lines: list[str], issues: list[Finding]) -> float:
        if not lines:
            return 100.0

        base_score = 100.0
        for issue in issues:
            if issue.severity == Severity.CRITICAL:
                base_score -= 20
            elif issue.severity == Severity.HIGH:
                base_score -= 10
            elif issue.severity == Severity.MEDIUM:
                base_score -= 5
            elif issue.severity == Severity.LOW:
                base_score -= 2
            else:
                base_score -= 1

        return max(0.0, base_score)

    def _generate_summary(
        self, file_path: Path, lines: list[str], issues: list[Finding], score: float
    ) -> str:
        critical = sum(1 for i in issues if i.severity == Severity.CRITICAL)
        high = sum(1 for i in issues if i.severity == Severity.HIGH)
        medium = sum(1 for i in issues if i.severity == Severity.MEDIUM)
        low = sum(1 for i in issues if i.severity == Severity.LOW)

        parts = [f"Review of {file_path.name}: {len(lines)} lines, score {score:.0f}/100"]
        if critical:
            parts.append(f"{critical} critical issues")
        if high:
            parts.append(f"{high} high issues")
        if medium:
            parts.append(f"{medium} medium issues")
        if low:
            parts.append(f"{low} low issues")

        return ". ".join(parts) + "."
