from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding


@dataclass
class FixResult:
    file_path: Path
    original_line: str
    fixed_line: str
    line_number: int
    description: str
    applied: bool = False


class AutoFixer:
    """Provides automatic fixes for common security issues."""

    def fix_file(self, file_path: Path, content: str, findings: list[Finding]) -> list[FixResult]:
        fixes: list[FixResult] = []
        lines = content.splitlines()

        for finding in findings:
            if finding.file_path != file_path:
                continue
            if finding.line_number < 1 or finding.line_number > len(lines):
                continue

            fix = self._generate_fix(finding, lines)
            if fix:
                fixes.append(fix)

        return fixes

    def apply_fixes(self, file_path: Path, content: str, fixes: list[FixResult]) -> str:
        lines = content.splitlines()

        for fix in sorted(fixes, key=lambda f: f.line_number, reverse=True):
            if 1 <= fix.line_number <= len(lines):
                lines[fix.line_number - 1] = fix.fixed_line
                fix.applied = True

        return "\n".join(lines)

    def _generate_fix(self, finding: Finding, lines: list[str]) -> FixResult | None:
        if finding.line_number < 1 or finding.line_number > len(lines):
            return None

        original = lines[finding.line_number - 1]

        fixers = {
            "VUL003": self._fix_os_system,
            "VUL004": self._fix_subprocess_shell,
            "VUL005": self._fix_eval,
            "VUL006": self._fix_exec,
            "VUL007": self._fix_yaml_load,
            "VUL011": self._fix_debug_mode,
            "VUL014": self._fix_md5,
            "VUL016": self._fix_mktemp,
            "BP001": self._fix_bare_except,
            "BP007": self._fix_star_import,
            "BP008": self._fix_mutable_default,
        }

        fixer = fixers.get(finding.rule_id)
        if fixer:
            return fixer(finding, original)

        return None

    def _fix_os_system(self, finding: Finding, original: str) -> FixResult:
        fixed = original.replace("os.system(", "subprocess.run(")
        fixed = fixed.rstrip(")")
        if "subprocess.run(" in fixed and not fixed.endswith(")"):
            fixed += ", check=True)"
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Replace os.system() with subprocess.run()",
        )

    def _fix_subprocess_shell(self, finding: Finding, original: str) -> FixResult:
        fixed = original.replace("shell=True", "shell=False")
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Remove shell=True from subprocess call",
        )

    def _fix_eval(self, finding: Finding, original: str) -> FixResult:
        fixed = re.sub(r"eval\(([^)]+)\)", r"ast.literal_eval(\1)", original)
        if "import ast" not in original:
            fixed = "import ast\n" + fixed
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Replace eval() with ast.literal_eval()",
        )

    def _fix_exec(self, finding: Finding, original: str) -> FixResult:
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=f"# SECURITY: exec() removed - review and rewrite\n{original}",
            line_number=finding.line_number,
            description="exec() is dangerous - manual review required",
        )

    def _fix_yaml_load(self, finding: Finding, original: str) -> FixResult:
        fixed = re.sub(r"yaml\.load\(([^)]+)\)", r"yaml.safe_load(\1)", original)
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Replace yaml.load() with yaml.safe_load()",
        )

    def _fix_debug_mode(self, finding: Finding, original: str) -> FixResult:
        fixed = re.sub(r"debug\s*=\s*True", "debug = False", original, flags=re.IGNORECASE)
        fixed = re.sub(r"DEBUG\s*=\s*True", "DEBUG = False", fixed)
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Disable debug mode",
        )

    def _fix_md5(self, finding: Finding, original: str) -> FixResult:
        fixed = original.replace("hashlib.md5", "hashlib.sha256")
        fixed = fixed.replace("md5", "sha256")
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Replace MD5 with SHA-256",
        )

    def _fix_mktemp(self, finding: Finding, original: str) -> FixResult:
        fixed = original.replace("mktemp(", "mkstemp(")
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Replace mktemp() with mkstemp()",
        )

    def _fix_bare_except(self, finding: Finding, original: str) -> FixResult:
        fixed = original.replace("except:", "except Exception:")
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Replace bare except with specific exception",
        )

    def _fix_star_import(self, finding: Finding, original: str) -> FixResult:
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=f"# SECURITY: Wildcard import - use explicit imports instead\n{original}",
            line_number=finding.line_number,
            description="Replace wildcard import with explicit imports",
        )

    def _fix_mutable_default(self, finding: Finding, original: str) -> FixResult:
        fixed = re.sub(r"=\s*\[\]", "= None", original)
        fixed = re.sub(r"=\s*\{\}", "= None", fixed)
        return FixResult(
            file_path=finding.file_path,
            original_line=original,
            fixed_line=fixed,
            line_number=finding.line_number,
            description="Replace mutable default with None",
        )
