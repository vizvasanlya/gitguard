from __future__ import annotations

import os
from pathlib import Path

from gitguard.core.models import Finding, ScanResult, Severity
from gitguard.detectors.patterns import scan_for_bad_patterns
from gitguard.detectors.secrets import scan_for_secrets
from gitguard.detectors.vulnerabilities import scan_for_vulnerabilities

IGNORED_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "vendor", ".next", ".nuxt", "target", "bin", "obj",
    ".eggs", "*.egg-info", "coverage", ".coverage",
}

IGNORED_EXTENSIONS = {
    ".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll",
    ".exe", ".o", ".a", ".lib", ".egg", ".whl",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".min.js", ".min.css",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".so", ".dylib", ".dll", ".exe", ".o", ".a",
}


class SecurityScanner:
    """Scans code for security issues, secrets, and vulnerabilities."""

    def __init__(
        self,
        path: str | Path,
        include_secrets: bool = True,
        include_vulnerabilities: bool = True,
        include_bad_patterns: bool = True,
        severity_threshold: Severity = Severity.LOW,
    ) -> None:
        self.path = Path(path).resolve()
        self.include_secrets = include_secrets
        self.include_vulnerabilities = include_vulnerabilities
        self.include_bad_patterns = include_bad_patterns
        self.severity_threshold = severity_threshold

    def scan(self) -> ScanResult:
        result = ScanResult()
        files = self._discover_files()

        for file_path in files:
            content = self._read_file(file_path)
            if content is None:
                continue

            result.files_scanned += 1
            result.lines_scanned += len(content.splitlines())

            findings = self._scan_file(file_path, content)
            result.findings.extend(findings)

        result.findings.sort(key=lambda f: self._severity_order(f.severity))
        return result

    def scan_diff(self, diff_content: str) -> ScanResult:
        result = ScanResult()
        current_file: Path | None = None
        current_lines: list[str] = []

        for line in diff_content.splitlines():
            if line.startswith("+++ b/"):
                if current_file and current_lines:
                    content = "\n".join(current_lines)
                    findings = self._scan_file(current_file, content)
                    result.findings.extend(findings)
                    result.files_scanned += 1
                    result.lines_scanned += len(current_lines)

                file_path = line[6:]
                current_file = Path(file_path)
                current_lines = []
            elif line.startswith("-"):
                continue
            elif line.startswith("+") and not line.startswith("+++"):
                current_lines.append(line[1:])
            elif not line.startswith("@@"):
                current_lines.append(line)

        if current_file and current_lines:
            content = "\n".join(current_lines)
            findings = self._scan_file(current_file, content)
            result.findings.extend(findings)
            result.files_scanned += 1
            result.lines_scanned += len(current_lines)

        result.findings.sort(key=lambda f: self._severity_order(f.severity))
        return result

    def _scan_file(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []

        if self.include_secrets:
            findings.extend(scan_for_secrets(file_path, content))

        if self.include_vulnerabilities:
            findings.extend(scan_for_vulnerabilities(file_path, content))

        if self.include_bad_patterns:
            findings.extend(scan_for_bad_patterns(file_path, content))

        severity_order = self._severity_order(self.severity_threshold)
        findings = [f for f in findings if self._severity_order(f.severity) <= severity_order]

        return findings

    def _discover_files(self) -> list[Path]:
        files: list[Path] = []
        for root, dirs, filenames in os.walk(self.path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for filename in filenames:
                if any(filename.endswith(ext) for ext in IGNORED_EXTENSIONS):
                    continue
                file_path = Path(root) / filename
                if file_path.suffix in BINARY_EXTENSIONS:
                    continue
                files.append(file_path)
        return files

    def _read_file(self, path: Path) -> str | None:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            if "\x00" in content:
                return None
            return content
        except (OSError, PermissionError):
            return None

    @staticmethod
    def _severity_order(severity: Severity) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order.get(severity, 4)
