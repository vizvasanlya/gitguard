from __future__ import annotations

import subprocess
from pathlib import Path

from gitguard.core.models import Finding, ScanResult, Severity
from gitguard.detectors.secrets import scan_for_secrets


class HistoryScanner:
    """Scans git commit history for leaked secrets."""

    def __init__(self, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path).resolve()

    def scan_history(
        self,
        max_commits: int = 1000,
        include_merge: bool = False,
    ) -> ScanResult:
        result = ScanResult()
        commits = self._get_commits(max_commits, include_merge)

        for commit_hash, commit_msg in commits:
            diff = self._get_commit_diff(commit_hash)
            if not diff:
                continue

            findings = self._scan_diff(commit_hash, commit_msg, diff)
            result.findings.extend(findings)
            result.files_scanned += 1

        result.findings.sort(key=lambda f: self._severity_order(f.severity))
        return result

    def scan_ref(self, ref: str = "HEAD") -> ScanResult:
        result = ScanResult()
        diff = self._get_ref_diff(ref)
        if diff:
            findings = self._scan_diff(ref, f"Scanning {ref}", diff)
            result.findings.extend(findings)
            result.files_scanned += 1
        return result

    def _get_commits(self, max_commits: int, include_merge: bool) -> list[tuple[str, str]]:
        try:
            cmd = ["git", "log", f"--max-count={max_commits}", "--pretty=format:%H|||%s"]
            if not include_merge:
                cmd.append("--no-merges")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=60,
            )

            if result.returncode != 0:
                return []

            commits = []
            for line in result.stdout.strip().splitlines():
                if "|||" in line:
                    hash_val, msg = line.split("|||", 1)
                    commits.append((hash_val.strip(), msg.strip()))

            return commits

        except (subprocess.SubprocessError, FileNotFoundError):
            return []

    def _get_commit_diff(self, commit_hash: str) -> str:
        try:
            result = subprocess.run(
                ["git", "show", "--pretty=format:", "--stat", "--patch", commit_hash],
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=30,
            )
            return result.stdout if result.returncode == 0 else ""
        except (subprocess.SubprocessError, FileNotFoundError):
            return ""

    def _get_ref_diff(self, ref: str) -> str:
        try:
            result = subprocess.run(
                ["git", "diff", f"{ref}~1..{ref}", "--pretty=format:", "--patch"],
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=30,
            )
            return result.stdout if result.returncode == 0 else ""
        except (subprocess.SubprocessError, FileNotFoundError):
            return ""

    def _scan_diff(self, commit_hash: str, commit_msg: str, diff: str) -> list[Finding]:
        findings: list[Finding] = []
        current_file: Path | None = None
        added_lines: list[str] = []

        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                if current_file and added_lines:
                    content = "\n".join(added_lines)
                    file_findings = scan_for_secrets(current_file, content)
                    for f in file_findings:
                        f.metadata["commit"] = commit_hash[:8]
                        f.metadata["commit_message"] = commit_msg[:100]
                    findings.extend(file_findings)
                current_file = Path(line[6:])
                added_lines = []
            elif line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])
            elif line.startswith("-"):
                continue

        if current_file and added_lines:
            content = "\n".join(added_lines)
            file_findings = scan_for_secrets(current_file, content)
            for f in file_findings:
                f.metadata["commit"] = commit_hash[:8]
                f.metadata["commit_message"] = commit_msg[:100]
            findings.extend(file_findings)

        return findings

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
