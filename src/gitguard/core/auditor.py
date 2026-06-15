from __future__ import annotations

import json
import re
from pathlib import Path

from gitguard.core.models import AuditResult, DependencyInfo, Finding, FindingType, Severity


class DependencyAuditor:
    """Audits project dependencies for known vulnerabilities."""

    KNOWN_VULNERABILITIES: dict[str, list[dict[str, str]]] = {
        "requests": [
            {"version": "<2.31.0", "cve": "CVE-2023-32681", "severity": "high"},
        ],
        "flask": [
            {"version": "<2.3.2", "cve": "CVE-2023-30861", "severity": "medium"},
        ],
        "django": [
            {"version": "<4.2.4", "cve": "CVE-2023-31047", "severity": "high"},
        ],
        "pillow": [
            {"version": "<10.0.0", "cve": "CVE-2023-35733", "severity": "high"},
        ],
        "cryptography": [
            {"version": "<41.0.2", "cve": "CVE-2023-38325", "severity": "high"},
        ],
        "aiohttp": [
            {"version": "<3.8.5", "cve": "CVE-2023-37276", "severity": "high"},
        ],
        "starlette": [
            {"version": "<0.27.0", "cve": "CVE-2023-29015", "severity": "medium"},
        ],
        "fastapi": [
            {"version": "<0.100.0", "cve": "CVE-2023-29703", "severity": "medium"},
        ],
        "werkzeug": [
            {"version": "<2.3.6", "cve": "CVE-2023-34000", "severity": "high"},
        ],
        "urllib3": [
            {"version": "<1.26.17", "cve": "CVE-2023-43804", "severity": "high"},
        ],
        "certifi": [
            {"version": "<2023.7.22", "cve": "CVE-2023-37920", "severity": "high"},
        ],
        "paramiko": [
            {"version": "<3.3.0", "cve": "CVE-2023-48795", "severity": "medium"},
        ],
        "pyopenssl": [
            {"version": "<23.2.0", "cve": "CVE-2023-40173", "severity": "medium"},
        ],
        "node-fetch": [
            {"version": "<2.6.7", "cve": "CVE-2022-0235", "severity": "high"},
        ],
        "express": [
            {"version": "<4.18.2", "cve": "CVE-2022-24999", "severity": "high"},
        ],
        "axios": [
            {"version": "<1.6.0", "cve": "CVE-2023-45857", "severity": "medium"},
        ],
        "jsonwebtoken": [
            {"version": "<9.0.0", "cve": "CVE-2022-23529", "severity": "high"},
        ],
    }

    def audit_project(self, project_path: Path) -> AuditResult:
        result = AuditResult()

        deps = self._parse_requirements(project_path)
        deps.extend(self._parse_package_json(project_path))
        deps.extend(self._parse_cargo_toml(project_path))
        deps.extend(self._parse_go_mod(project_path))

        result.dependencies = deps
        result.total_deps = len(deps)

        for dep in deps:
            vulns = self.KNOWN_VULNERABILITIES.get(dep.name.lower(), [])
            for vuln in vulns:
                dep.vulnerabilities.append(f"{vuln['cve']} ({vuln['severity']})")
                result.vulnerabilities.append(
                    Finding(
                        finding_type=FindingType.DEPENDENCY_VULN,
                        severity=Severity.HIGH if vuln["severity"] == "high" else Severity.MEDIUM,
                        message=f"{dep.name} {dep.version}: {vuln['cve']}",
                        file_path=project_path / "requirements.txt",
                        line_number=0,
                        line_content=f"{dep.name}=={dep.version}",
                        rule_id="DEP001",
                        suggestion=f"Update {dep.name} to a patched version",
                    )
                )

        result.vulnerable_deps = sum(1 for d in deps if d.is_vulnerable)
        return result

    def audit_requirements(self, requirements_path: Path) -> AuditResult:
        result = AuditResult()
        deps = self._parse_requirements_file(requirements_path)
        result.dependencies = deps
        result.total_deps = len(deps)

        for dep in deps:
            vulns = self.KNOWN_VULNERABILITIES.get(dep.name.lower(), [])
            for vuln in vulns:
                dep.vulnerabilities.append(f"{vuln['cve']} ({vuln['severity']})")
                result.vulnerabilities.append(
                    Finding(
                        finding_type=FindingType.DEPENDENCY_VULN,
                        severity=Severity.HIGH if vuln["severity"] == "high" else Severity.MEDIUM,
                        message=f"{dep.name} {dep.version}: {vuln['cve']}",
                        file_path=requirements_path,
                        line_number=0,
                        line_content=f"{dep.name}=={dep.version}",
                        rule_id="DEP001",
                        suggestion=f"Update {dep.name} to a patched version",
                    )
                )

        result.vulnerable_deps = sum(1 for d in deps if d.is_vulnerable)
        return result

    def _parse_requirements(self, project_path: Path) -> list[DependencyInfo]:
        deps: list[DependencyInfo] = []

        for req_file in ["requirements.txt", "requirements.in", "requirements-dev.txt"]:
            path = project_path / req_file
            if path.exists():
                deps.extend(self._parse_requirements_file(path))

        pyproject = project_path / "pyproject.toml"
        if pyproject.exists():
            deps.extend(self._parse_pyproject(pyproject))

        return deps

    def _parse_requirements_file(self, path: Path) -> list[DependencyInfo]:
        deps: list[DependencyInfo] = []
        try:
            content = path.read_text()
        except (OSError, PermissionError):
            return deps

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            match = re.match(r"([a-zA-Z0-9_-]+)\s*[=<>!~]+\s*([0-9.]+)", line)
            if match:
                deps.append(
                    DependencyInfo(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem="pypi",
                    )
                )
            elif re.match(r"[a-zA-Z0-9_-]+", line):
                deps.append(
                    DependencyInfo(
                        name=line.split("[")[0],
                        version="latest",
                        ecosystem="pypi",
                    )
                )

        return deps

    def _parse_pyproject(self, path: Path) -> list[DependencyInfo]:
        deps: list[DependencyInfo] = []
        try:
            content = path.read_text()
        except (OSError, PermissionError):
            return deps

        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "dependencies = [":
                in_deps = True
                continue
            if in_deps:
                if stripped == "]":
                    break
                match = re.match(r'"([a-zA-Z0-9_-]+)\s*[><=!~]+\s*([0-9.]+)"', stripped)
                if match:
                    deps.append(
                        DependencyInfo(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="pypi",
                        )
                    )

        return deps

    def _parse_package_json(self, project_path: Path) -> list[DependencyInfo]:
        deps: list[DependencyInfo] = []
        package_json = project_path / "package.json"
        if not package_json.exists():
            return deps

        try:
            data = json.loads(package_json.read_text())
        except (json.JSONDecodeError, OSError):
            return deps

        for section in ["dependencies", "devDependencies"]:
            for name, version in data.get(section, {}).items():
                version_str = str(version).lstrip("^~>=")
                deps.append(
                    DependencyInfo(
                        name=name,
                        version=version_str,
                        ecosystem="npm",
                        is_direct=section == "dependencies",
                    )
                )

        return deps

    def _parse_cargo_toml(self, project_path: Path) -> list[DependencyInfo]:
        deps: list[DependencyInfo] = []
        cargo_toml = project_path / "Cargo.toml"
        if not cargo_toml.exists():
            return deps

        try:
            content = cargo_toml.read_text()
        except (OSError, PermissionError):
            return deps

        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[dependencies]":
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("["):
                    break
                match = re.match(r'(\w+)\s*=\s*"([^"]+)"', stripped)
                if match:
                    deps.append(
                        DependencyInfo(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="cargo",
                        )
                    )

        return deps

    def _parse_go_mod(self, project_path: Path) -> list[DependencyInfo]:
        deps: list[DependencyInfo] = []
        go_mod = project_path / "go.mod"
        if not go_mod.exists():
            return deps

        try:
            content = go_mod.read_text()
        except (OSError, PermissionError):
            return deps

        in_require = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require:
                if stripped == ")":
                    break
                parts = stripped.split()
                if len(parts) >= 2:
                    deps.append(
                        DependencyInfo(
                            name=parts[0],
                            version=parts[1],
                            ecosystem="go",
                        )
                    )

        return deps
