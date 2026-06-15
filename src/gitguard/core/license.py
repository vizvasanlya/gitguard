from __future__ import annotations

import re
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity

LICENSE_PATTERNS: dict[str, re.Pattern[str]] = {
    "MIT": re.compile(r"MIT License|Permission is hereby granted, free of charge"),
    "Apache-2.0": re.compile(r"Apache License|Licensed under the Apache License"),
    "GPL-2.0": re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version 2"),
    "GPL-3.0": re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version 3"),
    "LGPL-2.1": re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1"),
    "LGPL-3.0": re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 3"),
    "BSD-2-Clause": re.compile(r"BSD 2-Clause|Redistribution and use in source and binary forms"),
    "BSD-3-Clause": re.compile(r"BSD 3-Clause|Neither the name of the copyright holder"),
    "MPL-2.0": re.compile(r"Mozilla Public License.*Version 2\.0"),
    "ISC": re.compile(r"ISC License|ISC license"),
    "Unlicense": re.compile(r"This is free and unencumbered software released into the public domain"),
    "AGPL-3.0": re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE.*Version 3"),
}

RESTRICTIVE_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0"}
PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"}

LICENSE_FILE_NAMES = [
    "LICENSE", "LICENSE.txt", "LICENSE.md", "LICENSE.rst",
    "COPYING", "COPYING.txt", "COPYING.md",
]


class LicenseChecker:
    """Checks project licenses for compliance issues."""

    def __init__(self, allowed_licenses: list[str] | None = None) -> None:
        self.allowed_licenses = allowed_licenses or list(PERMISSIVE_LICENSES)

    def check_project(self, project_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        project_license = self._detect_project_license(project_path)
        if project_license:
            if project_license not in self.allowed_licenses:
                findings.append(
                    Finding(
                        finding_type=FindingType.LICENSE_ISSUE,
                        severity=Severity.HIGH,
                        message=f"Project uses {project_license} license - not in allowed list",
                        file_path=project_path,
                        line_number=0,
                        line_content="",
                        rule_id="LIC001",
                        suggestion=f"Consider using a permissive license: {', '.join(PERMISSIVE_LICENSES)}",
                    )
                )
        else:
            findings.append(
                Finding(
                    finding_type=FindingType.LICENSE_ISSUE,
                    severity=Severity.MEDIUM,
                    message="No license file found",
                    file_path=project_path,
                    line_number=0,
                    line_content="",
                    rule_id="LIC002",
                    suggestion="Add a LICENSE file to your project",
                )
            )

        findings.extend(self._check_dependency_licenses(project_path))

        return findings

    def check_file(self, file_path: Path) -> str | None:
        return self._detect_license_in_file(file_path)

    def _detect_project_license(self, project_path: Path) -> str | None:
        for license_name in LICENSE_FILE_NAMES:
            for ext in ["", ".txt", ".md", ".rst"]:
                path = project_path / (license_name + ext)
                if path.exists():
                    detected = self._detect_license_in_file(path)
                    if detected:
                        return detected

        pyproject = project_path / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text()
                match = re.search(r'license\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    return self._normalize_license(match.group(1))
            except (OSError, PermissionError):
                pass

        return None

    def _detect_license_in_file(self, file_path: Path) -> str | None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return None

        return self._detect_license_in_text(content)

    def _detect_license_in_text(self, text: str) -> str | None:
        for license_name, pattern in LICENSE_PATTERNS.items():
            if pattern.search(text):
                return license_name
        return None

    def _normalize_license(self, license_str: str) -> str:
        normalized = license_str.strip().upper()
        normalized = normalized.replace(" ", "-")
        normalized = normalized.replace("LICENSE", "").strip("-")
        for known in LICENSE_PATTERNS:
            if known.upper() in normalized or normalized in known.upper():
                return known
        return license_str

    def _check_dependency_licenses(self, project_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        node_modules = project_path / "node_modules"
        if node_modules.exists():
            for pkg_dir in node_modules.iterdir():
                if not pkg_dir.is_dir() or pkg_dir.name.startswith("."):
                    continue
                pkg_json = pkg_dir / "package.json"
                if pkg_json.exists():
                    try:
                        data = __import__("json").loads(pkg_json.read_text())
                        lic = data.get("license", "")
                        if isinstance(lic, dict):
                            lic = lic.get("type", "")
                        if lic and self._normalize_license(str(lic)) not in self.allowed_licenses:
                            findings.append(
                                Finding(
                                    finding_type=FindingType.LICENSE_ISSUE,
                                    severity=Severity.MEDIUM,
                                    message=f"Dependency {pkg_dir.name} uses {lic} license",
                                    file_path=pkg_json,
                                    line_number=0,
                                    line_content="",
                                    rule_id="LIC003",
                                    suggestion=f"Review {lic} license compatibility",
                                )
                            )
                    except (KeyError, ValueError, OSError):
                        pass

        return findings
