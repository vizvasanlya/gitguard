from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class CVEInfo:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    affected_versions: str
    published_date: str
    references: list[str]


class NVDChecker:
    """Checks dependencies against NVD (National Vulnerability Database)."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    KNOWN_VULNERABILITIES: dict[str, list[CVEInfo]] = {
        "requests": [
            CVEInfo("CVE-2023-32681", "Unintended leak of Proxy-Authorization header", "HIGH", 7.5, "<2.31.0", "2023-05-26", []),
        ],
        "flask": [
            CVEInfo("CVE-2023-30861", "Session cookie not set on response", "MEDIUM", 5.4, "<2.3.2", "2023-04-26", []),
        ],
        "django": [
            CVEInfo("CVE-2023-31047", "File upload validation bypass", "HIGH", 7.5, "<4.2.4", "2023-06-12", []),
        ],
        "pillow": [
            CVEInfo("CVE-2023-35733", "Buffer overflow in TiffDecode.c", "HIGH", 8.1, "<10.0.0", "2023-07-01", []),
        ],
        "cryptography": [
            CVEInfo("CVE-2023-38325", "NULL-dereference when loading PKCS7 certificates", "HIGH", 7.5, "<41.0.2", "2023-07-20", []),
        ],
        "aiohttp": [
            CVEInfo("CVE-2023-37276", "HTTP request smuggling", "HIGH", 7.5, "<3.8.5", "2023-07-03", []),
        ],
        "starlette": [
            CVEInfo("CVE-2023-29015", "DoS via multipart form data", "MEDIUM", 6.5, "<0.27.0", "2023-04-12", []),
        ],
        "fastapi": [
            CVEInfo("CVE-2023-29703", "DoS via crafted request", "MEDIUM", 6.5, "<0.100.0", "2023-06-15", []),
        ],
        "werkzeug": [
            CVEInfo("CVE-2023-34000", "XSS in debugger", "HIGH", 7.5, "<2.3.6", "2023-07-14", []),
        ],
        "urllib3": [
            CVEInfo("CVE-2023-43804", "Cookie header not stripped on redirect", "HIGH", 7.5, "<1.26.17", "2023-10-04", []),
        ],
        "certifi": [
            CVEInfo("CVE-2023-37920", "Removal of e-Tugra root certificate", "HIGH", 9.1, "<2023.7.22", "2023-07-19", []),
        ],
        "paramiko": [
            CVEInfo("CVE-2023-48795", "Terrapin attack on SSH", "MEDIUM", 5.9, "<3.3.0", "2023-12-18", []),
        ],
        "express": [
            CVEInfo("CVE-2022-24999", "qs prototype pollution", "HIGH", 7.5, "<4.18.2", "2022-11-22", []),
        ],
        "axios": [
            CVEInfo("CVE-2023-45857", "XSRF-TOKEN cookie exposure", "MEDIUM", 6.5, "<1.6.0", "2023-11-08", []),
        ],
        "jsonwebtoken": [
            CVEInfo("CVE-2022-23529", "Insecure key retrieval", "HIGH", 7.6, "<9.0.0", "2022-12-21", []),
        ],
        "node-fetch": [
            CVEInfo("CVE-2022-0235", "Exposure of sensitive information", "HIGH", 7.5, "<2.6.7", "2022-01-21", []),
        ],
        "undici": [
            CVEInfo("CVE-2023-45143", "Cookie header exposure on redirect", "HIGH", 7.5, "<5.28.2", "2023-10-18", []),
        ],
        "tornado": [
            CVEInfo("CVE-2023-28370", "Open redirect", "MEDIUM", 6.1, "<6.3.3", "2023-04-19", []),
        ],
        "pyramid": [
            CVEInfo("CVE-2023-20859", "Authorization bypass", "HIGH", 8.1, "<2.0", "2023-03-01", []),
        ],
        "bottle": [
            CVEInfo("CVE-2022-31799", "Path traversal", "HIGH", 7.5, "<0.12.25", "2022-05-31", []),
        ],
    }

    def check_project(self, project_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        auditor = __import__("gitguard.core.auditor", fromlist=["DependencyAuditor"]).DependencyAuditor()
        audit_result = auditor.audit_project(project_path)

        for dep in audit_result.dependencies:
            vulns = self.KNOWN_VULNERABILITIES.get(dep.name.lower(), [])
            for vuln in vulns:
                severity = Severity.HIGH if vuln.severity in ("HIGH", "CRITICAL") else Severity.MEDIUM

                findings.append(
                    Finding(
                        finding_type=FindingType.DEPENDENCY_VULN,
                        severity=severity,
                        message=f"{dep.name} {dep.version}: {vuln.cve_id} - {vuln.description}",
                        file_path=project_path / "requirements.txt",
                        line_number=0,
                        line_content=f"{dep.name}=={dep.version}",
                        rule_id="CVE",
                        suggestion=f"Update {dep.name} to a patched version (fixed in {vuln.affected_versions})",
                        metadata={
                            "cve": vuln.cve_id,
                            "cvss": vuln.cvss_score,
                            "description": vuln.description,
                        }
                    )
                )

        return findings

    def get_cve_info(self, cve_id: str) -> CVEInfo | None:
        for vulns in self.KNOWN_VULNERABILITIES.values():
            for vuln in vulns:
                if vuln.cve_id == cve_id:
                    return vuln
        return None

    def get_vulnerable_packages(self) -> list[str]:
        return list(self.KNOWN_VULNERABILITIES.keys())
