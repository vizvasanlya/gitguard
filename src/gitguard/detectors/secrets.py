from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity = Severity.CRITICAL
    rule_id: str = ""
    description: str = ""


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        rule_id="SEC001",
        description="AWS Access Key ID detected",
    ),
    SecretPattern(
        name="AWS Secret Key",
        pattern=re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
        rule_id="SEC002",
        description="AWS Secret Access Key detected",
    ),
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"),
        rule_id="SEC003",
        description="GitHub Personal Access Token detected",
    ),
    SecretPattern(
        name="GitHub OAuth",
        pattern=re.compile(r"gho_[A-Za-z0-9]{36}"),
        rule_id="SEC004",
        description="GitHub OAuth Token detected",
    ),
    SecretPattern(
        name="GitLab Token",
        pattern=re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        rule_id="SEC005",
        description="GitLab Personal Access Token detected",
    ),
    SecretPattern(
        name="Slack Token",
        pattern=re.compile(r"xox[bpsar]-[0-9]{10,}-[A-Za-z0-9\-]+"),
        rule_id="SEC006",
        description="Slack Token detected",
    ),
    SecretPattern(
        name="Slack Webhook",
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        rule_id="SEC007",
        description="Slack Webhook URL detected",
    ),
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        rule_id="SEC008",
        description="Google API Key detected",
    ),
    SecretPattern(
        name="Google OAuth",
        pattern=re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
        rule_id="SEC009",
        description="Google OAuth Client ID detected",
    ),
    SecretPattern(
        name="Stripe Key",
        pattern=re.compile(r"[sr]k_(live|test)_[0-9a-zA-Z]{24,}"),
        rule_id="SEC010",
        description="Stripe API Key detected",
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        pattern=re.compile(r"pk_(live|test)_[0-9a-zA-Z]{24,}"),
        rule_id="SEC011",
        description="Stripe Publishable Key detected",
    ),
    SecretPattern(
        name="Private Key Block",
        pattern=re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        rule_id="SEC012",
        description="Private key detected",
    ),
    SecretPattern(
        name="SSH Private Key",
        pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        rule_id="SEC013",
        description="SSH private key detected",
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        severity=Severity.CRITICAL,
        rule_id="SEC014",
        description="PGP private key detected",
    ),
    SecretPattern(
        name="Generic API Key",
        pattern=re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?"),
        severity=Severity.HIGH,
        rule_id="SEC015",
        description="Potential API key detected",
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=re.compile(r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?"),
        severity=Severity.HIGH,
        rule_id="SEC016",
        description="Potential secret or password detected",
    ),
    SecretPattern(
        name="Connection String",
        pattern=re.compile(r"(?i)(mongodb|mysql|postgres|redis|amqp)://[^\s]+"),
        severity=Severity.HIGH,
        rule_id="SEC017",
        description="Database connection string detected",
    ),
    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+"),
        severity=Severity.HIGH,
        rule_id="SEC018",
        description="JWT token detected",
    ),
    SecretPattern(
        name="Bearer Token",
        pattern=re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]+"),
        severity=Severity.HIGH,
        rule_id="SEC019",
        description="Bearer token detected",
    ),
    SecretPattern(
        name="Base64 Encoded Secret",
        pattern=re.compile(r"(?i)(secret|password|key|token)\s*[=:]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?"),
        severity=Severity.MEDIUM,
        rule_id="SEC020",
        description="Potential base64-encoded secret detected",
    ),
]


def scan_for_secrets(file_path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if "example" in stripped.lower() or "placeholder" in stripped.lower():
            continue
        if "test" in file_path.parts or "mock" in file_path.parts:
            continue
        if file_path.suffix in (".md", ".txt", ".rst"):
            continue

        for secret_pattern in SECRET_PATTERNS:
            match = secret_pattern.pattern.search(stripped)
            if match:
                findings.append(
                    Finding(
                        finding_type=FindingType.SECRET,
                        severity=secret_pattern.severity,
                        message=secret_pattern.description,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=stripped[:120],
                        rule_id=secret_pattern.rule_id,
                        suggestion=f"Remove or rotate the {secret_pattern.name}. Use environment variables instead.",
                    )
                )

    return findings
