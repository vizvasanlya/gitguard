from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class VerifiedResult:
    finding: Finding
    is_verified: bool
    confidence: float
    test_method: str
    details: str


class VerifiedScanner:
    """Verifies if detected secrets are actually valid."""

    def __init__(self) -> None:
        self._cache: dict[str, VerifiedResult] = {}

    def verify(self, finding: Finding) -> VerifiedResult:
        cache_key = f"{finding.rule_id}:{finding.line_content[:50]}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = self._verify_secret(finding)
        self._cache[cache_key] = result
        return result

    def verify_batch(self, findings: list[Finding]) -> list[VerifiedResult]:
        return [self.verify(f) for f in findings]

    def _verify_secret(self, finding: Finding) -> VerifiedResult:
        rule_id = finding.rule_id
        content = finding.line_content

        if rule_id.startswith("SEC001"):
            return self._verify_aws_key(content)
        elif rule_id.startswith("SEC003"):
            return self._verify_github_token(content)
        elif rule_id.startswith("SEC012"):
            return self._verify_private_key(content)
        elif rule_id.startswith("SEC018"):
            return self._verify_jwt(content)
        elif rule_id.startswith("VUL"):
            return self._verify_vulnerability(finding)
        else:
            return VerifiedResult(
                finding=finding,
                is_verified=False,
                confidence=0.5,
                test_method="pattern_match",
                details="Pattern matched but not verified",
            )

    def _verify_aws_key(self, content: str) -> VerifiedResult:
        match = re.search(r"AKIA[0-9A-Z]{16}", content)
        if not match:
            return VerifiedResult(
                finding=Finding(
                    finding_type=FindingType.SECRET,
                    severity=Severity.HIGH,
                    message="Invalid AWS key format",
                    file_path=Path(""),
                    line_number=0,
                    line_content=content[:120],
                    rule_id="SEC001",
                ),
                is_verified=False,
                confidence=0.9,
                test_method="format_check",
                details="Key matches AKIA pattern but format may be invalid",
            )

        key = match.group(0)
        is_valid_format = len(key) == 20 and key.startswith("AKIA")

        return VerifiedResult(
            finding=Finding(
                finding_type=FindingType.SECRET,
                severity=Severity.CRITICAL if is_valid_format else Severity.HIGH,
                message="AWS Access Key detected",
                file_path=Path(""),
                line_number=0,
                line_content=content[:120],
                rule_id="SEC001",
            ),
            is_verified=is_valid_format,
            confidence=0.95 if is_valid_format else 0.7,
            test_method="format_validation",
            details=f"Key format {'valid' if is_valid_format else 'invalid'}: {key[:8]}...",
        )

    def _verify_github_token(self, content: str) -> VerifiedResult:
        match = re.search(r"ghp_[A-Za-z0-9]{36}", content)
        if not match:
            return VerifiedResult(
                finding=Finding(
                    finding_type=FindingType.SECRET,
                    severity=Severity.HIGH,
                    message="Invalid GitHub token format",
                    file_path=Path(""),
                    line_number=0,
                    line_content=content[:120],
                    rule_id="SEC003",
                ),
                is_verified=False,
                confidence=0.9,
                test_method="format_check",
                details="Token matches ghp_ pattern but format may be invalid",
            )

        token = match.group(0)
        is_valid_format = len(token) == 40 and token.startswith("ghp_")

        return VerifiedResult(
            finding=Finding(
                finding_type=FindingType.SECRET,
                severity=Severity.CRITICAL if is_valid_format else Severity.HIGH,
                message="GitHub Personal Access Token detected",
                file_path=Path(""),
                line_number=0,
                line_content=content[:120],
                rule_id="SEC003",
            ),
            is_verified=is_valid_format,
            confidence=0.95 if is_valid_format else 0.7,
            test_method="format_validation",
            details=f"Token format {'valid' if is_valid_format else 'invalid'}",
        )

    def _verify_private_key(self, content: str) -> VerifiedResult:
        has_begin = "-----BEGIN" in content
        has_end = "-----END" in content or "PRIVATE KEY" in content

        return VerifiedResult(
            finding=Finding(
                finding_type=FindingType.SECRET,
                severity=Severity.CRITICAL,
                message="Private key detected",
                file_path=Path(""),
                line_number=0,
                line_content=content[:120],
                rule_id="SEC012",
            ),
            is_verified=has_begin,
            confidence=0.99 if has_begin else 0.5,
            test_method="format_validation",
            details=f"Key block {'complete' if has_begin and has_end else 'incomplete'}",
        )

    def _verify_jwt(self, content: str) -> VerifiedResult:
        import base64
        import json

        match = re.search(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+", content)
        if not match:
            return VerifiedResult(
                finding=Finding(
                    finding_type=FindingType.SECRET,
                    severity=Severity.HIGH,
                    message="Invalid JWT format",
                    file_path=Path(""),
                    line_number=0,
                    line_content=content[:120],
                    rule_id="SEC018",
                ),
                is_verified=False,
                confidence=0.9,
                test_method="format_check",
                details="Token matches JWT pattern but format may be invalid",
            )

        token = match.group(0)
        parts = token.split(".")
        if len(parts) != 3:
            return VerifiedResult(
                finding=Finding(
                    finding_type=FindingType.SECRET,
                    severity=Severity.HIGH,
                    message="Invalid JWT structure",
                    file_path=Path(""),
                    line_number=0,
                    line_content=content[:120],
                    rule_id="SEC018",
                ),
                is_verified=False,
                confidence=0.8,
                test_method="structure_check",
                details="JWT has wrong number of parts",
            )

        try:
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            has_exp = "exp" in payload
            has_iat = "iat" in payload

            confidence = 0.9
            details = f"Header: {header.get('alg', 'unknown')}, "
            details += f"Has expiry: {has_exp}, "
            details += f"Issued: {has_iat}, "
            details += f"Issuer: {payload.get('iss', 'unknown')}"

            return VerifiedResult(
                finding=Finding(
                    finding_type=FindingType.SECRET,
                    severity=Severity.CRITICAL,
                    message="Valid JWT token detected",
                    file_path=Path(""),
                    line_number=0,
                    line_content=content[:120],
                    rule_id="SEC018",
                ),
                is_verified=True,
                confidence=confidence,
                test_method="jwt_decode",
                details=details,
            )

        except Exception:
            return VerifiedResult(
                finding=Finding(
                    finding_type=FindingType.SECRET,
                    severity=Severity.HIGH,
                    message="JWT token detected (invalid payload)",
                    file_path=Path(""),
                    line_number=0,
                    line_content=content[:120],
                    rule_id="SEC018",
                ),
                is_verified=False,
                confidence=0.7,
                test_method="jwt_decode",
                details="Could not decode JWT payload",
            )

    def _verify_vulnerability(self, finding: Finding) -> VerifiedResult:
        return VerifiedResult(
            finding=finding,
            is_verified=True,
            confidence=0.8,
            test_method="pattern_match",
            details="Vulnerability pattern matched",
        )
