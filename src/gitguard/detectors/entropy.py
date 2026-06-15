from __future__ import annotations

import math
import re
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0

    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)

    return entropy


def has_high_entropy(data: str, threshold: float = 4.5, min_length: int = 20) -> bool:
    if len(data) < min_length:
        return False

    cleaned = re.sub(r"[^a-zA-Z0-9]", "", data)
    if len(cleaned) < min_length:
        return False

    return calculate_entropy(cleaned) >= threshold


def is_likely_false_positive(line: str) -> bool:
    indicators = [
        "example", "placeholder", "test", "mock", "dummy",
        "fake", "sample", "template", "xxx", "yyy",
        "aaaa", "bbbb", "cccc", "1234",
    ]
    line_lower = line.lower()
    return any(ind in line_lower for ind in indicators)


def scan_for_entropy_secrets(file_path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    if file_path.suffix in (".md", ".txt", ".rst", ".json", ".yaml", ".yml", ".toml"):
        return findings

    if "test" in file_path.parts or "mock" in file_path.parts or "fixture" in file_path.parts:
        return findings

    secret_patterns = [
        (r'(?i)(?:key|secret|token|password|passwd|pwd)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']', "potential secret"),
        (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']', "potential API key"),
        (r'(?i)(?:access[_-]?key|secret[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']', "potential cloud credential"),
        (r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']', "potential encoded secret"),
    ]

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        if is_likely_false_positive(stripped):
            continue

        for pattern, description in secret_patterns:
            match = re.search(pattern, stripped)
            if match:
                value = match.group(1)
                if has_high_entropy(value, threshold=4.0, min_length=20):
                    findings.append(
                        Finding(
                            finding_type=FindingType.SECRET,
                            severity=Severity.HIGH,
                            message=f"High-entropy string detected ({description})",
                            file_path=file_path,
                            line_number=line_num,
                            line_content=stripped[:120],
                            rule_id="ENT001",
                            suggestion="Verify this is not a secret. Use environment variables for credentials.",
                            confidence=0.7,
                        )
                    )
                    break

    return findings


def calculate_string_entropy(data: str) -> float:
    return calculate_entropy(data)
