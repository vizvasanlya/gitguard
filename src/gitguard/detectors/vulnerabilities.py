from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class VulnerabilityPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    rule_id: str
    description: str
    languages: list[str]


VULNERABILITY_PATTERNS: list[VulnerabilityPattern] = [
    VulnerabilityPattern(
        name="SQL Injection",
        pattern=re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['\"]|['\"].*%s|['\"].*\+\s*\w)"""),
        severity=Severity.CRITICAL,
        rule_id="VUL001",
        description="Potential SQL injection vulnerability",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="SQL Injection Format String",
        pattern=re.compile(r"""(?:execute|query)\s*\(\s*['\"].*\{.*\}"""),
        severity=Severity.CRITICAL,
        rule_id="VUL002",
        description="SQL query using format string - potential injection",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="Command Injection os.system",
        pattern=re.compile(r"""os\.system\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL003",
        description="os.system() usage - potential command injection",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="Command Injection subprocess shell=True",
        pattern=re.compile(r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True"""),
        severity=Severity.HIGH,
        rule_id="VUL004",
        description="subprocess with shell=True - potential command injection",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="eval() Usage",
        pattern=re.compile(r"""(?<!\w)eval\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL005",
        description="eval() usage - potential code injection",
        languages=["python", "javascript", "typescript"],
    ),
    VulnerabilityPattern(
        name="exec() Usage",
        pattern=re.compile(r"""(?<!\w)exec\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL006",
        description="exec() usage - potential code injection",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="YAML Load Unsafe",
        pattern=re.compile(r"""yaml\.load\s*\((?!.*Loader\s*=)"""),
        severity=Severity.HIGH,
        rule_id="VUL007",
        description="yaml.load() without safe Loader - potential deserialization attack",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="Pickle Deserialization",
        pattern=re.compile(r"""pickle\.loads?\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL008",
        description="pickle deserialization - potential arbitrary code execution",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="Markdown XSS",
        pattern=re.compile(r"""(?:innerHTML|dangerouslySetInnerHTML|v-html)"""),
        severity=Severity.MEDIUM,
        rule_id="VUL009",
        description="Potential XSS via unsanitized HTML",
        languages=["javascript", "typescript", "jsx", "tsx"],
    ),
    VulnerabilityPattern(
        name="Hardcoded IP Address",
        pattern=re.compile(r"""(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"""),
        severity=Severity.LOW,
        rule_id="VUL010",
        description="Hardcoded IP address detected",
        languages=[],
    ),
    VulnerabilityPattern(
        name="Debug Mode Enabled",
        pattern=re.compile(r"""(?i)(?:debug\s*=\s*True|DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1)"""),
        severity=Severity.MEDIUM,
        rule_id="VUL011",
        description="Debug mode enabled in production code",
        languages=["python", "javascript"],
    ),
    VulnerabilityPattern(
        name="CORS Wildcard",
        pattern=re.compile(r"""(?:Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*|cors\s*\(\s*\))"""),
        severity=Severity.MEDIUM,
        rule_id="VUL012",
        description="CORS wildcard - allows any origin",
        languages=["javascript", "typescript"],
    ),
    VulnerabilityPattern(
        name="Insecure HTTP",
        pattern=re.compile(r"""(?:requests\.get|fetch|axios)\s*\(\s*['\"]http://"""),
        severity=Severity.LOW,
        rule_id="VUL013",
        description="HTTP request instead of HTTPS",
        languages=["python", "javascript", "typescript"],
    ),
    VulnerabilityPattern(
        name="Weak Hash MD5",
        pattern=re.compile(r"""(?:hashlib\.md5|crypto\.createHash\s*\(\s*['\"]md5['\"]|MD5\.New)"""),
        severity=Severity.MEDIUM,
        rule_id="VUL014",
        description="Weak hash algorithm (MD5) used for security purposes",
        languages=["python", "javascript"],
    ),
    VulnerabilityPattern(
        name="Weak Hash SHA1",
        pattern=re.compile(r"""(?:hashlib\.sha1|crypto\.createHash\s*\(\s*['\"]sha1['\"]|SHA\.New)"""),
        severity=Severity.LOW,
        rule_id="VUL015",
        description="Weak hash algorithm (SHA1) used",
        languages=["python", "javascript"],
    ),
    VulnerabilityPattern(
        name="Temp File Race Condition",
        pattern=re.compile(r"""(?:tempfile\.mktemp|mktemp\s*\()"""),
        severity=Severity.MEDIUM,
        rule_id="VUL016",
        description="tempfile.mktemp() is insecure - use tempfile.mkstemp() instead",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="Regex DoS (ReDoS)",
        pattern=re.compile(r"""re\.compile\s*\(\s*['\"].*(?:\.\*){2,}"""),
        severity=Severity.MEDIUM,
        rule_id="VUL017",
        description="Potentially vulnerable regex - multiple .* patterns may cause ReDoS",
        languages=["python"],
    ),
    VulnerabilityPattern(
        name="JavaScript eval",
        pattern=re.compile(r"""(?:eval|Function)\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL018",
        description="eval() or Function() usage - potential code injection",
        languages=["javascript", "typescript"],
    ),
    VulnerabilityPattern(
        name="NoSQL Injection",
        pattern=re.compile(r"""(?:\$\where|\$regex|\$gt|\$ne|\$lt)\s*:"""),
        severity=Severity.HIGH,
        rule_id="VUL019",
        description="Potential NoSQL injection via operator injection",
        languages=["javascript", "typescript"],
    ),
    VulnerabilityPattern(
        name="Prototype Pollution",
        pattern=re.compile(r"""(?:__proto__|constructor\[|prototype\[)"""),
        severity=Severity.HIGH,
        rule_id="VUL020",
        description="Potential prototype pollution vulnerability",
        languages=["javascript", "typescript"],
    ),
]


def scan_for_vulnerabilities(file_path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    suffix = file_path.suffix.lstrip(".")

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for vuln_pattern in VULNERABILITY_PATTERNS:
            if vuln_pattern.languages and suffix not in vuln_pattern.languages:
                continue

            match = vuln_pattern.pattern.search(stripped)
            if match:
                findings.append(
                    Finding(
                        finding_type=FindingType.VULNERABILITY,
                        severity=vuln_pattern.severity,
                        message=vuln_pattern.description,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=stripped[:120],
                        rule_id=vuln_pattern.rule_id,
                        suggestion=f"Review and fix: {vuln_pattern.name}",
                    )
                )

    return findings
