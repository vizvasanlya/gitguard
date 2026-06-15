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
        name="SQL Injection Python",
        pattern=re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['\"]|['\"].*%s|['\"].*\+\s*\w)"""),
        severity=Severity.CRITICAL,
        rule_id="VUL001",
        description="Potential SQL injection vulnerability",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="SQL Injection Format String",
        pattern=re.compile(r"""(?:execute|query)\s*\(\s*['\"].*\{.*\}"""),
        severity=Severity.CRITICAL,
        rule_id="VUL002",
        description="SQL query using format string - potential injection",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="Command Injection os.system",
        pattern=re.compile(r"""os\.system\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL003",
        description="os.system() usage - potential command injection",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="Command Injection subprocess shell=True",
        pattern=re.compile(r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True"""),
        severity=Severity.HIGH,
        rule_id="VUL004",
        description="subprocess with shell=True - potential command injection",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="eval() Usage Python",
        pattern=re.compile(r"""(?<!\w)eval\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL005",
        description="eval() usage - potential code injection",
        languages=["py", "js", "ts"],
    ),
    VulnerabilityPattern(
        name="exec() Usage Python",
        pattern=re.compile(r"""(?<!\w)exec\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL006",
        description="exec() usage - potential code injection",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="YAML Load Unsafe",
        pattern=re.compile(r"""yaml\.load\s*\((?!.*Loader\s*=)"""),
        severity=Severity.HIGH,
        rule_id="VUL007",
        description="yaml.load() without safe Loader - potential deserialization attack",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="Pickle Deserialization",
        pattern=re.compile(r"""pickle\.loads?\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL008",
        description="pickle deserialization - potential arbitrary code execution",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="Markdown XSS",
        pattern=re.compile(r"""(?:innerHTML|dangerouslySetInnerHTML|v-html)"""),
        severity=Severity.MEDIUM,
        rule_id="VUL009",
        description="Potential XSS via unsanitized HTML",
        languages=["js", "ts", "jsx", "tsx", "vue"],
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
        languages=["py", "js", "ts"],
    ),
    VulnerabilityPattern(
        name="CORS Wildcard",
        pattern=re.compile(r"""(?:Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*|cors\s*\(\s*\))"""),
        severity=Severity.MEDIUM,
        rule_id="VUL012",
        description="CORS wildcard - allows any origin",
        languages=["js", "ts"],
    ),
    VulnerabilityPattern(
        name="Insecure HTTP",
        pattern=re.compile(r"""(?:requests\.get|fetch|axios)\s*\(\s*['\"]http://"""),
        severity=Severity.LOW,
        rule_id="VUL013",
        description="HTTP request instead of HTTPS",
        languages=["py", "js", "ts"],
    ),
    VulnerabilityPattern(
        name="Weak Hash MD5",
        pattern=re.compile(r"""(?:hashlib\.md5|crypto\.createHash\s*\(\s*['\"]md5['\"]|MD5\.New)"""),
        severity=Severity.MEDIUM,
        rule_id="VUL014",
        description="Weak hash algorithm (MD5) used for security purposes",
        languages=["py", "js", "ts"],
    ),
    VulnerabilityPattern(
        name="Weak Hash SHA1",
        pattern=re.compile(r"""(?:hashlib\.sha1|crypto\.createHash\s*\(\s*['\"]sha1['\"]|SHA\.New)"""),
        severity=Severity.LOW,
        rule_id="VUL015",
        description="Weak hash algorithm (SHA1) used",
        languages=["py", "js", "ts"],
    ),
    VulnerabilityPattern(
        name="Temp File Race Condition",
        pattern=re.compile(r"""(?:tempfile\.mktemp|mktemp\s*\()"""),
        severity=Severity.MEDIUM,
        rule_id="VUL016",
        description="tempfile.mktemp() is insecure - use tempfile.mkstemp() instead",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="Regex DoS (ReDoS)",
        pattern=re.compile(r"""re\.compile\s*\(\s*['\"].*(?:\.\*){2,}"""),
        severity=Severity.MEDIUM,
        rule_id="VUL017",
        description="Potentially vulnerable regex - multiple .* patterns may cause ReDoS",
        languages=["py"],
    ),
    VulnerabilityPattern(
        name="JavaScript eval",
        pattern=re.compile(r"""(?:eval|Function)\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL018",
        description="eval() or Function() usage - potential code injection",
        languages=["js", "ts"],
    ),
    VulnerabilityPattern(
        name="NoSQL Injection",
        pattern=re.compile(r"""(?:\$\where|\$regex|\$gt|\$ne|\$lt)\s*:"""),
        severity=Severity.HIGH,
        rule_id="VUL019",
        description="Potential NoSQL injection via operator injection",
        languages=["js", "ts"],
    ),
    VulnerabilityPattern(
        name="Prototype Pollution",
        pattern=re.compile(r"""(?:__proto__|constructor\[|prototype\[)"""),
        severity=Severity.HIGH,
        rule_id="VUL020",
        description="Potential prototype pollution vulnerability",
        languages=["js", "ts"],
    ),
    # Go vulnerabilities
    VulnerabilityPattern(
        name="Go Command Injection exec.Command",
        pattern=re.compile(r"""exec\.Command\s*\(\s*["'][^"']*["']\s*,"""),
        severity=Severity.HIGH,
        rule_id="VUL021",
        description="Go exec.Command with variable arguments - potential command injection",
        languages=["go"],
    ),
    VulnerabilityPattern(
        name="Go SQL Injection fmt.Sprintf",
        pattern=re.compile(r"""fmt\.Sprintf\s*\(\s*["'].*%s"""),
        severity=Severity.HIGH,
        rule_id="VUL022",
        description="Go SQL query using fmt.Sprintf - potential injection",
        languages=["go"],
    ),
    VulnerabilityPattern(
        name="Go Unsafe Package",
        pattern=re.compile(r"""unsafe\.(?:Pointer|Sizeof|Offsetof)"""),
        severity=Severity.MEDIUM,
        rule_id="VUL023",
        description="Go unsafe package usage - potential memory safety issues",
        languages=["go"],
    ),
    VulnerabilityPattern(
        name="Go Weak Random",
        pattern=re.compile(r"""math/rand\.Intn"""),
        severity=Severity.MEDIUM,
        rule_id="VUL024",
        description="Go math/rand usage - use crypto/rand for security",
        languages=["go"],
    ),
    # Rust vulnerabilities
    VulnerabilityPattern(
        name="Rust Unsafe Block",
        pattern=re.compile(r"""unsafe\s*\{"""),
        severity=Severity.MEDIUM,
        rule_id="VUL025",
        description="Rust unsafe block - potential memory safety issues",
        languages=["rs"],
    ),
    VulnerabilityPattern(
        name="Rust Unwrap in Production",
        pattern=re.compile(r"""\.unwrap\(\)"""),
        severity=Severity.LOW,
        rule_id="VUL026",
        description="Rust unwrap() - use proper error handling instead",
        languages=["rs"],
    ),
    # Java vulnerabilities
    VulnerabilityPattern(
        name="Java Runtime.exec",
        pattern=re.compile(r"""Runtime\.getRuntime\(\)\.exec\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL027",
        description="Java Runtime.exec() - potential command injection",
        languages=["java"],
    ),
    VulnerabilityPattern(
        name="Java Deserialization",
        pattern=re.compile(r"""ObjectInputStream.*?readObject"""),
        severity=Severity.HIGH,
        rule_id="VUL028",
        description="Java deserialization - potential arbitrary code execution",
        languages=["java"],
    ),
    VulnerabilityPattern(
        name="Java SQL Injection",
        pattern=re.compile(r"""Statement.*?executeQuery\s*\(\s*["'].*\+"""),
        severity=Severity.HIGH,
        rule_id="VUL029",
        description="Java SQL query using string concatenation - potential injection",
        languages=["java"],
    ),
    # Ruby vulnerabilities
    VulnerabilityPattern(
        name="Ruby Eval",
        pattern=re.compile(r"""(?:eval|instance_eval|class_eval|module_eval)\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL030",
        description="Ruby eval() usage - potential code injection",
        languages=["rb"],
    ),
    VulnerabilityPattern(
        name="Ruby System Command",
        pattern=re.compile(r"""(?:system|exec|`|%x\{)\s*\(""" ),
        severity=Severity.HIGH,
        rule_id="VUL031",
        description="Ruby system command execution - potential command injection",
        languages=["rb"],
    ),
    VulnerabilityPattern(
        name="Ruby YAML Load",
        pattern=re.compile(r"""YAML\.load\s*\((?!.*permitted_classes)"""),
        severity=Severity.HIGH,
        rule_id="VUL032",
        description="Ruby YAML.load without permitted_classes - potential deserialization",
        languages=["rb"],
    ),
    # PHP vulnerabilities
    VulnerabilityPattern(
        name="PHP eval",
        pattern=re.compile(r"""eval\s*\(\s*\$"""),
        severity=Severity.HIGH,
        rule_id="VUL033",
        description="PHP eval() with variable - potential code injection",
        languages=["php"],
    ),
    VulnerabilityPattern(
        name="PHP system/exec",
        pattern=re.compile(r"""(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL034",
        description="PHP system command execution - potential command injection",
        languages=["php"],
    ),
    VulnerabilityPattern(
        name="PHP SQL Injection",
        pattern=re.compile(r"""mysql_query\s*\(\s*["'].*\$"""),
        severity=Severity.HIGH,
        rule_id="VUL035",
        description="PHP SQL query with variable - potential injection",
        languages=["php"],
    ),
    # C/C++ vulnerabilities
    VulnerabilityPattern(
        name="C strcpy",
        pattern=re.compile(r"""strcpy\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL036",
        description="C strcpy() - potential buffer overflow, use strncpy()",
        languages=["c", "cpp", "h", "hpp"],
    ),
    VulnerabilityPattern(
        name="C sprintf",
        pattern=re.compile(r"""sprintf\s*\("""),
        severity=Severity.HIGH,
        rule_id="VUL037",
        description="C sprintf() - potential buffer overflow, use snprintf()",
        languages=["c", "cpp", "h", "hpp"],
    ),
    VulnerabilityPattern(
        name="C gets",
        pattern=re.compile(r"""gets\s*\("""),
        severity=Severity.CRITICAL,
        rule_id="VUL038",
        description="C gets() - never use, always causes buffer overflow",
        languages=["c", "cpp", "h", "hpp"],
    ),
    VulnerabilityPattern(
        name="C scanf",
        pattern=re.compile(r"""scanf\s*\(\s*["']%s"""),
        severity=Severity.HIGH,
        rule_id="VUL039",
        description="C scanf %s - potential buffer overflow",
        languages=["c", "cpp", "h", "hpp"],
    ),
    # Shell script vulnerabilities
    VulnerabilityPattern(
        name="Shell Unquoted Variable",
        pattern=re.compile(r"""\$[A-Za-z_][A-Za-z0-9_]*(?![\"'])"""),
        severity=Severity.LOW,
        rule_id="VUL040",
        description="Shell unquoted variable - potential word splitting",
        languages=["sh", "bash"],
    ),
    VulnerabilityPattern(
        name="Shell eval",
        pattern=re.compile(r"""eval\s+"""),
        severity=Severity.HIGH,
        rule_id="VUL041",
        description="Shell eval usage - potential command injection",
        languages=["sh", "bash"],
    ),
    # TypeScript specific
    VulnerabilityPattern(
        name="TypeScript any type",
        pattern=re.compile(r""":\s*any\b"""),
        severity=Severity.LOW,
        rule_id="VUL042",
        description="TypeScript any type - bypasses type safety",
        languages=["ts", "tsx"],
    ),
    VulnerabilityPattern(
        name="TypeScript non-null assertion",
        pattern=re.compile(r"""!\.\w"""),
        severity=Severity.LOW,
        rule_id="VUL043",
        description="TypeScript non-null assertion - may cause runtime errors",
        languages=["ts", "tsx"],
    ),
    # Kubernetes/Docker
    VulnerabilityPattern(
        name="Docker privileged mode",
        pattern=re.compile(r"""--privileged"""),
        severity=Severity.HIGH,
        rule_id="VUL044",
        description="Docker privileged mode - container has full host access",
        languages=["dockerfile"],
    ),
    VulnerabilityPattern(
        name="Docker latest tag",
        pattern=re.compile(r"""FROM\s+\w+:latest"""),
        severity=Severity.MEDIUM,
        rule_id="VUL045",
        description="Docker using 'latest' tag - use specific version instead",
        languages=["dockerfile"],
    ),
    VulnerabilityPattern(
        name="Kubernetes allowPrivilegeEscalation",
        pattern=re.compile(r"""allowPrivilegeEscalation:\s*true"""),
        severity=Severity.HIGH,
        rule_id="VUL046",
        description="Kubernetes allows privilege escalation",
        languages=["yaml", "yml"],
    ),
    VulnerabilityPattern(
        name="Kubernetes hostNetwork",
        pattern=re.compile(r"""hostNetwork:\s*true"""),
        severity=Severity.HIGH,
        rule_id="VUL047",
        description="Kubernetes pod uses host network",
        languages=["yaml", "yml"],
    ),
    # Terraform
    VulnerabilityPattern(
        name="Terraform public S3 bucket",
        pattern=re.compile(r"""acl\s*=\s*["']public"""),
        severity=Severity.HIGH,
        rule_id="VUL048",
        description="Terraform S3 bucket is publicly accessible",
        languages=["tf"],
    ),
    VulnerabilityPattern(
        name="Terraform unencrypted EBS",
        pattern=re.compile(r"""encrypted\s*=\s*false"""),
        severity=Severity.MEDIUM,
        rule_id="VUL049",
        description="Terraform EBS volume is not encrypted",
        languages=["tf"],
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
