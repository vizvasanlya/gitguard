from __future__ import annotations

import json
from typing import Any

from gitguard.core.models import ScanResult, Severity


class SARIFFormatter:
    """Formats scan results in SARIF 2.1.0 format for GitHub Security tab."""

    SEVERITY_MAP = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    RULES: dict[str, dict[str, str]] = {
        "SEC001": {"name": "aws-access-key", "short": "AWS Access Key", "full": "AWS Access Key ID detected in source code"},
        "SEC002": {"name": "aws-secret-key", "short": "AWS Secret Key", "full": "AWS Secret Access Key detected in source code"},
        "SEC003": {"name": "github-token", "short": "GitHub Token", "full": "GitHub Personal Access Token detected"},
        "SEC004": {"name": "github-oauth", "short": "GitHub OAuth", "full": "GitHub OAuth Token detected"},
        "SEC005": {"name": "gitlab-token", "short": "GitLab Token", "full": "GitLab Personal Access Token detected"},
        "SEC006": {"name": "slack-token", "short": "Slack Token", "full": "Slack Token detected"},
        "SEC007": {"name": "slack-webhook", "short": "Slack Webhook", "full": "Slack Webhook URL detected"},
        "SEC008": {"name": "google-api-key", "short": "Google API Key", "full": "Google API Key detected"},
        "SEC009": {"name": "google-oauth", "short": "Google OAuth", "full": "Google OAuth Client ID detected"},
        "SEC010": {"name": "stripe-key", "short": "Stripe Key", "full": "Stripe API Key detected"},
        "SEC011": {"name": "stripe-publishable", "short": "Stripe Publishable", "full": "Stripe Publishable Key detected"},
        "SEC012": {"name": "private-key", "short": "Private Key", "full": "Private key detected in source code"},
        "SEC013": {"name": "ssh-private-key", "short": "SSH Private Key", "full": "SSH private key detected"},
        "SEC014": {"name": "pgp-private-key", "short": "PGP Private Key", "full": "PGP private key detected"},
        "SEC015": {"name": "generic-api-key", "short": "API Key", "full": "Potential API key detected"},
        "SEC016": {"name": "generic-secret", "short": "Secret", "full": "Potential secret or password detected"},
        "SEC017": {"name": "connection-string", "short": "Connection String", "full": "Database connection string detected"},
        "SEC018": {"name": "jwt-token", "short": "JWT Token", "full": "JWT token detected"},
        "SEC019": {"name": "bearer-token", "short": "Bearer Token", "full": "Bearer token detected"},
        "SEC020": {"name": "base64-secret", "short": "Base64 Secret", "full": "Potential base64-encoded secret detected"},
        "VUL001": {"name": "sql-injection", "short": "SQL Injection", "full": "Potential SQL injection vulnerability"},
        "VUL002": {"name": "sql-injection-format", "short": "SQL Injection", "full": "SQL query using format string - potential injection"},
        "VUL003": {"name": "cmd-injection-os", "short": "Command Injection", "full": "os.system() usage - potential command injection"},
        "VUL004": {"name": "cmd-injection-subprocess", "short": "Command Injection", "full": "subprocess with shell=True - potential command injection"},
        "VUL005": {"name": "eval-usage", "short": "Code Injection", "full": "eval() usage - potential code injection"},
        "VUL006": {"name": "exec-usage", "short": "Code Injection", "full": "exec() usage - potential code injection"},
        "VUL007": {"name": "yaml-unsafe-load", "short": "Deserialization", "full": "yaml.load() without safe Loader"},
        "VUL008": {"name": "pickle-deserialization", "short": "Deserialization", "full": "pickle deserialization - potential arbitrary code execution"},
        "VUL009": {"name": "xss-html", "short": "XSS", "full": "Potential XSS via unsanitized HTML"},
        "VUL010": {"name": "hardcoded-ip", "short": "Hardcoded IP", "full": "Hardcoded IP address detected"},
        "VUL011": {"name": "debug-enabled", "short": "Debug Mode", "full": "Debug mode enabled in production code"},
        "VUL012": {"name": "cors-wildcard", "short": "CORS", "full": "CORS wildcard - allows any origin"},
        "VUL013": {"name": "insecure-http", "short": "Insecure HTTP", "full": "HTTP request instead of HTTPS"},
        "VUL014": {"name": "weak-hash-md5", "short": "Weak Hash", "full": "Weak hash algorithm (MD5) used"},
        "VUL015": {"name": "weak-hash-sha1", "short": "Weak Hash", "full": "Weak hash algorithm (SHA1) used"},
        "VUL016": {"name": "tempfile-race", "short": "Race Condition", "full": "tempfile.mktemp() is insecure"},
        "VUL017": {"name": "redos", "short": "ReDoS", "full": "Potentially vulnerable regex - ReDoS"},
        "VUL018": {"name": "js-eval", "short": "Code Injection", "full": "eval() or Function() usage"},
        "VUL019": {"name": "nosql-injection", "short": "NoSQL Injection", "full": "Potential NoSQL injection"},
        "VUL020": {"name": "prototype-pollution", "short": "Prototype Pollution", "full": "Potential prototype pollution vulnerability"},
    }

    def format(self, result: ScanResult, tool_version: str = "0.1.0") -> str:
        runs = self._build_runs(result, tool_version)
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }
        return json.dumps(sarif, indent=2)

    def _build_runs(self, result: ScanResult, tool_version: str) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        tool_rules: dict[str, dict[str, str]] = {}

        for finding in result.findings:
            if finding.rule_id not in tool_rules:
                rule_info = self.RULES.get(finding.rule_id, {"name": finding.rule_id, "short": finding.rule_id, "full": finding.message})
                tool_rules[finding.rule_id] = rule_info

        for rule_id, info in tool_rules.items():
            rules.append({
                "id": rule_id,
                "name": info["name"],
                "shortDescription": {"text": info["short"]},
                "fullDescription": {"text": info["full"]},
                "helpUri": f"https://github.com/gitguard/gitguard/blob/main/docs/rules/{rule_id}.md",
            })

        results: list[dict[str, Any]] = []
        for finding in result.findings:
            sarif_result: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "message": {"text": finding.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.file_path)},
                        "region": {"startLine": finding.line_number},
                    }
                }],
                "level": self.SEVERITY_MAP.get(finding.severity, "warning"),
            }

            if finding.suggestion:
                sarif_result["fixes"] = [{
                    "description": {"text": finding.suggestion},
                }]

            results.append(sarif_result)

        tool = {
            "driver": {
                "name": "gitguard",
                "version": tool_version,
                "informationUri": "https://github.com/gitguard/gitguard",
                "rules": rules,
            }
        }

        return [{"tool": tool, "results": results}]
