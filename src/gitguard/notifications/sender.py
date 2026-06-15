from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from gitguard.core.models import ScanResult, Severity


@dataclass
class NotificationConfig:
    slack_webhook: str | None = None
    discord_webhook: str | None = None
    email: str | None = None
    notify_on: str = "high"
    include_details: bool = True


class NotificationSender:
    """Sends scan results to Slack, Discord, or email."""

    def __init__(self, config: NotificationConfig) -> None:
        self.config = config

    def send_scan_notification(self, result: ScanResult, project_name: str = "project") -> bool:
        if result.total_findings == 0:
            return True

        min_severity = Severity(self.config.notify_on)
        important_findings = [
            f for f in result.findings
            if self._severity_order(f.severity) <= self._severity_order(min_severity)
        ]

        if not important_findings:
            return True

        success = True

        if self.config.slack_webhook:
            success &= self._send_slack(important_findings, result, project_name)

        if self.config.discord_webhook:
            success &= self._send_discord(important_findings, result, project_name)

        return success

    def _send_slack(self, findings: list, result: ScanResult, project_name: str) -> bool:
        if not self.config.slack_webhook:
            return False

        try:
            import urllib.request

            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"GitGuard Security Scan: {project_name}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{result.total_findings}* issues found ({result.critical_count} critical, {result.high_count} high)"
                    }
                }
            ]

            if self.config.include_details:
                for finding in findings[:10]:
                    emoji = self._severity_emoji(finding.severity)
                    blocks.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{emoji} `{finding.rule_id}` {finding.message}\n       {finding.file_path}:{finding.line_number}"
                        }
                    })

                if len(findings) > 10:
                    blocks.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"_...and {len(findings) - 10} more issues_"
                        }
                    })

            payload = json.dumps({"blocks": blocks}).encode()

            req = urllib.request.Request(
                self.config.slack_webhook,
                data=payload,
                headers={"Content-Type": "application/json"}
            )

            with urllib.request.urlopen(req, timeout=10) as resp:
                return bool(resp.status == 200)

        except Exception:
            return False

    def _send_discord(self, findings: list, result: ScanResult, project_name: str) -> bool:
        if not self.config.discord_webhook:
            return False

        try:
            import urllib.request

            fields: list[dict[str, Any]] = []
            for finding in findings[:10]:
                emoji = self._severity_emoji(finding.severity)
                fields.append({
                    "name": f"{emoji} {finding.rule_id}",
                    "value": f"{finding.message}\n`{finding.file_path}:{finding.line_number}`",
                    "inline": False
                })

            if len(findings) > 10:
                fields.append({
                    "name": "More issues",
                    "value": f"...and {len(findings) - 10} more",
                    "inline": False
                })

            embed: dict[str, Any] = {
                "title": f"GitGuard Security Scan: {project_name}",
                "description": f"**{result.total_findings}** issues found",
                "color": self._severity_color(findings[0].severity) if findings else 0x00ff00,
                "fields": fields,
            }

            payload = json.dumps({"embeds": [embed]}).encode()

            req = urllib.request.Request(
                self.config.discord_webhook,
                data=payload,
                headers={"Content-Type": "application/json"}
            )

            with urllib.request.urlopen(req, timeout=10) as resp:
                return bool(resp.status == 204)

        except Exception:
            return False

    def _severity_emoji(self, severity: Severity) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }.get(severity, "⚪")

    def _severity_color(self, severity: Severity) -> int:
        return {
            Severity.CRITICAL: 0xff0000,
            Severity.HIGH: 0xff6600,
            Severity.MEDIUM: 0xffff00,
            Severity.LOW: 0x0066ff,
            Severity.INFO: 0xcccccc,
        }.get(severity, 0xcccccc)

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
