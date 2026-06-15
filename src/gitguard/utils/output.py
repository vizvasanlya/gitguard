from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from gitguard.core.models import (
    AuditResult,
    Finding,
    ReviewResult,
    ScanResult,
    Severity,
)

console = Console()


class OutputFormatter:
    """Formats scan results for terminal output."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "!!",
        Severity.HIGH: "!",
        Severity.MEDIUM: "~",
        Severity.LOW: "-",
        Severity.INFO: "i",
    }

    def print_scan_result(self, result: ScanResult, verbose: bool = False) -> None:
        if not result.findings:
            console.print(Panel("[green]No security issues found![/green]", title="Scan Results"))
            return

        summary = Table(title="Scan Summary", show_header=False)
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value")
        summary.add_row("Files Scanned", str(result.files_scanned))
        summary.add_row("Lines Scanned", str(result.lines_scanned))
        summary.add_row("Total Findings", str(result.total_findings))
        summary.add_row("Critical", f"[bold red]{result.critical_count}[/bold red]")
        summary.add_row("High", f"[red]{result.high_count}[/red]")
        console.print(summary)

        if verbose:
            self._print_findings_detail(result.findings)
        else:
            self._print_findings_compact(result.findings)

    def print_review_result(self, result: ReviewResult) -> None:
        score_color = "green" if result.score >= 80 else "yellow" if result.score >= 60 else "red"
        console.print(Panel(f"Score: [{score_color}]{result.score:.0f}/100[/{score_color}]", title="Code Review"))

        if result.summary:
            console.print(f"\n{result.summary}")

        if result.suggestions:
            console.print("\n[bold]Suggestions:[/bold]")
            for suggestion in result.suggestions:
                console.print(f"  [cyan]*[/cyan] {suggestion}")

        if result.issues:
            self._print_findings_compact(result.issues)

    def print_audit_result(self, result: AuditResult) -> None:
        summary = Table(title="Dependency Audit", show_header=False)
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value")
        summary.add_row("Total Dependencies", str(result.total_deps))
        summary.add_row("Vulnerable", f"[red]{result.vulnerable_deps}[/red]")
        console.print(summary)

        if result.vulnerabilities:
            console.print("\n[bold red]Vulnerabilities Found:[/bold red]")
            for vuln in result.vulnerabilities:
                severity_color = self.SEVERITY_COLORS.get(vuln.severity, "white")
                console.print(f"  [{severity_color}]{vuln.message}[/{severity_color}]")

    def print_findings_json(self, findings: list[Finding]) -> str:
        return json.dumps([f.to_dict() for f in findings], indent=2)

    def _print_findings_compact(self, findings: list[Finding]) -> None:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Sev", width=4)
        table.add_column("File", style="cyan")
        table.add_column("Line", justify="right")
        table.add_column("Message")
        table.add_column("Rule", style="dim")

        for finding in findings:
            color = self.SEVERITY_COLORS.get(finding.severity, "white")
            icon = self.SEVERITY_ICONS.get(finding.severity, "?")
            rel_path = finding.file_path.name if finding.file_path else "unknown"

            table.add_row(
                f"[{color}]{icon}[/{color}]",
                rel_path,
                str(finding.line_number),
                finding.message[:80],
                finding.rule_id,
            )

        console.print(table)

    def _print_findings_detail(self, findings: list[Finding]) -> None:
        for finding in findings:
            color = self.SEVERITY_COLORS.get(finding.severity, "white")
            icon = self.SEVERITY_ICONS.get(finding.severity, "?")

            header = f"[{color}]{icon} {finding.severity.value.upper()}[/{color}] {finding.rule_id}"
            body = f"{finding.message}\n\nFile: {finding.file_path}\nLine: {finding.line_number}"
            if finding.line_content:
                body += f"\nCode: {finding.line_content}"
            if finding.suggestion:
                body += f"\n\nSuggestion: {finding.suggestion}"

            console.print(Panel(body, title=header, border_style=color))

    def print_error(self, message: str) -> None:
        console.print(f"[red]Error: {message}[/red]")

    def print_success(self, message: str) -> None:
        console.print(f"[green]{message}[/green]")

    def print_warning(self, message: str) -> None:
        console.print(f"[yellow]Warning: {message}[/yellow]")
