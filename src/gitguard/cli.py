from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from gitguard.core.auditor import DependencyAuditor
from gitguard.core.autofix import AutoFixer
from gitguard.core.history import HistoryScanner
from gitguard.core.hooks import GitHooksManager
from gitguard.core.license import LicenseChecker
from gitguard.core.models import ReviewResult, Severity
from gitguard.core.reviewer import CodeReviewer
from gitguard.core.rules import RuleEngine
from gitguard.core.scanner import SecurityScanner
from gitguard.utils.config import get_config
from gitguard.utils.git import get_repo_root, get_staged_diff
from gitguard.utils.output import OutputFormatter
from gitguard.utils.sarif import SARIFFormatter

console = Console()
formatter = OutputFormatter()


@click.group()
@click.version_option(package_name="gitguard")
def main() -> None:
    """GitGuard - AI-powered git security scanner and code review toolkit."""
    pass


@main.command()
@click.argument("path", default=".")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="low")
@click.option("--diff", "-d", is_flag=True, help="Scan staged diff only")
@click.option("--output", "-o", type=click.Path(), help="Output JSON results to file")
@click.option("--exit-code", is_flag=True, help="Exit with code 1 if issues found")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings")
def scan(path: str, severity: str, diff: bool, output: str | None, exit_code: bool, verbose: bool) -> None:
    """Scan code for security issues, secrets, and vulnerabilities."""
    config = get_config(Path(path) if path != "." else None)
    severity_enum = Severity(severity)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        scanner = SecurityScanner(
            path=path,
            include_secrets=config.include_secrets,
            include_vulnerabilities=config.include_vulnerabilities,
            include_bad_patterns=config.include_bad_patterns,
            severity_threshold=severity_enum,
        )

        if diff:
            diff_content = get_staged_diff(Path(path) if path != "." else None)
            if not diff_content:
                progress.update(task, description="No staged changes found")
                return
            result = scanner.scan_diff(diff_content)
        else:
            result = scanner.scan()

        progress.update(task, description="Scan complete!")

    if output:
        with open(output, "w") as f:
            json.dump(formatter.print_findings_json(result.findings), f, indent=2)
        formatter.print_success(f"Results saved to {output}")

    formatter.print_scan_result(result, verbose=verbose)

    if exit_code and result.total_findings > 0:
        if result.has_critical or result.has_high:
            sys.exit(2)
        sys.exit(1)


@main.command()
@click.argument("path", default=".")
@click.option("--diff", "-d", is_flag=True, help="Review staged diff only")
@click.option("--output", "-o", type=click.Path(), help="Output results to file")
def review(path: str, diff: bool, output: str | None) -> None:
    """Review code quality and provide suggestions."""
    reviewer = CodeReviewer()

    if diff:
        diff_content = get_staged_diff(Path(path) if path != "." else None)
        if not diff_content:
            formatter.print_warning("No staged changes found")
            return
        result = reviewer.review_diff(diff_content)
    else:
        file_path = Path(path)
        if file_path.is_file():
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            result = reviewer.review_file(file_path, content)
        else:
            result = ReviewResult(summary="Please specify a file or use --diff")

    if output:
        output_data = {
            "summary": result.summary,
            "score": result.score,
            "suggestions": result.suggestions,
            "issues": [i.to_dict() for i in result.issues],
        }
        Path(output).write_text(json.dumps(output_data, indent=2))
        formatter.print_success(f"Results saved to {output}")

    formatter.print_review_result(result)


@main.command()
@click.argument("path", default=".")
@click.option("--output", "-o", type=click.Path(), help="Output results to file")
def audit(path: str, output: str | None) -> None:
    """Audit project dependencies for known vulnerabilities."""
    auditor = DependencyAuditor()
    project_path = Path(path)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing dependencies...", total=None)
        result = auditor.audit_project(project_path)
        progress.update(task, description="Audit complete!")

    if output:
        output_data = {
            "total_deps": result.total_deps,
            "vulnerable_deps": result.vulnerable_deps,
            "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
        }
        Path(output).write_text(json.dumps(output_data, indent=2))
        formatter.print_success(f"Results saved to {output}")

    formatter.print_audit_result(result)


@main.command()
@click.argument("path", default=".")
@click.option("--output", "-o", type=click.Path(), help="Output results to file")
def license(path: str, output: str | None) -> None:
    """Check project licenses for compliance issues."""
    checker = LicenseChecker()
    project_path = Path(path)

    findings = checker.check_project(project_path)

    if output:
        output_data = [f.to_dict() for f in findings]
        Path(output).write_text(json.dumps(output_data, indent=2))
        formatter.print_success(f"Results saved to {output}")

    if not findings:
        formatter.print_success("No license issues found!")
    else:
        for finding in findings:
            color = formatter.SEVERITY_COLORS.get(finding.severity, "white")
            console.print(f"[{color}]{finding.message}[/{color}]")


@main.command()
@click.option("--install", "-i", multiple=True, help="Install specific hooks (pre-commit, pre-push, commit-msg)")
@click.option("--uninstall", "-u", multiple=True, help="Uninstall specific hooks")
@click.option("--list", "-l", "list_hooks", is_flag=True, help="List installed hooks")
def hooks(install: tuple[str, ...], uninstall: tuple[str, ...], list_hooks: bool) -> None:
    """Manage git hooks for GitGuard integration."""
    repo_root = get_repo_root()
    if not repo_root:
        formatter.print_error("Not a git repository")
        sys.exit(1)

    manager = GitHooksManager(repo_root)

    if list_hooks:
        installed_hooks = manager.list_hooks()
        table = Table(title="Git Hooks")
        table.add_column("Hook", style="cyan")
        table.add_column("GitGuard", style="green")
        for hook_name, is_gitguard in installed_hooks.items():
            status = "[green]Yes[/green]" if is_gitguard else "[dim]No[/dim]"
            table.add_row(hook_name, status)
        console.print(table)
        return

    if install:
        installed = manager.install_hooks(list(install))
        for hook_path in installed:
            formatter.print_success(f"Installed: {hook_path.name}")

    if uninstall:
        removed = manager.uninstall_hooks(list(uninstall))
        for hook_path in removed:
            formatter.print_success(f"Removed: {hook_path.name}")

    if not install and not uninstall and not list_hooks:
        installed = manager.install_hooks()
        for hook_path in installed:
            formatter.print_success(f"Installed: {hook_path.name}")


@main.command()
@click.argument("path", default=".")
def full(path: str) -> None:
    """Run full security audit (scan + review + audit + license)."""
    project_path = Path(path)

    console.print(Panel("[bold]GitGuard Full Security Audit[/bold]", border_style="cyan"))

    scanner = SecurityScanner(project_path)
    scan_result = scanner.scan()
    formatter.print_scan_result(scan_result)

    audit_result = DependencyAuditor().audit_project(project_path)
    formatter.print_audit_result(audit_result)

    license_findings = LicenseChecker().check_project(project_path)
    if license_findings:
        console.print("\n[bold]License Issues:[/bold]")
        for finding in license_findings:
            color = formatter.SEVERITY_COLORS.get(finding.severity, "white")
            console.print(f"  [{color}]{finding.message}[/{color}]")

    total_issues = scan_result.total_findings + len(audit_result.vulnerabilities) + len(license_findings)
    if total_issues == 0:
        formatter.print_success("\nAll checks passed!")
    else:
        console.print(f"\n[bold red]Total issues found: {total_issues}[/bold red]")


@main.command()
def init() -> None:
    """Initialize GitGuard configuration in current directory."""
    config_path = Path(".gitguard.json")

    if config_path.exists():
        formatter.print_warning("Configuration already exists")
        return

    default_config = {
        "severity_threshold": "low",
        "include_secrets": True,
        "include_vulnerabilities": True,
        "include_bad_patterns": True,
        "include_license_check": True,
        "include_dependency_audit": True,
        "ignore_dirs": ["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"],
        "allowed_licenses": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
    }

    config_path.write_text(json.dumps(default_config, indent=2))
    formatter.print_success(f"Created {config_path}")


@main.command()
@click.argument("path", default=".")
@click.option("--format", "-f", "output_format", type=click.Choice(["sarif", "json"]), default="sarif")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def sarif(path: str, output_format: str, output: str | None) -> None:
    """Generate SARIF output for GitHub Security tab."""
    scanner = SecurityScanner(path)
    result = scanner.scan()

    sarif_formatter = SARIFFormatter()
    sarif_output = sarif_formatter.format(result)

    if output:
        Path(output).write_text(sarif_output)
        formatter.print_success(f"SARIF output saved to {output}")
    else:
        console.print(sarif_output)


@main.command()
@click.argument("path", default=".")
@click.option("--max-commits", "-n", default=100, help="Maximum commits to scan")
@click.option("--output", "-o", type=click.Path(), help="Output JSON results")
def history(path: str, max_commits: int, output: str | None) -> None:
    """Scan git history for leaked secrets."""
    scanner = HistoryScanner(path)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning git history...", total=None)
        result = scanner.scan_history(max_commits=max_commits)
        progress.update(task, description="History scan complete!")

    if output:
        output_data = [f.to_dict() for f in result.findings]
        Path(output).write_text(json.dumps(output_data, indent=2))
        formatter.print_success(f"Results saved to {output}")

    if not result.findings:
        formatter.print_success("No secrets found in git history!")
    else:
        formatter.print_scan_result(result)


@main.command()
@click.argument("path", default=".")
@click.option("--dry-run", is_flag=True, help="Show fixes without applying")
@click.option("--interactive", "-i", is_flag=True, help="Confirm each fix")
def fix(path: str, dry_run: bool, interactive: bool) -> None:
    """Auto-fix common security issues."""
    scanner = SecurityScanner(path)
    fixer = AutoFixer()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning for fixable issues...", total=None)
        result = scanner.scan()
        progress.update(task, description="Scan complete!")

    fixable = [f for f in result.findings if f.rule_id in (
        "VUL003", "VUL004", "VUL005", "VUL006", "VUL007",
        "VUL011", "VUL014", "VUL016", "BP001", "BP007", "BP008"
    )]

    if not fixable:
        formatter.print_success("No auto-fixable issues found!")
        return

    console.print(f"\n[bold]Found {len(fixable)} fixable issues:[/bold]\n")

    files_fixed: dict[Path, list] = {}
    for finding in fixable:
        try:
            content = finding.file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        fixes = fixer.fix_file(finding.file_path, content, [finding])
        if fixes:
            if finding.file_path not in files_fixed:
                files_fixed[finding.file_path] = []
            files_fixed[finding.file_path].extend(fixes)

    for file_path, fixes in files_fixed.items():
        console.print(f"\n[cyan]{file_path}[/cyan]")
        for fix_item in fixes:
            color = "yellow" if dry_run else "green"
            console.print(f"  [{color}]Line {fix_item.line_number}:[/{color}] {fix_item.description}")
            console.print(f"    [dim]- {fix_item.original_line.strip()}[/dim]")
            console.print(f"    [green]+ {fix_item.fixed_line.strip()}[/green]")

            if interactive and not dry_run and click.confirm("    Apply this fix?"):
                fix_item.applied = True

    if dry_run:
        console.print("\n[yellow]Dry run - no changes applied[/yellow]")
        return

    applied_count = 0
    for file_path, fixes in files_fixed.items():
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            new_content = fixer.apply_fixes(file_path, content, fixes)
            file_path.write_text(new_content)
            applied_count += sum(1 for f in fixes if f.applied)
        except (OSError, PermissionError) as e:
            formatter.print_error(f"Could not write {file_path}: {e}")

    formatter.print_success(f"Applied {applied_count} fixes!")


@main.command()
@click.argument("path", default=".")
@click.option("--rule-file", "-r", type=click.Path(exists=True), help="Load rules from file")
def rules(path: str, rule_file: str | None) -> None:
    """Manage and run custom security rules."""
    engine = RuleEngine()

    if rule_file:
        count = engine.load_rules_from_file(Path(rule_file))
        formatter.print_success(f"Loaded {count} rules from {rule_file}")

    custom_rules = engine.get_rules()
    if not custom_rules:
        console.print("[dim]No custom rules loaded. Create rules in ~/.gitguard/rules/[/dim]")
        console.print("\nExample rule (JSON):")
        console.print("""{
  "id": "CUSTOM001",
  "name": "no-print",
  "pattern": "print\\\\(",
  "severity": "low",
  "message": "print() statement found",
  "languages": ["python"],
  "suggestion": "Use logging instead of print()"
}""")
        return

    table = Table(title="Custom Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Languages")

    for rule in custom_rules:
        table.add_row(rule.id, rule.name, rule.severity, ", ".join(rule.languages) or "all")

    console.print(table)


@main.command()
@click.argument("finding_rule")
@click.option("--context", "-c", default="", help="Additional context")
def explain(finding_rule: str, context: str) -> None:
    """Explain a security finding in detail."""
    explanations = {
        "SEC001": "AWS Access Keys follow the pattern AKIA followed by 16 uppercase alphanumeric characters. These grant full access to AWS services. If leaked, attackers can access your cloud infrastructure, steal data, or incur large bills.",
        "SEC003": "GitHub Personal Access Tokens (ghp_) provide access to your GitHub repositories. A leaked token can be used to push code, access private repos, or modify CI/CD pipelines.",
        "VUL001": "SQL Injection occurs when user input is directly concatenated into SQL queries. Attackers can execute arbitrary SQL commands, potentially reading sensitive data or deleting databases.",
        "VUL003": "os.system() executes shell commands and is vulnerable to command injection. Attackers can inject arbitrary commands through unsanitized input.",
        "VUL005": "eval() executes arbitrary Python code from strings. If user input reaches eval(), attackers can execute any Python code on your system.",
        "VUL008": "pickle deserialization can execute arbitrary code during unpickling. Never unpickle data from untrusted sources.",
    }

    explanation = explanations.get(finding_rule, f"Rule {finding_rule}: Consult the GitGuard documentation for details on this rule.")

    console.print(Panel(explanation, title=f"Rule: {finding_rule}", border_style="cyan"))


@main.command()
@click.argument("path", default=".")
@click.option("--format", "-f", "output_format", type=click.Choice(["cyclonedx", "spdx"]), default="cyclonedx")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def sbom(path: str, output_format: str, output: str | None) -> None:
    """Generate Software Bill of Materials (SBOM)."""
    from gitguard.core.sbom import SBOMGenerator

    generator = SBOMGenerator(path)

    if output_format == "cyclonedx":
        content = generator.generate_cyclonedx()
    else:
        content = generator.generate_spdx()

    if output:
        Path(output).write_text(content)
        formatter.print_success(f"SBOM saved to {output}")
    else:
        console.print(content)


@main.command()
@click.argument("path", default=".")
@click.option("--port", "-p", default=8080, help="Dashboard port")
def dashboard(path: str, port: int) -> None:
    """Launch web dashboard for security overview."""
    from gitguard.dashboard.server import DashboardServer

    server = DashboardServer(path, port=port)
    server.start()


@main.command()
@click.argument("path", default=".")
@click.option("--output", "-o", type=click.Path(), help="Output JSON results")
def nvd(path: str, output: str | None) -> None:
    """Check dependencies against NVD vulnerability database."""
    from gitguard.core.nvd import NVDChecker

    checker = NVDChecker()
    project_path = Path(path)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Checking NVD database...", total=None)
        findings = checker.check_project(project_path)
        progress.update(task, description="NVD check complete!")

    if output:
        output_data = [f.to_dict() for f in findings]
        Path(output).write_text(json.dumps(output_data, indent=2))
        formatter.print_success(f"Results saved to {output}")

    if not findings:
        formatter.print_success("No known CVEs found in dependencies!")
    else:
        console.print(f"\n[bold red]Found {len(findings)} CVEs:[/bold red]\n")
        for finding in findings:
            color = formatter.SEVERITY_COLORS.get(finding.severity, "white")
            console.print(f"  [{color}]{finding.message}[/{color}]")
            if finding.suggestion:
                console.print(f"    [green]{finding.suggestion}[/green]")


if __name__ == "__main__":
    main()
