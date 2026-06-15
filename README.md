# GitGuard

> AI-powered git security scanner and code review toolkit

[![CI](https://github.com/gitguard/gitguard/actions/workflows/ci.yml/badge.svg)](https://github.com/gitguard/gitguard/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/gitguard.svg)](https://pypi.org/project/gitguard/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## The Problem

Developers accidentally commit secrets, vulnerable dependencies, and insecure code patterns every day. Existing security tools require cloud accounts, complex setup, or only work in CI/CD pipelines. By the time they catch issues, it's too late.

## The Solution

GitGuard catches security issues **before they reach your repository**. Run it locally, in your pre-commit hook, or as part of your CI/CD pipeline. No cloud account required. No telemetry. Works offline.

## Features

- **Secret Detection** - Catches AWS keys, GitHub tokens, private keys, API keys, and 20+ secret patterns
- **Vulnerability Scanning** - Finds SQL injection, command injection, eval(), and other security issues
- **Code Review** - AI-powered code quality analysis with actionable suggestions
- **Dependency Audit** - Checks for known vulnerabilities in your dependencies
- **License Compliance** - Detects license issues in your project and dependencies
- **Git Hooks** - One-command setup for pre-commit, pre-push, and commit-msg hooks
- **CI/CD Integration** - Works with GitHub Actions, GitLab CI, and any CI system
- **Local-first** - No cloud required. Your code never leaves your machine

## Installation

```bash
pip install gitguard
```

## Quick Start

### Scan Your Project

```bash
# Full scan
gitguard scan .

# Scan only staged changes
gitguard scan --diff

# Scan with severity filter
gitguard scan . --severity high
```

### Review Code

```bash
# Review a file
gitguard review src/main.py

# Review staged changes
gitguard review --diff
```

### Audit Dependencies

```bash
gitguard audit .
```

### Check Licenses

```bash
gitguard license .
```

### Run Full Audit

```bash
gitguard full .
```

## Git Hooks

Install git hooks to catch issues before they're committed:

```bash
# Install all hooks
gitguard hooks --install pre-commit --install pre-push --install commit-msg

# Or install all at once
gitguard hooks

# List installed hooks
gitguard hooks --list
```

### Pre-commit Hook

The pre-commit hook scans staged changes for:
- Secrets (API keys, tokens, private keys)
- Vulnerabilities (SQL injection, command injection, etc.)
- Bad code patterns

### Pre-push Hook

The pre-push hook runs a full scan before pushing to remote.

### Commit Message Hook

The commit message hook:
- Prevents committing messages that contain secrets
- Warns about long first lines

## Configuration

Create `.gitguard.json` in your project root:

```json
{
  "severity_threshold": "low",
  "include_secrets": true,
  "include_vulnerabilities": true,
  "include_bad_patterns": true,
  "include_license_check": true,
  "include_dependency_audit": true,
  "ignore_dirs": ["node_modules", ".git", "__pycache__"],
  "allowed_licenses": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install gitguard
      - run: gitguard scan . --exit-code --output results.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-results
          path: results.json
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install gitguard
    - gitguard scan . --exit-code
```

## Python API

```python
from gitguard import SecurityScanner, CodeReviewer, DependencyAuditor

# Scan for security issues
scanner = SecurityScanner("/path/to/project")
result = scanner.scan()

print(f"Found {result.total_findings} issues")
print(f"Critical: {result.critical_count}")
print(f"High: {result.high_count}")

# Review code
reviewer = CodeReviewer()
review = reviewer.review_file(Path("src/main.py"), content)
print(f"Score: {review.score}/100")

# Audit dependencies
auditor = DependencyAuditor()
audit = auditor.audit_project(Path("/path/to/project"))
print(f"Vulnerable deps: {audit.vulnerable_deps}/{audit.total_deps}")
```

## What GitGuard Catches

### Secrets
- AWS Access Keys & Secret Keys
- GitHub/GitLab/Bitbucket Tokens
- Slack/Discord Tokens
- Google API Keys
- Stripe API Keys
- Private Keys (RSA, SSH, PGP)
- Database Connection Strings
- JWT Tokens
- Generic API Keys & Passwords

### Vulnerabilities
- SQL Injection
- Command Injection (os.system, subprocess shell=True)
- eval() / exec() Usage
- Unsafe YAML Deserialization
- Pickle Deserialization
- Prototype Pollution
- XSS Vulnerabilities
- Weak Cryptographic Hashes
- Debug Mode in Production

### Bad Practices
- Bare except clauses
- Wildcard imports
- Mutable default arguments
- Deep nesting
- Magic numbers
- TODO/FIXME comments

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
