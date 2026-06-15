# GitGuard

> AI-powered git security scanner that detects secrets, vulnerabilities, and fixes your code automatically

[![CI](https://github.com/gitguard/gitguard/actions/workflows/ci.yml/badge.svg)](https://github.com/gitguard/gitguard/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/gitguard.svg)](https://pypi.org/project/gitguard/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why GitGuard?

Other security tools just **complain**. GitGuard **fixes your code**.

```bash
# Scan your project
gitguard scan .

# Auto-fix issues
gitguard fix .

# Understand why something is dangerous
gitguard explain SEC001
```

## Quick Start

### Install

```bash
# pip
pip install gitguard

# Homebrew (macOS)
brew install gitguard
```

### First Scan

```bash
cd your-project
gitguard scan .
```

## Commands (15 total)

| Command | Description |
|---------|-------------|
| `gitguard scan .` | Scan for secrets, vulnerabilities, bad patterns |
| `gitguard review file.py` | AI-powered code review with risk scoring |
| `gitguard fix .` | Auto-fix 11 common security issues |
| `gitguard history .` | Scan git history for leaked secrets |
| `gitguard sarif .` | Generate SARIF output for GitHub Security tab |
| `gitguard audit .` | Check dependencies for known CVEs |
| `gitguard nvd .` | Check NVD vulnerability database |
| `gitguard license .` | Check license compliance |
| `gitguard sbom .` | Generate Software Bill of Materials |
| `gitguard explain RULE` | Explain a security rule in detail |
| `gitguard rules` | Manage custom security rules |
| `gitguard hooks` | Install git pre-commit hooks |
| `gitguard dashboard` | Launch web dashboard |
| `gitguard full .` | Run all checks at once |
| `gitguard init` | Create configuration file |

## What GitGuard Catches

### Secrets (100+ patterns)

| Category | Services |
|----------|----------|
| **Cloud** | AWS, Azure, GCP, DigitalOcean, Alibaba, Oracle, IBM |
| **Version Control** | GitHub, GitLab, Bitbucket |
| **Communication** | Slack, Discord, Mattermost |
| **Payment** | Stripe, PayPal, Shopify |
| **AI/ML** | OpenAI, Hugging Face, Anthropic |
| **DevOps** | Docker, Kubernetes, Terraform, Ansible, Vault |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis, Cosmos DB |
| **Packages** | npm, PyPI, RubyGems, Docker Hub |
| **Keys** | RSA, SSH, PGP, EC private keys |
| **Tokens** | JWT, Bearer, API keys, access tokens |
| **And 30+ more services...** |

### Vulnerabilities (49 patterns)

| Language | What's Detected |
|----------|-----------------|
| **Python** | SQL injection, command injection, eval, pickle, yaml.load, tempfile |
| **JavaScript/TypeScript** | XSS, prototype pollution, eval, NoSQL injection, CORS |
| **Go** | Command injection, fmt.Sprintf SQL, unsafe package |
| **Rust** | Unsafe blocks, unwrap() usage |
| **Java** | Runtime.exec, deserialization, SQL injection |
| **Ruby** | Eval, system, YAML.load |
| **PHP** | Eval, system, SQL injection |
| **C/C++** | strcpy, sprintf, gets, scanf buffer overflows |
| **Shell** | Eval, unquoted variables |
| **Docker** | Privileged mode, latest tag |
| **Kubernetes** | Privilege escalation, hostNetwork |
| **Terraform** | Public S3, unencrypted EBS |

## Unique Features

### Auto-Fix
```bash
gitguard fix .
```
Automatically fixes 11 issue types:
- `os.system()` → `subprocess.run()`
- `shell=True` → `shell=False`
- `eval()` → `ast.literal_eval()`
- `yaml.load()` → `yaml.safe_load()`
- `hashlib.md5` → `hashlib.sha256`
- `mktemp()` → `mkstemp()`
- Bare except → specific exception
- Wildcard imports → explicit imports
- Mutable defaults → None
- Debug mode → disabled
- And more...

### AI Code Review
```bash
gitguard review src/main.py
```
- LLM-powered analysis (OpenAI, Anthropic, local models)
- Risk scoring (0-100)
- Context-aware explanations
- Fix suggestions

### Git History Scanning
```bash
gitguard history .
```
Find secrets leaked in old commits — even if they were removed.

### SARIF Output
```bash
gitguard sarif . --output results.sarif
```
Integrates with GitHub Security tab. See findings directly in your PR.

### SBOM Generation
```bash
gitguard sbom . --format cyclonedx
```
Generate Software Bill of Materials in CycloneDX or SPDX format.

### NVD Integration
```bash
gitguard nvd .
```
Check dependencies against National Vulnerability Database for known CVEs.

### Web Dashboard
```bash
gitguard dashboard
```
Beautiful web UI with real-time scan results, SARIF/SBOM export.

### Notifications
```bash
# Set environment variables
export GITGUARD_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export GITGUARD_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."

# Scan sends notifications automatically
gitguard scan .
```

### Custom Rules
```json
{
  "id": "CUSTOM001",
  "name": "no-print",
  "pattern": "print\\(",
  "severity": "low",
  "message": "print() statement found",
  "languages": ["python"],
  "suggestion": "Use logging instead of print()"
}
```

## Comparison

| Feature | GitGuard | Gitleaks | TruffleHog | Semgrep |
|---------|----------|----------|------------|---------|
| Secret detection | 100+ patterns | 100+ patterns | 50+ patterns | Custom rules |
| Vulnerability scanning | 49 patterns | ❌ | ❌ | 2000+ rules |
| Auto-fix | ✅ 11 fixers | ❌ | ❌ | ❌ |
| AI explanations | ✅ | ❌ | ❌ | ❌ |
| AI code review | ✅ | ❌ | ❌ | ❌ |
| SARIF output | ✅ | ✅ | ❌ | ✅ |
| Git history scan | ✅ | ❌ | ✅ | ❌ |
| SBOM generation | ✅ | ❌ | ❌ | ❌ |
| NVD integration | ✅ | ❌ | ❌ | ❌ |
| Web dashboard | ✅ | ❌ | ❌ | ❌ |
| Notifications | ✅ Slack/Discord | ❌ | ❌ | ❌ |
| Custom rules | ✅ JSON/YAML | ✅ TOML | ❌ | ✅ YAML |
| Git hooks | ✅ | ✅ | ❌ | ❌ |
| VS Code extension | ✅ | ❌ | ❌ | ❌ |
| Homebrew | ✅ | ✅ | ✅ | ✅ |
| Languages | 12 | All | All | 30+ |
| GitHub Action | ✅ | ✅ | ✅ | ✅ |
| Price | Free | Free | Free | Free |

**Unique to GitGuard:** Auto-fix, AI explanations, AI code review, SBOM, NVD, Dashboard, Notifications

## Performance

| Metric | GitGuard | Gitleaks | TruffleHog |
|--------|----------|----------|------------|
| Scan time (1K files) | 2.3s | 1.8s | 4.2s |
| Scan time (10K files) | 8.1s | 6.2s | 18.5s |
| Memory usage | 45MB | 32MB | 128MB |

See [benchmarks/](benchmarks/) for detailed comparison.

## Installation

### pip
```bash
pip install gitguard
```

### Homebrew
```bash
brew install gitguard
```

### From source
```bash
git clone https://github.com/gitguard/gitguard.git
cd gitguard
pip install -e .
```

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
      - run: gitguard scan . --exit-code --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install gitguard
    - gitguard scan . --exit-code
```

### Using the GitHub Action

```yaml
- uses: gitguard/gitguard-action@v1
  with:
    scan-type: full
    severity: low
    fail-on-severity: high
```

## Python API

```python
from gitguard import SecurityScanner, CodeReviewer, DependencyAuditor

# Scan for security issues
scanner = SecurityScanner("/path/to/project")
result = scanner.scan()
print(f"Found {result.total_findings} issues")

# Review code
reviewer = CodeReviewer()
review = reviewer.review_file(Path("src/main.py"), content)
print(f"Score: {review.score}/100")

# Audit dependencies
auditor = DependencyAuditor()
audit = auditor.audit_project(Path("/path/to/project"))
print(f"Vulnerable deps: {audit.vulnerable_deps}/{audit.total_deps}")

# Generate SBOM
from gitguard.core.sbom import SBOMGenerator
sbom = SBOMGenerator("/path/to/project")
cyclonedx = sbom.generate_cyclonedx()

# Check NVD
from gitguard.core.nvd import NVDChecker
nvd = NVDChecker()
findings = nvd.check_project(Path("/path/to/project"))
```

## VS Code Extension

Install the extension for real-time security scanning:

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "GitGuard"
4. Install

Features:
- Scan on file save
- Inline diagnostics
- Quick fixes
- Severity filtering

## Demo

See [docs/demos/](docs/demos/) for demo recording scripts.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
