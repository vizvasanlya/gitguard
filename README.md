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

## Features

### Core Scanning
- **100+ secret patterns** — AWS, Azure, GCP, GitHub, Stripe, OpenAI, and 50+ services
- **49 vulnerability patterns** — SQL injection, command injection, XSS, deserialization, and more
- **12 languages** — Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, PHP, C/C++, Shell, Docker, K8s
- **Entropy detection** — Catches randomly generated secrets that regex misses

### AI-Powered
- **Code review** — LLM-powered analysis with risk scoring
- **Explain findings** — `gitguard explain SEC001` teaches you about vulnerabilities
- **Context-aware** — Understands code structure, not just text patterns

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
- And 6 more...

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

### Git Hooks
```bash
# Install pre-commit hook
gitguard hooks --install pre-commit

# Scan before every commit automatically
```

## Quick Start

### Installation

```bash
pip install gitguard
```

### First Scan

```bash
cd your-project
gitguard scan .
```

Output:
```
Scan Summary
┌────────────────┬──────┐
│ Files Scanned  │ 42   │
│ Lines Scanned  │ 3,293│
│ Total Findings │ 22   │
│ Critical       │ 13   │
│ High           │ 8    │
└────────────────┴──────┘
```

## Commands

| Command | Description |
|---------|-------------|
| `gitguard scan .` | Scan for security issues |
| `gitguard review file.py` | AI-powered code review |
| `gitguard fix .` | Auto-fix common issues |
| `gitguard history .` | Scan git history for secrets |
| `gitguard sarif .` | Generate SARIF for GitHub |
| `gitguard audit .` | Check dependencies for CVEs |
| `gitguard license .` | Check license compliance |
| `gitguard explain RULE` | Explain a security rule |
| `gitguard rules` | Manage custom rules |
| `gitguard hooks` | Install git hooks |
| `gitguard full .` | Run all checks |
| `gitguard init` | Create config file |

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
| Custom rules | ✅ JSON/YAML | ✅ TOML | ❌ | ✅ YAML |
| Git hooks | ✅ | ✅ | ❌ | ❌ |
| Languages | 12 | All | All | 30+ |
| GitHub Action | ✅ | ✅ | ✅ | ✅ |
| Price | Free | Free | Free | Free |

**Unique to GitGuard:** Auto-fix, AI explanations, AI code review

## Language Support

| Language | Secrets | Vulnerabilities |
|----------|---------|-----------------|
| Python | ✅ | ✅ SQL injection, command injection, eval, pickle, yaml |
| JavaScript | ✅ | ✅ XSS, prototype pollution, eval, NoSQL injection |
| TypeScript | ✅ | ✅ XSS, prototype pollution, eval, NoSQL injection |
| Go | ✅ | ✅ Command injection, fmt.Sprintf SQL, unsafe |
| Rust | ✅ | ✅ Unsafe blocks, unwrap() |
| Java | ✅ | ✅ Runtime.exec, deserialization, SQL injection |
| Ruby | ✅ | ✅ Eval, system, YAML.load |
| PHP | ✅ | ✅ Eval, system, SQL injection |
| C/C++ | ✅ | ✅ strcpy, sprintf, gets, scanf |
| Shell | ✅ | ✅ Eval, unquoted variables |
| Dockerfile | ✅ | ✅ Privileged mode, latest tag |
| Kubernetes | ✅ | ✅ Privilege escalation, hostNetwork |
| Terraform | ✅ | ✅ Public S3, unencrypted EBS |

## Cloud & Service Coverage

### Cloud Providers
AWS, Azure, GCP, DigitalOcean, Alibaba Cloud, Oracle Cloud, IBM Cloud

### Version Control
GitHub, GitLab, Bitbucket

### Communication
Slack, Discord, Mattermost

### Payment
Stripe, PayPal, Shopify

### AI/ML
OpenAI, Hugging Face, Anthropic

### DevOps
Docker, Kubernetes, Terraform, Ansible, Vault, CircleCI, Travis CI, Jenkins

### Databases
MongoDB, PostgreSQL, MySQL, Redis, SQLite, Cosmos DB

### Package Registries
npm, PyPI, RubyGems, Docker Hub

### And 30+ more services...

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

### Secrets (100+ patterns)
- AWS Access Keys & Secret Keys
- Azure Storage Keys & SAS Tokens
- GCP Service Account Keys
- GitHub/GitLab/Bitbucket Tokens
- Slack/Discord Webhooks
- Stripe/PayPal/Shopify Keys
- OpenAI/Hugging Face API Keys
- Docker/npm/PyPI Tokens
- Database Connection Strings
- JWT Tokens
- Private Keys (RSA, SSH, PGP, EC)
- And 80+ more...

### Vulnerabilities (49 patterns)
- SQL Injection (Python, Java, PHP, Go)
- Command Injection (Python, Java, Ruby, PHP, Go)
- Code Injection (eval, exec)
- XSS (JavaScript, TypeScript)
- Prototype Pollution
- Deserialization (pickle, yaml, Java ObjectInputStream)
- Buffer Overflows (C/C++ strcpy, sprintf, gets)
- Weak Cryptography (MD5, SHA1)
- Debug Mode in Production
- Docker/Kubernetes Misconfigurations
- Terraform Security Issues

### Bad Practices
- Bare except clauses
- Wildcard imports
- Mutable default arguments
- Deep nesting
- Magic numbers

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
