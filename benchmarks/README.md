# GitGuard Benchmarks

> Performance and detection benchmarks — coming soon after real-world testing

## Planned Tests

### Test Repositories
1. django/django - Python web framework
2. expressjs/express - Node.js web framework
3. golang/go - Go standard library
4. rust-lang/rust - Rust compiler
5. spring-projects/spring-boot - Java framework
6. kubernetes/kubernetes - Container orchestration
7. hashicorp/terraform - Infrastructure as Code

### Metrics to Measure
- Secret detection accuracy (true positives, false positives)
- Vulnerability detection coverage
- Scan time (1K, 10K, 100K files)
- Memory usage
- CPU usage
- Comparison vs Gitleaks, TruffleHog, Semgrep

## How to Run Benchmarks

```bash
# Install all tools
pip install gitguard
brew install gitleaks
brew install trufflehog

# Clone test repo
git clone https://github.com/django/django
cd django

# GitGuard
time gitguard scan .

# Gitleaks
time gitleaks detect .

# TruffleHog
time trufflehog git file://.
```

## Contributing Benchmarks

If you run benchmarks, please submit a PR with your results:
1. Include hardware specs
2. Include tool versions
3. Include raw data
4. Include methodology
