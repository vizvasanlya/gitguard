# GitGuard

> AI-powered git security scanner that detects secrets, vulnerabilities, and fixes your code automatically

## What is this?

GitGuard is a security scanner for your codebase. It finds:
- **Secrets** (API keys, passwords, tokens) in 100+ patterns
- **Vulnerabilities** (SQL injection, command injection, XSS) in 49 patterns
- **Bad practices** across 12 programming languages

And it can **fix** many of these issues automatically.

## Quick Start

```bash
pip install gitguard
gitguard scan .
```

## Features

- **100+ secret patterns** — AWS, Azure, GCP, GitHub, Stripe, OpenAI, and 50+ services
- **49 vulnerability patterns** — SQL injection, command injection, XSS, and more
- **12 languages** — Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, PHP, C/C++, Shell, Docker, K8s
- **Auto-fix** — Automatically fix 11 common security issues
- **AI review** — LLM-powered code review with 18 providers
- **Git history** — Find secrets leaked in old commits
- **SARIF output** — Integrates with GitHub Security tab
- **SBOM** — Generate Software Bill of Materials
- **NVD** — Check dependencies against CVE database
- **Dashboard** — Web UI for security overview
- **Notifications** — Slack and Discord alerts
- **VS Code** — Real-time security scanning
- **Homebrew** — Install with `brew install gitguard`

## Commands

| Command | Description |
|---------|-------------|
| `gitguard scan .` | Scan for security issues |
| `gitguard fix .` | Auto-fix common issues |
| `gitguard review file.py` | AI-powered code review |
| `gitguard history .` | Scan git history for secrets |
| `gitguard sarif .` | Generate SARIF for GitHub |
| `gitguard sbom .` | Generate SBOM |
| `gitguard nvd .` | Check NVD vulnerabilities |
| `gitguard explain RULE` | Explain a security rule |
| `gitguard dashboard` | Launch web dashboard |
| `gitguard ai-config` | Configure AI settings |

## AI Configuration

GitGuard supports 18 AI providers:

```json
{
  "ai": {
    "enabled": true,
    "provider": "openai",
    "model": "gpt-4"
  }
}
```

Providers: OpenAI, Anthropic, Google, Groq, Ollama, Together AI, Fireworks AI, DeepSeek, Azure, OpenRouter, Mistral, Cohere, Perplexity, LM Studio, llama.cpp, vLLM, Text Generation WebUI, Custom

## License

MIT
