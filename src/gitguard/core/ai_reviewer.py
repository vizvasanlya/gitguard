from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gitguard.core.models import Finding, FindingType, Severity
from gitguard.utils.config import AIConfig


@dataclass
class AIReviewResult:
    summary: str
    findings: list[Finding]
    suggestions: list[str]
    risk_score: float
    raw_response: str = ""


class AIReviewer:
    """AI-powered code review supporting multiple LLM providers."""

    PROVIDERS = {
        "openai": {
            "name": "OpenAI",
            "models": ["gpt-4", "gpt-4-turbo", "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
            "env_key": "OPENAI_API_KEY",
            "base_url": "https://api.openai.com/v1",
        },
        "anthropic": {
            "name": "Anthropic",
            "models": ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku", "claude-3.5-sonnet"],
            "env_key": "ANTHROPIC_API_KEY",
            "base_url": "https://api.anthropic.com/v1",
        },
        "google": {
            "name": "Google",
            "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"],
            "env_key": "GOOGLE_API_KEY",
            "base_url": "https://generativelanguage.googleapis.com/v1",
        },
        "groq": {
            "name": "Groq",
            "models": ["llama-3-70b-8192", "mixtral-8x7b-32768", "gemma-7b-it"],
            "env_key": "GROQ_API_KEY",
            "base_url": "https://api.groq.com/openai/v1",
        },
        "ollama": {
            "name": "Ollama (Local)",
            "models": ["llama3", "codellama", "mistral", "mixtral", "phi3"],
            "env_key": "",
            "base_url": "http://localhost:11434/v1",
        },
        "together": {
            "name": "Together AI",
            "models": ["meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
            "env_key": "TOGETHER_API_KEY",
            "base_url": "https://api.together.xyz/v1",
        },
        "fireworks": {
            "name": "Fireworks AI",
            "models": ["accounts/fireworks/models/llama-v3-70b", "accounts/fireworks/models/mixtral-8x7b"],
            "env_key": "FIREWORKS_API_KEY",
            "base_url": "https://api.fireworks.ai/inference/v1",
        },
        "deepseek": {
            "name": "DeepSeek",
            "models": ["deepseek-chat", "deepseek-coder"],
            "env_key": "DEEPSEEK_API_KEY",
            "base_url": "https://api.deepseek.com/v1",
        },
        "azure": {
            "name": "Azure OpenAI",
            "models": ["gpt-4", "gpt-35-turbo"],
            "env_key": "AZURE_OPENAI_API_KEY",
            "base_url": "",
        },
        "local": {
            "name": "Local (LM Studio/llama.cpp)",
            "models": ["any"],
            "env_key": "",
            "base_url": "http://localhost:1234/v1",
        },
    }

    def __init__(self, config: AIConfig | None = None) -> None:
        self.config = config or AIConfig()
        if not self.config.enabled:
            return

        api_key = self.config.get_api_key()
        base_url = self.config.get_base_url()

        self._headers: dict[str, str] = {}
        self._api_url = ""

        if self.config.provider == "anthropic":
            self._api_url = f"{base_url}/messages"
            self._headers = {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
        elif self.config.provider == "google":
            self._api_url = f"{base_url}/models/{self.config.model}:generateContent?key={api_key}"
            self._headers = {"Content-Type": "application/json"}
        else:
            self._api_url = f"{base_url}/chat/completions"
            self._headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            }

    def review_code(self, file_path: Path, content: str) -> AIReviewResult:
        if not self.config.enabled:
            return AIReviewResult(
                summary="AI review disabled. Enable in .gitguard.json under 'ai' section.",
                findings=[],
                suggestions=["Enable AI review: set 'ai.enabled' to true in .gitguard.json"],
                risk_score=0,
            )

        prompt = self._build_review_prompt(file_path, content)
        response = self._call_llm(prompt)
        return self._parse_review_response(response, file_path)

    def review_diff(self, diff_content: str) -> AIReviewResult:
        if not self.config.enabled:
            return AIReviewResult(
                summary="AI review disabled.",
                findings=[],
                suggestions=["Enable AI review in .gitguard.json"],
                risk_score=0,
            )

        prompt = self._build_diff_prompt(diff_content)
        response = self._call_llm(prompt)
        return self._parse_review_response(response, Path("diff"))

    def explain_finding(self, finding: Finding, context: str = "") -> str:
        if not self.config.enabled:
            return "AI explanations disabled. Enable in .gitguard.json under 'ai' section."

        prompt = self._build_explain_prompt(finding, context)
        return self._call_llm(prompt)

    def suggest_fix(self, finding: Finding, content: str) -> str:
        if not self.config.enabled:
            return "AI suggestions disabled. Enable in .gitguard.json under 'ai' section."

        prompt = self._build_fix_prompt(finding, content)
        return self._call_llm(prompt)

    def _build_review_prompt(self, file_path: Path, content: str) -> str:
        return f"""You are a security expert reviewing code. Analyze this file for security vulnerabilities, secrets, and bad practices.

File: {file_path.name}
Content:
```
{content[:4000]}
```

Respond in JSON format:
{{
    "summary": "Brief security assessment",
    "risk_score": 0-100,
    "findings": [
        {{
            "severity": "critical|high|medium|low|info",
            "message": "Description of issue",
            "line": line_number,
            "suggestion": "How to fix"
        }}
    ],
    "suggestions": ["General improvement suggestions"]
}}"""

    def _build_diff_prompt(self, diff: str) -> str:
        return f"""You are a security expert reviewing a git diff. Identify any security issues in the changes.

Diff:
```
{diff[:4000]}
```

Respond in JSON format:
{{
    "summary": "Security assessment of changes",
    "risk_score": 0-100,
    "findings": [
        {{
            "severity": "critical|high|medium|low|info",
            "message": "Description of issue",
            "file": "filename",
            "line": line_number,
            "suggestion": "How to fix"
        }}
    ],
    "suggestions": ["General improvement suggestions"]
}}"""

    def _build_explain_prompt(self, finding: Finding, context: str) -> str:
        return f"""Explain this security finding in detail. Why is it dangerous? How could it be exploited?

Finding: {finding.message}
Rule: {finding.rule_id}
Severity: {finding.severity.value}
Code: {finding.line_content}
{f"Context: {context}" if context else ""}

Provide:
1. What the vulnerability is
2. Why it's dangerous
3. Real-world attack scenarios
4. How to fix it"""

    def _build_fix_prompt(self, finding: Finding, content: str) -> str:
        return f"""Suggest a fix for this security issue. Provide the corrected code.

Issue: {finding.message}
Rule: {finding.rule_id}
Line {finding.line_number}: {finding.line_content}

Full file context:
```
{content[:3000]}
```

Provide:
1. The exact code change needed
2. Explanation of the fix
3. Any alternative approaches"""

    def _call_llm(self, prompt: str) -> str:
        api_key = self.config.get_api_key()
        if not api_key and self.config.provider not in ("ollama", "local"):
            return json.dumps({
                "summary": "AI review requires API key. Set environment variable or add to .gitguard.json",
                "risk_score": 0,
                "findings": [],
                "suggestions": [
                    f"Configure {self.config.provider}: add 'ai' section to .gitguard.json",
                    f"Or set environment variable: export {self.PROVIDERS.get(self.config.provider, {}).get('env_key', 'API_KEY')}=your-key"
                ],
            })

        try:
            import urllib.request

            payload = self._build_payload(prompt)
            data = json.dumps(payload).encode()

            req = urllib.request.Request(
                self._api_url,
                data=data,
                headers=self._headers,
            )

            with urllib.request.urlopen(req, timeout=60) as resp:
                response_data = json.loads(resp.read().decode())
                return self._extract_response(response_data)

        except Exception as e:
            return json.dumps({
                "summary": f"AI review failed: {e}",
                "risk_score": 0,
                "findings": [],
                "suggestions": [f"Check your {self.config.provider} API key and network connection"],
            })

    def _build_payload(self, prompt: str) -> dict[str, Any]:
        if self.config.provider == "anthropic":
            return {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
        elif self.config.provider == "google":
            return {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": self.config.max_tokens,
                    "temperature": self.config.temperature,
                },
            }
        else:
            return {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            }

    def _extract_response(self, data: dict[str, Any]) -> str:
        if self.config.provider == "anthropic":
            content = data.get("content", [])
            if content and isinstance(content, list):
                return str(content[0].get("text", ""))
            return str(data)
        elif self.config.provider == "google":
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return str(parts[0].get("text", ""))
            return str(data)
        else:
            choices = data.get("choices", [])
            if choices:
                return str(choices[0].get("message", {}).get("content", ""))
            return str(data)

    def _parse_review_response(self, response: str, file_path: Path) -> AIReviewResult:
        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            return AIReviewResult(
                summary=response[:500],
                findings=[],
                suggestions=[],
                risk_score=0,
                raw_response=response,
            )

        findings: list[Finding] = []
        for f in data.get("findings", []):
            findings.append(
                Finding(
                    finding_type=FindingType.SECURITY,
                    severity=Severity(f.get("severity", "medium")),
                    message=f.get("message", ""),
                    file_path=Path(f.get("file", str(file_path))),
                    line_number=f.get("line", 0),
                    line_content="",
                    rule_id="AI001",
                    suggestion=f.get("suggestion", ""),
                )
            )

        return AIReviewResult(
            summary=data.get("summary", ""),
            findings=findings,
            suggestions=data.get("suggestions", []),
            risk_score=data.get("risk_score", 0),
            raw_response=response,
        )

    @classmethod
    def list_providers(cls) -> dict[str, dict[str, Any]]:
        return cls.PROVIDERS

    @classmethod
    def list_models(cls, provider: str) -> list[str]:
        provider_info = cls.PROVIDERS.get(provider, {})
        return list(provider_info.get("models", []))
