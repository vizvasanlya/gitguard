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
            "models": ["gpt-4", "gpt-4-turbo", "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo", "o1-preview", "o1-mini"],
            "env_key": "OPENAI_API_KEY",
            "default_base_url": "https://api.openai.com/v1",
            "api_format": "openai",
        },
        "anthropic": {
            "name": "Anthropic",
            "models": ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307", "claude-3.5-sonnet-20241022", "claude-3.5-haiku-20241022"],
            "env_key": "ANTHROPIC_API_KEY",
            "default_base_url": "https://api.anthropic.com/v1",
            "api_format": "anthropic",
        },
        "google": {
            "name": "Google Gemini",
            "models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"],
            "env_key": "GOOGLE_API_KEY",
            "default_base_url": "https://generativelanguage.googleapis.com/v1",
            "api_format": "google",
        },
        "groq": {
            "name": "Groq",
            "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
            "env_key": "GROQ_API_KEY",
            "default_base_url": "https://api.groq.com/openai/v1",
            "api_format": "openai",
        },
        "ollama": {
            "name": "Ollama (Local)",
            "models": ["llama3.2", "llama3.1", "llama3", "codellama", "mistral", "mixtral", "phi3", "gemma2", "qwen2.5", "deepseek-coder-v2"],
            "env_key": "",
            "default_base_url": "http://localhost:11434/v1",
            "api_format": "openai",
        },
        "together": {
            "name": "Together AI",
            "models": ["meta-llama/Llama-3.3-70B-Instruct-Turbo", "meta-llama/Llama-3.1-405B-Instruct-Turbo", "mistralai/Mixtral-8x22B-Instruct-v0.1", "Qwen/Qwen2.5-72B-Instruct-Turbo"],
            "env_key": "TOGETHER_API_KEY",
            "default_base_url": "https://api.together.xyz/v1",
            "api_format": "openai",
        },
        "fireworks": {
            "name": "Fireworks AI",
            "models": ["accounts/fireworks/models/llama-v3p3-70b-instruct", "accounts/fireworks/models/mixtral-8x22b-instruct", "accounts/fireworks/models/qwen-2.5-72b-instruct"],
            "env_key": "FIREWORKS_API_KEY",
            "default_base_url": "https://api.fireworks.ai/inference/v1",
            "api_format": "openai",
        },
        "deepseek": {
            "name": "DeepSeek",
            "models": ["deepseek-chat", "deepseek-reasoner"],
            "env_key": "DEEPSEEK_API_KEY",
            "default_base_url": "https://api.deepseek.com/v1",
            "api_format": "openai",
        },
        "azure": {
            "name": "Azure OpenAI",
            "models": ["gpt-4", "gpt-4-turbo", "gpt-4o", "gpt-35-turbo"],
            "env_key": "AZURE_OPENAI_API_KEY",
            "default_base_url": "",
            "api_format": "openai",
            "note": "Requires AZURE_OPENAI_ENDPOINT env var",
        },
        "openrouter": {
            "name": "OpenRouter",
            "models": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o", "meta-llama/llama-3.3-70b-instruct", "google/gemini-2.0-flash-001"],
            "env_key": "OPENROUTER_API_KEY",
            "default_base_url": "https://openrouter.ai/api/v1",
            "api_format": "openai",
        },
        "mistral": {
            "name": "Mistral AI",
            "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest", "codestral-latest", "open-mixtral-8x22b"],
            "env_key": "MISTRAL_API_KEY",
            "default_base_url": "https://api.mistral.ai/v1",
            "api_format": "openai",
        },
        "cohere": {
            "name": "Cohere",
            "models": ["command-r-plus", "command-r", "command-light"],
            "env_key": "COHERE_API_KEY",
            "default_base_url": "https://api.cohere.ai/v2",
            "api_format": "cohere",
        },
        "perplexity": {
            "name": "Perplexity",
            "models": ["llama-3.1-sonar-large-128k-online", "llama-3.1-sonar-small-128k-online"],
            "env_key": "PERPLEXITY_API_KEY",
            "default_base_url": "https://api.perplexity.ai",
            "api_format": "openai",
        },
        "lmstudio": {
            "name": "LM Studio",
            "models": [],
            "env_key": "",
            "default_base_url": "http://localhost:1234/v1",
            "api_format": "openai",
        },
        "llamacpp": {
            "name": "llama.cpp Server",
            "models": [],
            "env_key": "",
            "default_base_url": "http://localhost:8080/v1",
            "api_format": "openai",
        },
        "vllm": {
            "name": "vLLM Server",
            "models": [],
            "env_key": "",
            "default_base_url": "http://localhost:8000/v1",
            "api_format": "openai",
        },
        "text-generation-webui": {
            "name": "Text Generation WebUI",
            "models": [],
            "env_key": "",
            "default_base_url": "http://localhost:5000/v1",
            "api_format": "openai",
        },
        "custom": {
            "name": "Custom OpenAI-Compatible",
            "models": [],
            "env_key": "",
            "default_base_url": "",
            "api_format": "openai",
        },
    }

    def __init__(self, config: AIConfig | None = None) -> None:
        self.config = config or AIConfig()
        self._provider_info = self.PROVIDERS.get(self.config.provider, self.PROVIDERS.get("custom", {}))
        self._api_format = self._provider_info.get("api_format", "openai")
        self._api_url = ""
        self._headers: dict[str, str] = {}

        if self.config.enabled:
            self._setup_connection()

    def _setup_connection(self) -> None:
        api_key = self.config.get_api_key()
        base_url = self.config.get_base_url()

        if self._api_format == "anthropic":
            self._api_url = f"{base_url}/messages"
            self._headers = {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
        elif self._api_format == "google":
            model = self.config.model or "gemini-pro"
            self._api_url = f"{base_url}/models/{model}:generateContent"
            self._headers = {"Content-Type": "application/json"}
            if api_key:
                self._api_url += f"?key={api_key}"
        elif self._api_format == "cohere":
            self._api_url = f"{base_url}/chat"
            self._headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            }
        else:
            self._api_url = f"{base_url}/chat/completions"
            self._headers = {
                "Content-Type": "application/json",
            }
            if api_key:
                self._headers["Authorization"] = f"Bearer {api_key}"

    def review_code(self, file_path: Path, content: str) -> AIReviewResult:
        if not self.config.enabled:
            return self._disabled_result()

        prompt = self._build_review_prompt(file_path, content)
        response = self._call_llm(prompt)
        return self._parse_review_response(response, file_path)

    def review_diff(self, diff_content: str) -> AIReviewResult:
        if not self.config.enabled:
            return self._disabled_result()

        prompt = self._build_diff_prompt(diff_content)
        response = self._call_llm(prompt)
        return self._parse_review_response(response, Path("diff"))

    def explain_finding(self, finding: Finding, context: str = "") -> str:
        if not self.config.enabled:
            return "AI disabled. Enable in .gitguard.json: {\"ai\": {\"enabled\": true}}"

        prompt = self._build_explain_prompt(finding, context)
        return self._call_llm(prompt)

    def suggest_fix(self, finding: Finding, content: str) -> str:
        if not self.config.enabled:
            return "AI disabled. Enable in .gitguard.json: {\"ai\": {\"enabled\": true}}"

        prompt = self._build_fix_prompt(finding, content)
        return self._call_llm(prompt)

    def _disabled_result(self) -> AIReviewResult:
        return AIReviewResult(
            summary="AI review disabled. Enable in .gitguard.json under 'ai' section.",
            findings=[],
            suggestions=[
                "Enable AI: gitguard ai-config --enabled",
                "Or add to .gitguard.json: {\"ai\": {\"enabled\": true, \"provider\": \"ollama\"}}",
            ],
            risk_score=0,
        )

    def _build_review_prompt(self, file_path: Path, content: str) -> str:
        return f"""You are a security expert reviewing code. Analyze for vulnerabilities, secrets, and bad practices.

File: {file_path.name}
Content:
```
{content[:4000]}
```

Respond in JSON:
{{
    "summary": "Brief security assessment",
    "risk_score": 0-100,
    "findings": [
        {{"severity": "critical|high|medium|low|info", "message": "Description", "line": 1, "suggestion": "How to fix"}}
    ],
    "suggestions": ["Improvement suggestions"]
}}"""

    def _build_diff_prompt(self, diff: str) -> str:
        return f"""You are a security expert reviewing a git diff. Identify security issues.

Diff:
```
{diff[:4000]}
```

Respond in JSON:
{{
    "summary": "Security assessment",
    "risk_score": 0-100,
    "findings": [
        {{"severity": "critical|high|medium|low|info", "message": "Description", "file": "file.py", "line": 1, "suggestion": "How to fix"}}
    ],
    "suggestions": ["Suggestions"]
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
        return f"""Suggest a fix for this security issue. Provide corrected code.

Issue: {finding.message}
Rule: {finding.rule_id}
Line {finding.line_number}: {finding.line_content}

File context:
```
{content[:3000]}
```

Provide:
1. The exact code change needed
2. Explanation of the fix
3. Alternative approaches"""

    def _call_llm(self, prompt: str) -> str:
        api_key = self.config.get_api_key()
        if not api_key and self.config.provider not in ("ollama", "lmstudio", "llamacpp", "vllm", "text-generation-webui", "local"):
            return json.dumps({
                "summary": f"AI requires API key for {self.config.provider}",
                "risk_score": 0,
                "findings": [],
                "suggestions": [
                    f"Set environment variable: {self._provider_info.get('env_key', 'API_KEY')}=your-key",
                    "Or add to .gitguard.json: {\"ai\": {\"api_key\": \"your-key\"}}",
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
                "summary": f"AI error: {e}",
                "risk_score": 0,
                "findings": [],
                "suggestions": [f"Check {self.config.provider} API key and connection"],
            })

    def _build_payload(self, prompt: str) -> dict[str, Any]:
        if self._api_format == "anthropic":
            return {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
        elif self._api_format == "google":
            return {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": self.config.max_tokens,
                    "temperature": self.config.temperature,
                },
            }
        elif self._api_format == "cohere":
            return {
                "model": self.config.model,
                "message": prompt,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            }
        else:
            payload: dict[str, Any] = {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            }
            return payload

    def _extract_response(self, data: dict[str, Any]) -> str:
        if self._api_format == "anthropic":
            content = data.get("content", [])
            if content and isinstance(content, list):
                return str(content[0].get("text", ""))
            return str(data)
        elif self._api_format == "google":
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return str(parts[0].get("text", ""))
            return str(data)
        elif self._api_format == "cohere":
            return str(data.get("message", {}).get("content", ""))
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
