from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class AIReviewResult:
    summary: str
    findings: list[Finding]
    suggestions: list[str]
    risk_score: float
    raw_response: str = ""


class AIReviewer:
    """AI-powered code review using LLM APIs."""

    def __init__(self, api_key: str | None = None, model: str = "gpt-4", base_url: str | None = None) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url or "https://api.openai.com/v1"

    def review_code(self, file_path: Path, content: str) -> AIReviewResult:
        prompt = self._build_review_prompt(file_path, content)
        response = self._call_llm(prompt)
        return self._parse_review_response(response, file_path)

    def review_diff(self, diff_content: str) -> AIReviewResult:
        prompt = self._build_diff_prompt(diff_content)
        response = self._call_llm(prompt)
        return self._parse_review_response(response, Path("diff"))

    def explain_finding(self, finding: Finding, context: str = "") -> str:
        prompt = self._build_explain_prompt(finding, context)
        return self._call_llm(prompt)

    def suggest_fix(self, finding: Finding, content: str) -> str:
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
        if not self.api_key:
            return self._mock_response(prompt)

        try:
            import urllib.error
            import urllib.request

            url = f"{self.base_url}/chat/completions"
            payload = json.dumps({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 2000,
            }).encode()

            req = urllib.request.Request(url, data=payload, headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            })

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                return str(data["choices"][0]["message"]["content"])

        except Exception as e:
            return f"Error calling LLM: {e}"

    def _mock_response(self, prompt: str) -> str:
        return json.dumps({
            "summary": "AI review requires API key configuration. Set GITGUARD_API_KEY environment variable.",
            "risk_score": 0,
            "findings": [],
            "suggestions": ["Configure API key for AI-powered reviews: export GITGUARD_API_KEY=your-key"],
        })

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
