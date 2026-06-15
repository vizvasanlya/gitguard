from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_IGNORE_DIRS = ["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"]
DEFAULT_IGNORE_FILES = ["*.pyc", "*.pyo", "*.pyd", "*.so", "*.dylib"]
DEFAULT_ALLOWED_LICENSES = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"]


@dataclass
class AIConfig:
    provider: str = "openai"
    model: str = "gpt-4"
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 4000
    temperature: float = 0.3
    enabled: bool = False

    def get_api_key(self) -> str:
        if self.api_key:
            return self.api_key

        env_keys = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "google": "GOOGLE_API_KEY",
            "azure": "AZURE_OPENAI_API_KEY",
            "ollama": "",
            "local": "",
            "groq": "GROQ_API_KEY",
            "together": "TOGETHER_API_KEY",
            "fireworks": "FIREWORKS_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
        }

        env_key = env_keys.get(self.provider, "")
        if env_key:
            return os.environ.get(env_key, "")
        return ""

    def get_base_url(self) -> str:
        if self.base_url:
            return self.base_url

        base_urls = {
            "openai": "https://api.openai.com/v1",
            "anthropic": "https://api.anthropic.com/v1",
            "google": "https://generativelanguage.googleapis.com/v1",
            "ollama": "http://localhost:11434/v1",
            "groq": "https://api.groq.com/openai/v1",
            "together": "https://api.together.xyz/v1",
            "fireworks": "https://api.fireworks.ai/inference/v1",
            "deepseek": "https://api.deepseek.com/v1",
            "local": "http://localhost:11434/v1",
        }

        return base_urls.get(self.provider, "https://api.openai.com/v1")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AIConfig:
        return cls(
            provider=data.get("provider", "openai"),
            model=data.get("model", "gpt-4"),
            api_key=data.get("api_key", ""),
            base_url=data.get("base_url", ""),
            max_tokens=data.get("max_tokens", 4000),
            temperature=data.get("temperature", 0.3),
            enabled=data.get("enabled", False),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "api_key": self.api_key,
            "base_url": self.base_url,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "enabled": self.enabled,
        }


@dataclass
class NotificationConfig:
    slack_webhook: str = ""
    discord_webhook: str = ""
    notify_on: str = "high"
    enabled: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NotificationConfig:
        return cls(
            slack_webhook=data.get("slack_webhook", ""),
            discord_webhook=data.get("discord_webhook", ""),
            notify_on=data.get("notify_on", "high"),
            enabled=data.get("enabled", False),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "slack_webhook": self.slack_webhook,
            "discord_webhook": self.discord_webhook,
            "notify_on": self.notify_on,
            "enabled": self.enabled,
        }


@dataclass
class Config:
    severity_threshold: str = "low"
    include_secrets: bool = True
    include_vulnerabilities: bool = True
    include_bad_patterns: bool = True
    include_license_check: bool = True
    include_dependency_audit: bool = True
    ignore_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_DIRS))
    ignore_files: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_FILES))
    allowed_licenses: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_LICENSES))
    auto_install_hooks: bool = False
    ai: AIConfig = field(default_factory=AIConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        ai_data = data.get("ai", {})
        notif_data = data.get("notifications", {})

        return cls(
            severity_threshold=data.get("severity_threshold", "low"),
            include_secrets=data.get("include_secrets", True),
            include_vulnerabilities=data.get("include_vulnerabilities", True),
            include_bad_patterns=data.get("include_bad_patterns", True),
            include_license_check=data.get("include_license_check", True),
            include_dependency_audit=data.get("include_dependency_audit", True),
            ignore_dirs=data.get("ignore_dirs", DEFAULT_IGNORE_DIRS),
            ignore_files=data.get("ignore_files", DEFAULT_IGNORE_FILES),
            allowed_licenses=data.get("allowed_licenses", DEFAULT_ALLOWED_LICENSES),
            auto_install_hooks=data.get("auto_install_hooks", False),
            ai=AIConfig.from_dict(ai_data) if ai_data else AIConfig(),
            notifications=NotificationConfig.from_dict(notif_data) if notif_data else NotificationConfig(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity_threshold": self.severity_threshold,
            "include_secrets": self.include_secrets,
            "include_vulnerabilities": self.include_vulnerabilities,
            "include_bad_patterns": self.include_bad_patterns,
            "include_license_check": self.include_license_check,
            "include_dependency_audit": self.include_dependency_audit,
            "ignore_dirs": self.ignore_dirs,
            "ignore_files": self.ignore_files,
            "allowed_licenses": self.allowed_licenses,
            "auto_install_hooks": self.auto_install_hooks,
            "ai": self.ai.to_dict(),
            "notifications": self.notifications.to_dict(),
        }


_config: Config | None = None


def get_config(project_path: Path | None = None) -> Config:
    global _config
    if _config is not None:
        return _config

    config_file = _find_config_file(project_path)
    if config_file and config_file.exists():
        try:
            data = json.loads(config_file.read_text())
            _config = Config.from_dict(data)
            return _config
        except (json.JSONDecodeError, OSError):
            pass

    _config = Config()
    return _config


def reset_config() -> None:
    global _config
    _config = None


def _find_config_file(project_path: Path | None = None) -> Path | None:
    if project_path is None:
        project_path = Path.cwd()

    candidates = [
        project_path / ".gitguard.json",
        project_path / ".gitguard" / "config.json",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    home = Path.home()
    home_config = home / ".gitguard" / "config.json"
    if home_config.exists():
        return home_config

    return None
