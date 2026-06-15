from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, str | int | list[str] | bool] = {
    "severity_threshold": "low",
    "include_secrets": True,
    "include_vulnerabilities": True,
    "include_bad_patterns": True,
    "include_license_check": True,
    "include_dependency_audit": True,
    "ignore_dirs": ["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"],
    "ignore_files": ["*.pyc", "*.pyo", "*.pyd", "*.so", "*.dylib"],
    "allowed_licenses": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
    "auto_install_hooks": False,
}


@dataclass
class Config:
    severity_threshold: str = "low"
    include_secrets: bool = True
    include_vulnerabilities: bool = True
    include_bad_patterns: bool = True
    include_license_check: bool = True
    include_dependency_audit: bool = True
    ignore_dirs: list[str] = field(default_factory=lambda: ["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"])
    ignore_files: list[str] = field(default_factory=lambda: ["*.pyc", "*.pyo", "*.pyd", "*.so", "*.dylib"])
    allowed_licenses: list[str] = field(default_factory=lambda: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"])
    auto_install_hooks: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        return cls(
            severity_threshold=data.get("severity_threshold", "low"),
            include_secrets=data.get("include_secrets", True),
            include_vulnerabilities=data.get("include_vulnerabilities", True),
            include_bad_patterns=data.get("include_bad_patterns", True),
            include_license_check=data.get("include_license_check", True),
            include_dependency_audit=data.get("include_dependency_audit", True),
            ignore_dirs=data.get("ignore_dirs", DEFAULT_CONFIG["ignore_dirs"]),
            ignore_files=data.get("ignore_files", DEFAULT_CONFIG["ignore_files"]),
            allowed_licenses=data.get("allowed_licenses", DEFAULT_CONFIG["allowed_licenses"]),
            auto_install_hooks=data.get("auto_install_hooks", False),
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
