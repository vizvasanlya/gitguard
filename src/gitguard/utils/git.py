from __future__ import annotations

import subprocess
from pathlib import Path


def is_git_repo(path: Path | None = None) -> bool:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_repo_root(path: Path | None = None) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=5,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def get_staged_diff(path: Path | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=30,
        )
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def get_unstaged_diff(path: Path | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "diff"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=30,
        )
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def get_full_diff(path: Path | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "diff", "HEAD"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=30,
        )
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def get_staged_files(path: Path | None = None) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=10,
        )
        if result.returncode == 0:
            return [f for f in result.stdout.strip().splitlines() if f]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return []


def get_last_commit_message(path: Path | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--pretty=%B"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=5,
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def stage_file(file_path: str | Path, cwd: Path | None = None) -> bool:
    try:
        result = subprocess.run(
            ["git", "add", str(file_path)],
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_branch_name(path: Path | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            cwd=path,
            timeout=5,
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"
