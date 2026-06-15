from __future__ import annotations

import stat
from pathlib import Path

PRE_COMMIT_HOOK = """#!/bin/sh
# GitGuard pre-commit hook
# Scans staged files for security issues

echo "Running GitGuard security scan..."

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "No staged files to scan."
    exit 0
fi

# Run gitguard scan on staged diff
DIFF=$(git diff --cached)
echo "$DIFF" | gitguard scan --diff --exit-code

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "GitGuard found security issues. Please fix them before committing."
    echo "To bypass this check, use: git commit --no-verify"
    exit 1
fi

echo "GitGuard: No security issues found."
exit 0
"""

PRE_PUSH_HOOK = """#!/bin/sh
# GitGuard pre-push hook
# Runs security scan before pushing

echo "Running GitGuard pre-push scan..."

DIFF=$(git diff origin/main...HEAD 2>/dev/null || git diff origin/master...HEAD 2>/dev/null || git log --pretty=format: --name-only HEAD~10..HEAD)

if [ -z "$DIFF" ]; then
    echo "No changes to scan."
    exit 0
fi

gitguard scan --path . --severity medium --exit-code

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "GitGuard found issues. Please fix before pushing."
    exit 1
fi

echo "GitGuard: All clear."
exit 0
"""

COMMIT_MSG_HOOK = """#!/bin/sh
# GitGuard commit message hook
# Validates commit message format

COMMIT_MSG_FILE=$1
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Check for secrets in commit message
if echo "$COMMIT_MSG" | grep -qiE "(password|secret|token|api.key|private.key)"; then
    echo "WARNING: Commit message may contain sensitive information."
    echo "Please review your commit message."
    exit 1
fi

# Check commit message length
FIRST_LINE=$(echo "$COMMIT_MSG" | head -n 1)
if [ ${#FIRST_LINE} -gt 72 ]; then
    echo "WARNING: First line of commit message is longer than 72 characters."
    echo "Consider shortening it."
fi

exit 0
"""


class GitHooksManager:
    """Manages git hooks for GitGuard integration."""

    def __init__(self, project_path: str | Path) -> None:
        self.project_path = Path(project_path).resolve()
        self.git_dir = self._find_git_dir()
        self.hooks_dir = self.git_dir / "hooks" if self.git_dir else None

    def install_hooks(self, hooks: list[str] | None = None) -> list[Path]:
        if not self.hooks_dir:
            raise RuntimeError("Not a git repository or .git directory not found")

        self.hooks_dir.mkdir(parents=True, exist_ok=True)

        installed: list[Path] = []
        hooks = hooks or ["pre-commit", "pre-push", "commit-msg"]

        hook_contents = {
            "pre-commit": PRE_COMMIT_HOOK,
            "pre-push": PRE_PUSH_HOOK,
            "commit-msg": COMMIT_MSG_HOOK,
        }

        for hook_name in hooks:
            if hook_name in hook_contents:
                hook_path = self.hooks_dir / hook_name
                hook_path.write_text(hook_contents[hook_name])
                hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
                installed.append(hook_path)

        return installed

    def uninstall_hooks(self, hooks: list[str] | None = None) -> list[Path]:
        if not self.hooks_dir:
            return []

        removed: list[Path] = []
        hooks = hooks or ["pre-commit", "pre-push", "commit-msg"]

        for hook_name in hooks:
            hook_path = self.hooks_dir / hook_name
            if hook_path.exists():
                try:
                    content = hook_path.read_text()
                    if "GitGuard" in content:
                        hook_path.unlink()
                        removed.append(hook_path)
                except (OSError, PermissionError):
                    pass

        return removed

    def list_hooks(self) -> dict[str, bool]:
        if not self.hooks_dir:
            return {}

        hooks = {}
        for hook_name in ["pre-commit", "pre-push", "commit-msg"]:
            hook_path = self.hooks_dir / hook_name
            if hook_path.exists():
                try:
                    content = hook_path.read_text()
                    hooks[hook_name] = "GitGuard" in content
                except (OSError, PermissionError):
                    hooks[hook_name] = False
            else:
                hooks[hook_name] = False

        return hooks

    def _find_git_dir(self) -> Path | None:
        current = self.project_path
        while current != current.parent:
            git_dir = current / ".git"
            if git_dir.exists():
                return git_dir
            current = current.parent

        git_dir = self.project_path / ".git"
        if git_dir.exists():
            return git_dir

        return None
