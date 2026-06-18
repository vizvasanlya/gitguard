from __future__ import annotations

import ast
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


class ASTAnalyzer:
    """AST-based code analysis for Python files."""

    def analyze_file(self, file_path: Path, content: str) -> list[Finding]:
        if file_path.suffix != ".py":
            return []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            findings.extend(self._check_node(node, file_path, lines))

        return findings

    def _check_node(self, node: ast.AST, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        if isinstance(node, ast.Call):
            findings.extend(self._check_function_call(node, file_path, lines))

        if isinstance(node, ast.Import):
            findings.extend(self._check_import(node, file_path, lines))

        if isinstance(node, ast.ImportFrom):
            findings.extend(self._check_import_from(node, file_path, lines))

        if isinstance(node, ast.FunctionDef):
            findings.extend(self._check_function_def(node, file_path, lines))

        if isinstance(node, ast.ClassDef):
            findings.extend(self._check_class_def(node, file_path, lines))

        if isinstance(node, ast.Assign):
            findings.extend(self._check_assignment(node, file_path, lines))

        return findings

    def _check_function_call(self, node: ast.Call, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        else:
            return findings

        line_num = getattr(node, "lineno", 0)
        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        dangerous_funcs = {
            "eval": ("VUL005", Severity.HIGH, "eval() usage - potential code injection"),
            "exec": ("VUL006", Severity.HIGH, "exec() usage - potential code injection"),
            "compile": ("INFO", Severity.LOW, "compile() usage - review for security"),
            "getattr": ("INFO", Severity.LOW, "getattr() usage - review for security"),
            "setattr": ("INFO", Severity.LOW, "setattr() usage - review for security"),
            "delattr": ("INFO", Severity.LOW, "delattr() usage - review for security"),
            "input": ("INFO", Severity.LOW, "input() usage - review for security"),
            "open": ("INFO", Severity.LOW, "open() usage - review path traversal"),
            "__import__": ("VUL005", Severity.HIGH, "__import__() usage - potential code injection"),
            "globals": ("INFO", Severity.LOW, "globals() usage - review for security"),
            "locals": ("INFO", Severity.LOW, "locals() usage - review for security"),
            "vars": ("INFO", Severity.LOW, "vars() usage - review for security"),
            "dir": ("INFO", Severity.LOW, "dir() usage - review for security"),
            "type": ("INFO", Severity.LOW, "type() usage - use isinstance() instead"),
            "repr": ("INFO", Severity.LOW, "repr() usage - review for security"),
        }

        if func_name in dangerous_funcs:
            rule_id, severity, message = dangerous_funcs[func_name]
            findings.append(Finding(
                finding_type=FindingType.SECURITY,
                severity=severity,
                message=message,
                file_path=file_path,
                line_number=line_num,
                line_content=line_content[:120],
                rule_id=rule_id,
                suggestion=f"Review {func_name}() usage for security",
            ))

        if func_name == "os" and isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                findings.append(Finding(
                    finding_type=FindingType.VULNERABILITY,
                    severity=Severity.HIGH,
                    message="os.system() usage - potential command injection",
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line_content[:120],
                    rule_id="VUL003",
                    suggestion="Use subprocess.run() instead",
                ))

        return findings

    def _check_import(self, node: ast.Import, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        line_num = getattr(node, "lineno", 0)
        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        dangerous_imports = {
            "pickle": ("VUL008", Severity.HIGH, "pickle module - potential deserialization attack"),
            "shelve": ("VUL008", Severity.HIGH, "shelve module - potential deserialization attack"),
            "marshal": ("VUL008", Severity.HIGH, "marshal module - potential deserialization attack"),
            "subprocess": ("INFO", Severity.LOW, "subprocess module - review for command injection"),
            "os": ("INFO", Severity.LOW, "os module - review for path traversal"),
            "sys": ("INFO", Severity.LOW, "sys module - review for security"),
            "socket": ("INFO", Severity.LOW, "socket module - review for network security"),
            "ctypes": ("VUL005", Severity.HIGH, "ctypes module - potential memory safety issues"),
            "ctypes.util": ("VUL005", Severity.HIGH, "ctypes.util - potential memory safety issues"),
        }

        for alias in node.names:
            module_name = alias.name
            if module_name in dangerous_imports:
                rule_id, severity, message = dangerous_imports[module_name]
                findings.append(Finding(
                    finding_type=FindingType.SECURITY,
                    severity=severity,
                    message=message,
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line_content[:120],
                    rule_id=rule_id,
                    suggestion=f"Review {module_name} import for security",
                ))

        return findings

    def _check_import_from(self, node: ast.ImportFrom, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        line_num = getattr(node, "lineno", 0)
        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        if node.module and node.names:
            for alias in node.names:
                if alias.name == "*":
                    findings.append(Finding(
                        finding_type=FindingType.BAD_PRACTICE,
                        severity=Severity.MEDIUM,
                        message=f"Wildcard import from {node.module}",
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_content[:120],
                        rule_id="BP007",
                        suggestion="Use explicit imports instead",
                    ))

        return findings

    def _check_function_def(self, node: ast.FunctionDef, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        line_num = getattr(node, "lineno", 0)
        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                findings.append(Finding(
                    finding_type=FindingType.BAD_PRACTICE,
                    severity=Severity.MEDIUM,
                    message=f"Mutable default argument in {node.name}()",
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line_content[:120],
                    rule_id="BP008",
                    suggestion="Use None as default and initialize in function body",
                ))
                break

        if node.args.args:
            first_arg = node.args.args[0]
            if first_arg.arg == "self" or not first_arg.arg.startswith("_"):
                pass

        return findings

    def _check_class_def(self, node: ast.ClassDef, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        has_init = any(
            isinstance(item, ast.FunctionDef) and item.name == "__init__"
            for item in node.body
        )

        if not has_init and not any(
            isinstance(item, ast.FunctionDef)
            for item in node.body
        ):
            pass

        return findings

    def _check_assignment(self, node: ast.Assign, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        line_num = getattr(node, "lineno", 0)
        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id

                dangerous_vars = {
                    "DEBUG": ("VUL011", Severity.MEDIUM, "DEBUG variable set to potentially insecure value"),
                    "SECRET_KEY": ("SEC016", Severity.HIGH, "SECRET_KEY variable detected"),
                    "PASSWORD": ("SEC016", Severity.HIGH, "PASSWORD variable detected"),
                    "API_KEY": ("SEC015", Severity.HIGH, "API_KEY variable detected"),
                    "TOKEN": ("SEC019", Severity.HIGH, "TOKEN variable detected"),
                    "PRIVATE_KEY": ("SEC012", Severity.CRITICAL, "PRIVATE_KEY variable detected"),
                }

                upper_name = var_name.upper()
                if upper_name in dangerous_vars:
                    rule_id, severity, message = dangerous_vars[upper_name]
                    findings.append(Finding(
                        finding_type=FindingType.SECURITY,
                        severity=severity,
                        message=message,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_content[:120],
                        rule_id=rule_id,
                        suggestion=f"Review {var_name} assignment for security",
                    ))

        return findings
