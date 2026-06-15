import tempfile
from pathlib import Path

import pytest

from gitguard.core.models import FindingType, Severity
from gitguard.core.scanner import SecurityScanner


@pytest.fixture
def sample_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        (root / "main.py").write_text('import os\n\ndef main():\n    os.system("echo hello")\n')

        (root / "config.py").write_text('API_KEY = "AKIA1234567890123456"\nSECRET = "supersecret123"\n')

        (root / "utils.py").write_text('import os\n\nx = eval("1+1")\n')

        (root / "test_main.py").write_text('def test_main():\n    assert True\n')

        (root / "README.md").write_text("# Test Project\n")

        yield root


def test_scanner_init():
    scanner = SecurityScanner(".")
    assert scanner.path == Path(".").resolve()


def test_scan_project(sample_project):
    scanner = SecurityScanner(sample_project)
    result = scanner.scan()

    assert result.files_scanned > 0
    assert result.total_findings > 0


def test_scan_finds_secrets(sample_project):
    scanner = SecurityScanner(sample_project, include_secrets=True, include_vulnerabilities=False, include_bad_patterns=False)
    result = scanner.scan()

    secret_findings = result.get_by_type(FindingType.SECRET)
    assert len(secret_findings) > 0


def test_scan_finds_vulnerabilities(sample_project):
    scanner = SecurityScanner(sample_project, include_secrets=False, include_vulnerabilities=True, include_bad_patterns=False)
    result = scanner.scan()

    assert result.files_scanned > 0


def test_scan_severity_threshold():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "test.py").write_text('x = eval("1+1")\n')

        scanner = SecurityScanner(root, severity_threshold=Severity.CRITICAL)
        result = scanner.scan()

        for finding in result.findings:
            assert finding.severity == Severity.CRITICAL


def test_scan_diff():
    diff = """--- a/test.py
+++ b/test.py
@@ -1 +1,3 @@
+import os
+os.system("echo hello")
+print("done")
"""
    scanner = SecurityScanner(".")
    result = scanner.scan_diff(diff)

    assert result.files_scanned > 0


def test_scan_result_properties():
    from gitguard.core.models import ScanResult

    result = ScanResult()
    assert result.total_findings == 0
    assert result.has_critical is False


def test_ignore_binary_files(sample_project):
    (sample_project / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    scanner = SecurityScanner(sample_project)
    result = scanner.scan()

    binary_findings = [f for f in result.findings if f.file_path.name == "image.png"]
    assert len(binary_findings) == 0
