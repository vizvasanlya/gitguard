import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from gitguard.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.py").write_text('import os\n\nos.system("echo hello")\n')
        (root / "config.py").write_text('API_KEY = "AKIA1234567890123456"\n')
        yield root


def test_main_help(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "GitGuard" in result.output


def test_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0


def test_scan_command(runner, sample_project):
    result = runner.invoke(main, ["scan", str(sample_project)])
    assert result.exit_code == 0


def test_scan_verbose(runner, sample_project):
    result = runner.invoke(main, ["scan", str(sample_project), "-v"])
    assert result.exit_code == 0


def test_scan_severity(runner, sample_project):
    result = runner.invoke(main, ["scan", str(sample_project), "-s", "critical"])
    assert result.exit_code == 0


def test_review_command(runner, sample_project):
    result = runner.invoke(main, ["review", str(sample_project / "main.py")])
    assert result.exit_code == 0


def test_audit_command(runner, sample_project):
    result = runner.invoke(main, ["audit", str(sample_project)])
    assert result.exit_code == 0


def test_license_command(runner, sample_project):
    result = runner.invoke(main, ["license", str(sample_project)])
    assert result.exit_code == 0


def test_init_command(runner):
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        assert Path(".gitguard.json").exists()


def test_full_command(runner, sample_project):
    result = runner.invoke(main, ["full", str(sample_project)])
    assert result.exit_code == 0
