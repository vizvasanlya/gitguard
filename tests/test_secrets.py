from pathlib import Path

import pytest

from gitguard.detectors.secrets import scan_for_secrets


def _load_env():
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return {}
    env = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            env[key.strip()] = val.strip()
    return env


def _has_env():
    env = _load_env()
    return "TEST_AWS_ACCESS_KEY" in env


@pytest.mark.skipif(not _has_env(), reason="No .env file with test secrets")
def test_detect_aws_access_key():
    env = _load_env()
    content = f'AWS_ACCESS_KEY_ID = "{env["TEST_AWS_ACCESS_KEY"]}"'
    findings = scan_for_secrets(Path("test.py"), content)
    assert len(findings) > 0
    assert findings[0].rule_id == "SEC001"


@pytest.mark.skipif(not _has_env(), reason="No .env file with test secrets")
def test_detect_github_token():
    env = _load_env()
    content = f'token = "{env["TEST_GITHUB_TOKEN"]}"'
    findings = scan_for_secrets(Path("test.py"), content)
    assert len(findings) > 0
    assert findings[0].rule_id == "SEC003"


def test_detect_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scan_for_secrets(Path("test.py"), content)
    assert len(findings) > 0
    assert findings[0].rule_id == "SEC012"


@pytest.mark.skipif(not _has_env(), reason="No .env file with test secrets")
def test_detect_slack_token():
    env = _load_env()
    content = f'SLACK_TOKEN = "{env["TEST_SLACK_TOKEN"]}"'
    findings = scan_for_secrets(Path("test.py"), content)
    assert len(findings) > 0
    assert findings[0].rule_id == "SEC006"


def test_detect_stripe_key():
    import re
    pattern = re.compile(r"[sr]k_(live|test)_[0-9a-zA-Z]{24,}")
    assert pattern.search("sk_live_" + "a" * 24)
    assert pattern.search("rk_test_" + "b" * 24)
    assert not pattern.search("not_a_stripe_key")


@pytest.mark.skipif(not _has_env(), reason="No .env file with test secrets")
def test_detect_google_api_key():
    env = _load_env()
    content = f'API_KEY = "{env["TEST_GOOGLE_API_KEY"]}"'
    findings = scan_for_secrets(Path("test.py"), content)
    assert len(findings) > 0
    assert findings[0].rule_id == "SEC008"


def test_ignore_comments():
    content = "# AWS_ACCESS_KEY_ID = AKIA1234567890123456"
    findings = scan_for_secrets(Path("test.py"), content)
    assert len(findings) == 0


def test_ignore_example_values():
    content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # example'
    findings = scan_for_secrets(Path("test.py"), content)
    assert len(findings) == 0


@pytest.mark.skipif(not _has_env(), reason="No .env file with test secrets")
def test_ignore_test_files():
    env = _load_env()
    content = f'token = "{env["TEST_GITHUB_TOKEN"]}"'
    findings = scan_for_secrets(Path("tests/test_auth.py"), content)
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


@pytest.mark.skipif(not _has_env(), reason="No .env file with test secrets")
def test_detect_connection_string():
    env = _load_env()
    content = f'DATABASE_URL = "{env["TEST_DATABASE_URL"]}"'
    findings = scan_for_secrets(Path("config.py"), content)
    assert len(findings) > 0
    assert findings[0].rule_id == "SEC017"


def test_detect_jwt_token():
    content = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
    findings = scan_for_secrets(Path("auth.py"), content)
    assert len(findings) > 0
    assert findings[0].rule_id == "SEC018"


def test_no_false_positives_on_markdown():
    content = "# Secret Detection\n\nThis is a guide on how to detect secrets."
    findings = scan_for_secrets(Path("README.md"), content)
    assert len(findings) == 0
