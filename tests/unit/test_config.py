"""Unit tests for ScanConfig and config constants."""
import re
import pytest
from webvulnscanner.config import ScanConfig, REGEX_SECRETS, SENSITIVE_FILES, SECURITY_HEADERS


class TestScanConfig:

    def test_defaults(self):
        cfg = ScanConfig(start_url="http://example.com")
        assert cfg.max_pages == 100
        assert cfg.concurrency == 20
        assert cfg.checks == []
        assert cfg.authorized is False
        assert cfg.allow_intrusive is False

    def test_custom_values(self):
        cfg = ScanConfig(
            start_url="https://target.com",
            max_pages=10,
            concurrency=5,
            checks=["xss", "sqli"],
        )
        assert cfg.max_pages == 10
        assert cfg.concurrency == 5
        assert cfg.checks == ["xss", "sqli"]


class TestRegexSecrets:

    def test_aws_api_key_matches(self):
        pattern = REGEX_SECRETS['AWS API Key']
        # A real-looking AKIA key (20 chars: AKIA + 16 alphanumeric)
        sample = "AKIAIOSFODNN7EXAMPLE"
        assert re.search(pattern, sample)

    def test_aws_api_key_no_false_positive_short(self):
        pattern = REGEX_SECRETS['AWS API Key']
        # Too short — must NOT match
        assert not re.search(pattern, "AKIA1234")

    def test_no_generic_20char_uppercase_key(self):
        """BUG-8 regression: ensure the old overly-broad AWS regex is gone."""
        assert 'AWS Access Key' not in REGEX_SECRETS

    def test_google_api_key_matches(self):
        pattern = REGEX_SECRETS['Google API Key']
        sample = "AIza" + "A" * 35
        assert re.search(pattern, sample)

    def test_generic_token_matches(self):
        pattern = REGEX_SECRETS['Generic Token']
        sample = 'api_key = "abcdefghijklmnopqrstu"'
        assert re.search(pattern, sample)

    def test_private_key_matches(self):
        pattern = REGEX_SECRETS['Private Key']
        sample = "-----BEGIN RSA PRIVATE KEY-----"
        assert re.search(pattern, sample)


class TestSensitiveFiles:

    def test_env_file_present(self):
        assert '.env' in SENSITIVE_FILES

    def test_git_head_present(self):
        assert '.git/HEAD' in SENSITIVE_FILES


class TestSecurityHeaders:

    def test_csp_present(self):
        assert 'Content-Security-Policy' in SECURITY_HEADERS

    def test_hsts_present(self):
        assert 'Strict-Transport-Security' in SECURITY_HEADERS
