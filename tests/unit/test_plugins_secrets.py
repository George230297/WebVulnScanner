"""Unit tests for SecretsCheck plugin."""
import pytest
from tests.conftest import make_probe_response
from webvulnscanner.plugins.secrets import SecretsCheck


@pytest.fixture
def secrets_check() -> SecretsCheck:
    return SecretsCheck()


class TestSecretsCheck:

    def test_name_property(self, secrets_check: SecretsCheck):
        assert secrets_check.name == "Secrets & Tokens"

    def test_name_is_property_not_class_attr(self):
        assert isinstance(type(SecretsCheck()).name, property)

    async def test_no_html_returns_empty(self, secrets_check: SecretsCheck, mock_session):
        result = await secrets_check.check(mock_session, "http://example.com", html="")
        assert result == []

    async def test_google_api_key_detected(self, secrets_check: SecretsCheck, mock_session):
        # A syntactically valid Google API key (AIza + 35 chars)
        html = 'var key = "AIza' + 'A' * 35 + '"'
        result = await secrets_check.check(mock_session, "http://example.com/app.js", html=html)
        assert len(result) >= 1
        assert any("Google API Key" in v.evidence for v in result)
        assert all(v.severity == "High" for v in result)

    async def test_aws_akia_key_detected(self, secrets_check: SecretsCheck, mock_session):
        html = "AKIAIOSFODNN7EXAMPLE"
        result = await secrets_check.check(mock_session, "http://example.com/app.js", html=html)
        assert any("AWS API Key" in v.evidence for v in result)

    async def test_private_key_detected(self, secrets_check: SecretsCheck, mock_session):
        html = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."
        result = await secrets_check.check(mock_session, "http://example.com/app.js", html=html)
        assert any("Private Key" in v.evidence for v in result)

    async def test_generic_token_detected(self, secrets_check: SecretsCheck, mock_session):
        html = 'api_key = "thisisasecrettoken123456"'
        result = await secrets_check.check(mock_session, "http://example.com/app.js", html=html)
        assert any("Generic Token" in v.evidence for v in result)

    async def test_clean_html_returns_empty(self, secrets_check: SecretsCheck, mock_session):
        html = "<html><body><p>Hello World</p></body></html>"
        result = await secrets_check.check(mock_session, "http://example.com", html=html)
        assert result == []

    async def test_evidence_truncated_at_20_chars(self, secrets_check: SecretsCheck, mock_session):
        """Evidence display should be truncated for long secrets."""
        long_key = "AKIAIOSFODNN7EXAMPLE"  # 20 chars exactly
        html = long_key
        result = await secrets_check.check(mock_session, "http://example.com", html=html)
        for v in result:
            # Evidence should not expose the full secret beyond 20+3 chars ('...')
            evidence_value = v.evidence.split(": ", 1)[-1]
            assert len(evidence_value) <= 23  # 20 chars + '...'
