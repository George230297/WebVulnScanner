"""Unit tests for SecurityHeadersCheck plugin."""
import pytest
from webvulnscanner.plugins.headers import SecurityHeadersCheck
from webvulnscanner.config import SECURITY_HEADERS


@pytest.fixture
def headers_check() -> SecurityHeadersCheck:
    return SecurityHeadersCheck()


ALL_SECURITY_HEADERS = {h: "value" for h in SECURITY_HEADERS}


class TestSecurityHeadersCheck:

    def test_name_property(self, headers_check: SecurityHeadersCheck):
        assert headers_check.name == "Security Headers"

    def test_name_is_property_not_class_attr(self):
        assert isinstance(type(SecurityHeadersCheck()).name, property)

    async def test_no_headers_returns_empty(self, headers_check: SecurityHeadersCheck, mock_session):
        result = await headers_check.check(mock_session, "http://example.com", headers=None)
        assert result == []

    async def test_all_headers_present_returns_empty(self, headers_check: SecurityHeadersCheck, mock_session):
        result = await headers_check.check(
            mock_session,
            "http://example.com",
            headers=ALL_SECURITY_HEADERS,
        )
        assert result == []

    async def test_missing_csp_detected(self, headers_check: SecurityHeadersCheck, mock_session):
        headers = {k: v for k, v in ALL_SECURITY_HEADERS.items() if k != 'Content-Security-Policy'}
        result = await headers_check.check(mock_session, "http://example.com", headers=headers)
        types = [v.type for v in result]
        evidences = [v.evidence for v in result]
        assert "Missing Security Header" in types
        assert "Content-Security-Policy" in evidences

    async def test_missing_hsts_detected(self, headers_check: SecurityHeadersCheck, mock_session):
        headers = {k: v for k, v in ALL_SECURITY_HEADERS.items() if k != 'Strict-Transport-Security'}
        result = await headers_check.check(mock_session, "http://example.com", headers=headers)
        assert any(v.evidence == 'Strict-Transport-Security' for v in result)

    async def test_case_insensitive_header_check(self, headers_check: SecurityHeadersCheck, mock_session):
        """Headers provided in different case should still be recognized."""
        # Lowercase versions of all security headers
        lowercased = {k.lower(): "value" for k in SECURITY_HEADERS}
        result = await headers_check.check(mock_session, "http://example.com", headers=lowercased)
        assert result == []

    async def test_all_missing_returns_all_vulns(self, headers_check: SecurityHeadersCheck, mock_session):
        result = await headers_check.check(mock_session, "http://example.com", headers={"Server": "nginx"})
        assert len(result) == len(SECURITY_HEADERS)
        assert all(v.severity == "Low" for v in result)
