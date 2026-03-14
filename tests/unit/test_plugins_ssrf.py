"""Unit tests for SSRFCheck plugin."""
import pytest
from webvulnscanner.plugins.ssrf import SSRFCheck


@pytest.fixture
def ssrf_check() -> SSRFCheck:
    return SSRFCheck()


class TestSSRFCheck:

    def test_name_property(self, ssrf_check: SSRFCheck):
        assert ssrf_check.name == "SSRF Candidate"

    def test_name_is_property_not_class_attr(self):
        assert isinstance(type(SSRFCheck()).name, property)

    async def test_no_params_returns_empty(self, ssrf_check: SSRFCheck, mock_session):
        result = await ssrf_check.check(mock_session, "http://example.com", params=None)
        assert result == []

    async def test_url_param_detected(self, ssrf_check: SSRFCheck, mock_session):
        result = await ssrf_check.check(
            mock_session,
            "http://example.com",
            params={"url": "http://internal"},
        )
        assert len(result) == 1
        assert result[0].type == "SSRF Candidate"
        assert result[0].param == "url"
        assert result[0].severity == "Medium"

    async def test_redirect_param_detected(self, ssrf_check: SSRFCheck, mock_session):
        result = await ssrf_check.check(
            mock_session,
            "http://example.com",
            params={"redirect": "http://evil.com"},
        )
        assert any(v.param == "redirect" for v in result)

    async def test_redirect_url_substring_detected(self, ssrf_check: SSRFCheck, mock_session):
        """BUG-10 regression: 'redirect_url' must match because it contains 'redirect'."""
        result = await ssrf_check.check(
            mock_session,
            "http://example.com/oauth",
            params={"redirect_url": "http://callback.example.com"},
        )
        assert len(result) == 1
        assert result[0].param == "redirect_url"

    async def test_safe_params_not_detected(self, ssrf_check: SSRFCheck, mock_session):
        result = await ssrf_check.check(
            mock_session,
            "http://example.com",
            params={"page": "1", "category": "news"},
        )
        assert result == []

    async def test_multiple_ssrf_params_detected(self, ssrf_check: SSRFCheck, mock_session):
        result = await ssrf_check.check(
            mock_session,
            "http://example.com",
            params={"url": "x", "dest": "y", "page": "1"},
        )
        params_found = {v.param for v in result}
        assert "url" in params_found
        assert "dest" in params_found
        assert "page" not in params_found
