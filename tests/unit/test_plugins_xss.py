"""Unit tests for XSSCheck plugin."""
import pytest
from unittest.mock import AsyncMock, patch
from tests.conftest import make_probe_response
from webvulnscanner.plugins.xss import XSSCheck


@pytest.fixture
def xss_check() -> XSSCheck:
    return XSSCheck()


class TestXSSCheck:

    def test_name_property(self, xss_check: XSSCheck):
        assert xss_check.name == "Reflected XSS"

    def test_name_is_property_not_class_attr(self):
        """BUG-1 regression: name must be a property on the instance."""
        check = XSSCheck()
        # Access via instance — should work through @property
        assert isinstance(type(check).name, property)

    async def test_no_params_returns_empty(self, xss_check: XSSCheck, mock_session):
        result = await xss_check.check(mock_session, "http://example.com", params=None)
        assert result == []

    async def test_xss_detected_when_payload_reflected(self, xss_check: XSSCheck, mock_session):
        payload = xss_check.payloads[0]
        reflected_response = make_probe_response(status=200, text=f"<html>{payload}</html>")

        with patch("webvulnscanner.plugins.xss.send_probe", new=AsyncMock(return_value=reflected_response)):
            result = await xss_check.check(
                mock_session,
                "http://example.com/search",
                params={"q": "hello"},
            )

        assert len(result) == 1
        assert result[0].type == "Reflected XSS"
        assert result[0].param == "q"
        assert result[0].severity == "High"
        assert result[0].evidence == payload

    async def test_xss_not_detected_when_payload_not_reflected(self, xss_check: XSSCheck, mock_session):
        safe_response = make_probe_response(status=200, text="<html>safe output</html>")

        with patch("webvulnscanner.plugins.xss.send_probe", new=AsyncMock(return_value=safe_response)):
            result = await xss_check.check(
                mock_session,
                "http://example.com/search",
                params={"q": "hello"},
            )

        assert result == []

    async def test_network_failure_returns_empty(self, xss_check: XSSCheck, mock_session):
        """status=0 means network failure; should not report a vulnerability."""
        failed_response = make_probe_response(status=0, text="")

        with patch("webvulnscanner.plugins.xss.send_probe", new=AsyncMock(return_value=failed_response)):
            result = await xss_check.check(
                mock_session,
                "http://example.com/page",
                params={"id": "1"},
            )

        assert result == []

    async def test_only_first_payload_per_param_reported(self, xss_check: XSSCheck, mock_session):
        """Once a vuln is found for a param, no further payloads should be tested for it."""
        payload = xss_check.payloads[0]
        call_count = 0

        async def counting_probe(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return make_probe_response(status=200, text=payload)

        with patch("webvulnscanner.plugins.xss.send_probe", new=counting_probe):
            result = await xss_check.check(
                mock_session,
                "http://example.com/page",
                params={"q": "hello"},
            )

        # Should stop after first hit
        assert len(result) == 1
        assert call_count == 1
