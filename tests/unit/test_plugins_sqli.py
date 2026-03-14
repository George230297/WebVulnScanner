"""Unit tests for SQLiCheck plugin."""
import pytest
from unittest.mock import AsyncMock, patch
from tests.conftest import make_probe_response
from webvulnscanner.plugins.sqli import SQLiCheck


@pytest.fixture
def sqli_check() -> SQLiCheck:
    return SQLiCheck()


class TestSQLiCheck:

    def test_name_property(self, sqli_check: SQLiCheck):
        assert sqli_check.name == "Error-Based SQLi"

    def test_name_is_property_not_class_attr(self):
        """BUG-1 regression: name must be a @property."""
        assert isinstance(type(SQLiCheck()).name, property)

    async def test_no_params_returns_empty(self, sqli_check: SQLiCheck, mock_session):
        result = await sqli_check.check(mock_session, "http://example.com", params=None)
        assert result == []

    async def test_sqli_detected_on_db_error(self, sqli_check: SQLiCheck, mock_session):
        # Simulate a response containing a SQL error
        db_error_response = make_probe_response(
            status=200,
            text="You have an error in your SQL syntax near '1''",
        )
        with patch("webvulnscanner.plugins.sqli.send_probe", new=AsyncMock(return_value=db_error_response)):
            result = await sqli_check.check(
                mock_session,
                "http://example.com/items",
                params={"id": "1"},
            )

        assert len(result) == 1
        assert result[0].type == "SQLi Error-Based"
        assert result[0].param == "id"
        assert result[0].severity == "Critical"
        assert "DB Error triggered" in result[0].evidence

    async def test_sqli_not_detected_on_clean_response(self, sqli_check: SQLiCheck, mock_session):
        clean_response = make_probe_response(status=200, text="<html>Normal page</html>")
        with patch("webvulnscanner.plugins.sqli.send_probe", new=AsyncMock(return_value=clean_response)):
            result = await sqli_check.check(
                mock_session,
                "http://example.com/items",
                params={"id": "1"},
            )
        assert result == []

    async def test_network_failure_skipped(self, sqli_check: SQLiCheck, mock_session):
        """status=0 (network failure) must not produce a false positive."""
        failed = make_probe_response(status=0, text="you have an error in your sql syntax")
        with patch("webvulnscanner.plugins.sqli.send_probe", new=AsyncMock(return_value=failed)):
            result = await sqli_check.check(
                mock_session,
                "http://example.com/items",
                params={"id": "1"},
            )
        assert result == []

    async def test_multiple_params_checked(self, sqli_check: SQLiCheck, mock_session):
        """Each param should be probed independently."""
        probes = []

        async def recording_probe(url, method, params):
            probes.append(dict(params))
            return make_probe_response(status=200, text="no error")

        with patch("webvulnscanner.plugins.sqli.send_probe", new=recording_probe):
            await sqli_check.check(
                mock_session,
                "http://example.com/page",
                params={"id": "1", "cat": "2"},
            )

        assert len(probes) == 2
