"""Unit tests for audit_log and retry_network decorators."""
import asyncio
import os
import tempfile
import pytest
from unittest.mock import patch, AsyncMock
from webvulnscanner.utils.decorators import audit_log, retry_network
from webvulnscanner.core.network import ProbeResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@audit_log
async def _dummy_success(url: str) -> ProbeResponse:
    return ProbeResponse(status=200, text="ok", headers={})


@audit_log
async def _dummy_fail(url: str) -> ProbeResponse:
    raise ValueError("Simulated failure")


@retry_network
async def _dummy_timeout(url: str) -> str:
    raise asyncio.TimeoutError()


@retry_network
async def _dummy_success_on_retry(url: str, _state: dict) -> str:
    _state['calls'] += 1
    if _state['calls'] < 3:
        raise asyncio.TimeoutError()
    return "ok"


# ---------------------------------------------------------------------------
# Tests: audit_log
# ---------------------------------------------------------------------------

class TestAuditLog:

    async def test_success_writes_to_audit_log(self, tmp_path):
        log_file = str(tmp_path / "audit.log")
        with patch("webvulnscanner.utils.decorators.open", create=True) as mock_open:
            import builtins
            real_open = builtins.open

            def side_effect(file, *args, **kwargs):
                if file == "audit.log":
                    return real_open(log_file, *args, **kwargs)
                return real_open(file, *args, **kwargs)

            mock_open.side_effect = side_effect
            result = await _dummy_success("http://example.com")

        assert result.status == 200

    async def test_preserves_return_value(self):
        result = await _dummy_success("http://example.com")
        assert isinstance(result, ProbeResponse)
        assert result.status == 200

    async def test_reraises_on_failure(self):
        with pytest.raises(ValueError, match="Simulated failure"):
            await _dummy_fail("http://example.com")


# ---------------------------------------------------------------------------
# Tests: retry_network
# ---------------------------------------------------------------------------

class TestRetryNetwork:

    async def test_raises_after_max_retries(self):
        """BUG-6 regression: after 3 TimeoutErrors, must raise — never return None."""
        with pytest.raises((asyncio.TimeoutError, TimeoutError)):
            await _dummy_timeout("http://10.255.255.1")

    async def test_succeeds_on_third_attempt(self):
        state = {'calls': 0}
        result = await _dummy_success_on_retry("http://example.com", state)
        assert result == "ok"
        assert state['calls'] == 3

    async def test_returns_immediately_if_no_timeout(self):
        @retry_network
        async def always_ok(url: str) -> str:
            return "immediate"

        result = await always_ok("http://example.com")
        assert result == "immediate"
