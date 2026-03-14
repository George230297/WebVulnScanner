"""
Shared fixtures for WebVulnScanner test suite.

Uses unittest.mock to avoid real HTTP calls in unit tests.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from webvulnscanner.core.network import ProbeResponse


@pytest.fixture
def sample_url() -> str:
    return "http://example.com/page?id=1&q=hello"


@pytest.fixture
def mock_session() -> MagicMock:
    """Returns a MagicMock that mimics an aiohttp.ClientSession."""
    return MagicMock()


def make_probe_response(status: int = 200, text: str = "") -> ProbeResponse:
    """Helper to create a ProbeResponse for testing."""
    return ProbeResponse(status=status, text=text, headers={})
