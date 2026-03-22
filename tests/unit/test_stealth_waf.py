import pytest
import asyncio
from unittest.mock import patch, MagicMock
from webvulnscanner.core.stealth import StealthManager

@pytest.mark.asyncio
async def test_stealth_header_spoofing():
    # Setup
    manager = StealthManager()
    
    captured_kwargs = {}
    
    async def dummy_request(url, *args, **kwargs):
        captured_kwargs.update(kwargs)
        class MockResponse:
            status = 200
        return MockResponse()

    # Fast forward Jitter by patching asyncio.sleep
    with patch("asyncio.sleep", return_value=None):
        await manager.execute_with_stealth(dummy_request, "http://example.com")
    
    headers = captured_kwargs.get('headers', {})
    assert headers.get('X-Forwarded-For') == "127.0.0.1"
    assert headers.get('Client-IP') == "127.0.0.1"
    assert 'User-Agent' in headers

@patch('os.path.exists', return_value=True)
def test_proxy_rotation(mock_exists):
    # Setup mock file reading 
    with patch('builtins.open', new_callable=MagicMock) as mock_open:
        mock_file = MagicMock()
        mock_file.__iter__.return_value = ["1.1.1.1:8080\n", "2.2.2.2:9090\n"]
        mock_open.return_value.__enter__.return_value = mock_file
        
        manager = StealthManager()
        assert len(manager.proxies) == 2
        
        proxy = manager.get_random_proxy()
        assert proxy in ["1.1.1.1:8080", "2.2.2.2:9090"]
        
        manager.remove_proxy(proxy)
        assert len(manager.proxies) == 1
        assert manager.proxies[0] != proxy
