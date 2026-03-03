import asyncio
from webvulnscanner.core.network import send_probe

async def test_error_handling():
    print("[*] Testing timeout handling...")
    # This URL is a blackhole that will timeout
    resp_timeout = await send_probe("http://10.255.255.1", method="GET")
    print(f"Timeout Resp: {resp_timeout}")
    assert resp_timeout.status == 0, "Timeout should yield status 0"
    
    print("[*] Testing 500 error handling...")
    # We simulate a 500 by making a bad request to httpbin
    resp_500 = await send_probe("https://httpstat.us/500", method="GET")
    print(f"500 Resp: {resp_500}")
    assert resp_500.status == 500, "500 should yield status 500"
    
    print("[+] Error handling tests passed.")

if __name__ == "__main__":
    asyncio.run(test_error_handling())
