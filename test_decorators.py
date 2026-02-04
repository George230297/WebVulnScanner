
import asyncio
import os
from webvulnscanner.core.network import send_probe

async def main():
    test_url = "http://example.com"
    payload = {"test": "data"}
    
    print(f"Sending probe to {test_url}...")
    try:
        response = await send_probe(test_url, payload)
        print(f"Response Status: {response.status}")
        print(f"Response Text Length: {len(response.text)}")
    except Exception as e:
        print(f"Error: {e}")

    # Check audit log
    if os.path.exists("audit.log"):
        print("\nAudit Log Content:")
        with open("audit.log", "r") as f:
            print(f.read())
    else:
        print("\nAudit log was not created.")

if __name__ == "__main__":
    asyncio.run(main())
