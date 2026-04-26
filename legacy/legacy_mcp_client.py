#!/usr/bin/env python3
import asyncio
from fastmcp import Client

async def main():
    client = Client("http://127.0.0.1:8000/mcp")
    async with client:
        result = await client.call_tool(
            "scan_home_network",
            {
                "file_path": "devices.txt",
                "threads": 8,
                "top1000": True,
                "ports": None,
                "use_ollama": False,
                "model": "llama3.2",
            },
        )
        print(result.data)

if __name__ == "__main__":
    asyncio.run(main())
