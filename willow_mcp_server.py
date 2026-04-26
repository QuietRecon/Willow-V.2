#!/usr/bin/env python3
from __future__ import annotations

from fastmcp import FastMCP
from willow import run_scan

mcp = FastMCP("Willow")

@mcp.tool()
def scan_home_network(
    file_path: str = "devices.txt",
    threads: int = 8,
    top1000: bool = True,
    ports: str | None = None,
    use_ollama: bool = False,
    model: str = "llama3.2",
) -> dict:
    """
    Scan owned/authorized home-network IPs from a file, enrich with hostnames/MACs/banners,
    compare against previous scan, optionally summarize with Ollama, and return structured JSON.
    """
    return run_scan(
        file_path=file_path,
        threads=threads,
        top_1000=top1000,
        ports=ports,
        use_ollama=use_ollama,
        model=model,
    )

if __name__ == "__main__":
    mcp.run(transport="http", port=8000)
