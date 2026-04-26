from __future__ import annotations

import json
import subprocess
import json
import urllib.request
from typing import Dict, Any, List

def generate_ollama_summary(
    scan_data: Dict[str, Any],
    changes: List[str],
    model: str = "llama3.2"
) -> str:
    summary_data = {
        "changes": changes,
        "results": [
            {
                "ip": item["ip"],
                "hostname": item["hostname"],
                "open_ports": [
                    {
                        "port": p["port"],
                        "service": p["service"],
                        "risk": p["risk"],
                    }
                    for p in item.get("open_ports", [])
                ],
            }
            for item in scan_data.get("results", [])
        ],
    }

    prompt = (
         "Summarize these home network scan results in plain English. "
         "List all open ports found for each device. "
         "Preserve the exact risk labels provided in the scan data. "
         "Highlight devices with exposed web interfaces or higher-risk ports. "
         "Only mention KEV if a vulnerability is explicitly marked kev=true. "
         "Do not invent, omit, or downgrade findings. "
         "Keep it concise and educational.\n\n"
        f"{json.dumps(summary_data, indent=2)}"
    )

    payload = json.dumps({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a careful network analysis assistant. Return plain text only."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "stream": False,
        "keep_alive": "10m"
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        print(f"[+] Asking Ollama model: {model}")
        print("[+] Waiting for Ollama response...")

        with urllib.request.urlopen(req, timeout=180) as resp:
            raw = resp.read().decode("utf-8")
            print("[+] Ollama responded.")
            data = json.loads(raw)
            return data["message"]["content"].strip()

    except Exception as exc:
        return f"Ollama summary unavailable: {exc}"
