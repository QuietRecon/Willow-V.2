# utils.py

import html
from datetime import datetime
from typing import Any

def truncate(text: Any, max_len: int = 40) -> str:
    if text is None:
        return "-"
    text = str(text).strip()
    if not text or text == "-":
        return "-"
    return text if len(text) <= max_len else text[: max_len - 3] + "..."

def risk_style(risk: str) -> str:
    risk = str(risk or "").upper()
    if risk == "HIGH":
        return "bold red"
    if risk == "MEDIUM":
        return "bold yellow"
    if risk == "LOW":
        return "bold green"
    if risk == "INFO":
        return "bold cyan"
    return "white"

def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default

    if isinstance(value, str) and not value.strip():
        return default

    return html.escape(str(value))
