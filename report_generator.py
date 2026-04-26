from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import csv
import html
from utils import truncate, risk_style, safe_text
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from config import SCAN_HISTORY_FILE, CSV_EXPORT_FILE
from config import HTML_REPORT_FILE, SCAN_HISTORY_FILE, CSV_EXPORT_FILE

def export_html_report(
    scan_data: Dict[str, Any],
    changes: List[str],
    filename: str = HTML_REPORT_FILE
) -> None:
    rows = []

    for item in scan_data["results"]:
        ip = safe_text(item.get("ip"))
        hostname = safe_text(item.get("hostname"), "Hostname unresolved")
        mac = safe_text(item.get("mac"))
        vendor = safe_text(item.get("vendor"), "Unknown Vendor")
        ports = item.get("open_ports", [])

        if not ports:
            rows.append(f"""
            <tr>
                <td>{ip}</td>
                <td>{hostname}</td>
                <td>{mac}</td>
                <td>{vendor}</td>
                <td>-</td>
                <td>No open ports</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
            </tr>
            """)
            continue

        for p in ports:
            port = safe_text(p.get("port"))
            service = safe_text(p.get("service"))
            description = safe_text(p.get("description"), "No description available")
            product = safe_text(p.get("product"), "Unknown product")
            version = safe_text(p.get("version"), "Unknown version")

            risk_raw = str(p.get("risk") or "UNKNOWN").upper()
            risk = html.escape(risk_raw)
            risk_class = risk_raw.lower() if risk_raw.lower() in {"high", "medium", "low", "info"} else ""

            banner = safe_text(p.get("banner"), "No banner captured")
            vulnerabilities = p.get("vulnerabilities") or []

            if vulnerabilities:
                vuln_text = "<br>".join(
                    f"{safe_text(v.get('cve_id') or v.get('cve'))} ({safe_text(v.get('severity'), 'UNKNOWN')})"
                    for v in vulnerabilities[:3]
                )
                vuln_section_html = f"""
                <tr>
                    <td colspan="12">
                        {render_vulnerability_section(vulnerabilities)}
                    </td>
                </tr>
                """
            else:
                vuln_text = "No CVEs mapped"
                vuln_section_html = ""

            rows.append(f"""
            <tr>
                <td>{ip}</td>
                <td>{hostname}</td>
                <td>{mac}</td>
                <td>{vendor}</td>
                <td>{port}</td>
                <td>{service}</td>
                <td>{description}</td>
                <td>{product}</td>
                <td>{version}</td>
                <td class="{risk_class}">{risk}</td>
                <td>{banner}</td>
                <td>{vuln_text}</td>
            </tr>
            {vuln_section_html}
            """)

    change_items = "".join(f"<li>{html.escape(change)}</li>" for change in changes)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Willow Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f8f9fa;
            color: #222;
        }}
        h1, h2 {{
            color: #1f3b5b;
        }}
        .summary {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            vertical-align: top;
            font-size: 14px;
        }}
        th {{
            background: #1f3b5b;
            color: white;
        }}
        tr:nth-child(even) {{
            background: #f2f2f2;
        }}
        .high {{
            background: #ffd6d6;
            font-weight: bold;
        }}
        .medium {{
            background: #fff0c2;
            font-weight: bold;
        }}
        .low {{
            background: #e6f4d7;
            font-weight: bold;
        }}
        .info {{
            background: #dbeafe;
        }}
        .vuln-section {{
            margin-top: 20px;
            padding: 15px;
            background: #0f172a;
            border-radius: 10px;
            border: 1px solid #334155;
        }}

        .vuln-card {{
            margin-bottom: 12px;
            padding: 12px;
            background: #1e293b;
            border-left: 4px solid #3b82f6;
            border-radius: 8px;
            color: #f8fafc;
        }}

         .vuln-card p {{
            color: #e2e8f0;
            line-height: 1.5;
        }}
        
         .vuln-header strong {{
            color: #ffffff;
            font-size: 1rem;

        }}

        .severity-badge {{
            background: #374151;
            color: white;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .severity-badge.high {{
            background: #dc2626;
        }}

        .severity-badge.medium {{
            background: #f59e0b;
            color: #111827;
        }}

        .severity-badge.low {{
            background: #16a34a;
        }}

        .severity-badge.info {{
            background: #2563eb;
        }}

        .kev-badge {{
            background: #b91c1c;
            color: white;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.8em;
            font-weight: bold;
            border: 1px solid #ef4444;
        }}

        ul {{
            margin-top: 0;
        }}
        
    </style>
</head>
<body>
    <h1>Willow Scan Report</h1>

    <div class="summary">
        <p><strong>Status:</strong> {html.escape(scan_data.get("status", "-"))}</p>
        <p><strong>Timestamp:</strong> {html.escape(scan_data.get("timestamp", "-"))}</p>
        <p><strong>Devices Scanned:</strong> {scan_data.get("devices_scanned", 0)}</p>
    </div>

    <div class="summary">
        <h2>Changes Since Last Scan</h2>
        <ul>
            {change_items}
        </ul>
    </div>

    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC Address</th>
                <th>Vendor</th>
                <th>Port</th>
                <th>Service</th>
                <th>Description</th>
                <th>Product</th>
                <th>Version</th>
                <th>Risk</th>
                <th>Banner</th>
                <th>Top CVEs</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
</body>
</html>
"""

    Path(filename).write_text(html_content, encoding="utf-8")

def render_vulnerability_section(vulnerabilities):
    if not vulnerabilities:
        return """
        <div class="vuln-section">
            <h3>Vulnerabilities</h3>
            <p>No vulnerability data available.</p>
        </div>
        """

    rows = []

    for vuln in vulnerabilities:
        cve = vuln.get("cve") or vuln.get("cve_id") or "Unknown CVE"
        severity = vuln.get("severity", "Unknown")
        description = vuln.get("description", "No description available")
        remediation = vuln.get("remediation", "No remediation note available")
        kev = vuln.get("kev", False)

        severity_class = safe_text(vuln.get("severity", "info")).lower()
        
        kev_html = ""
        if kev:
            kev_html = '<span class="kev-badge">⚠ Known Exploited</span>'

        rows.append(f"""
        <div class="vuln-card">
            <div class="vuln-header">
                <strong>{cve}</strong>
                <span class="severity-badge {severity_class}">{severity}</span>
                {kev_html}
           </div>
           <p><strong>Description:</strong> {description}</p>
           <p><strong>Remediation:</strong> {remediation}</p>
        </div>
        """)

    return f"""
    <div class="vuln-section">
        <h3>Vulnerabilities</h3>
        {''.join(rows)}
    </div>
    """

def print_scan_results_grouped(scan_data, console):
    for item in scan_data.get("results", []):
        ip = item.get("ip", "-")
        hostname = item.get("hostname") or "-"
        mac = item.get("mac") or "-"
        vendor = item.get("vendor") or "-"
        ports = item.get("open_ports", [])

        console.print(f"\n[bold cyan]Device:[/bold cyan] {ip}")
        console.print(f"[bold]Hostname:[/bold] {hostname}")
        console.print(f"[bold]MAC:[/bold] {mac}")
        console.print(f"[bold]Vendor:[/bold] {vendor}")

        table = Table(show_header=True, header_style="bold white")
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("Service", no_wrap=True)
        table.add_column("Product")
        table.add_column("Version")
        table.add_column("Risk", no_wrap=True)
        table.add_column("Banner", style="white", overflow="fold", max_width=45)

        if not ports:
            table.add_row("-", "No open ports", "-", "-", "-", "-")
        else:
            for p in ports:
                risk_raw = str(p.get("risk") or "UNKNOWN").upper()
                table.add_row(
                    str(p.get("port", "-")),
                    str(p.get("service", "-")),
                    truncate(p.get("product", "-"), 18),
                    truncate(p.get("version", "-"), 22),
                    Text(risk_raw, style=risk_style(risk_raw)),
                    truncate(p.get("banner", "-"), 40),
                )

        console.print(table)

def save_scan_results(data: Dict[str, Any], file_path: str = SCAN_HISTORY_FILE) -> None:
    Path(file_path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def export_csv(results: List[Dict[str, Any]], filename: str = CSV_EXPORT_FILE) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow([
            "IP Address",
            "Hostname",
            "MAC Address",
            "Vendor",
            "Port",
            "Protocol",
            "State",
            "Service",
            "Product",
            "Version",
            "Description",
            "Risk",
            "Banner"
        ])

        for item in results:
            ip = item.get("ip", "-")
            hostname = item.get("hostname", "-")
            mac = item.get("mac", "-")
            ports = item.get("open_ports", [])

            if not ports:
                writer.writerow([
                    ip,
                    hostname,
                    mac,
                    item.get("vendor", "-"),
                    "-",
                    "-",
                    "-",
                    "No open ports",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                ])
                continue

            for p in ports:
                writer.writerow([
                    ip,
                    hostname,
                    mac,
                    item.get("vendor", "-"),
                    p.get("port", "-"),
                    p.get("protocol", "-"),
                    p.get("state", "-"),
                    p.get("service", "-"),
                    p.get("product", "-"),
                    p.get("version", "-"),
                    p.get("description", "-"),
                    p.get("risk", "-"),
                    p.get("banner", "-"),
                ])


def load_previous_scan(file_path: str = SCAN_HISTORY_FILE) -> Optional[Dict[str, Any]]:
    path = Path(file_path)

    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def compare_scans(previous, current):
    previous_results = previous.get("results", []) if isinstance(previous, dict) else previous or []
    current_results = current.get("results", []) if isinstance(current, dict) else current or []

    previous_map = {
        item.get("ip"): item
        for item in previous_results
        if isinstance(item, dict) and item.get("ip")
    }

    current_map = {
        item.get("ip"): item
        for item in current_results
        if isinstance(item, dict) and item.get("ip")
    }

    changes = []

    previous_ips = set(previous_map.keys())
    current_ips = set(current_map.keys())

    new_ips = current_ips - previous_ips
    removed_ips = previous_ips - current_ips
    common_ips = previous_ips & current_ips

    for ip in sorted(new_ips):
        changes.append(f"New device detected: {ip}")

    for ip in sorted(removed_ips):
        changes.append(f"Device removed: {ip}")

    for ip in sorted(common_ips):
        prev_ports = {p.get('port') for p in previous_map[ip].get("open_ports", [])}
        curr_ports = {p.get('port') for p in current_map[ip].get("open_ports", [])}

        added_ports = curr_ports - prev_ports
        removed_ports = prev_ports - curr_ports

        for port in sorted(added_ports):
            changes.append(f"{ip}: port {port} opened")

        for port in sorted(removed_ports):
            changes.append(f"{ip}: port {port} closed")

    return changes
