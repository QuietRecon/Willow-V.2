#!/usr/bin/env python3
"""
Willow network scanner for educational use on networks you own or are authorized to assess.

Features:
- Reads target IPs from devices.txt
- Scans Nmap's default top 1000 TCP ports by default
- Optional full TCP port scan with --allports
- Optional service/version detection with Nmap -sV
- Prints clean columned terminal output
- Hostname lookup
- MAC lookup from ARP / ip neigh cache
- Basic service banner grabbing for common services
- Risk labels for notable ports
- Compares current results to previous scan JSON
- Optional Ollama summary report
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse
import ipaddress
import json
import socket
import ssl
import subprocess
import urllib.request
import csv
import html
import re
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel

SCAN_HISTORY_FILE = "scan_results_latest.json"
CSV_EXPORT_FILE = "scan_results.csv"
HTML_REPORT_FILE = "scan_report.html"
DEFAULT_THREADS = 8
MAC_VENDOR_CACHE: Dict[str, str] = {}
NVD_RESULTS_LIMIT = 4

RISK_PORTS = {
    21: ("FTP", "MEDIUM"),
    22: ("SSH", "LOW"),
    23: ("Telnet", "HIGH"),
    25: ("SMTP", "LOW"),
    53: ("DNS", "LOW"),
    80: ("HTTP", "INFO"),
    110: ("POP3", "MEDIUM"),
    139: ("NetBIOS", "MEDIUM"),
    143: ("IMAP", "LOW"),
    443: ("HTTPS", "INFO"),
    445: ("SMB", "HIGH"),
    3306: ("MySQL", "MEDIUM"),
    3389: ("RDP", "HIGH"),
    5432: ("PostgreSQL", "MEDIUM"),
    5900: ("VNC", "HIGH"),
    6379: ("Redis", "HIGH"),
    8080: ("HTTP-Alt", "INFO"),
    8443: ("HTTPS-Alt", "INFO"),
}

SERVICE_DESCRIPTIONS = {
    "http": "Web interface or web service",
    "https": "Encrypted web interface or web service",
    "http-proxy": "Alternate HTTP web service or proxy",
    "http-alt": "Alternate HTTP service",
    "domain": "DNS service",
    "netbios-ssn": "Legacy Windows file and printer sharing support",
    "microsoft-ds": "SMB file sharing service used by Windows systems",
    "msrpc": "Microsoft Remote Procedure Call service",
    "wsdapi": "Windows Web Services for Devices",
    "ipp": "Internet Printing Protocol service",
    "jetdirect": "Raw network printer service",
    "upnp": "Universal Plug and Play service",
    "trivnet1": "Unknown or uncommon service",
    "unknown": "Service could not be identified clearly",
    "iphone-sync": "Apple device synchronization service",
    "nati-svrloc": "Service location or vendor-specific discovery service",
}

BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443}
console = Console()

console.print(
    Panel.fit(
        "[bold cyan]WILLOW[/bold cyan]\n"
        "[white]AI-Assisted Network Scanner[/white]\n\n"
        "[green][OK][/green] Scanner Module Ready\n"
        "[green][OK][/green] HTML Reporting Ready\n"
        "[green][OK][/green] Ollama Ready\n"
        "[green][OK][/green] MCP Ready",
        border_style="bright_blue",
        title="[bold white]Willow Startup[/bold white]"
    )
)

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

def print_scan_results_grouped(scan_data):
    for item in scan_data["results"]:
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

def load_devices(file_path: str) -> List[str]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"{file_path} not found")

    devices: List[str] = []
    seen = set()

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        line = line.replace("(", "").replace(")", "").strip()

        try:
            ip = str(ipaddress.ip_address(line))
            if ip not in seen:
                seen.add(ip)
                devices.append(ip)
            else:
                print(f"[!] Skipping duplicate IP: {ip}")
        except ValueError:
            print(f"[!] Skipping invalid IP: {line}")

    return devices

def run_command(cmd: List[str], timeout: int = 90) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else result.stderr
    except subprocess.TimeoutExpired:
        return "ERROR: command timed out"
    except Exception as exc:
        return f"ERROR: {exc}"


def lookup_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


def lookup_mac(ip: str) -> str:
    output = run_command(["ip", "neigh", "show", ip], timeout=10)
    if output and "lladdr" in output:
        parts = output.strip().split()
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                return parts[idx + 1]

    output = run_command(["arp", "-n", ip], timeout=10)
    for token in output.split():
        if ":" in token and len(token) >= 17:
            return token

    return "-"

def lookup_mac_vendor(mac: str) -> str:
    if not mac or mac == "-":
        return "-"

    mac_prefix = mac.upper().replace(":", "")[:6]

    if mac_prefix in MAC_VENDOR_CACHE:
        return MAC_VENDOR_CACHE[mac_prefix]

    try:
        req = urllib.request.Request(
            f"https://api.macvendors.com/{mac_prefix}",
            headers={"User-Agent": "HomeNetworkScanner/1.0"}
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            vendor = resp.read().decode("utf-8").strip()
            vendor = vendor if vendor else "Unknown Vendor"
            MAC_VENDOR_CACHE[mac_prefix] = vendor
            return vendor

    except Exception:
        return "Unknown Vendor"

def parse_nmap_output(ip: str, text: str) -> List[Dict[str, Any]]:
    open_ports: List[Dict[str, Any]] = []

    for raw in text.splitlines():
        line = raw.strip()

        if "/tcp" in line and " open " in f" {line} ":
            parts = line.split()

            if len(parts) >= 3:
                port_proto = parts[0]
                state = parts[1]
                service = parts[2]

                port = int(port_proto.split("/")[0])

                product = parts[3] if len(parts) >= 4 else "-"
                version = " ".join(parts[4:]) if len(parts) >= 5 else "-"

                open_ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                })

    return open_ports


def scan_nmap(ip: str, all_ports: bool = False, ports: Optional[str] = None) -> List[Dict[str, Any]]:
    if ports:
        cmd = ["nmap", "-Pn", "-sV", "-p", ports, ip]
    elif all_ports:
        cmd = ["nmap", "-Pn", "-sV", "-p-", ip]
    else:
        cmd = ["nmap", "-Pn", "-sV", ip]

    output = run_command(cmd, timeout=300)
    return parse_nmap_output(ip, output)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    if port not in BANNER_PORTS:
        return "-"

    if port in {80, 8080}:
        try:
            req = urllib.request.Request(f"http://{ip}:{port}/", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                server = resp.headers.get("Server", "-")
                return f"HTTP {resp.status}; Server={server}"
        except Exception:
            return "-"

    if port in {443, 8443}:
        try:
            req = urllib.request.Request(f"https://{ip}:{port}/", headers={"User-Agent": "Mozilla/5.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                server = resp.headers.get("Server", "-")
                return f"HTTPS {resp.status}; Server={server}"
        except Exception:
            return "-"

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
                if data:
                    return data.decode(errors="ignore").strip().replace("\n", " ")[:120] or "-"
            except Exception:
                pass
    except Exception:
        return "-"

    return "-"


def risk_label_for_port(port: int) -> str:
    info = RISK_PORTS.get(port)
    return info[1] if info else "INFO"

def describe_service(service: str) -> str:
    return SERVICE_DESCRIPTIONS.get(service, "No description available")

def clean_version_string(version: str) -> str:
    if not version or version == "-":
        return ""

    match = re.search(r"\d+(?:\.\d+)+", version)
    return match.group(0) if match else ""


def lookup_vulnerabilities(product: str, version: str) -> List[Dict[str, str]]:
    if not product or product == "-":
        return []

    cleaned_version = clean_version_string(version)

    keyword = product
    if cleaned_version:
        keyword += f" {cleaned_version}"

    try:
        query = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": NVD_RESULTS_LIMIT,
        })

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "HomeNetworkScanner/1.0"}
        )

        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        findings = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "-")

            description = "-"
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "-")
                    break

            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                severity = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]

            findings.append({
                "cve_id": cve_id,
                "severity": severity,
                "description": description[:160],
            })

        return findings

    except Exception:
        return []

def enrich_result(ip: str, all_ports: bool, ports: Optional[str]) -> Dict[str, Any]:
    hostname = lookup_hostname(ip)
    mac = lookup_mac(ip)
    vendor = lookup_mac_vendor(mac)
    print(f"[+] {ip} -> MAC: {mac} -> Vendor: {vendor}")
    open_ports = scan_nmap(ip, all_ports=all_ports, ports=ports)

    enriched_ports = []

    for entry in open_ports:
        port = entry["port"]
        product = entry.get("product", "-")
        version = entry.get("version", "-")
        vulnerabilities = lookup_vulnerabilities(product, version)

        enriched_ports.append({
            **entry,
            "banner": grab_banner(ip, port),
            "risk": risk_label_for_port(port),
            "description": describe_service(entry["service"]),
            "vulnerabilities": vulnerabilities,
        })

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "open_ports": enriched_ports,
        "open_ports_count": len(enriched_ports),
    }

def safe_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    if isinstance(value, str) and not value.strip():
        return default
    return html.escape(str(value))

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
                    f"{safe_text(v.get('cve_id'))} ({safe_text(v.get('severity'), 'UNKNOWN')})"
                    for v in vulnerabilities[:3]
                )
            else:
                vuln_text = "No CVEs mapped"

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
            {''.join(rows)}
        </tbody>
    </table>
</body>
</html>
"""

    Path(filename).write_text(html_content, encoding="utf-8")

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


def compare_scans(previous: Optional[Dict[str, Any]], current: Dict[str, Any]) -> List[str]:
    changes: List[str] = []
    if not previous:
        changes.append("No previous scan found. This is the baseline scan.")
        return changes

    prev_map = {
        item["ip"]: {p["port"] for p in item.get("open_ports", [])}
        for item in previous.get("results", [])
    }
    curr_map = {
        item["ip"]: {p["port"] for p in item.get("open_ports", [])}
        for item in current.get("results", [])
    }

    all_ips = sorted(set(prev_map) | set(curr_map))
    for ip in all_ips:
        prev_ports = prev_map.get(ip, set())
        curr_ports = curr_map.get(ip, set())

        new_ports = sorted(curr_ports - prev_ports)
        gone_ports = sorted(prev_ports - curr_ports)

        if new_ports:
            changes.append(f"{ip}: new open ports {new_ports}")
        if gone_ports:
            changes.append(f"{ip}: ports no longer open {gone_ports}")

    if not changes:
        changes.append("No port changes detected compared to the previous scan.")

    return changes

def ollama_summary(scan_data: Dict[str, Any], changes: List[str], model: str = "llama3.2") -> str:
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
                    for p in item["open_ports"]
                ],
            }
            for item in scan_data["results"]
        ],
    }

    prompt = (
        "Summarize these home network scan results in plain English. "
        "Highlight devices with exposed web interfaces or higher-risk ports. "
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
        "http://localhost:11434/api/chat",
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

def print_results_table(results: List[Dict[str, Any]]) -> None:
    print("\n=== HOME NETWORK PORT SCAN ===\n")
    header = (
        f"{'IP Address':<16} "
        f"{'Hostname':<25} "
        f"{'MAC Address':<20} "
        f"{'Vendor':<22} "
        f"{'Port':<8} "
        f"{'Service':<15} "
        f"{'Product':<18} "
        f"{'Version':<25} "
        f"{'Risk':<8} "
        f"{'Banner':<40}"
    )
    print(header)
    print("-" * len(header))

    for item in results:
        ip = item["ip"]
        hostname = item.get("hostname", "-")[:24]
        mac = item.get("mac", "-")[:19]
        vendor = str(item.get("vendor", "-"))[:21]
        ports = item.get("open_ports", [])

        if not ports:
            print(
                f"{ip:<16} "
                f"{hostname:<25} "
                f"{mac:<20} "
                f"{vendor:<22} "
                f"{'-':<8} "
                f"{'No open ports':<15} "
                f"{'-':<18} "
                f"{'-':<25} "
                f"{'-':<8} "
                f"{'-':<40}"
            )
            continue

        for p in ports:
            product = str(p.get("product", "-"))[:17]
            version = str(p.get("version", "-"))[:24]
            banner = str(p.get("banner", "-")).replace("\n", " ")[:39]

            print(
                f"{ip:<16} "
                f"{hostname:<25} "
                f"{mac:<20} "
                f"{vendor:<22} "
                f"{str(p['port']):<8} "
                f"{p['service']:<15} "
                f"{product:<18} "
                f"{version:<25} "
                f"{p['risk']:<8} "
                f"{banner:<40}"
            )

def run_scan(file_path: str, threads: int, all_ports: bool, ports: Optional[str], use_ollama: bool, model: str) -> Dict[str, Any]:
    devices = load_devices(file_path)
    print(f"[+] Loaded {len(devices)} unique devices: {devices}")

    results: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(enrich_result, ip, all_ports, ports): ip
            for ip in devices
        }

        for future in as_completed(future_map):
            results.append(future.result())

    unique_results = {}
    for item in results:
        ip = item["ip"]

        if ip not in unique_results:
            unique_results[ip] = item
        else:
            old_count = unique_results[ip].get("open_ports_count", 0)
            new_count = item.get("open_ports_count", 0)
            if new_count > old_count:
                unique_results[ip] = item

    results = list(unique_results.values())
    results.sort(key=lambda item: tuple(int(part) for part in item["ip"].split(".")))

    scan_data = {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "devices_scanned": len(results),
        "results": results,
    }

    previous = load_previous_scan()
    changes = compare_scans(previous, scan_data)

    print_scan_results_grouped(scan_data)
    print("\n=== CHANGES SINCE LAST SCAN ===")
    for change in changes:
        print(f"- {change}")

    save_scan_results(scan_data)
    export_csv(results)
    export_html_report(scan_data, changes)

    print(f"\n[+] CSV report saved to {CSV_EXPORT_FILE}")
    print(f"[+] HTML report saved to {HTML_REPORT_FILE}")
    if use_ollama:
        print("\n=== OLLAMA SUMMARY ===")
        print(ollama_summary(scan_data, changes, model=model))

    return scan_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Home network scanner for owned/authorized networks.")
    parser.add_argument("--file", default="devices.txt", help="Path to devices file")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Worker threads")
    parser.add_argument("--ports", default=None, help="Custom ports like 22,80,443 or 1-1024")
    parser.add_argument("--allports", action="store_true", help="Scan all TCP ports")
    parser.add_argument("--ollama", action="store_true", help="Ask local Ollama to summarize results")
    parser.add_argument("--model", default="llama3.2", help="Ollama model name")
    args = parser.parse_args()

    all_ports = args.allports
    print(f"[+] Full port scan enabled: {all_ports}")

    run_scan(
        file_path=args.file,
        threads=max(1, args.threads),
        all_ports=all_ports,
        ports=args.ports,
        use_ollama=args.ollama,
        model=args.model,
    )


if __name__ == "__main__":
    main()
