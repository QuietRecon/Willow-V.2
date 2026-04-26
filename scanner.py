from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Any, Optional
import ipaddress
import socket
import ssl
import subprocess
from pathlib import Path
import ipaddress
from config import MAC_VENDOR_CACHE
from config import BANNER_PORTS
import json
import re
import urllib.parse
import urllib.request
from typing import List, Dict
from config import RISK_PORTS, SERVICE_DESCRIPTIONS, NVD_RESULTS_LIMIT
from config import HTTP_PORTS

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
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
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
            headers={"User-Agent": "Willow/1.0"}
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            vendor = resp.read().decode("utf-8").strip()
            vendor = vendor if vendor else "Unknown Vendor"

            MAC_VENDOR_CACHE[mac_prefix] = vendor
            return vendor

    except Exception:
        return "Unknown Vendor"

def is_http_service(port):
    return port in HTTP_PORTS
    if is_http_service(port):
        result["is_http"] = True

def parse_nmap_output(text: str) -> List[Dict[str, Any]]:
    open_ports: List[Dict[str, Any]] = []

    for raw in text.splitlines():
        line = raw.strip()

        if "/tcp" not in line:
            continue

        parts = line.split()

        if len(parts) < 3:
            continue

        port_proto = parts[0]
        state = parts[1]

        if state.lower() != "open":
            continue

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
    return parse_nmap_output(output)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    if port not in BANNER_PORTS:
        return "-"

    if port in {80, 8080}:
        try:
            req = urllib.request.Request(
                f"http://{ip}:{port}/",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                server = resp.headers.get("Server", "-")
                return f"HTTP {resp.status}; Server={server}"
        except Exception:
            return "-"

    if port in {443, 8443}:
        try:
            req = urllib.request.Request(
                f"https://{ip}:{port}/",
                headers={"User-Agent": "Mozilla/5.0"}
            )
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
    return SERVICE_DESCRIPTIONS.get((service or "").lower(), "No description available")

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
            headers={"User-Agent": "Willow/1.0"}
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

def run_scan(file_path: str, threads: int, all_ports: bool, ports: Optional[str]) -> Dict[str, Any]:
    devices = load_devices(file_path)
    #print(f"[+] Loaded {len(devices)} unique devices: {devices}") --verbose output
    print(f"[+] Loaded {len(devices)} devices for scanning")
    print("[+] Scanning ports...")
    
    results: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(enrich_result, ip, all_ports, ports): ip
            for ip in devices
        }

        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                print(f"[ERROR] Failed to scan {ip}: {exc}")

    unique_results = {}
    for item in results:
        ip = item.get("ip", "-")

        if ip not in unique_results:
            unique_results[ip] = item
        else:
            old_count = unique_results[ip].get("open_ports_count", 0)
            new_count = item.get("open_ports_count", 0)
            if new_count > old_count:
                unique_results[ip] = item

    results = list(unique_results.values())
    results.sort(key=lambda item: tuple(int(part) for part in item.get("ip", "0.0.0.0").split(".")))

    scan_data = {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "devices_scanned": len(results),
        "results": results,
    }

    return scan_data
