from __future__ import annotations

import csv
import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"


def safe_text(value: Any, default: str = "-") -> str:
    """Return clean printable text."""
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


class KEVLookup:
    """
    Loads and indexes the CISA Known Exploited Vulnerabilities catalog by CVE ID.
    """

    def __init__(self, csv_path: str | Path):
        self.csv_path = Path(csv_path)
        self.index: Dict[str, Dict[str, Any]] = {}

    def download_catalog(self) -> None:
        """
        Download the latest KEV CSV from CISA to the configured path.
        """
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)

        with urllib.request.urlopen(KEV_CSV_URL, timeout=30) as response:
            data = response.read()

        self.csv_path.write_bytes(data)

    def load(self) -> None:
        """
        Load the KEV CSV into memory and build a CVE-keyed index.
        """
        if not self.csv_path.exists():
            raise FileNotFoundError(f"KEV CSV not found: {self.csv_path}")

        self.index.clear()

        with self.csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                cve_id = safe_text(row.get("cveID"), "").upper()
                if not cve_id:
                    continue

                self.index[cve_id] = {
                    "cve_id": cve_id,
                    "vendor_project": safe_text(row.get("vendorProject")),
                    "product": safe_text(row.get("product")),
                    "vulnerability_name": safe_text(row.get("vulnerabilityName")),
                    "date_added": safe_text(row.get("dateAdded")),
                    "short_description": safe_text(row.get("shortDescription")),
                    "required_action": safe_text(row.get("requiredAction")),
                    "due_date": safe_text(row.get("dueDate")),
                    "known_ransomware_campaign_use": safe_text(
                        row.get("knownRansomwareCampaignUse")
                    ),
                    "notes": safe_text(row.get("notes")),
                    "cwes": safe_text(row.get("cwes")),
                }

    def refresh(self) -> None:
        """
        Download and reload the KEV catalog.
        """
        self.download_catalog()
        self.load()

    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Return KEV details for a single CVE ID if present.
        """
        if not cve_id:
            return None
        return self.index.get(cve_id.strip().upper())

    def enrich_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return a copy of a vulnerability dict with KEV metadata attached.
        """
        enriched = dict(vuln)

        cve_id = (
            vuln.get("cve_id")
            or vuln.get("cve")
            or vuln.get("id")
            or ""
        )
        cve_id = safe_text(cve_id, "").upper()

        kev_match = self.lookup_cve(cve_id) if cve_id else None

        enriched["cve_id"] = cve_id or "-"
        enriched["kev"] = bool(kev_match)
        enriched["kev_details"] = kev_match if kev_match else None

        return enriched

    def enrich_port(self, port: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return a copy of a port dict with enriched vulnerability data.
        """
        enriched = dict(port)
        vulns = port.get("vulnerabilities", []) or []

        enriched_vulns = [self.enrich_vulnerability(v) for v in vulns]
        enriched["vulnerabilities"] = enriched_vulns
        enriched["kev_count"] = sum(1 for v in enriched_vulns if v.get("kev"))

        return enriched

    def enrich_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Return a copy of scan results with KEV metadata attached to vulnerabilities.
        Also print debug information about scan CVEs vs loaded KEV index.
        """
        scan_cves = []

        for device in results:
            for port in device.get("open_ports", []):
                for vuln in port.get("vulnerabilities", []):
                    cve = safe_text(vuln.get("cve_id"), "").upper()
                    if cve:
                        scan_cves.append(cve)

        print(f"[DEBUG] Loaded KEV index entries: {len(self.index)}")
        print(f"[DEBUG] Sample KEV CVEs: {list(sorted(self.index.keys()))[:10]}")
        print(f"[DEBUG] Scan CVEs found: {len(scan_cves)}")
        print(f"[DEBUG] Sample scan CVEs: {scan_cves[:10]}")

        matches = [cve for cve in scan_cves if cve in self.index]

        print(f"[DEBUG] KEV matches: {len(matches)}")
        print(f"[DEBUG] Matching CVEs: {matches}")

        enriched_results = []

        for device in results:
            enriched_device = dict(device)
            ports = device.get("open_ports", []) or []
            enriched_ports = [self.enrich_port(port) for port in ports]

            enriched_device["open_ports"] = enriched_ports
            enriched_device["kev_count"] = sum(p.get("kev_count", 0) for p in enriched_ports)

            enriched_results.append(enriched_device)

        return enriched_results

    def summary_stats(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Return simple KEV stats for reporting/logging.
        """
        device_count = len(results)
        port_count = 0
        vuln_count = 0
        kev_count = 0

        for device in results:
            for port in device.get("open_ports", []) or []:
                port_count += 1
                vulns = port.get("vulnerabilities", []) or []
                vuln_count += len(vulns)
                kev_count += sum(1 for v in vulns if v.get("kev"))

        return {
            "devices": device_count,
            "ports": port_count,
            "vulnerabilities": vuln_count,
            "kev_matches": kev_count,
        }


def save_enriched_json(results: List[Dict[str, Any]], output_path: str | Path) -> None:
    """
    Save enriched results to JSON for reporting or Ollama input.
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

