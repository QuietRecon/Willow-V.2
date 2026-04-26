import json
import urllib.request


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_catalog():
    with urllib.request.urlopen(KEV_URL, timeout=15) as response:
        data = json.loads(response.read().decode("utf-8"))
    return data.get("vulnerabilities", [])


def build_kev_index(vulnerabilities):
    return {item["cveID"]: item for item in vulnerabilities if "cveID" in item}


def get_kev_index():
    kev_list = fetch_kev_catalog()
    return build_kev_index(kev_list)


def enrich_with_kev(vulns, kev_index):
    """
    vulns = list of dicts like:
    {
        "cve": "CVE-2023-1234",
        "severity": "High",
        "description": "...",
        "remediation": "..."
    }
    """
    enriched = []

    for vuln in vulns:
        cve = (vuln.get("cve") or vuln.get("cve_id") or "").strip()
        kev_match = kev_index.get(cve)

        vuln_copy = vuln.copy()
        vuln_copy["kev"] = bool(kev_match)
        vuln_copy["kev_details"] = kev_match if kev_match else None

        enriched.append(vuln_copy)

    return enriched
