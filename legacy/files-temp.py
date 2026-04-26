def load_kev_data(self):
    response = requests.get(self.kev_url)
    data = response.json()

    kev_entries = data.get("vulnerabilities", [])

    print(f"[DEBUG] Loaded KEV raw entries: {len(kev_entries)}")

    kev_cve_set = {
        entry.get("cveID", "").strip().upper()
        for entry in kev_entries
        if entry.get("cveID")
    }

    print(f"[DEBUG] Normalized KEV CVE set size: {len(kev_cve_set)}")
    print(f"[DEBUG] Sample KEV CVEs: {list(sorted(kev_cve_set))[:10]}")

    return kev_cve_set
