from __future__ import annotations

import argparse

from rich.console import Console
from rich.panel import Panel
from scanner import run_scan
from report_generator import (
    print_scan_results_grouped,
    export_html_report,
    save_scan_results,
    export_csv,
    load_previous_scan,
    compare_scans,
)
from ollama_summary import generate_ollama_summary
from config import DEFAULT_THREADS
from kev_lookup import KEVLookup, save_enriched_json
from ui import print_results_table

console = Console()

def show_startup_banner() -> None:
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

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Willow AI-Assisted Network Scanner")
    parser.add_argument("--devices", default="assets/devices.txt", help="Path to device list")
    parser.add_argument("--all-ports", action="store_true", help="Scan all TCP ports")
    parser.add_argument("--ports", help="Specific ports to scan, e.g. 22,80,443")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Number of worker threads")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    show_startup_banner()

    scan_data = run_scan(
        file_path=args.devices,
        threads=args.threads,
        all_ports=args.all_ports,
        ports=args.ports,
    )

    kev = KEVLookup("assets/kev_catalog.csv")

    try:
        kev.refresh()
    except Exception as e:
        print(f"[!] KEV refresh failed: {e}")
        try:
            kev.load()
        except Exception as load_error:
            print(f"[!] No local KEV catalog available: {load_error}")
            kev = None

    if kev:
        results = scan_data.get("results", [])
        results = kev.enrich_results(results)
        scan_data["results"] = results

        stats = kev.summary_stats(results)

        print(
            f"[+] KEV enrichment complete: "
            f"{stats['kev_matches']} KEV match(es) across "
            f"{stats['vulnerabilities']} vulnerability record(s)."
        )

        save_enriched_json(results, "reports/scan_results_latest.json")
    else:
        print("[!] KEV index unavailable; continuing without KEV enrichment")

    previous_scan = load_previous_scan()
    changes = compare_scans(previous_scan, scan_data)

    print_scan_results_grouped(scan_data, console)
    print_results_table(scan_data.get("results", []))

    print("\n=== CHANGES SINCE LAST SCAN ===")
    for change in changes:
        print(f"- {change}")

    save_scan_results(scan_data)
    export_csv(scan_data.get("results", []))
    export_html_report(scan_data, changes)

    summary = generate_ollama_summary(scan_data, changes)

    console.print("\n[bold magenta]=== OLLAMA SUMMARY ===[/bold magenta]")
    console.print(summary)

if __name__ == "__main__":
    main()
