from typing import List, Dict, Any


def truncate(text: str, max_len: int) -> str:
    text = str(text)
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


from typing import List, Dict, Any

def print_results_table(results: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 90)
    print("=== WILLOW PORT SCAN ===")
    print("=" * 90)

    for item in results:
        ip = item.get("ip", "-")
        hostname = item.get("hostname", "-")
        mac = item.get("mac", "-")
        vendor = item.get("vendor", "-")
        ports = item.get("open_ports", [])

        print(f"\n[DEVICE] {ip}")
        print(f"Hostname : {hostname}")
        print(f"MAC      : {mac}")
        print(f"Vendor   : {vendor}")

        if not ports:
            print("No open ports found.")
            print("-" * 90)
            continue

        print("-" * 90)
        print(
            f"{'Port':<8}"
            f"{'Service':<18}"
            f"{'Product':<28}"
            f"{'Version':<26}"
            f"{'Risk':<10}"
        )
        print("-" * 90)

        for p in ports:
            port = str(p.get("port", "-"))
            service = truncate(str(p.get("service", "-")), 17)
            product = truncate(str(p.get("product", "-")), 27)
            version = truncate(str(p.get("version", "-")), 25)
            risk = str(p.get("risk", "-"))

            print(
                f"{port:<8}"
                f"{service:<18}"
                f"{product:<28}"
                f"{version:<26}"
                f"{risk:<10}"
            )

        print("-" * 90)
