# config.py

from typing import Dict

APP_NAME = "Willow"
OLLAMA_MODEL = "llama3.2"

DEFAULT_TIMEOUT = 1
DEFAULT_THREADS = 100
DEFAULT_TOP_PORTS = 100

REPORTS_DIR = "reports"
ASSETS_DIR = "assets"
TEMPLATES_DIR = "templates"
SCAN_HISTORY_FILE = "reports/scan_results_latest.json"
CSV_EXPORT_FILE = "reports/scan_results.csv"
HTML_REPORT_FILE = "reports/scan_report.html"

DEFAULT_THREADS = 8
NVD_RESULTS_LIMIT = 4

MAC_VENDOR_CACHE: Dict[str, str] = {}

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

HTTP_PORTS = [80, 443, 3000, 8000, 8080, 5000]

HTTP_TIMEOUT = 3

HTTP_HEADERS = {
    "User-Agent": "WillowRecon/1.0",
    "Accept": "*/*"
}

ENABLE_HTTP_ENUM = True
ENABLE_HEADER_ANALYSIS = True
ENABLE_BASIC_ENDPOINT_CHECKS = True
