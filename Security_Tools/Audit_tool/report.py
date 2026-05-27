"""
report.py — Audit Report Module
Network Security Audit Tool

Takes the completed scan results from scanner.py and generates a
timestamped JSON report file documenting all discovered devices,
scanned ports, and flagged high risk findings.

Usage:
    Called automatically from main audit tool
    Output: audit_report_YYYY-MM-DD_HH-MM-SS.json
"""

import json
import argparse
from datetime import datetime
from scanner import scan_all_devices
from discovery import main as discover_devices

def generate_report(scan_results: list, subnet: str) -> dict:
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subnet":    subnet,
    }

    total_open = 0
    for device in scan_results:
        for port, info in device["ports"].items():
            if info["status"] == "open":
                total_open += 1

    report["total_devices"]    = len(scan_results)
    report["total_open_ports"] = total_open

    high_risk = []
    for device in scan_results:
        for port, info in device["ports"].items():
            if info["status"] == "open" and info["risk"] in ("High", "Critical"):
                high_risk.append({
                    "ip":      device["ip"],
                    "port":    port,
                    "service": info["service"],
                    "risk":    info["risk"]
                })

    report["high_risk_findings"] = high_risk
    report["devices"]            = scan_results
    return report


def save_report(report: dict) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename  = f"audit_report_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    return filename


def main():
    subnet       = "10.0.0.0/24"
    devices      = discover_devices()
    scan_results = scan_all_devices(devices)
    report       = generate_report(scan_results, "10.0.0.0/24")
    filename     = save_report(report)
    print(f"\n[+] Report saved to: {filename}")

if __name__ == "__main__":
    main()