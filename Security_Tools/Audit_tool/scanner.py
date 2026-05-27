"""
scanner.py — Port Scanner Module
Network Security Audit Tool

Uses TCP connect scanning to check for open ports on discovered devices.
Identifies open, closed, and filtered ports and flags high risk services.

Usage:
    python3 scanner.py
    python3 scanner.py --subnet 10.0.0.0/24
"""

import socket
import threading
import ipaddress
import argparse
from datetime import datetime
from discovery import main as discover_devices

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class _Fore:
        GREEN = YELLOW = RED = CYAN = WHITE = ""
    class _Style:
        BRIGHT = RESET_ALL = ""
    Fore = _Fore()
    Style = _Style()

PORTS = {
    21: {"service": "FTP", "risk": "High"},
    22: {"service": "SSH", "risk": "Medium"},
    23: {"service": "Telnet", "risk": "Critical"},
    80: {"service": "HTTP", "risk": "Low"},
    443: {"service": "HTTPS", "risk": "Low"},
    445: {"service": "SMB", "risk": "Critical"},
    3389: {"service": "RDP", "risk": "High"},
}

def scan_port(ip: str, port: int) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except:
        return
    
def scan_device(device: dict) -> dict:
    ip = device["ip"]
    results = {
    "ip":       device["ip"],
    "mac":      device["mac"],
    "hostname": device["hostname"],
    "ports":    {}
}
    
    for port in PORTS:
        status = scan_port(ip, port)
        results["ports"][port] = {
            "status":  status,
            "service": PORTS[port]["service"],
            "risk":    PORTS[port]["risk"]
        }

    return results

def scan_all_devices(devices: list) -> list:
    results = []
    lock    = threading.Lock()
    threads = []

    def scan_and_store(device):
        result = scan_device(device)
        with lock:
            results.append(result)

    for device in devices:
        t = threading.Thread(target=scan_and_store, args=(device,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results


def print_results(scan_results: list) -> None:
    if not scan_results:
        print("No scan results to display.")
        return

    for device in scan_results:
        print(f"\n{Style.BRIGHT}{'─'*50}")
        print(f" Device: {device['ip']} | Hostname: {device['hostname']}")
        print(f"{'─'*50}{Style.RESET_ALL}")

        for port, info in device["ports"].items():
            status  = info["status"]
            service = info["service"]
            risk    = info["risk"]

            if status == "open" and risk in ("High", "Critical"):
                color = Fore.RED
            elif status == "open":
                color = Fore.GREEN
            else:
                color = Fore.WHITE

            print(f"  {color}Port {port:<6} {service:<10} {status:<12} Risk: {risk}{Style.RESET_ALL}")

def main():
    print(f"\n{Style.BRIGHT}{'─'*50}")
    print(" Network Security Audit Tool — Port Scanner")
    print(f"{'─'*50}{Style.RESET_ALL}")
    
    devices = discover_devices()
    scan_results = scan_all_devices(devices)
    print_results(scan_results)

if __name__ == "__main__":
    main()