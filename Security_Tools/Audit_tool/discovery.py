"""
discovery.py — Device Discovery Module
Network Security Audit Tool

Uses TCP connect scanning to identify active hosts on a network.
Works in WSL and environments where raw ARP packets are restricted.

Usage:
    python3 discovery.py
    python3 discovery.py --subnet 10.0.0.0/24
    python3 discovery.py --timeout 1
"""

import socket
import threading
import ipaddress
import argparse
from datetime import datetime

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

def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "unknown"
    


def scan_host(ip: str, results: list, lock, timeout: int = 1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 80))  
        s.close()
        hostname = get_hostname(ip)
        with lock:
            results.append({
                "ip":           ip,
                "mac":          "N/A",
                "hostname":     hostname,
                "discovered_at": datetime.now().isoformat(timespec="seconds")
            })
    except:
        pass


def tcp_scan(subnet: str, timeout: int = 1) -> list:
    network  = ipaddress.IPv4Network(str(subnet), strict=False)
    results  = []
    lock     = threading.Lock()
    threads  = []

    for ip in network.hosts():
        t = threading.Thread(target=scan_host, args=(str(ip), results, lock, timeout))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    results.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return results


def print_devices(devices: list) -> None:
    if not devices:
        print("No devices found")
        return
    
    print(f"\n{'IP Address':<18}{'Hostname':<35}{'MAC'}")
    print("-" * 60)
    for d in devices:
        print(f"{d['ip']:<18}{d['hostname']:<35}{d['mac']}")
    
    print(f"\n[+] {len(devices)} device(s) found.")


def main() -> list:
    parser = argparse.ArgumentParser(description="TCP-based device discovery.")
    parser.add_argument("--subnet", "-s", type=str, default=None)
    parser.add_argument("--timeout", "-t", type=int, default=1)
    args = parser.parse_args()

    subnet = args.subnet if args.subnet else "10.0.0.0/24"

    print(f"\n{'─'*50}")
    print(" Network Security Audit Tool — Device Discovery")
    print(f"{'─'*50}")
    print(f"  Subnet  : {subnet}")
    print(f"  Timeout : {args.timeout}s")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    devices = tcp_scan(subnet, timeout=args.timeout)
    print_devices(devices)
    return devices

if __name__ == "__main__":
    main()


def get_local_subnet() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return "10.0.0.0/24"