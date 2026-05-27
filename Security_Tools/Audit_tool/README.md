# Network Security Audit Tool

A Python-based network security scanner that discovers active devices on a local network, scans common ports on each device, flags high risk findings, and generates a timestamped JSON audit report.

## Features

- **Device Discovery** — Finds all active hosts on a subnet using TCP connect scanning
- **Port Scanning** — Checks 7 common ports per device (FTP, SSH, Telnet, HTTP, HTTPS, SMB, RDP)
- **Risk Flagging** — Automatically labels open ports as Low, Medium, High, or Critical risk
- **Audit Report** — Generates a timestamped JSON report of all findings
- **WSL Compatible** — Works in Windows Subsystem for Linux without raw packet privileges

## Technologies Used

- Python 3
- `socket` — TCP connect scanning
- `threading` — Concurrent scanning for performance
- `ipaddress` — Subnet parsing and IP math
- `json` — Report generation
- `colorama` — Colored terminal output

## Installation

```bash
git clone https://github.com/eli-the-marcsman/Cyber_Projects.git
cd Cyber_Projects
pip install colorama
```

## Usage

**Run device discovery only:**
```bash
python3 discovery.py --subnet 10.0.0.0/24
```

**Run port scanner:**
```bash
python3 scanner.py --subnet 10.0.0.0/24
```

**Run full audit and generate report:**
```bash
python3 report.py
```

## Project Structure

```
Audit_tool/
├── discovery.py    # Device discovery — finds active hosts via TCP scan
├── scanner.py      # Port scanner — checks common ports and flags risks
├── report.py       # Report generator — saves findings to JSON
└── README.md       # Project documentation
```

## Ports Scanned

| Port | Service | Risk Level | Notes |
|------|---------|------------|-------|
| 21   | FTP     | High       | Unencrypted file transfer |
| 22   | SSH     | Medium     | Secure remote access |
| 23   | Telnet  | Critical   | Unencrypted remote access — should never be open |
| 80   | HTTP    | Low        | Standard web traffic |
| 443  | HTTPS   | Low        | Encrypted web traffic |
| 445  | SMB     | Critical   | Windows file sharing — WannaCry vector |
| 3389 | RDP     | High       | Windows remote desktop |

## Disclaimer

This tool is intended for use on networks you own or have explicit permission to scan. Unauthorized network scanning may violate the Computer Fraud and Abuse Act (CFAA) and other applicable laws. Always obtain proper authorization before scanning any network.