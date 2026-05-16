# Security Assessment Report
## Threat Detection Capability Assessment — Windows 11 Enterprise Endpoint

---

| | |
|---|---|
| **Prepared By** | Elijah Marcisz |
| **Institution** | Indiana University Bloomington |
| **Assessment Date** | May 10–14, 2026 |
| **Report Date** | May 15, 2026 |
| **Classification** | Confidential |
| **Version** | 1.0 |
| **Environment** | Windows 11 Enterprise — Batmans-PC |
| **SIEM Platform** | Wazuh 4.7.3 |

---

## 1. Executive Summary

### Overview
A threat detection capability assessment was conducted on a Windows 11
Enterprise endpoint between May 10–14, 2026. The assessment simulated
five real-world adversary techniques documented in the MITRE ATT&CK
framework using Atomic Red Team, and evaluated detection coverage using
the Wazuh SIEM platform with Sysmon endpoint telemetry.

### Overall Risk Rating: HIGH

The environment demonstrated partial detection capability across four
of five simulated techniques. However, several critical gaps were
identified including a missing network reconnaissance detection rule,
insufficient alert severity tuning for credential dumping activity,
and no SIEM visibility into Windows Defender block events. The CIS
Windows 11 Enterprise benchmark score of 33% indicates the endpoint
is significantly under-hardened relative to industry standards.

### Key Findings Summary
- **4 of 5** ATT&CK techniques generated Wazuh alerts
- **LSASS credential dumping succeeded** — 93MB dump written in
  0.6 seconds — indicating Windows Protected Process Light is
  not enabled
- **Network reconnaissance has no detection coverage** — Wazuh
  lacks threshold-based port scanning correlation rules
- **Windows Defender events not ingested** — preventive blocks
  are invisible to the SIEM
- **CIS Benchmark score: 33%** — well below the recommended 75%

### Top 3 Recommendations
1. Enable Windows Credential Guard and Protected Process Light
   to prevent LSASS memory access
2. Add Windows Defender event channel to Wazuh agent config
   to close the preventive control visibility gap
3. Remediate top CIS benchmark failures to reduce overall
   attack surface

---

## 2. Scope and Methodology

### Scope
| Item | Detail |
|---|---|
| **System Assessed** | Windows 11 Enterprise Endpoint |
| **Hostname** | Batmans-PC |
| **Agent ID** | 001 |
| **Assessment Type** | Purple Team / Detection Validation |
| **Assessment Period** | May 10–14, 2026 |
| **Frameworks Referenced** | MITRE ATT&CK v14, NIST CSF 2.0, CIS Controls v8 |

### Methodology
Attack simulations were conducted using Atomic Red Team, an
open-source adversary simulation framework maintained by Red Canary.
Each test maps to a specific MITRE ATT&CK technique and generates
realistic telemetry on the target system. Detection coverage was
evaluated using Wazuh 4.7.3, an open-source SIEM and XDR platform
configured to collect Windows Event Logs and Sysmon telemetry via
the SwiftOnSecurity Sysmon configuration.

For each technique, the following workflow was followed:
1. Execute atomic test in PowerShell as Administrator
2. Monitor Wazuh Security Events in real time
3. Document alerts, rule IDs, and evidence fields
4. Run cleanup to restore system state
5. Document findings and gaps

### Tools Used
| Tool | Version | Purpose |
|---|---|---|
| Wazuh | 4.7.3 | SIEM and detection platform |
| Wazuh Agent | 4.7.3 | Windows endpoint telemetry collection |
| Sysmon | Latest | Rich endpoint event logging |
| SwiftOnSecurity Config | Latest | Sysmon ATT&CK-mapped ruleset |
| Atomic Red Team | Latest | Adversary simulation framework |
| Docker (WSL2) | Latest | Wazuh infrastructure deployment |
| ProcDump | 12.0 | LSASS dump simulation (Sysinternals) |

### Setup Issues Encountered
| Issue | Resolution |
|---|---|
| Port 55000 blocked by Windows reserved range | Remapped to 55001 in docker-compose.yml |
| Docker volume mount errors in PowerShell | Switched to Ubuntu WSL terminal |
| Wazuh agent ossec.conf syntax error | Rewrote config via PowerShell to fix malformed localfile block |
| Windows Defender policy blocking exclusions | Ran Atomic Red Team install directly without exclusion |
| T1046 no compatible Windows tests | Documented as detection gap, reviewed native capability manually |

---

## 3. Baseline Assessment

Prior to running attack simulations, a baseline of the environment
was established. Wazuh's Security Configuration Assessment (SCA)
module automatically evaluated the endpoint against the CIS Microsoft
Windows 11 Enterprise Benchmark v1.0.0.

### Baseline Metrics
| Metric | Value |
|---|---|
| Total events at baseline | 617 |
| CIS Benchmark Score | 33% |
| CIS Benchmark Threshold | 75% |
| Assessment Date | May 10, 2026 |

### Notable Baseline Findings
| Rule ID | Description | Level |
|---|---|---|
| 19004 | CIS score below 50% | 7 |
| 19007 | Preview builds/feature update settings misconfigured | 7 |
| 19008 | Automatic update settings misconfigured | 3 |
| 19009 | Quality update scheduling misconfigured | 3 |

---

## 4. Technical Findings

---

### F-001 — Suspicious PowerShell Execution Detected
**Severity:** Medium
**ATT&CK Technique:** T1059.001 — PowerShell
**ATT&CK Tactic:** Execution
**NIST CSF:** DE.CM-4
**CIS Control:** CIS Control 8, 10
**Status:** Open

**Description:**
Wazuh successfully detected obfuscated PowerShell execution
using Base64 encoded payloads and the -EncodedCommand flag.
Four separate rules fired across two test variations,
demonstrating layered detection coverage for this technique.
Test T1059.001-1 (Mimikatz download) was blocked by Windows
Defender AMSI but the block event was not captured in Wazuh,
indicating a logging gap for preventive control actions.

**Evidence:**
| Rule ID | Description | Level |
|---|---|---|
| 92041 | Base64 value added to registry key | 10 |
| 92057 | PowerShell spawned base64 encoded command | 12 |
| 92058 | Application Compatibility Database launched | 12 |
| 92213 | Executable dropped in malware folder | 15 |

**Key Fields Observed:**
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- TargetFilename: C:\Users\elija\AppData\Local\Temp\PSScriptPolicyTest
- Channel: Microsoft-Windows-Sysmon/Operational
- EventID: 1, 11
- Timestamp: May 13, 2026 @ 00:52:16

**Risk:**
Attackers commonly use PowerShell with obfuscation flags to
execute malicious code while evading signature-based detection.
Without behavioral controls, encoded payloads can deliver
any capability including credential theft, lateral movement,
and ransomware deployment.

**Recommendations:**
- Enable PowerShell Script Block Logging via Group Policy
- Implement AMSI integration for behavioral inspection
- Add Windows Defender Operational event channel to Wazuh
  to capture AMSI block events
- Consider PowerShell Constrained Language Mode for
  non-administrative users

---

### F-002 — Scheduled Task Creation Detected
**Severity:** Medium
**ATT&CK Technique:** T1053.005 — Scheduled Task
**ATT&CK Tactic:** Persistence, Privilege Escalation
**NIST CSF:** DE.CM-1
**CIS Control:** CIS Control 8
**Status:** Open

**Description:**
Wazuh detected the creation of a scheduled task via Windows
Security Event ID 4698. The detection fired successfully and
captured the task name and creating user account. This technique
is commonly used by attackers to establish persistence that
survives system reboots.

**Evidence:**
| Rule ID | Description | Level |
|---|---|---|
| 60009 | Windows scheduled task created | Medium |

**Key Fields Observed:**
- EventID: 4698
- SubjectUserName: elija
- Channel: WinEventLog:Security
- Timestamp: May 13, 2026

**Risk:**
Scheduled tasks allow attackers to maintain persistent access
without requiring an active session. If the creating account
is compromised, the attacker can ensure their tooling executes
on every reboot or at defined intervals indefinitely.

**Recommendations:**
- Establish a baseline inventory of all legitimate scheduled
  tasks in the environment
- Alert on task creation outside of defined change windows
- Implement application whitelisting to prevent unauthorized
  binaries from being scheduled

---

### F-003 — LSASS Credential Dump Successful
**Severity:** High
**ATT&CK Technique:** T1003.001 — LSASS Memory
**ATT&CK Tactic:** Credential Access
**NIST CSF:** DE.CM-1
**CIS Control:** CIS Control 16
**Status:** Open

**Description:**
ProcDump successfully created a 93MB memory dump of the
lsass.exe process in 0.6 seconds, confirming that Windows
Protected Process Light (PPL) is not enabled on this endpoint.
Wazuh detected the activity via Sysmon Process Create (Event
ID 1) but only at Level 3 severity, which is insufficient
for a Critical-tier credential access event. The dump file
was written to C:\Windows\Temp\lsass_dump.dmp and could be
exfiltrated for offline credential extraction.

**Evidence:**
| Rule ID | Description | Level |
|---|---|---|
| 92032 | Suspicious Windows cmd shell execution | 3 |

**Key Fields Observed:**
- Image: C:\AtomicRedTeam\ExternalPayloads\procdump.exe
- CommandLine: procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
- IntegrityLevel: High
- Company: Sysinternals
- ParentImage: C:\Windows\System32\cmd.exe
- DumpFile: C:\Windows\Temp\lsass_dump.dmp (93MB)
- Timestamp: May 14, 2026 @ 21:17:00

**Risk:**
A successful LSASS dump gives an attacker access to all
credential material for accounts that have authenticated
on this machine including domain accounts. NTLM hashes
can be used for Pass-the-Hash attacks enabling lateral
movement across the entire domain without knowing plaintext
passwords. This is one of the highest-impact post-exploitation
techniques in use today.

**Recommendations:**
- Enable Windows Credential Guard immediately to prevent
  credential material from being stored in LSASS memory
- Enable Protected Process Light (PPL) for LSASS via registry
- Create a dedicated high-severity Wazuh rule for any process
  accessing lsass.exe to elevate this from Level 3 to Critical
- Implement application whitelisting to block unauthorized
  use of ProcDump and similar tools

---

### F-004 — Registry Run Key Persistence Detected
**Severity:** Medium
**ATT&CK Technique:** T1547.001 — Registry Run Keys
**ATT&CK Tactic:** Persistence, Privilege Escalation
**NIST CSF:** DE.CM-1
**CIS Control:** CIS Control 10
**Status:** Open

**Description:**
Wazuh detected a registry modification to the CurrentVersion\Run
key via Sysmon Event ID 13 (Registry Value Set). The detection
is notable because Sysmon's SwiftOnSecurity configuration
automatically tagged the event with the ATT&CK technique
identifier T1060/RunKey, demonstrating the value of a
properly configured Sysmon deployment. The malicious entry
pointed to C:\Path\AtomicRedTeam.exe and would execute on
every user logon.

**Evidence:**
| Rule ID | Description | Level |
|---|---|---|
| 92302 | Registry entry modified for next logon via reg.exe | 6 |
| 92307 | New service creation found in registry | 3 |

**Key Fields Observed:**
- TargetObject: HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team
- Details: C:\\Path\\AtomicRedTeam.exe
- EventType: SetValue
- Image: C:\\Windows\\system32\\reg.exe
- RuleName: T1060, RunKey
- User: BatmansPC\elija
- Timestamp: May 14, 2026 @ 21:31:26

**Risk:**
Registry Run key persistence allows attackers to survive
reboots and maintain long-term access without requiring
elevated privileges. Combined with credential theft this
enables sustained access to the environment that is
difficult to fully eradicate without a thorough IR process.

**Recommendations:**
- Implement registry integrity monitoring with a known-good
  baseline of all legitimate Run key entries
- Alert on any modification to autostart registry locations
  outside of defined change windows
- Regularly audit Run keys for unexpected entries

---

### F-005 — Network Reconnaissance Detection Gap
**Severity:** Medium
**ATT&CK Technique:** T1046 — Network Service Discovery
**ATT&CK Tactic:** Discovery
**NIST CSF:** DE.CM-1
**CIS Control:** CIS Control 13
**Status:** Open

**Description:**
No Atomic Red Team tests for T1046 were compatible with the
Windows 11 platform. Manual review confirmed that while
Sysmon Event ID 3 (Network Connection) events are being
collected, Wazuh has no correlation rule to detect
high-volume port scanning behavior from a single process.
Individual connection events are logged but cannot be
aggregated into a port scan detection without a custom
threshold rule.

**Evidence:**
No T1046-specific alerts fired. Side-effect alerts observed:
| Rule ID | Description | Level |
|---|---|---|
| 92052 | Windows command prompt started by abnormal process | 4 |
| 61017 | Process terminated due to unhandled exception | 9 |

**Risk:**
Network reconnaissance is typically performed between
initial compromise and lateral movement. Without detection
coverage for this technique, an attacker can silently map
the internal network and identify high-value targets such
as domain controllers and database servers before moving
laterally — potentially going undetected until significant
damage has been done.

**Recommendations:**
- Implement a custom Wazuh threshold rule alerting when
  a single process generates connections to more than 10
  distinct destination ports within 60 seconds
- Deploy network-level detection (IDS/IPS) to complement
  endpoint-based Sysmon logging
- Consider deploying Zeek or Suricata for network traffic
  analysis

---

### F-006 — CIS Benchmark Score Below Threshold
**Severity:** High
**ATT&CK Technique:** N/A
**NIST CSF:** ID.RA-1
**CIS Control:** CIS IG1
**Status:** Open

**Description:**
Wazuh's Security Configuration Assessment module evaluated
the endpoint against the CIS Microsoft Windows 11 Enterprise
Benchmark v1.0.0 and reported a score of 33%, significantly
below the recommended minimum threshold of 75%. This indicates
that the majority of baseline security hardening controls
recommended by the Center for Internet Security have not
been implemented on this endpoint.

**Evidence:**
- Wazuh SCA Rule ID: 19004
- Score: 33% (33 of ~100 checks passing)
- Benchmark: CIS Microsoft Windows 11 Enterprise v1.0.0
- Timestamp: May 10, 2026

**Notable Failing Checks:**
- Quality update scheduling not configured per CIS standard
- Preview builds and feature update settings misconfigured
- Automatic update settings not compliant
- Pause Updates access not restricted

**Risk:**
A low CIS benchmark score indicates the system has not been
hardened against common attack vectors. Each failing check
represents a potential avenue for exploitation. In aggregate
a score of 33% means the endpoint presents significantly
more attack surface than a hardened system, increasing the
likelihood of successful exploitation across multiple
ATT&CK techniques.

**Recommendations:**
- Prioritize remediation of all CIS IG1 controls as
  immediate actions — these are the baseline minimum
- Develop a hardening roadmap targeting 75% score
  within 90 days
- Re-run SCA assessment after each remediation batch
  to track progress
- Consider using a GPO to enforce CIS settings at scale

---

## 5. Risk Summary Matrix

| ID | Finding | Severity | ATT&CK ID | Status |
|---|---|---|---|---|
| F-001 | Suspicious PowerShell Execution | Medium | T1059.001 | Open |
| F-002 | Scheduled Task Creation | Medium | T1053.005 | Open |
| F-003 | LSASS Credential Dump Successful | High | T1003.001 | Open |
| F-004 | Registry Run Key Persistence | Medium | T1547.001 | Open |
| F-005 | Network Reconnaissance Detection Gap | Medium | T1046 | Open |
| F-006 | CIS Benchmark Score Below Threshold | High | N/A | Open |

### Severity Distribution
| Severity | Count |
|---|---|
| Critical | 0 |
| High | 2 |
| Medium | 4 |
| Low | 0 |
| Informational | 0 |

---

## 6. Detection Coverage Summary

| Technique | Detected | Rule IDs | Max Severity |
|---|---|---|---|
| T1059.001 PowerShell | ✅ Yes | 92041, 92057, 92058, 92213 | 15 |
| T1053.005 Scheduled Task | ✅ Yes | 60009 | Medium |
| T1003.001 LSASS Dumping | ⚠️ Partial | 92032 | 3 (under-tuned) |
| T1547.001 Registry Persistence | ✅ Yes | 92302, 92307 | 6 |
| T1046 Network Recon | ❌ No | N/A | N/A |

**Detection Rate: 4/5 techniques detected (80%)**
**Gap: 1 technique with no detection coverage**
**Tuning Required: 1 technique detected at insufficient severity**

---

## 7. Appendix

### A — References
| Resource | URL |
|---|---|
| MITRE ATT&CK | https://attack.mitre.org |
| NIST CSF 2.0 | https://www.nist.gov/cyberframework |
| CIS Controls v8 | https://www.cisecurity.org/controls |
| Wazuh Documentation | https://documentation.wazuh.com |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |
| SwiftOnSecurity Sysmon Config | https://github.com/SwiftOnSecurity/sysmon-config |

### B — Environment Configuration
- Wazuh 4.7.3 single-node deployment via Docker on WSL2
- Sysmon with SwiftOnSecurity configuration
- Wazuh agent ossec.conf configured with Sysmon
  Operational event channel
- Assessment conducted on Windows 11 Enterprise

### C — Screenshots
| File | Description |
|---|---|
| T1059-alert.png | Detection 1 — PowerShell alerts dashboard |
| T1059-detail.png | Detection 1 — Expanded event fields |
| T1053-alert.png | Detection 2 — Scheduled task alert |
| T1003-alert.png | Detection 3 — LSASS ProcDump alert |
| T1547-alert.png | Detection 4 — Registry Run key alert |
| T1547-detail.png | Detection 4 — Expanded event fields |
| cis-benchmark.png | F-006 — CIS benchmark score 33% |
| wazuh-dashboard.png | Overall MITRE ATT&CK dashboard view |
