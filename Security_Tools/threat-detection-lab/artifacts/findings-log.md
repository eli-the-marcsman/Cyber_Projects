# Findings Log — Risk Register
## Wazuh Threat Detection Capability Assessment

---

| | |
|---|---|
| **Prepared By** | Elijah Marcisz |
| **Institution** | Indiana University Bloomington |
| **Assessment Date** | May 10–14, 2026 |
| **Environment** | Windows 11 Enterprise — Batmans-PC |
| **Total Findings** | 6 |
| **Open** | 6 |
| **Closed** | 0 |

---

## Risk Register

| ID | Title | Severity | CVSS | ATT&CK ID | Tactic | NIST CSF | CIS Control | Status | Owner | Due Date |
|---|---|---|---|---|---|---|---|---|---|---|
| F-001 | Suspicious PowerShell Execution | Medium | 6.1 | T1059.001 | Execution | DE.CM-4 | CIS 8, 10 | Open | Endpoint Team | 90 days |
| F-002 | Scheduled Task Creation | Medium | 5.5 | T1053.005 | Persistence | DE.CM-1 | CIS 8 | Open | Endpoint Team | 90 days |
| F-003 | LSASS Credential Dump Successful | High | 8.4 | T1003.001 | Credential Access | DE.CM-1 | CIS 16 | Open | Security Team | 30 days |
| F-004 | Registry Run Key Persistence | Medium | 5.5 | T1547.001 | Persistence | DE.CM-1 | CIS 10 | Open | Endpoint Team | 90 days |
| F-005 | Network Recon Detection Gap | Medium | 5.3 | T1046 | Discovery | DE.CM-1 | CIS 13 | Open | SOC Team | 90 days |
| F-006 | CIS Benchmark Score Below Threshold | High | 7.2 | N/A | N/A | ID.RA-1 | CIS IG1 | Open | IT/Security Team | 90 days |

---

## Finding Details

---

### F-001 — Suspicious PowerShell Execution
**Severity:** Medium
**CVSS Score:** 6.1
**ATT&CK:** T1059.001 — Execution

**Description:**
Wazuh detected obfuscated PowerShell execution using Base64
encoded payloads and -EncodedCommand flags. Four rules fired
at severity levels up to 15. Defender AMSI blocked a Mimikatz
download but the block was not logged in Wazuh.

**Affected Asset:** Batmans-PC
**Wazuh Rules:** 92041, 92057, 92058, 92213
**First Observed:** May 13, 2026 @ 00:52:16

**Remediation:**
- Enable PowerShell Script Block Logging via GPO
- Add Windows Defender event channel to Wazuh
- Implement AMSI integration
- Consider Constrained Language Mode for standard users

**Residual Risk if Unaddressed:**
Attackers can execute arbitrary code via encoded PowerShell
with limited detection visibility.

---

### F-002 — Scheduled Task Creation
**Severity:** Medium
**CVSS Score:** 5.5
**ATT&CK:** T1053.005 — Persistence

**Description:**
Wazuh detected scheduled task creation via Windows Security
Event ID 4698. Detection fired successfully but high false
positive rate expected without a task baseline in place.

**Affected Asset:** Batmans-PC
**Wazuh Rules:** 60009
**First Observed:** May 13, 2026

**Remediation:**
- Baseline all legitimate scheduled tasks
- Alert on tasks created outside change windows
- Implement application whitelisting for scheduled binaries

**Residual Risk if Unaddressed:**
Attackers can maintain persistent access through scheduled
tasks that survive reboots indefinitely.

---

### F-003 — LSASS Credential Dump Successful
**Severity:** High
**CVSS Score:** 8.4
**ATT&CK:** T1003.001 — Credential Access

**Description:**
ProcDump successfully dumped LSASS memory to disk (93MB in
0.6 seconds) confirming Windows PPL is disabled. Wazuh
detected the activity at Level 3 only — insufficient for
a Critical credential access event. Full credential material
for all accounts authenticated on this machine is at risk.

**Affected Asset:** Batmans-PC
**Wazuh Rules:** 92032
**First Observed:** May 14, 2026 @ 21:17:00

**Remediation:**
- Enable Windows Credential Guard — Priority 1
- Enable Protected Process Light for LSASS
- Create dedicated Critical-severity Wazuh rule for
  any process accessing lsass.exe
- Implement application whitelisting to block ProcDump

**Residual Risk if Unaddressed:**
All domain credentials that have touched this machine
are extractable. Enables unrestricted lateral movement
via Pass-the-Hash across the entire domain.

---

### F-004 — Registry Run Key Persistence
**Severity:** Medium
**CVSS Score:** 5.5
**ATT&CK:** T1547.001 — Persistence

**Description:**
Wazuh detected registry modification to CurrentVersion\Run
via Sysmon Event ID 13. Sysmon's SwiftOnSecurity config
auto-tagged the event as T1060/RunKey. Two rules fired
capturing the malicious binary path and registry key name.

**Affected Asset:** Batmans-PC
**Wazuh Rules:** 92302, 92307
**First Observed:** May 14, 2026 @ 21:31:26

**Remediation:**
- Baseline all legitimate Run key entries
- Alert on modifications outside change windows
- Regularly audit autostart registry locations

**Residual Risk if Unaddressed:**
Attackers maintain logon persistence without elevated
privileges, enabling long-term access that is difficult
to fully eradicate.

---

### F-005 — Network Reconnaissance Detection Gap
**Severity:** Medium
**CVSS Score:** 5.3
**ATT&CK:** T1046 — Discovery

**Description:**
Wazuh has no correlation rule to detect high-volume port
scanning from a single endpoint process. Sysmon Event ID 3
logs individual connections but they are not aggregated
into a port scan detection. No compatible Atomic Red Team
tests exist for T1046 on Windows 11.

**Affected Asset:** Batmans-PC / Entire Network
**Wazuh Rules:** None
**First Observed:** May 14, 2026

**Remediation:**
- Implement custom Wazuh threshold rule for port scanning
- Deploy network-layer IDS/IPS (Zeek, Suricata)
- Alert when single process connects to 10+ distinct
  ports within 60 seconds

**Residual Risk if Unaddressed:**
Attackers can silently map the internal network after
initial compromise with no SOC visibility, enabling
targeted lateral movement to high-value systems.

---

### F-006 — CIS Benchmark Score Below Threshold
**Severity:** High
**CVSS Score:** 7.2
**ATT&CK:** N/A

**Description:**
Wazuh SCA module evaluated the endpoint against CIS
Microsoft Windows 11 Enterprise Benchmark v1.0.0 and
reported a score of 33%, below the recommended 75%
threshold. Numerous baseline hardening controls are
not implemented including update management, feature
configuration, and access control settings.

**Affected Asset:** Batmans-PC
**Wazuh Rules:** 19004, 19007, 19008, 19009
**First Observed:** May 10, 2026

**Remediation:**
- Remediate all CIS IG1 controls immediately
- Develop 90-day hardening roadmap to reach 75%
- Use GPO to enforce CIS settings at scale
- Re-run SCA after each remediation batch

**Residual Risk if Unaddressed:**
Each failing CIS check represents an attack surface
that increases the likelihood of successful exploitation
across multiple ATT&CK techniques.

---

## Severity Summary

| Severity | Count | Percentage |
|---|---|---|
| Critical | 0 | 0% |
| High | 2 | 33% |
| Medium | 4 | 67% |
| Low | 0 | 0% |
| **Total** | **6** | **100%** |

---

## Remediation Priority Order

| Priority | Finding | Action | Timeline |
|---|---|---|---|
| 1 | F-003 LSASS | Enable Credential Guard + PPL | Immediate |
| 2 | F-006 CIS Benchmark | Remediate IG1 controls | 30 days |
| 3 | F-001 PowerShell | Enable Script Block Logging | 60 days |
| 4 | F-005 Network Recon | Implement threshold detection rule | 60 days |
| 5 | F-002 Scheduled Tasks | Baseline and tune alert | 90 days |
| 6 | F-004 Registry Persistence | Baseline Run keys | 90 days |
