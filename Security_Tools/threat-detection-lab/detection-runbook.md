# Detection Runbook
## Wazuh Threat Detection Lab — Batmans-PC

**Analyst:** Elijah Marcisz
**Assessment Period:** May 10–14, 2026
**Environment:** Windows 11 Enterprise — Batmans-PC
**SIEM:** Wazuh 4.7.3
**Simulation Framework:** Atomic Red Team

---

## Runbook Entry 1 — T1059.001 PowerShell Execution

**Detection Name:** Suspicious PowerShell Execution
**ATT&CK Technique ID:** T1059.001
**ATT&CK Tactic:** Execution
**Severity:** Medium
**Atomic Tests Used:** T1059.001-10, T1059.001-17

**What the Test Did:**
Executed fileless PowerShell payloads using Base64 encoding
and the -EncodedCommand flag to simulate attacker obfuscation
techniques designed to evade string-based detection.

**Log Sources:**
- Microsoft-Windows-Sysmon/Operational
- Sysmon Event IDs: 1 (Process Create), 11 (File Create)

**Wazuh Rule IDs That Fired:**
- 92041 — Base64 value in registry key (Level 10)
- 92057 — PowerShell base64 encoded command (Level 12)
- 92058 — Application Compatibility Database (Level 12)
- 92213 — Executable dropped in malware folder (Level 15)

**Key Fields:**
- data.win.eventdata.image: powershell.exe
- data.win.eventdata.targetFilename: PSScriptPolicyTest
- data.win.eventdata.parentImage: powershell.exe

**False Positive Considerations:**
Legitimate admin scripts may use encoded commands. Verify
parent process and user context before escalating.

**Would You Escalate?** Yes — Level 15 alert with Base64
encoding and file drops warrants Tier 2 review.

**Analyst Notes:**
Mimikatz test (T1059.001-1) blocked by Defender AMSI.
Block not logged in Wazuh — Defender logging gap identified.

---

## Runbook Entry 2 — T1053.005 Scheduled Task Creation

**Detection Name:** Scheduled Task Created
**ATT&CK Technique ID:** T1053.005
**ATT&CK Tactic:** Persistence, Privilege Escalation
**Severity:** Medium
**Atomic Test Used:** T1053.005-1

**What the Test Did:**
Created a scheduled task via schtasks.exe to simulate an
attacker establishing persistence that survives reboots.

**Log Sources:**
- WinEventLog:Security
- Event ID: 4698 (Scheduled Task Created)

**Wazuh Rule IDs That Fired:**
- 60009 — Windows scheduled task created

**Key Fields:**
- data.win.system.eventID: 4698
- data.win.eventdata.subjectUserName: elija

**False Positive Considerations:**
Extremely common — software installers create tasks regularly.
Baseline known-good tasks and alert on deviations only.

**Would You Escalate?** Yes if task binary is in temp directory
or task name is randomized. Otherwise investigate further.

**Analyst Notes:**
High false positive rate expected in production. Recommend
building a whitelist of known-good scheduled tasks before
deploying this rule in a live environment.

---

## Runbook Entry 3 — T1003.001 LSASS Credential Dumping

**Detection Name:** LSASS Memory Access / Credential Dump
**ATT&CK Technique ID:** T1003.001
**ATT&CK Tactic:** Credential Access
**Severity:** High
**Atomic Test Used:** T1003.001-1

**What the Test Did:**
Used ProcDump to create a 93MB memory dump of lsass.exe.
This dump contains extractable credential material including
NTLM hashes and Kerberos tickets.

**Log Sources:**
- Microsoft-Windows-Sysmon/Operational
- Sysmon Event ID: 1 (Process Create)

**Wazuh Rule IDs That Fired:**
- 92032 — Suspicious Windows cmd shell execution (Level 3)

**Key Fields:**
- data.win.eventdata.image: procdump.exe
- data.win.eventdata.commandLine: procdump.exe -ma lsass.exe
- data.win.eventdata.integrityLevel: High
- data.win.eventdata.company: Sysinternals

**False Positive Considerations:**
ProcDump targeting lsass.exe has virtually no legitimate use
case. Treat any instance as malicious until proven otherwise.

**Would You Escalate?** Yes — immediately. Critical severity.
Assume credential compromise and initiate IR process.

**Analyst Notes:**
93MB dump written successfully in 0.6 seconds. Windows PPL
not enabled on this endpoint — primary remediation action.
Alert fired at low severity (Level 3) — rule tuning needed
to elevate LSASS-specific ProcDump to Critical.

---

## Runbook Entry 4 — T1547.001 Registry Run Key Persistence

**Detection Name:** Registry Run Key Modified for Persistence
**ATT&CK Technique ID:** T1547.001
**ATT&CK Tactic:** Persistence, Privilege Escalation
**Severity:** Medium
**Atomic Test Used:** T1547.001-1

**What the Test Did:**
Added a registry entry under CurrentVersion\Run pointing to
a malicious binary path, ensuring execution on every logon.

**Log Sources:**
- Microsoft-Windows-Sysmon/Operational
- Sysmon Event ID: 13 (Registry Value Set)

**Wazuh Rule IDs That Fired:**
- 92302 — Registry entry modified for next logon (Level 6)
- 92307 — New service creation in registry (Level 3)

**Key Fields:**
- data.win.eventdata.targetObject: ...\CurrentVersion\Run\Atomic Red Team
- data.win.eventdata.details: C:\\Path\\AtomicRedTeam.exe
- data.win.eventdata.ruleName: T1060, RunKey
- data.win.eventdata.image: reg.exe

**False Positive Considerations:**
Legitimate software writes to Run keys during install.
Check binary signature and path — unsigned binaries in
user-writable directories are high confidence malicious.

**Would You Escalate?** Yes if binary is unsigned or in
an unexpected path. Sysmon auto-tagged this as T1060/RunKey
which increases confidence.

**Analyst Notes:**
Sysmon's SwiftOnSecurity config automatically tagged the
event with the ATT&CK technique. Demonstrates value of
proper Sysmon configuration for detection quality.

---

## Runbook Entry 5 — T1046 Network Reconnaissance

**Detection Name:** Network Service Discovery / Port Scan
**ATT&CK Technique ID:** T1046
**ATT&CK Tactic:** Discovery
**Severity:** Medium
**Atomic Test Used:** N/A — No compatible Windows tests

**What the Attack Does:**
Internal port scanning to enumerate services and identify
lateral movement targets after initial compromise.

**Detection Result:** Gap identified — no Wazuh rule fires
on high-volume port scanning from a single process.

**Log Sources:**
- Microsoft-Windows-Sysmon/Operational
- Sysmon Event ID: 3 (Network Connection) — logged but
  no correlation rule exists

**Wazuh Rule IDs That Fired:** None specific to T1046

**False Positive Considerations:**
Vulnerability scanners and monitoring tools generate similar
traffic. Correlate with scheduled scan windows.

**Would You Escalate?** Yes if scanning targets critical
systems and no scheduled scan is on record.

**Analyst Notes:**
Detection gap documented. Custom threshold rule recommended.
Side-effect alerts (92052, 61017) suggest the test framework
attempted execution but no platform-compatible test ran.
