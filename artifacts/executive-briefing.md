# Executive Security Briefing
## Threat Detection Capability Assessment

---

| | |
|---|---|
| **Prepared By** | Elijah Marcisz |
| **Date** | May 15, 2026 |
| **Classification** | Confidential |
| **Audience** | Executive Leadership |

---

## Bottom Line Up Front

A security assessment conducted May 10–14, 2026 found that
the assessed Windows 11 endpoint can detect most common
attack techniques but cannot prevent credential theft and
has no visibility into network reconnaissance activity.
The most urgent risk is that an attacker who gains access
to this machine can steal all stored passwords in under
one second — and the security team would receive only a
low-priority alert.

---

## What We Tested

We simulated five real-world attack techniques used by
threat actors against Windows environments — the same
techniques documented by the MITRE ATT&CK framework used
by security teams worldwide. Each simulation was safe,
controlled, and fully reversible.

The five techniques tested were:
- **Malicious PowerShell execution** — how attackers run
  hidden commands
- **Scheduled task creation** — how attackers survive reboots
- **Password theft from memory** — how attackers steal credentials
- **Registry persistence** — how attackers maintain long-term access
- **Network scanning** — how attackers map your environment

---

## What We Found

### The Good
The security monitoring platform (Wazuh) successfully detected
4 out of 5 attack techniques and generated alerts. The endpoint
telemetry tool (Sysmon) is configured well and providing rich
data to the SIEM.

### The Concerning

**Password theft is possible and nearly undetectable at the
right severity level.**
An attacker who gains access to this machine can extract all
stored passwords from memory in under one second using freely
available tools. While the action does generate a low-level
alert, it is not configured to trigger an urgent response.
By the time an analyst reviews it, the credentials may already
be in use elsewhere.

**The machine is not hardened to industry standards.**
The endpoint scored 33% on the CIS Windows 11 security
benchmark — industry standard is 75% or higher. This means
roughly two-thirds of recommended security configurations
are not in place, leaving the machine more vulnerable to
a wider range of attacks.

**Network scanning goes completely undetected.**
If an attacker gains access and begins scanning the internal
network to find other systems to compromise, there is currently
no alert that would fire. This is a significant blind spot
because network scanning almost always precedes lateral movement
to higher-value targets.

**The security team cannot see when antivirus blocks something.**
When Windows Defender blocked a malicious file download during
testing, that block event was not sent to the SIEM. This means
preventive actions are invisible to the security monitoring
platform — analysts cannot see how often attacks are being
blocked or identify patterns in blocked activity.

---

## Business Risk Summary

| Risk | Likelihood | Impact | Priority |
|---|---|---|---|
| Credential theft enabling lateral movement | Medium | Critical | Immediate |
| Endpoint compromise via unhardened config | Medium | High | 30 days |
| Attacker mapping network undetected | Medium | High | 60 days |
| Missed detections from logging gaps | Low | Medium | 60 days |

---

## What Needs to Happen

### Immediate Actions (This Week)
**Enable Windows Credential Guard**
This is a built-in Windows security feature that prevents
password theft from memory. It requires a configuration
change and reboot. Zero cost, high impact.

### Short Term (30 Days)
**Remediate top CIS benchmark failures**
Work through the failing security configuration checks
identified by the assessment. Many are simple configuration
changes that can be deployed via Group Policy.

### Medium Term (60–90 Days)
**Implement network scanning detection**
Add a custom detection rule that alerts when a single
device connects to an unusual number of internal systems
in a short time window.

**Connect antivirus logs to the SIEM**
Configure Windows Defender to send its event logs to
the security monitoring platform so the team has full
visibility into both blocked and detected threats.

---

## Investment Required

All recommended actions use existing tools and technologies
already deployed in the environment. No new vendor purchases
are required to address the findings in this report.

| Action | Effort | Cost |
|---|---|---|
| Enable Credential Guard | Low — config change | $0 |
| CIS benchmark remediation | Medium — 4–8 hours | Staff time only |
| Network detection rule | Low — 1–2 hours | $0 |
| Defender log integration | Low — 1 hour | $0 |

---

## Detection Coverage Achieved

As a result of this assessment the following detection
capabilities are now validated and operational:

| Attack Technique | Can We Detect It? |
|---|---|
| Malicious PowerShell | ✅ Yes |
| Scheduled Task Persistence | ✅ Yes |
| Credential Dumping | ⚠️ Yes, but under-prioritized |
| Registry Persistence | ✅ Yes |
| Network Reconnaissance | ❌ No — gap identified |

---

*Full technical findings, evidence, and remediation details
are available in the accompanying Security Assessment Report.*

*Prepared by Elijah Marcisz — Indiana University Bloomington*
*Cybersecurity | Networking | GRC & Security Operations*
