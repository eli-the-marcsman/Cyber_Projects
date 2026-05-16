# T1046 — Network Service Discovery

## Detection Summary
| Field | Value |
|---|---|
| **ATT&CK Technique** | T1046 |
| **ATT&CK Tactic** | Discovery |
| **Severity** | Medium |
| **Wazuh Rule ID** | N/A — Detection Gap |
| **Test Used** | Atomic Red Team T1046 |
| **Date Tested** | May 14, 2026 |
| **Agent** | Batmans-PC |

## What the Attack Does
An attacker performs internal network scanning to enumerate
open ports and services on reachable hosts. This is typically
performed after initial access to map the environment and
identify targets for lateral movement and exploitation.

## Test Result
No applicable Atomic Red Team tests for T1046 were compatible
with the Windows 11 platform. Manual review of Wazuh's detection
capability was performed instead.

## Detection Gap Identified
Wazuh does not have a built-in correlation rule to detect
high-volume port scanning behavior originating from a single
endpoint process. Individual Sysmon Event ID 3 (Network
Connection) events are logged but no threshold-based alerting
exists to correlate them into a port scan detection.

## Evidence of Related Activity
Side-effect alerts observed during T1046 testing:
| Rule ID | Description | Level |
|---|---|---|
| 92052 | Windows command prompt started by abnormal process | 4 |
| 61017 | Process terminated due to unhandled exception | 9 |

## Recommended Custom Detection Rule
```xml
<rule id="100001" level="10">
  <if_sid>61613</if_sid>
  <same_source_ip />
  <description>Possible port scan detected from single host
  </description>
  <mitre>
    <id>T1046</id>
  </mitre>
  <group>network_scan,</group>
</rule>
```

## NIST CSF Mapping
- Function: Detect
- Category: DE.CM-1 — Network communications monitored

## CIS Control Mapping
- CIS Control 13 — Network Monitoring and Defense

## False Positive Considerations
- Vulnerability scanners run by IT teams generate similar traffic
- Network monitoring tools may perform internal port checks
- Distinguish by correlating with scheduled scan windows and
  known scanner IP addresses

## Triage Steps
1. Identify the source process performing the connections
2. Check the destination IPs — internal vs external
3. Determine if this coincides with a scheduled vulnerability scan
4. If no scheduled scan — treat as post-compromise reconnaissance
5. Review other alerts from same host for lateral movement indicators

## Escalation Decision
**Escalate: Yes if** — source process is unexpected, scanning
targets critical infrastructure (domain controllers, databases),
or coincides with other high-severity alerts on same host.

## Analyst Notes
This finding highlights a gap in the current detection coverage.
Network reconnaissance is a high-value detection opportunity
because it often occurs between initial compromise and lateral
movement — catching it early can contain an incident before
it spreads. Implementing threshold-based Sysmon network
connection alerting is a high-priority recommendation.
