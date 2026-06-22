# MITRE ATT&CK Threat Map: Wazuh SIEM Lab Detections

This is a threat map I built by running MITRE ATT&CK technique simulations through my home lab and cross-referencing them against real detections in Wazuh. The goal was simple: stop reading about detections and actually generate them.

Everything in this artifact came from real telemetry. I ran the simulations, watched the alerts fire, and documented what Wazuh caught, what it partially caught, and what it missed. That gap analysis is the most useful part.

## Techniques simulated

| ATT&CK ID | Technique | Detection Result |
|---|---|---|
| T1059.001 | PowerShell execution | Detected |
| T1053.005 | Scheduled Task/Job | Detected |
| T1003.001 | LSASS Memory (credential dumping) | Detected |
| T1547.001 | Registry Run Keys / Startup Folder (persistence) | Detected |
| T1046 | Network Service Discovery | Detected |

## Lab environment

- Wazuh 4.7.3 deployed via Docker on WSL2
- Windows Server (evaluation) as the target endpoint
- Kali Linux for simulation
- Detections logged and reviewed in the Wazuh dashboard

## Why I built this

A home lab without documentation is just a computer. I wanted something I could point to in an interview and walk through: here's the technique, here's the detection rule that fired, here's the log, here's what I'd do next in a real SOC environment. That's the difference between saying you know SIEM and showing it.

The MITRE ATT&CK framework is the closest thing the industry has to a shared language for adversary behavior. Learning to map detections back to it is a core skill for any SOC analyst or security consultant, and this was my way of building that muscle hands-on.

## Frameworks referenced

- MITRE ATT&CK v14 (Enterprise)
- NIST CSF 2.0 (Detect function)
- CIS Controls v8

## Context

This artifact is part of a consulting-style portfolio I've been building alongside my ISC2 CC certification and active job search targeting SOC Analyst and Security Consultant roles in the Greater Chicago Area. Built to reflect the kind of deliverable I'd hand to a client, not just a lab exercise for myself.
