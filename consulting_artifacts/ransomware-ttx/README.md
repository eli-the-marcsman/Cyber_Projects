# Ransomware Tabletop Exercise: Maplewood Regional Medical Center

This is a ransomware tabletop exercise I built and facilitated for a fictional healthcare organization, Maplewood Regional Medical Center. The scenario simulates a ransomware intrusion hitting a hospital environment mid-shift and forces decisions around isolation, notification, and recovery under pressure.

I designed this because healthcare is one of the most targeted sectors in cybersecurity and one of the highest-stakes environments for incident response. When a hospital's systems go down, patient care is directly affected. I wanted to build something that reflected that reality, not just a generic "company got hacked" scenario.

## What's in the artifact

- Full scenario narrative with inject timeline
- Role assignments and facilitation guide
- Decision points mapped to NIST SP 800-61 incident response phases (Preparation, Detection & Analysis, Containment, Eradication & Recovery, Post-Incident Activity)
- HIPAA breach notification considerations baked into the timeline
- After-action review (AAR) structured as blameless, focused on process gaps and not blame

## What I learned running this

Isolation decisions are instinctive once you've thought through them. The harder part is the notification timeline. HIPAA requires breach notification within 60 days to HHS and, depending on the size, media notification too. Under pressure in a real incident, that clock starts whether you're ready or not. This TTX exposed that gap early.

The AAR structure also matters more than people give it credit for. If the debrief feels like a blame session, nobody learns anything. Building it blameless from the start changes the whole tone.

## Tools and frameworks referenced

- NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
- HIPAA Breach Notification Rule (45 CFR §§ 164.400-414)
- MITRE ATT&CK for general threat actor behavior framing

## Context

This is part of a broader consulting-style portfolio I've been building while job searching in the Greater Chicago Area. Every artifact here is designed the way I'd deliver it to a real client: documented, mapped to a framework, and written for an audience beyond just myself.
