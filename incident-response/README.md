# Incident Response Playbooks and Procedures

Comprehensive incident response documentation for Security Operations Center (SOC) analysts.

## Overview

This directory contains standardized playbooks, runbooks, and templates for responding to security incidents. All procedures follow the NIST Incident Response Framework phases:

1. **Preparation**
2. **Detection & Analysis**
3. **Containment, Eradication & Recovery**
4. **Post-Incident Activity**

## Incident Response Framework

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      INCIDENT RESPONSE LIFECYCLE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │             │    │  Detection  │    │ Containment │    │   Post-     │ │
│  │ Preparation │───▶│      &      │───▶│ Eradication │───▶│  Incident   │ │
│  │             │    │  Analysis   │    │  Recovery   │    │  Activity   │ │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘ │
│         │                                                         │        │
│         └─────────────────────────────────────────────────────────┘        │
│                              Lessons Learned                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Severity Classification

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| **Critical (P1)** | Active threat with business impact | Immediate (15 min) | Ransomware, active data breach |
| **High (P2)** | Confirmed compromise requiring urgent action | 1 hour | Malware infection, credential theft |
| **Medium (P3)** | Security event requiring investigation | 4 hours | Suspicious activity, policy violation |
| **Low (P4)** | Informational security event | 24 hours | False positive, minor policy violation |

## Playbooks

### Attack-Specific Playbooks

| Playbook | Severity | Trigger | Documentation |
|----------|----------|---------|---------------|
| [Malware Infection](playbooks/malware-infection.md) | High | EDR/AV alert | Full response procedure |
| [Phishing Attack](playbooks/phishing-attack.md) | Medium-High | User report/Gateway alert | Email investigation |
| [Data Breach](playbooks/data-breach.md) | Critical | DLP/SIEM alert | Exfiltration response |
| [Ransomware](playbooks/ransomware.md) | Critical | Encryption detected | Emergency response |
| [Insider Threat](playbooks/insider-threat.md) | High | UEBA/HR referral | Internal investigation |
| [DDoS Attack](playbooks/ddos-attack.md) | High | Network monitoring | Availability incident |

### Use Case Matrix

| Scenario | Primary Playbook | Secondary Playbooks |
|----------|------------------|---------------------|
| Crypto-mining malware | Malware Infection | Network Intrusion |
| Business Email Compromise | Phishing Attack | Insider Threat |
| Supply chain compromise | Malware Infection | Data Breach |
| Credential stuffing | Account Compromise | Data Breach |
| APT intrusion | Network Intrusion | Data Breach, Malware |

## Runbooks

Detailed technical procedures for specific tasks:

| Runbook | Purpose | Tools Used |
|---------|---------|------------|
| [Evidence Collection](runbooks/evidence-collection.md) | Forensic artifact gathering | Wazuh, Velociraptor |
| [Containment Procedures](runbooks/containment-procedures.md) | Threat containment actions | EDR, Firewall, NAC |
| [Recovery Procedures](runbooks/recovery-procedures.md) | System restoration | Backup, Imaging |

## Templates

Standardized documentation templates:

| Template | Purpose |
|----------|---------|
| [Incident Report](templates/incident-report.md) | Final incident documentation |
| [Post-Incident Review](templates/post-incident-review.md) | Lessons learned documentation |

## Escalation Matrix

### Escalation Paths

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCALATION MATRIX                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Severity    Tier 1          Tier 2          Tier 3            │
│  ─────────────────────────────────────────────────────────────  │
│  Low         SOC Analyst     -               -                 │
│                                                                 │
│  Medium      SOC Analyst ───▶ Sr. Analyst    -                 │
│                  (4 hrs)                                        │
│                                                                 │
│  High        SOC Analyst ───▶ Sr. Analyst ───▶ IR Lead         │
│                  (1 hr)          (2 hrs)                        │
│                                                                 │
│  Critical    SOC Analyst ───▶ IR Lead ───────▶ CISO/Executive  │
│               (Immediate)      (30 min)                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Contact Information

| Role | Primary Contact | Backup Contact | Escalation Time |
|------|-----------------|----------------|-----------------|
| SOC Manager | On-call | SOC Lead | 15 min |
| IR Lead | On-call | Security Director | 30 min |
| CISO | Direct line | Deputy CISO | 1 hour |
| Legal | General Counsel | External Counsel | As needed |
| Communications | PR Director | Executive Assistant | As needed |

## Response Time SLAs

| Metric | P1 Critical | P2 High | P3 Medium | P4 Low |
|--------|-------------|---------|-----------|--------|
| Initial Response | 15 min | 1 hour | 4 hours | 24 hours |
| Containment | 1 hour | 4 hours | 24 hours | 72 hours |
| Eradication | 4 hours | 24 hours | 72 hours | 1 week |
| Recovery | 8 hours | 48 hours | 1 week | 2 weeks |
| Post-Incident Review | 48 hours | 1 week | 2 weeks | 1 month |

## Communication Templates

### Internal Notification Template

```
SECURITY INCIDENT NOTIFICATION
==============================
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Incident ID: [CASE-XXXXXX]
Time Detected: [YYYY-MM-DD HH:MM UTC]

Summary:
[Brief description of the incident]

Impact:
[Systems/users/data affected]

Current Status:
[Containment/Investigation/Remediation]

Actions Required:
[What recipients need to do]

Next Update: [Time of next update]

Contact: SOC Team - soc@company.com
```

### Executive Briefing Template

```
EXECUTIVE SECURITY BRIEFING
===========================
Incident: [Title]
Date: [Date]
Classification: [Severity]

SITUATION
- What happened
- When it was detected
- Systems/data affected

IMPACT
- Business impact
- Customer impact
- Regulatory implications

RESPONSE
- Actions taken
- Current status
- Timeline for resolution

RECOMMENDATIONS
- Immediate actions needed
- Long-term improvements
```

## Integration with SOC Tools

### TheHive Integration
- Automatic case creation from alerts
- Task assignment based on playbook
- Observable tracking and enrichment
- Metrics collection

### Shuffle SOAR Integration
- Automated initial response actions
- Evidence collection triggers
- Notification workflows
- Escalation automation

### Wazuh Integration
- Alert correlation
- Active response commands
- Log collection
- Compliance reporting

## Metrics and KPIs

### Key Performance Indicators

| Metric | Target | Measurement |
|--------|--------|-------------|
| Mean Time to Detect (MTTD) | < 24 hours | Time from compromise to detection |
| Mean Time to Respond (MTTR) | < 4 hours | Time from detection to containment |
| Mean Time to Recover | < 48 hours | Time to full restoration |
| False Positive Rate | < 10% | Alerts that are not actual incidents |
| Incidents per Month | Trending down | Month-over-month comparison |

### Reporting

Weekly metrics reports should include:
- Total incidents by severity
- MTTD/MTTR trends
- Top incident categories
- Open vs. closed cases
- SLA compliance

## Training Requirements

### SOC Analyst (Tier 1)
- Basic incident response procedures
- Alert triage and classification
- Evidence collection basics
- Tool proficiency (SIEM, EDR)

### Senior Analyst (Tier 2)
- Advanced investigation techniques
- Malware analysis fundamentals
- Threat intelligence
- Playbook execution

### IR Lead (Tier 3)
- Incident command
- Forensic investigation
- Crisis communication
- Legal/compliance requirements

## References

- [NIST SP 800-61r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) - Computer Security Incident Handling Guide
- [SANS Incident Handler's Handbook](https://www.sans.org/reading-room/whitepapers/incident/paper/33901)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [FIRST CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1)
