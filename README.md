# SOC Automation Lab

A comprehensive Security Operations Center (SOC) automation laboratory featuring Shuffle SOAR, TheHive case management, incident response workflows, and automated threat mitigation capabilities.

## Lab Overview

| Component | Description | Purpose |
|-----------|-------------|---------|
| **Shuffle SOAR** | Security Orchestration, Automation and Response | Workflow automation and integration |
| **TheHive** | Security Incident Response Platform | Case management and collaboration |
| **Cortex** | Observable Analysis Engine | Automated threat intelligence |
| **MISP** | Malware Information Sharing Platform | Threat intelligence sharing |
| **Wazuh** | Security Monitoring Platform | Log analysis and alerting |
| **Elasticsearch** | Search and Analytics Engine | Log storage and querying |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SOC AUTOMATION LAB ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Wazuh      │    │  Suricata    │    │   Zeek       │    │  Sysmon      │  │
│  │   Agent      │    │    IDS       │    │   NSM        │    │  Logs        │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘  │
│         │                   │                   │                   │          │
│         └───────────────────┴───────────────────┴───────────────────┘          │
│                                      │                                          │
│                                      ▼                                          │
│                        ┌─────────────────────────┐                              │
│                        │     Wazuh Manager       │                              │
│                        │   (Log Aggregation)     │                              │
│                        └───────────┬─────────────┘                              │
│                                    │                                            │
│                                    ▼                                            │
│                        ┌─────────────────────────┐                              │
│                        │    Elasticsearch        │                              │
│                        │   (SIEM Backend)        │                              │
│                        └───────────┬─────────────┘                              │
│                                    │                                            │
│         ┌──────────────────────────┼──────────────────────────┐                │
│         │                          │                          │                │
│         ▼                          ▼                          ▼                │
│  ┌─────────────┐          ┌───────────────┐          ┌─────────────┐          │
│  │   Kibana    │          │    Shuffle    │          │  Grafana    │          │
│  │ (Visualize) │          │    SOAR       │          │ (Metrics)   │          │
│  └─────────────┘          └───────┬───────┘          └─────────────┘          │
│                                   │                                            │
│                    ┌──────────────┼──────────────┐                            │
│                    │              │              │                            │
│                    ▼              ▼              ▼                            │
│             ┌──────────┐  ┌─────────────┐  ┌──────────┐                       │
│             │ TheHive  │  │   Cortex    │  │   MISP   │                       │
│             │  (Cases) │  │ (Analysis)  │  │ (Intel)  │                       │
│             └──────────┘  └─────────────┘  └──────────┘                       │
│                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │                        AUTOMATED RESPONSE ACTIONS                        │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐   │  │
│  │  │ Firewall│  │  EDR    │  │  Email  │  │  Ticket │  │ Quarantine  │   │  │
│  │  │  Block  │  │ Isolate │  │  Alert  │  │ Create  │  │   Host      │   │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Lab Objectives

### Security Automation with Shuffle SOAR
- [ ] Deploy and configure Shuffle SOAR platform
- [ ] Create automated alert triage workflows
- [ ] Integrate with threat intelligence feeds
- [ ] Build enrichment pipelines for IOCs
- [ ] Develop automated response playbooks

### Incident Response Planning and Execution
- [ ] Develop IR playbooks for common attack scenarios
- [ ] Create escalation procedures and runbooks
- [ ] Implement automated evidence collection
- [ ] Build communication templates and procedures
- [ ] Establish metrics and KPIs tracking

### Case Management with TheHive
- [ ] Deploy TheHive with Cortex integration
- [ ] Configure case templates and custom fields
- [ ] Set up automated case creation from alerts
- [ ] Implement analyst workflow procedures
- [ ] Create reporting dashboards

### Scripting and Automation for Threat Mitigation
- [ ] Develop IOC extraction and enrichment scripts
- [ ] Create automated blocking/containment scripts
- [ ] Build threat hunting automation tools
- [ ] Implement log parsing and analysis scripts
- [ ] Create integration scripts for tooling

## Directory Structure

```
SOC-Automation-Lab/
├── README.md
├── docker-compose.yml
├── .env.example
├── shuffle/
│   ├── README.md
│   ├── workflows/
│   │   ├── alert-triage.json
│   │   ├── phishing-response.json
│   │   ├── malware-response.json
│   │   └── threat-intel-enrichment.json
│   └── apps/
│       └── custom-apps/
├── thehive/
│   ├── README.md
│   ├── config/
│   │   └── application.conf
│   ├── templates/
│   │   ├── case-templates/
│   │   └── task-templates/
│   └── cortex/
│       ├── analyzers/
│       └── responders/
├── incident-response/
│   ├── README.md
│   ├── playbooks/
│   │   ├── malware-infection.md
│   │   ├── phishing-attack.md
│   │   ├── data-breach.md
│   │   ├── ransomware.md
│   │   ├── insider-threat.md
│   │   └── ddos-attack.md
│   ├── runbooks/
│   │   ├── evidence-collection.md
│   │   ├── containment-procedures.md
│   │   └── recovery-procedures.md
│   └── templates/
│       ├── incident-report.md
│       └── post-incident-review.md
├── scripts/
│   ├── README.md
│   ├── python/
│   │   ├── ioc_extractor.py
│   │   ├── threat_enrichment.py
│   │   ├── automated_blocking.py
│   │   └── log_analyzer.py
│   ├── bash/
│   │   ├── collect_evidence.sh
│   │   ├── isolate_host.sh
│   │   └── backup_logs.sh
│   └── powershell/
│       ├── Get-ForensicArtifacts.ps1
│       ├── Block-ThreatIP.ps1
│       └── Invoke-MemoryDump.ps1
├── integrations/
│   ├── README.md
│   ├── wazuh/
│   ├── elasticsearch/
│   └── misp/
└── docs/
    ├── setup-guide.md
    ├── architecture.md
    ├── api-reference.md
    └── troubleshooting.md
```

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Minimum 16GB RAM
- 100GB available disk space
- Linux host (Ubuntu 22.04 recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SOC-Automation-Lab.git
   cd SOC-Automation-Lab
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   nano .env
   ```

3. **Set required system parameters**
   ```bash
   # Increase virtual memory for Elasticsearch
   sudo sysctl -w vm.max_map_count=262144
   echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
   ```

4. **Deploy the lab**
   ```bash
   docker-compose up -d
   ```

5. **Verify deployment**
   ```bash
   docker-compose ps
   ```

### Access Points

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Shuffle SOAR | http://localhost:3001 | admin@shuffle.local / shuffle |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |
| Cortex | http://localhost:9001 | admin / secret |
| Kibana | http://localhost:5601 | elastic / changeme |
| Wazuh Dashboard | http://localhost:443 | admin / SecretPassword |

## Component Documentation

- [Shuffle SOAR Setup](shuffle/README.md)
- [TheHive Configuration](thehive/README.md)
- [Incident Response Playbooks](incident-response/README.md)
- [Automation Scripts](scripts/README.md)
- [Integration Guides](integrations/README.md)

## Lab Exercises

### Exercise 1: Alert Triage Automation
Configure Shuffle to automatically triage and enrich incoming security alerts from Wazuh.

### Exercise 2: Phishing Response Workflow
Build an end-to-end phishing incident response workflow with automated analysis and containment.

### Exercise 3: Case Management Integration
Set up automated case creation in TheHive with Cortex analysis integration.

### Exercise 4: Threat Intelligence Enrichment
Create automated IOC enrichment pipelines using multiple threat intelligence sources.

### Exercise 5: Automated Incident Response
Develop automated response actions for common security incidents.

## Skills Developed

- Security Orchestration and Automation (SOAR)
- Incident Response Planning and Execution
- Case Management and Workflow Design
- Python/Bash Scripting for Security
- API Integration and Development
- Threat Intelligence Operations
- Log Analysis and Correlation
- Security Tool Integration

## References

- [Shuffle SOAR Documentation](https://shuffler.io/docs)
- [TheHive Project](https://thehive-project.org/)
- [Cortex Documentation](https://github.com/TheHive-Project/Cortex)
- [MISP Project](https://www.misp-project.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [NIST Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.
