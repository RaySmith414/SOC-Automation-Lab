# TheHive Case Management

Security Incident Response Platform for collaborative investigation and case management.

## Overview

TheHive is a scalable, open-source Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, and CERTs. It integrates with MISP and Cortex for threat intelligence and automated analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          THEHIVE ECOSYSTEM                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                         THEHIVE                                  │  │
│  │                                                                  │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │  Cases   │  │  Alerts  │  │   Tasks  │  │Observables│       │  │
│  │  │          │  │          │  │          │  │          │       │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │  │
│  │                                                                  │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │                    DASHBOARDS & REPORTS                   │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────┬──────────────────────────────────┘  │
│                              │                                      │
│         ┌────────────────────┼────────────────────┐                │
│         │                    │                    │                │
│         ▼                    ▼                    ▼                │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐         │
│  │   CORTEX    │     │    MISP     │     │  Webhooks   │         │
│  │             │     │             │     │             │         │
│  │ ┌─────────┐ │     │ Threat Intel│     │ ┌─────────┐ │         │
│  │ │Analyzers│ │     │   Sharing   │     │ │ Shuffle │ │         │
│  │ └─────────┘ │     │             │     │ └─────────┘ │         │
│  │ ┌─────────┐ │     │             │     │ ┌─────────┐ │         │
│  │ │Responders│ │     │             │     │ │  Slack  │ │         │
│  │ └─────────┘ │     │             │     │ └─────────┘ │         │
│  └─────────────┘     └─────────────┘     └─────────────┘         │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    ELASTICSEARCH/CASSANDRA                  │  │
│  │                      (Backend Storage)                      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Installation

### Docker Deployment

TheHive is deployed as part of the main docker-compose.yml:

```yaml
thehive:
  image: strangebee/thehive:5.2
  container_name: thehive
  depends_on:
    - cassandra
    - elasticsearch
    - cortex
  ports:
    - "9000:9000"
  environment:
    - JVM_OPTS=-Xms1024m -Xmx1024m
  volumes:
    - ./thehive/config/application.conf:/etc/thehive/application.conf
    - thehive-data:/opt/thp/thehive/data
  restart: unless-stopped
```

### Initial Configuration

1. Access TheHive at `http://localhost:9000`
2. Create admin account on first login
3. Configure organization settings
4. Set up Cortex integration
5. Configure MISP integration

## Configuration

### Application Configuration

See [config/application.conf](config/application.conf) for the full configuration.

Key settings:
```hocon
# Database configuration
db.janusgraph {
  storage.backend = cql
  storage.hostname = ["cassandra"]
  index.search.backend = elasticsearch
  index.search.hostname = ["elasticsearch"]
}

# Cortex integration
play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule
cortex {
  servers = [
    {
      name = "local"
      url = "http://cortex:9001"
      auth {
        type = "bearer"
        key = "API_KEY"
      }
    }
  ]
}

# MISP integration
play.modules.enabled += org.thp.thehive.connector.misp.MispModule
misp {
  interval = 1 hour
  servers = [
    {
      name = "local"
      url = "https://misp"
      auth {
        type = "key"
        key = "MISP_API_KEY"
      }
    }
  ]
}
```

## Case Templates

### Available Templates

| Template | Use Case | Default Tasks |
|----------|----------|---------------|
| [Malware Incident](templates/case-templates/malware-incident.json) | Malware detection response | 8 tasks |
| [Phishing Investigation](templates/case-templates/phishing-investigation.json) | Email phishing analysis | 6 tasks |
| [Data Breach](templates/case-templates/data-breach.json) | Data exfiltration incident | 10 tasks |
| [Ransomware](templates/case-templates/ransomware.json) | Ransomware attack response | 12 tasks |
| [Insider Threat](templates/case-templates/insider-threat.json) | Internal threat investigation | 7 tasks |
| [Network Intrusion](templates/case-templates/network-intrusion.json) | Unauthorized access | 9 tasks |

### Creating Case Templates

Templates can be created via:
1. TheHive UI (Admin > Case Templates)
2. API import
3. Configuration files

## Task Templates

Standard task templates for consistent investigation workflows:

### Evidence Collection Tasks
- Collect system logs
- Capture network traffic
- Memory acquisition
- Disk imaging
- Screenshot collection

### Analysis Tasks
- Malware analysis
- Log analysis
- Network traffic analysis
- Timeline analysis
- IOC extraction

### Containment Tasks
- Isolate affected systems
- Block malicious IPs/domains
- Disable compromised accounts
- Revoke access tokens

### Recovery Tasks
- System restoration
- Password resets
- Security patch deployment
- Configuration hardening

## Cortex Integration

### Analyzers

Available analyzers for observable enrichment:

| Analyzer | Data Types | Description |
|----------|------------|-------------|
| VirusTotal | hash, ip, domain, url | Multi-engine malware scan |
| AbuseIPDB | ip | IP abuse reports |
| Shodan | ip | Internet device search |
| URLScan | url | Website analysis |
| MISP | all | Threat intel correlation |
| MaxMind | ip | GeoIP lookup |
| Whois | domain, ip | Registration info |
| DNSLookup | domain | DNS records |

### Responders

Automated response actions:

| Responder | Action | Description |
|-----------|--------|-------------|
| Wazuh_Block | Block IP | Add IP to Wazuh active response |
| TheHive_Webhook | Notify | Send webhook notification |
| MISP_Export | Export | Export IOCs to MISP |
| Mail_Send | Email | Send notification email |

## API Usage

### Authentication

```bash
# Using API key
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:9000/api/case
```

### Create Case

```bash
curl -X POST http://localhost:9000/api/case \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Malware Detection - Host123",
    "description": "Malware detected on endpoint",
    "severity": 3,
    "tags": ["malware", "automated"],
    "flag": false,
    "tlp": 2,
    "pap": 2
  }'
```

### Create Alert

```bash
curl -X POST http://localhost:9000/api/alert \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Wazuh Alert - Suspicious Process",
    "description": "Suspicious process execution detected",
    "type": "wazuh",
    "source": "wazuh-manager",
    "sourceRef": "alert-12345",
    "severity": 2,
    "tags": ["wazuh", "process"]
  }'
```

### Add Observable

```bash
curl -X POST http://localhost:9000/api/case/{caseId}/artifact \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "ip",
    "data": "192.168.1.100",
    "message": "Source IP of attack",
    "tags": ["attacker", "c2"],
    "ioc": true,
    "sighted": true
  }'
```

## Workflows

### Standard Investigation Workflow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Alert     │────▶│   Triage    │────▶│  Promote    │
│  Received   │     │   Alert     │     │  to Case    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌──────────────────────────┘
                    │
                    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Assign    │────▶│ Investigate │────▶│  Analyze    │
│  Analyst    │     │   Case      │     │ Observables │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌──────────────────────────┘
                    │
                    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Contain   │────▶│ Remediate   │────▶│   Close     │
│   Threat    │     │   Issue     │     │   Case      │
└─────────────┘     └─────────────┘     └─────────────┘
```

### Alert to Case Promotion

1. Review incoming alert
2. Assess severity and validity
3. Check for duplicates/related cases
4. Promote to case with appropriate template
5. Assign to analyst
6. Begin investigation

## Best Practices

### Case Management

1. **Use Templates**: Start cases from templates for consistency
2. **Tag Everything**: Apply relevant tags for searchability
3. **Link Related Cases**: Connect related incidents
4. **Document Actions**: Record all investigation steps
5. **Track Time**: Log time spent on tasks

### Observable Management

1. **Mark IOCs**: Flag confirmed indicators of compromise
2. **Run Analyzers**: Enrich all observables automatically
3. **Sighted Status**: Track when observables are seen
4. **Export to MISP**: Share confirmed threats

### Collaboration

1. **Assign Ownership**: Each case has a responsible analyst
2. **Use Comments**: Document findings in case comments
3. **Task Assignment**: Distribute work via tasks
4. **Status Updates**: Keep case status current

## Metrics and Reporting

### Key Metrics

- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Cases by severity
- Cases by type
- Analyst workload
- SLA compliance

### Dashboard Queries

```json
// Cases opened this week
{
  "query": {
    "range": {
      "createdAt": {
        "gte": "now-7d"
      }
    }
  }
}

// High severity open cases
{
  "query": {
    "bool": {
      "must": [
        { "term": { "severity": 3 } },
        { "term": { "status": "Open" } }
      ]
    }
  }
}
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Cannot connect to Cortex | Check API key and network connectivity |
| Alerts not syncing from MISP | Verify MISP API key permissions |
| Slow performance | Increase JVM memory, check Elasticsearch |
| Login failures | Check LDAP/SSO configuration |

### Logs

```bash
# View TheHive logs
docker logs -f thehive

# View Cortex logs
docker logs -f cortex
```

## Security Considerations

- Enable TLS for all connections
- Use strong API keys
- Implement RBAC for user access
- Regular backup of case data
- Audit log monitoring

## References

- [TheHive Documentation](https://docs.strangebee.com/)
- [TheHive GitHub](https://github.com/TheHive-Project/TheHive)
- [Cortex Documentation](https://github.com/TheHive-Project/CortexDocs)
- [TheHive4py Library](https://github.com/TheHive-Project/TheHive4py)
