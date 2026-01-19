# Shuffle SOAR Configuration

Security Orchestration, Automation and Response (SOAR) platform for automating security workflows and integrating security tools.

## Overview

Shuffle is an open-source SOAR platform that enables security teams to automate repetitive tasks, orchestrate security tools, and respond to incidents faster.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SHUFFLE SOAR                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│  │   Triggers  │    │  Workflows  │    │   Actions   │            │
│  │             │───▶│             │───▶│             │            │
│  │ - Webhook   │    │ - Logic     │    │ - API Calls │            │
│  │ - Schedule  │    │ - Conditions│    │ - Scripts   │            │
│  │ - Email     │    │ - Loops     │    │ - Notify    │            │
│  └─────────────┘    └─────────────┘    └─────────────┘            │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                      INTEGRATIONS                            │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ │  │
│  │  │ TheHive │ │ Cortex  │ │  MISP   │ │  Wazuh  │ │ Email │ │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └───────┘ │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ │  │
│  │  │VirusTotal│ │ AbuseIPDB│ │ Shodan │ │ Slack  │ │Jira   │ │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └───────┘ │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Installation

### Docker Deployment

```yaml
# Included in main docker-compose.yml
shuffle:
  image: ghcr.io/shuffle/shuffle-frontend:latest
  container_name: shuffle-frontend
  hostname: shuffle-frontend
  ports:
    - "3001:80"
    - "3443:443"
  environment:
    - BACKEND_HOSTNAME=shuffle-backend
  restart: unless-stopped
  depends_on:
    - shuffle-backend
```

### Initial Setup

1. Access Shuffle at `http://localhost:3001`
2. Create admin account on first login
3. Configure organization settings
4. Add API integrations

## Workflows

### Available Workflows

| Workflow | Description | Trigger |
|----------|-------------|---------|
| [Alert Triage](workflows/alert-triage.json) | Automated alert classification and enrichment | Webhook from Wazuh |
| [Phishing Response](workflows/phishing-response.json) | Email analysis and containment | Email/Manual |
| [Malware Response](workflows/malware-response.json) | Malware containment and remediation | Alert trigger |
| [Threat Intel Enrichment](workflows/threat-intel-enrichment.json) | IOC enrichment pipeline | Webhook/Schedule |

### Workflow Categories

#### 1. Alert Triage
- Automatic severity classification
- IOC extraction and enrichment
- False positive filtering
- Escalation routing

#### 2. Incident Response
- Automated containment actions
- Evidence collection triggers
- Notification workflows
- Case creation

#### 3. Threat Intelligence
- IOC ingestion from feeds
- Automated enrichment
- Reputation scoring
- Blocklist updates

#### 4. Reporting
- Metrics collection
- Dashboard updates
- Report generation
- Compliance tracking

## Configuration

### Environment Variables

```bash
# Shuffle Configuration
SHUFFLE_BACKEND_URL=http://shuffle-backend:5001
SHUFFLE_OPENSEARCH_URL=https://opensearch:9200
SHUFFLE_ENCRYPTION_KEY=your-encryption-key-here
SHUFFLE_DEFAULT_USERNAME=admin@shuffle.local
SHUFFLE_DEFAULT_PASSWORD=shuffle_password
SHUFFLE_DEFAULT_APIKEY=your-api-key-here
```

### API Integration Setup

#### TheHive Integration
```json
{
  "name": "TheHive",
  "url": "http://thehive:9000",
  "api_key": "YOUR_THEHIVE_API_KEY",
  "verify_ssl": false
}
```

#### Cortex Integration
```json
{
  "name": "Cortex",
  "url": "http://cortex:9001",
  "api_key": "YOUR_CORTEX_API_KEY",
  "verify_ssl": false
}
```

#### VirusTotal Integration
```json
{
  "name": "VirusTotal",
  "api_key": "YOUR_VT_API_KEY",
  "rate_limit": 4
}
```

#### MISP Integration
```json
{
  "name": "MISP",
  "url": "https://misp:443",
  "api_key": "YOUR_MISP_API_KEY",
  "verify_ssl": false
}
```

## Creating Workflows

### Basic Workflow Structure

```json
{
  "name": "Example Workflow",
  "description": "Template workflow structure",
  "triggers": [
    {
      "type": "webhook",
      "name": "Incoming Alert"
    }
  ],
  "actions": [
    {
      "name": "Parse Alert",
      "app_name": "Shuffle Tools",
      "action": "parse_json"
    },
    {
      "name": "Enrich IOC",
      "app_name": "VirusTotal",
      "action": "get_ip_report"
    },
    {
      "name": "Create Case",
      "app_name": "TheHive",
      "action": "create_case"
    }
  ],
  "conditions": [
    {
      "name": "Check Severity",
      "condition": "$parse_alert.severity >= 3"
    }
  ]
}
```

### Workflow Best Practices

1. **Use Descriptive Names**: Name workflows and actions clearly
2. **Add Error Handling**: Include fallback actions for failures
3. **Implement Logging**: Log important steps for debugging
4. **Use Variables**: Leverage workflow variables for reusability
5. **Test Thoroughly**: Test with sample data before production

## Use Cases

### Use Case 1: Automated Alert Triage

**Scenario**: High volume of security alerts requiring initial analysis

**Workflow**:
1. Receive alert via webhook
2. Extract IOCs (IPs, domains, hashes)
3. Query threat intelligence sources
4. Calculate risk score
5. Route based on severity
6. Create case if threshold met

### Use Case 2: Phishing Investigation

**Scenario**: User reports suspicious email

**Workflow**:
1. Receive email submission
2. Extract headers, URLs, attachments
3. Analyze URLs with urlscan.io
4. Check attachments in sandbox
5. Query email reputation
6. Create incident case
7. Notify security team

### Use Case 3: Endpoint Containment

**Scenario**: Malware detected on endpoint

**Workflow**:
1. Receive malware alert
2. Verify alert validity
3. Gather endpoint details
4. Initiate network isolation
5. Trigger memory dump
6. Create forensic case
7. Notify incident responders

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Workflow not triggering | Check webhook URL and authentication |
| App connection failed | Verify API keys and network connectivity |
| Action timeout | Increase timeout or optimize query |
| Variable not found | Check variable naming and scope |

### Debug Mode

Enable debug logging:
```bash
docker logs -f shuffle-backend 2>&1 | grep -i "workflow"
```

### Health Check

```bash
curl -X GET http://localhost:3001/api/v1/health
```

## Security Considerations

- Store API keys in environment variables
- Use HTTPS for all external connections
- Implement rate limiting for API calls
- Review workflow permissions regularly
- Audit workflow execution logs

## References

- [Shuffle Documentation](https://shuffler.io/docs)
- [Shuffle GitHub](https://github.com/Shuffle/Shuffle)
- [Shuffle Apps Library](https://shuffler.io/apps)
- [SOAR Best Practices](https://shuffler.io/docs/best_practices)
