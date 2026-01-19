# Security Automation Scripts

Collection of scripts for automated threat detection, analysis, and response.

## Overview

This directory contains automation scripts organized by language:

```
scripts/
├── python/           # Python automation scripts
│   ├── ioc_extractor.py
│   ├── threat_enrichment.py
│   ├── automated_blocking.py
│   └── log_analyzer.py
├── bash/             # Bash scripts for Linux/Unix
│   ├── collect_evidence.sh
│   ├── isolate_host.sh
│   └── backup_logs.sh
└── powershell/       # PowerShell scripts for Windows
    ├── Get-ForensicArtifacts.ps1
    ├── Block-ThreatIP.ps1
    └── Invoke-MemoryDump.ps1
```

## Python Scripts

### Requirements

```bash
pip install -r requirements.txt
```

### ioc_extractor.py

Extracts Indicators of Compromise (IOCs) from various input sources.

**Usage:**
```bash
# Extract from file
python ioc_extractor.py --input suspicious_email.eml --output iocs.json

# Extract from text
python ioc_extractor.py --text "Check this IP: 192.168.1.1 and domain malware.com"

# Extract from URL
python ioc_extractor.py --url "https://pastebin.com/raw/xxxxx"
```

**Supported IOC Types:**
- IPv4/IPv6 addresses
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- Bitcoin/Ethereum addresses
- CVE identifiers

### threat_enrichment.py

Enriches IOCs using multiple threat intelligence sources.

**Usage:**
```bash
# Enrich single IOC
python threat_enrichment.py --ioc 192.168.1.1 --type ip

# Enrich from file
python threat_enrichment.py --input iocs.json --output enriched.json

# Specify services
python threat_enrichment.py --ioc malware.com --services virustotal,abuseipdb
```

**Supported Services:**
- VirusTotal
- AbuseIPDB
- Shodan
- GreyNoise
- URLScan.io
- AlienVault OTX

### automated_blocking.py

Automates blocking of malicious indicators across security tools.

**Usage:**
```bash
# Block IP on firewall
python automated_blocking.py --type ip --value 192.168.1.1 --target firewall

# Block domain on proxy
python automated_blocking.py --type domain --value malware.com --target proxy

# Block hash on EDR
python automated_blocking.py --type hash --value abc123... --target edr

# Bulk block from file
python automated_blocking.py --input blocklist.json --target all
```

### log_analyzer.py

Analyzes logs for security events and anomalies.

**Usage:**
```bash
# Analyze Windows Event Log
python log_analyzer.py --input security.evtx --type windows

# Analyze Syslog
python log_analyzer.py --input /var/log/syslog --type syslog

# Search for specific patterns
python log_analyzer.py --input logs/ --search "failed login"
```

## Bash Scripts

### collect_evidence.sh

Collects forensic artifacts from Linux systems.

**Usage:**
```bash
# Full collection
sudo ./collect_evidence.sh --full --output /evidence/host01

# Quick collection
sudo ./collect_evidence.sh --quick --output /evidence/host01

# Specific artifacts
sudo ./collect_evidence.sh --memory --logs --network
```

### isolate_host.sh

Network isolation script for compromised hosts.

**Usage:**
```bash
# Isolate host
sudo ./isolate_host.sh --isolate --host 192.168.1.100

# Remove isolation
sudo ./isolate_host.sh --restore --host 192.168.1.100
```

### backup_logs.sh

Automated log backup and rotation.

**Usage:**
```bash
# Backup all logs
./backup_logs.sh --all --destination /backup/logs

# Backup specific logs
./backup_logs.sh --logs "auth,syslog,apache"
```

## PowerShell Scripts

### Get-ForensicArtifacts.ps1

Collects forensic artifacts from Windows systems.

**Usage:**
```powershell
# Full collection
.\Get-ForensicArtifacts.ps1 -Full -OutputPath C:\Evidence

# Quick triage
.\Get-ForensicArtifacts.ps1 -Triage -OutputPath C:\Evidence

# Specific artifacts
.\Get-ForensicArtifacts.ps1 -Artifacts "EventLogs","Registry","Prefetch"
```

### Block-ThreatIP.ps1

Blocks malicious IPs on Windows Firewall.

**Usage:**
```powershell
# Block single IP
.\Block-ThreatIP.ps1 -IPAddress 192.168.1.1 -Direction Both

# Block from file
.\Block-ThreatIP.ps1 -InputFile blocklist.txt

# Block with expiration
.\Block-ThreatIP.ps1 -IPAddress 192.168.1.1 -ExpirationHours 24
```

### Invoke-MemoryDump.ps1

Captures memory dump from running system.

**Usage:**
```powershell
# Full memory dump
.\Invoke-MemoryDump.ps1 -OutputPath C:\Evidence\memory.raw

# Process dump
.\Invoke-MemoryDump.ps1 -ProcessName "suspicious.exe" -OutputPath C:\Evidence
```

## Integration with SOAR

### Shuffle Integration

Scripts can be called from Shuffle workflows:

```json
{
  "app_name": "SSH",
  "action": "run_command",
  "parameters": {
    "host": "$target_host",
    "command": "python3 /opt/scripts/ioc_extractor.py --text '$alert_data'"
  }
}
```

### TheHive Integration

Scripts can be triggered by Cortex responders.

## Environment Variables

Required environment variables for script execution:

```bash
# API Keys
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
export GREYNOISE_API_KEY="your_key"
export URLSCAN_API_KEY="your_key"
export OTX_API_KEY="your_key"

# Tool Endpoints
export WAZUH_API_URL="https://wazuh-manager:55000"
export WAZUH_API_USER="wazuh"
export WAZUH_API_PASS="password"
export THEHIVE_URL="http://thehive:9000"
export THEHIVE_API_KEY="your_key"
```

## Best Practices

1. **Always test in non-production first**
2. **Use configuration files, not hardcoded values**
3. **Implement proper error handling**
4. **Log all actions for audit trail**
5. **Use appropriate permissions (least privilege)**
6. **Validate all inputs before processing**
7. **Handle API rate limits gracefully**

## Security Considerations

- Store API keys in secure credential manager
- Use encrypted connections (HTTPS/TLS)
- Validate certificates
- Sanitize user inputs
- Follow secure coding practices
- Regular security reviews of scripts
