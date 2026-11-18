# Ransomware Attack Response Playbook

## Overview

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PLY-003 |
| **Version** | 1.0 |
| **Last Updated** | 2024-01-15 |
| **Severity** | CRITICAL (P1) |
| **MITRE ATT&CK** | T1486 - Data Encrypted for Impact |

## Purpose

This playbook provides emergency response procedures for ransomware attacks. Ransomware incidents require immediate, coordinated action to minimize impact and preserve evidence.

## CRITICAL: Initial Response Priorities

```
╔══════════════════════════════════════════════════════════════════════╗
║                    RANSOMWARE RESPONSE PRIORITIES                    ║
╠══════════════════════════════════════════════════════════════════════╣
║  1. CONTAIN - Stop the spread IMMEDIATELY                           ║
║  2. PRESERVE - Do NOT power off systems (preserve evidence)         ║
║  3. ASSESS - Determine scope and backup status                      ║
║  4. COMMUNICATE - Notify leadership and stakeholders                ║
║  5. DO NOT PAY - Engage law enforcement before any payment decision ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Phase 1: Immediate Response (First 30 Minutes)

### 1.1 IMMEDIATE: Network Isolation

**TIME CRITICAL - Execute within 5 minutes of detection**

| Priority | Action | Command/Tool |
|----------|--------|--------------|
| 1 | Isolate affected segment | Network switch/Firewall |
| 2 | Disable network shares | Group Policy/Manual |
| 3 | Block SMB/RDP traffic | Firewall rules |
| 4 | Isolate infected endpoints | EDR network isolation |
| 5 | Disconnect backup systems | Manual/Automated |

**Network Isolation Commands:**

```bash
# Block SMB traffic at firewall
firewall-cli block --port 445 --direction both --scope segment
firewall-cli block --port 139 --direction both --scope segment

# Block RDP
firewall-cli block --port 3389 --direction both --scope segment

# EDR mass isolation (if available)
edr-cli isolate-hosts --query "segment:affected_vlan" --force
```

**CRITICAL: Protect Backups**

```bash
# Disconnect backup servers from network
# Air-gap backup systems IMMEDIATELY
# Verify backup integrity before reconnecting
```

### 1.2 Identify Ransomware Variant

**Estimated Time:** 10-15 minutes

| Step | Action | Resource |
|------|--------|----------|
| 1 | Collect ransom note | Photo/Screenshot |
| 2 | Document file extensions | List encrypted files |
| 3 | Identify ransomware family | ID Ransomware |
| 4 | Check for decryptor | No More Ransom |

**Ransomware Identification:**

```bash
# Upload ransom note to ID Ransomware
curl -X POST "https://id-ransomware.malwarehunterteam.com/identify.php" \
  -F "note=@ransom_note.txt" \
  -F "file=@encrypted_sample.enc"

# Check No More Ransom for decryptor
# https://www.nomoreransom.org/en/decryption-tools.html
```

### 1.3 Initial Scope Assessment

**Questions to Answer IMMEDIATELY:**

- [ ] How many systems are encrypted?
- [ ] Are domain controllers affected?
- [ ] Is encryption still spreading?
- [ ] What data types are affected?
- [ ] Are backups accessible and intact?
- [ ] What is the ransom demand?

### 1.4 Activate Incident Response

```
ESCALATION PATH:
1. SOC Analyst → IR Lead (Immediate)
2. IR Lead → CISO (15 minutes)
3. CISO → Executive Leadership (30 minutes)
4. Legal Counsel (30 minutes)
5. Cyber Insurance (1 hour)
6. Law Enforcement (Consider within 24 hours)
```

---

## Phase 2: Containment (First 2 Hours)

### 2.1 Stop Ransomware Spread

**Identify and isolate patient zero:**

```sql
-- Find first encrypted file timestamp
SELECT host, file_path, modified_time
FROM endpoint_events
WHERE file_extension IN ('.encrypted', '.locked', '.cry', '.crypt')
ORDER BY modified_time ASC
LIMIT 10

-- Identify lateral movement
SELECT src_host, dst_host, timestamp, connection_type
FROM network_logs
WHERE dst_port IN (445, 3389, 5985)
AND timestamp > '<FIRST_ENCRYPTION_TIME>'
ORDER BY timestamp
```

### 2.2 Disable Compromised Accounts

```powershell
# Disable all potentially compromised accounts
# Start with service accounts and admin accounts

# Disable specific account
Disable-ADAccount -Identity "compromised_user"

# Force password reset
Set-ADAccountPassword -Identity "admin_user" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempP@ssw0rd123!" -Force)

# Reset KRBTGT (if domain compromise suspected - coordinate carefully)
# This will invalidate all Kerberos tickets
```

### 2.3 Block All Known IOCs

```bash
# Block ransomware C2 infrastructure
firewall-cli block --type ip --values "C2_IP_LIST"
firewall-cli block --type domain --values "C2_DOMAIN_LIST"

# Block ransomware hashes
edr-cli block-hash --hashes "RANSOMWARE_HASHES" --scope organization

# Block malicious email addresses
email-gateway block-sender --address "attacker@domain.com"
```

### 2.4 Backup Verification

**CRITICAL: Verify before ANY recovery attempt**

| Check | Status | Notes |
|-------|--------|-------|
| Offline backups exist | ☐ | |
| Backups not encrypted | ☐ | |
| Backup integrity verified | ☐ | |
| Recovery tested | ☐ | |
| Backup age acceptable | ☐ | |

```bash
# Verify backup integrity (example for Veeam)
veeam-cli verify-backup --job "Critical_Servers" --type integrity

# Check last successful backup
veeam-cli list-restore-points --vm "server01" --last 10
```

---

## Phase 3: Investigation

### 3.1 Evidence Preservation

**DO NOT POWER OFF SYSTEMS**

| Evidence | Collection Method | Priority |
|----------|-------------------|----------|
| Memory dumps | WinPMEM/Velociraptor | Critical |
| Ransomware samples | EDR/Manual collection | Critical |
| Ransom notes | Screenshot/Copy | Critical |
| Event logs | Export before cleanup | High |
| Network traffic | PCAP from IDS/Firewall | High |
| Encrypted file samples | Copy encrypted files | Medium |

**Memory Collection:**

```bash
# Collect memory from infected system
winpmem_mini_x64.exe infected_host_memory.raw

# Via Velociraptor
velociraptor --config client.config.yaml query \
  "SELECT * FROM Artifact.Windows.Memory.Acquisition()" \
  --output memory_dump.zip
```

### 3.2 Determine Initial Access Vector

**Common Ransomware Entry Points:**

| Vector | Investigation Focus |
|--------|---------------------|
| Phishing | Email logs, user reports |
| RDP Exposure | VPN/RDP logs, brute force |
| Vulnerability | Patch status, exploit logs |
| Supply Chain | Third-party access logs |
| Insider | User activity analysis |

```sql
-- Check for RDP brute force
SELECT src_ip, COUNT(*) as attempts, MIN(timestamp) as first_seen
FROM auth_logs
WHERE event_type = 'failed_login'
AND dest_port = 3389
AND timestamp > now() - interval '30 days'
GROUP BY src_ip
HAVING COUNT(*) > 100

-- Check for vulnerable systems
SELECT hostname, cve_id, severity
FROM vulnerability_scan
WHERE cve_id IN ('CVE-2021-34527', 'CVE-2021-44228', 'CVE-2020-1472')
AND patched = false
```

### 3.3 Map Attack Timeline

Document the complete attack chain:

```
ATTACK TIMELINE TEMPLATE:

[T-30 days] Initial access - How did attacker get in?
[T-14 days] Reconnaissance - What did they discover?
[T-7 days]  Credential theft - What accounts compromised?
[T-3 days]  Lateral movement - How did they spread?
[T-1 day]   Data staging - Was data exfiltrated?
[T-0]       Ransomware deployment - Encryption begins
[T+0]       Detection - When was it discovered?
[Now]       Current status - Containment status
```

### 3.4 Assess Data Exfiltration

**Double extortion check:**

```sql
-- Check for large data transfers
SELECT src_ip, dst_ip, SUM(bytes) as total_bytes
FROM network_logs
WHERE direction = 'outbound'
AND dst_ip NOT IN (SELECT ip FROM known_good_destinations)
AND timestamp > '<COMPROMISE_START>'
GROUP BY src_ip, dst_ip
HAVING SUM(bytes) > 1000000000  -- 1GB threshold
ORDER BY total_bytes DESC

-- Check for known exfiltration tools
SELECT host, process_name, command_line
FROM endpoint_events
WHERE process_name IN ('rclone', 'megasync', '7za', 'winscp')
OR command_line LIKE '%curl%' OR command_line LIKE '%wget%'
```

---

## Phase 4: Decision Points

### 4.1 Recovery Strategy Decision

```
╔════════════════════════════════════════════════════════════════════╗
║              RECOVERY DECISION MATRIX                              ║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  OPTION 1: RESTORE FROM BACKUP                                     ║
║  ├─ Prerequisites:                                                 ║
║  │  ✓ Clean backups available                                     ║
║  │  ✓ Backup age acceptable                                       ║
║  │  ✓ Can accept data loss since backup                          ║
║  └─ Recommended if criteria met                                   ║
║                                                                    ║
║  OPTION 2: DECRYPTION TOOL AVAILABLE                              ║
║  ├─ Check: nomoreransom.org                                       ║
║  ├─ Check: Vendor/CISA advisories                                 ║
║  └─ Test on non-critical system first                             ║
║                                                                    ║
║  OPTION 3: REBUILD FROM SCRATCH                                    ║
║  ├─ When: No backups, no decryptor                                ║
║  ├─ Significant time and resource investment                      ║
║  └─ May be necessary for full compromise                          ║
║                                                                    ║
║  OPTION 4: NEGOTIATE/PAY RANSOM (LAST RESORT)                     ║
║  ├─ Consult: Legal counsel, law enforcement                       ║
║  ├─ Consider: OFAC sanctions check                                ║
║  ├─ No guarantee of decryption                                    ║
║  └─ May fund future attacks                                       ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
```

### 4.2 Ransom Payment Considerations

**IF considering payment (not recommended):**

1. [ ] Engage law enforcement (FBI IC3)
2. [ ] Verify OFAC sanctions (legal requirement)
3. [ ] Engage professional negotiators
4. [ ] Verify decryptor works (test file)
5. [ ] Prepare cryptocurrency (if proceeding)
6. [ ] Document everything for legal/insurance

**WARNING:** Payment does not guarantee:
- Working decryption keys
- Complete data recovery
- Attacker won't return
- Data won't be leaked

---

## Phase 5: Eradication

### 5.1 Complete Environment Cleanup

| Task | Status | Notes |
|------|--------|-------|
| All ransomware removed | ☐ | |
| Persistence mechanisms cleared | ☐ | |
| Compromised credentials reset | ☐ | |
| Vulnerable systems patched | ☐ | |
| Attack vector closed | ☐ | |
| Domain trust verified | ☐ | |

### 5.2 Credential Reset

**Assume full credential compromise:**

```powershell
# Reset all administrative passwords
# Reset service account passwords
# Reset KRBTGT twice (wait 10+ hours between)
# Rotate all API keys/secrets
# Invalidate all active sessions

# Example KRBTGT reset process
$Domain = Get-ADDomain
Reset-KRBTGTKeys -Domain $Domain.DNSRoot -First
# Wait 10+ hours
Reset-KRBTGTKeys -Domain $Domain.DNSRoot -Second
```

### 5.3 Vulnerability Remediation

Address the initial access vector:

```bash
# Patch critical vulnerabilities
wsus-cli approve-patches --category critical --force

# Disable unnecessary services
sc config RemoteRegistry start= disabled
sc config NetBT start= disabled

# Harden RDP (if required)
# - Enable NLA
# - Restrict access via firewall
# - Implement MFA
```

---

## Phase 6: Recovery

### 6.1 Prioritized Recovery Plan

| Priority | Systems | Recovery Method | Timeline |
|----------|---------|-----------------|----------|
| 1 | Domain Controllers | Restore/Rebuild | 24-48 hrs |
| 2 | Critical Business Apps | Restore from backup | 48-72 hrs |
| 3 | File Servers | Restore from backup | 72-96 hrs |
| 4 | Workstations | Reimage | 1-2 weeks |
| 5 | Non-critical systems | Reimage | 2-4 weeks |

### 6.2 Secure Recovery Process

```
RECOVERY CHECKLIST PER SYSTEM:

☐ Verify backup integrity before restore
☐ Restore to isolated network segment
☐ Full malware scan before network connection
☐ Verify no ransomware presence
☐ Patch all vulnerabilities
☐ Harden configuration
☐ Restore to production network
☐ Monitor closely for 72 hours
```

### 6.3 Extra Monitoring

Add monitoring during recovery:

```yaml
# Enhanced detection rules
rules:
  - name: Ransomware extension detection
    query: file.extension IN ransomware_extensions
    action: alert_critical

  - name: Mass file modification
    query: COUNT(file.modified) > 100 PER 1m
    action: alert_critical

  - name: Encryption behavior
    query: process.name creates encrypted_files
    action: isolate_host
```

---

## Phase 7: Post-Incident

### 7.1 Lessons Learned

**Mandatory Review Questions:**

1. How did the attacker gain initial access?
2. How long were they in the environment? (Dwell time)
3. What detection gaps allowed this?
4. Was the backup strategy adequate?
5. Was the response effective?
6. What would we do differently?

### 7.2 Security Improvements

**Immediate Improvements:**

- [ ] Implement/improve network segmentation
- [ ] Deploy or extend EDR coverage
- [ ] Enable MFA everywhere
- [ ] Implement 3-2-1 backup strategy
- [ ] Regular offline backup testing
- [ ] Privileged access management
- [ ] Security awareness training

### 7.3 Regulatory Notifications

| Requirement | Timeline | Status |
|------------|----------|--------|
| Cyber insurance | 24-48 hours | ☐ |
| Law enforcement (FBI) | 72 hours | ☐ |
| Data protection authority | 72 hours (GDPR) | ☐ |
| Affected individuals | As required | ☐ |
| SEC (if public company) | 4 business days | ☐ |

---

## Appendix

### Ransomware Identification Resources

- ID Ransomware: https://id-ransomware.malwarehunterteam.com/
- No More Ransom: https://www.nomoreransom.org/
- Emsisoft Decryptors: https://www.emsisoft.com/ransomware-decryption-tools/

### Law Enforcement Contacts

- FBI IC3: https://www.ic3.gov/
- CISA: https://www.cisa.gov/
- Secret Service: Local field office

### Related Playbooks

- [Malware Infection](malware-infection.md)

### References

- CISA Ransomware Guide: https://www.cisa.gov/ransomware
- NIST Ransomware Tips: https://www.nist.gov/ransomware
- No More Ransom: https://www.nomoreransom.org/
