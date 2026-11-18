# Phishing Attack Response Playbook

## Overview

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PLY-002 |
| **Version** | 1.0 |
| **Last Updated** | 2024-01-15 |
| **Severity** | Medium-High (P2-P3) |
| **MITRE ATT&CK** | T1566 - Phishing |

## Purpose

This playbook provides guidance for responding to phishing attacks, including credential harvesting, malware delivery by email and business email compromise (BEC) attempts.

## Scope

- User-reported suspicious emails
- Email gateway phishing detections
- Credential harvesting attempts
- Malicious attachment delivery
- Business Email Compromise (BEC)

---

## Phase 1: Detection & Initial Analysis

### 1.1 Alert Sources

| Source | Alert Type | Priority |
|--------|------------|----------|
| User Report | Suspicious email reported | High |
| Email Gateway | Phishing detection | High |
| SIEM | URL reputation alert | Medium |
| Web Proxy | Malicious URL access | High |

### 1.2 Initial Triage

**Estimated Time:** 10-15 minutes

| Step | Action | Tool |
|------|--------|------|
| 1 | Obtain original email (with headers) | Email client/Gateway |
| 2 | Document reporter information | Ticketing system |
| 3 | Identify email subject, sender, time | Email analysis |
| 4 | Check if user clicked any links | Web proxy logs |
| 5 | Check if attachments were opened | EDR telemetry |

### 1.3 Severity Assessment

```
SEVERITY DETERMINATION:

CRITICAL (P1):
- Executive targeted (whaling)
- Active credential theft confirmed
- Financial transaction attempted
- Malware execution confirmed

HIGH (P2):
- Multiple users targeted
- User clicked link/opened attachment
- Credential submission suspected
- Sensitive data exposure possible

MEDIUM (P3):
- Single user targeted
- Email reported before interaction
- Blocked by security controls
- No user interaction

LOW (P4):
- Spam/marketing misidentified
- No malicious content confirmed
- Already blocked at gateway
```

### 1.4 Create Investigation Case

```
Create TheHive case using "Phishing Investigation" template
- Title: Phishing - [Brief Description]
- Severity: Based on assessment
- Tags: phishing, [campaign-name if known]
```

---

## Phase 2: Email Analysis

### 2.1 Header Analysis

**Extract and analyze:**

```bash
# Key headers to examine
From: (display name vs actual address)
Reply-To: (mismatch indicates phishing)
Return-Path: (actual sending server)
Received: (trace email path)
X-Originating-IP: (sender IP)
Authentication-Results: (SPF/DKIM/DMARC)
```

**Authentication Checks:**

| Check | Pass | Fail Indication |
|-------|------|-----------------|
| SPF | Sender authorized | Spoofed domain |
| DKIM | Signature valid | Modified content |
| DMARC | Policy satisfied | Domain abuse |

### 2.2 Content Analysis

**Examine for indicators:**

- [ ] Urgency language ("immediate action required")
- [ ] Authority impersonation (CEO, IT, HR)
- [ ] Grammar/spelling errors
- [ ] Generic greetings
- [ ] Mismatched or suspicious URLs
- [ ] Unusual sender domain (typosquatting)
- [ ] Request for credentials/sensitive info

### 2.3 URL Analysis

**Safe URL Analysis Procedure:**

```bash
# Defang URLs before sharing
echo "https://malicious.com/phish" | sed 's/http/hxxp/g; s/\./[.]/g'
# Result: hxxps://malicious[.]com/phish

# Submit to URLScan (safe)
curl -X POST "https://urlscan.io/api/v1/scan/" \
  -H "API-Key: $URLSCAN_KEY" \
  -d '{"url": "https://suspicious-url.com", "visibility": "private"}'

# Check VirusTotal
curl "https://www.virustotal.com/api/v3/urls/<URL_ID>" \
  -H "x-apikey: $VT_KEY"
```

**URL Red Flags:**

- Newly registered domain (< 30 days)
- Suspicious TLD (.xyz, .top, .click)
- URL shorteners hiding destination
- IP address instead of domain
- Typosquatting legitimate brands
- Excessive subdomains

### 2.4 Attachment Analysis

**Safe Handling:**

1. Never open attachments on production systems
2. Calculate hash before analysis
3. Submit to sandbox environment

```bash
# Calculate hashes
sha256sum suspicious_attachment.doc
md5sum suspicious_attachment.doc

# Submit to VirusTotal
curl --request POST \
  --url 'https://www.virustotal.com/api/v3/files' \
  --header 'x-apikey: $VT_KEY' \
  --form file=@suspicious_attachment.doc

# Submit to Any.Run sandbox
curl -X POST "https://api.any.run/v1/analysis" \
  -H "Authorization: API-Key $ANYRUN_KEY" \
  -F "file=@suspicious_attachment.doc"
```

---

## Phase 3: Impact Assessment

### 3.1 Identify All Recipients

```sql
-- Email gateway query for recipients
SELECT recipient, delivery_time, delivery_status
FROM email_logs
WHERE (subject LIKE '%<SUBJECT>%'
   OR sender_address = '<SENDER>')
AND timestamp > now() - interval '7 days'
```

### 3.2 Determine User Interactions

**Check for link clicks:**

```sql
-- Web proxy query
SELECT user, timestamp, url, action
FROM proxy_logs
WHERE url LIKE '%<PHISHING_DOMAIN>%'
ORDER BY timestamp
```

**Check for credential submission:**

- Review web proxy POST requests to phishing URL
- Check authentication logs for suspicious logins
- Review VPN/SSO logs for compromised accounts

### 3.3 Check for Malware Execution

If attachment was opened:

```sql
-- EDR query for file execution
SELECT host, user, file_name, file_hash, process_tree
FROM endpoint_events
WHERE file_hash = '<ATTACHMENT_HASH>'
OR file_name = '<ATTACHMENT_NAME>'
```

---

## Phase 4: Containment

### 4.1 Email Containment

**Immediate Actions:**

| Priority | Action | Tool |
|----------|--------|------|
| 1 | Block sender address | Email Gateway |
| 2 | Block sender domain | Email Gateway |
| 3 | Search and remove from mailboxes | Exchange/O365 |
| 4 | Block phishing URL at proxy | Web Proxy |

**Exchange/O365 Message Removal:**

```powershell
# Search for phishing emails
$Search = New-ComplianceSearch -Name "Phishing Removal" -ExchangeLocation All `
  -ContentMatchQuery 'subject:"<SUBJECT>" AND from:<SENDER>'
Start-ComplianceSearch -Identity $Search.Name

# Preview results
Get-ComplianceSearch -Identity "Phishing Removal" | FL

# Purge messages (SoftDelete)
New-ComplianceSearchAction -SearchName "Phishing Removal" -Purge -PurgeType SoftDelete
```

### 4.2 Credential Compromise Response

If credentials may be compromised:

| Priority | Action | Verification |
|----------|--------|--------------|
| 1 | Force password reset | User notified |
| 2 | Revoke active sessions | Sessions terminated |
| 3 | Enable/verify MFA | MFA active |
| 4 | Review recent activity | No unauthorized access |
| 5 | Check for mail rules | No forwarding rules |

**Check for malicious mail rules:**

```powershell
# Check inbox rules for all affected users
Get-InboxRule -Mailbox user@company.com |
  Where-Object {$_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.DeleteMessage}
```

### 4.3 Block Indicators

```bash
# Add to firewall blocklist
firewall-cli add-block --type domain --value "phishing-domain.com"
firewall-cli add-block --type ip --value "192.168.1.100"

# Add to web proxy blocklist
proxy-cli block-url --url "https://phishing-site.com/*"

# Block file hash if attachment was malicious
edr-cli block-hash --hash "<SHA256>" --scope organization
```

---

## Phase 5: Eradication

### 5.1 Complete Email Removal

Verify all phishing emails removed:

```powershell
# Verify removal
Get-ComplianceSearchAction -Identity "Phishing Removal_Purge" | FL

# Check mailboxes for remaining copies
Get-MailboxSearch -Identity "Phishing Removal" | Get-MailboxSearchResults
```

### 5.2 Clean Compromised Systems

If malware was executed:
- Follow [Malware Infection Playbook](malware-infection.md)
- Full system scan
- Check for persistence
- Consider reimaging

### 5.3 Verify Account Security

For each compromised account:

- [ ] Password reset completed
- [ ] MFA enabled and verified
- [ ] No unauthorized mail rules
- [ ] No unauthorized app permissions
- [ ] Recent sign-ins reviewed
- [ ] No data exfiltration detected

---

## Phase 6: Recovery & Communication

### 6.1 User Communication

**Template for Affected Users:**

```
Subject: Security Notice - Phishing Email Alert

Dear [User],

Our security team identified a phishing email that was sent to you on [DATE].

The email appeared to be from: [SENDER]
Subject: [SUBJECT]

ACTION REQUIRED:
1. Do NOT click any links or open attachments from this email
2. Delete the email if still in your mailbox
3. If you clicked any links or entered credentials, contact IT Security immediately

[If credentials were entered]
Your password has been reset as a precaution. Please create a new password at [LINK].

If you have any questions, please contact the IT Security team.

Thank you for your vigilance.
IT Security Team
```

### 6.2 Awareness Alert

If widespread campaign, send organization-wide alert:

```
Subject: Security Alert - Phishing Campaign

The IT Security team has identified an active phishing campaign targeting our organization.

WARNING SIGNS:
- Emails claiming to be from [IMPERSONATED ENTITY]
- Subject lines containing [KEYWORDS]
- Requests for [TYPE OF INFORMATION]

IF YOU RECEIVE SUCH AN EMAIL:
1. Do NOT click links or open attachments
2. Report it using the "Report Phishing" button
3. Delete the email

Thank you for helping protect our organization.
```

---

## Phase 7: Post-Incident

### 7.1 Documentation

Complete investigation documentation:

- [ ] Full email analysis report
- [ ] List of all recipients
- [ ] Users who interacted with email
- [ ] Containment actions taken
- [ ] IOCs extracted
- [ ] Timeline of events

### 7.2 Threat Intelligence

**Export IOCs:**

```json
{
  "indicators": [
    {"type": "email", "value": "attacker@phishing-domain.com"},
    {"type": "domain", "value": "phishing-domain.com"},
    {"type": "url", "value": "https://phishing-domain.com/login"},
    {"type": "ip", "value": "192.168.1.100"},
    {"type": "sha256", "value": "<ATTACHMENT_HASH>"}
  ],
  "campaign": "Finance Impersonation Q1 2024",
  "first_seen": "2024-01-15T10:30:00Z",
  "tlp": "amber"
}
```

### 7.3 Improvements

- [ ] Update email filtering rules
- [ ] Add sender/domain to blocklists
- [ ] Review user awareness training
- [ ] Update phishing simulation scenarios
- [ ] Improve detection rules

---

## Appendix

### Phishing Indicators Quick Reference

| Category | Indicator |
|----------|-----------|
| **Sender** | Mismatched display name/address |
| **Domain** | Typosquatting, new registration |
| **Subject** | Urgency, authority, threats |
| **Content** | Grammar errors, generic greeting |
| **Links** | Shortened, IP-based, mismatched |
| **Attachments** | Office macros, executables |

### Related Playbooks

- [Malware Infection](malware-infection.md)

### References

- APWG Phishing Reports: https://apwg.org/
- PhishTank: https://phishtank.org/
- URLScan.io: https://urlscan.io/
