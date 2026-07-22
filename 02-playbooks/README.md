# SOC Response Playbooks

Step-by-step incident response procedures for common attack scenarios.
Each playbook includes: trigger, severity, investigation steps, and MITRE mapping.

---

## Playbook 1 — RDP Brute Force

**Trigger:** More than 20 Event ID 4625 (Logon_Type=10) within 5 minutes  
**Severity:** HIGH  
**MITRE:** T1110.001 → T1078 → T1136 → T1543  

### Step 1 — Triage (5 min)
- [ ] Query Splunk for failed logins count and source IP
- [ ] Check source IP on AbuseIPDB
- [ ] Determine if any successful login followed the failures (Event 4624)

### Step 2 — Analysis (10 min)
- [ ] No successful login → classify as MEDIUM, continue monitoring
- [ ] Successful login found → classify as HIGH, escalate immediately
- [ ] Review processes spawned after login (Event 4688)
- [ ] Check for lateral movement (Event 5140, Event 4624 Logon Type 3)

### Step 3 — Containment
- [ ] Block source IP at the firewall
- [ ] Disable the compromised account
- [ ] Isolate the host if active compromise is confirmed

### Step 4 — Documentation
- [ ] Open a ticket with all IOCs (IP, account, timestamps)
- [ ] Escalate to L2 with full timeline
- [ ] Add IP to SIEM blocklist

---

## Playbook 2 — Phishing Email

**Trigger:** User report or email gateway alert  
**Severity:** MEDIUM → HIGH (if user clicked or opened attachment)  
**MITRE:** T1566.001 → T1204.002 → T1059  

### Step 1 — Email Analysis (10 min)
- [ ] Analyze email headers using MXToolbox
- [ ] Check SPF / DKIM / DMARC results
- [ ] Compare From and Reply-To domains
- [ ] Check X-Originating-IP on AbuseIPDB

### Step 2 — Content Analysis (10 min)
- [ ] Submit URLs to URLScan.io and VirusTotal
- [ ] Get file hash from attachment → submit to VirusTotal
- [ ] Look for urgency language, impersonation, generic greetings

### Step 3 — Impact Assessment (5 min)
- [ ] Who received the email? How many recipients?
- [ ] Did anyone click the link? → investigate their hosts
- [ ] Did anyone open the attachment? → escalate to CRITICAL

### Step 4 — Containment
- [ ] Delete email from all mailboxes
- [ ] Block sender domain and IP
- [ ] Block malicious URL
- [ ] If attachment was opened → isolate affected host immediately

---

## Playbook 3 — Malware Detection

**Trigger:** AV or EDR alert on suspicious file  
**Severity:** HIGH  
**MITRE:** T1566 → T1059 → T1547 → T1071  

### Step 1 — Verification (5 min)
- [ ] Get file hash → submit to VirusTotal (how many engines detected?)
- [ ] Check file location (is it in a suspicious directory?)
- [ ] Identify parent process that executed the file

### Step 2 — Sandbox Analysis (15 min)
- [ ] Submit hash to Hybrid Analysis or Any.run
- [ ] Review: process tree, network connections, registry changes, file drops
- [ ] Extract all IOCs from the sandbox report

### Step 3 — Containment
- [ ] Isolate the host from the network IMMEDIATELY
- [ ] Preserve a copy of the malicious file for further analysis
- [ ] Search for similar files across other endpoints
- [ ] Disable the compromised user account

### Step 4 — Escalation
- [ ] Escalate to L2 with full sandbox report and IOC list
- [ ] Add all IOCs to SIEM blocklist and threat intel feed
- [ ] Document full timeline for post-incident review
