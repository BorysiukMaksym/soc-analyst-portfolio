# Incident Reports

Real-world style incident investigations with full documentation.
Each report includes: timeline, IOCs, MITRE mapping, and recommendations.

## IR-001 — RDP Brute Force + Successful Login

**Severity:** 🔴 HIGH  
**Date:** 2025-01-06  
**Status:** Escalated to L2  

### Summary
Detected 847 failed RDP login attempts over 3 minutes from IP 185.220.101.5.
At 03:17 UTC, a successful login was recorded under the Administrator account,
followed by suspicious process execution and backdoor account creation.

### Timeline

- Time (UTC) | Event                                           | Event ID
- -----------|-------------------------------------------------|----------
- 03:14:22   | First failed RDP login attempt                  | 4625 
- 03:14:22   | 03:17:01 | 847 failed attempts in 3 minutes     | 4625 
- 03:17:03   | Successful RDP login (Logon Type 10)            | 4624 
- 03:17:45   | cmd.exe spawned                                 | 4688 
- 03:18:12   | New account created: svc_update                 | 4720 
- 03:18:14   | svc_update added to Administrators group        | 4732 
- 03:19:01   | New service installed: WindowsUpdateSvc         | 7045 

### Indicators of Compromise (IOC)

- Type      | Value                       | Status 
- ----------|-----------------------------|--------------------------------
- IP        | 185.220.101.5               | Malicious — AbuseIPDB 98% 
- Account   | svc_update                  | Backdoor account 
- Service   | WindowsUpdateSvc            | Malicious service 
- File Path | C:\Users\Public\update.exe  | Suspicious 

### MITRE ATT&CK Mapping

- Tactic          | Technique                                        | ID 
- ----------------|--------------------------------------------------|----------
- Initial Access  | Brute Force: Password Guessing                   | T1110.001 
- Persistence     | Create Account: Local Account                    | T1136.001 
- Persistence     | Create or Modify System Process: Windows Service | T1543.003 
- Defense Evasion | Valid Accounts                                   | T1078 

### Actions Taken
1. Confirmed attack via Splunk (index=windows EventCode=4625/4624)
2. Verified IP 185.220.101.5 on AbuseIPDB — 98% abuse confidence
3. Escalated to L2 at 03:25 UTC
4. Recommended: block IP, reset password, remove backdoor account, disable service

### Recommendations
1. Block 185.220.101.5 at the firewall level
2. Reset Administrator account password immediately
3. Delete backdoor account svc_update
4. Disable and remove service WindowsUpdateSvc
5. Enforce MFA for all RDP access
6. Restrict RDP to corporate VPN only

---

## IR-002 — Phishing Email → Macro Execution → C2

**Severity:** 🔴 HIGH  
**Date:** 2025-01-07  
**Status:** Escalated to L2  

### Summary
An HR employee received a spearphishing email with attachment Q4_Salary_2025.docm.
Upon opening, a malicious macro launched PowerShell which downloaded a second-stage
payload, established persistence via Registry Run Key, and initiated C2 communication.

### Timeline

- Time (UTC) | Event 
- -----------|-----------------------------------------------------
- 08:23      | Phishing email received by HR user 
- 08:31      | File opened — winword.exe executed 
- 08:31      | winword.exe → powershell.exe spawned (EventID 4688) 
- 08:32      | PowerShell downloaded stage2.exe from 185.220.101.5 
- 08:33      | Registry Run Key created for persistence 
- 08:33      | DNS queries to evil-update.com (C2 beaconing) 

### Indicators of Compromise (IOC)

- Type        | Value                            | Status 
- ------------|----------------------------------|--------------------
- Domain      | company-payroll.com              | Phishing domain 
- IP          | 185.220.101.5                    | C2 Server 
- Hash (MD5)  | 44d88612fea8a8f36de82e1278abb02f | Trojan 
- File        | C:\Users\Public\svchost32.exe    | Malware payload 
- Registry    | HKCU\...\Run\WindowsHelper       | Persistence key 

### MITRE ATT&CK Mapping

- Tactic            | Technique | ID |
- ------------------|-----------------------------------------------|----------
- Initial Access    | Phishing: Spearphishing Attachment            | T1566.001 
- Execution         | Command and Scripting Interpreter: PowerShell | T1059.001 
- Execution         | User Execution: Malicious File                | T1204.002 
- Persistence       | Boot or Logon Autostart: Registry Run Keys    | T1547.001 
- Command & Control | Application Layer Protocol: DNS               | T1071.004 

### Actions Taken
1. Identified malicious email via gateway alert
2. Analyzed file hash on VirusTotal — 42/72 detections
3. Submitted sample to Any.run sandbox — confirmed Trojan behavior
4. Escalated to L2 with full IOC report
5. Email deleted from all mailboxes, domain blocked

### Recommendations
1. Block domain company-payroll.com and IP 185.220.101.5
2. Isolate affected host immediately
3. Disable macros in Office via Group Policy
4. Conduct user awareness training on phishing
5. Implement email attachment sandboxing

   
