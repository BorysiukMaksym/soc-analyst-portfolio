# MITRE ATT&CK Mapping

Real attack scenarios mapped to MITRE ATT&CK tactics and techniques.
Used to understand attacker behavior and improve detection coverage.

---

## Scenario 1 — RDP Brute Force + Backdoor Installation

### Cyber Kill Chain
Reconnaissance → Initial Access → Execution → Persistence → Defense Evasion


### ATT&CK Matrix

| # | Tactic | Technique | ID | What Happened |
|---|--------|-----------|-----|--------------|
| 1 | Initial Access | Brute Force: Password Guessing | T1110.001 | 847 failed RDP attempts |
| 2 | Initial Access | Valid Accounts | T1078 | Successful login with guessed credentials |
| 3 | Execution | Windows Command Shell | T1059.003 | cmd.exe launched after login |
| 4 | Persistence | Create Account: Local Account | T1136.001 | Backdoor account svc_update created |
| 5 | Persistence | Create or Modify System Process | T1543.003 | Malicious service WindowsUpdateSvc installed |
| 6 | Privilege Escalation | Account Manipulation | T1098 | svc_update added to Administrators group |
| 7 | Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | Security log cleared (EventID 1102) |

### Detection Coverage

| Technique | ID | Detected By | SPL Available |
|-----------|-----|------------|--------------|
| Password Guessing | T1110.001 | EventID 4625 | Section 3 |
| Valid Accounts | T1078 | EventID 4624 | Section 3 |
| New Local Account | T1136.001 | EventID 4720 | Section 3 |
| New Service | T1543.003 | EventID 7045 | Section 3 |
| Log Clearing | T1070.001 | EventID 1102 | Section 3 |

---


## Scenario 2 — Phishing Email → Macro → C2

### Cyber Kill Chain
Delivery → Exploitation → Installation → Command & Control → Actions on Objectives


### ATT&CK Matrix

| # | Tactic | Technique | ID | What Happened |
|---|--------|-----------|-----|--------------|
| 1 | Initial Access | Phishing: Spearphishing Attachment | T1566.001 | .docm file sent to HR employee |
| 2 | Execution | User Execution: Malicious File | T1204.002 | User opened the document |
| 3 | Execution | PowerShell | T1059.001 | winword.exe → powershell.exe |
| 4 | Defense Evasion | Obfuscated Files or Information | T1027 | PowerShell payload encoded in Base64 |
| 5 | Persistence | Registry Run Keys | T1547.001 | HKCU\Run key created for auto-start |
| 6 | Command & Control | Application Layer Protocol: DNS | T1071.004 | DNS beaconing to evil-update.com |
| 7 | Command & Control | Application Layer Protocol: Web | T1071.001 | HTTPS C2 traffic on port 443 |

### Detection Coverage

| Technique | ID | Detected By | SPL Available |
|-----------|-----|------------|--------------|
| Spearphishing | T1566.001 | Email gateway logs | Manual analysis |
| PowerShell | T1059.001 | EventID 4688 | Section 3 |
| Encoded Commands | T1027 | EventID 4688 -enc flag | Section 3 |
| Registry Persistence | T1547.001 | EventID 4657 | Section 3 |
| DNS C2 | T1071.004 | DNS logs query length | Section 3 |

---

## Overall Detection Coverage Summary
Covered (SPL query exists): 7 techniques
Partially covered (manual): 2 techniques
Not yet covered: 1 technique

Coverage rate: 70% of documented techniques
Next steps: Add Sigma rules for email gateway and endpoint telemetry

---

## 🔗 Useful Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

