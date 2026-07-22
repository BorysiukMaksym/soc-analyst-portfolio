# Threat Intelligence

IOC tracking, OSINT investigation workflow, and TI tool reference.

---

## 📋 IOC Master List

| Type | Value | Threat | Source | Date Added |
|------|-------|--------|--------|------------|
| IP | 185.220.101.5 | TOR Exit Node / C2 | AbuseIPDB | 2025-01-06 |
| IP | 91.108.4.22 | RDP Scanner | AbuseIPDB | 2025-01-06 |
| Domain | evil-update.com | C2 Server | VirusTotal | 2025-01-07 |
| Domain | company-payroll.com | Phishing Domain | URLScan.io | 2025-01-07 |
| Hash (MD5) | 44d88612fea8a8f36de82e1278abb02f | Trojan Dropper | VirusTotal | 2025-01-07 |
| URL | `hxxp://185.220.101.5/stage2.exe` | Malware Payload | Hybrid Analysis | 2025-01-07 |
| Email | hr@company-payroll.com | Phishing Sender | Manual Analysis | 2025-01-07 |

> ⚠️ Note: Malicious URLs are defanged using `hxxp` to prevent accidental clicks.

---

## Investigation Workflow

### Investigating an IP Address
1. AbuseIPDB → Confidence of Abuse % (>80% = block immediately)
2. VirusTotal → IP tab → Detection engines count
3. ipinfo.io → Country, ASN, ISP, Organization
4. Shodan.io → Open ports, running services, banners
5. Greynoise.io → Is it internet background noise or targeted?

### Investigating a Domain
1. VirusTotal → Domain tab → Detection ratio
2. URLScan.io → Screenshot, verdict, linked IPs
3. whois lookup → Registration date (new domain < 30 days = suspicious!)
4. MXToolbox.com → SPF, DKIM, MX records, blacklist check
5. urlvoid.com → Multi-engine domain reputation

### Investigating a File Hash
1. VirusTotal → File hash → Detection count (>5 = likely malicious)
2. Hybrid Analysis → Full sandbox report, process tree, network IOCs
3. Any.run → Interactive sandbox, real-time behavior
4. Bazaar.abuse.ch → Malware family classification
5. MalwareBazaar → Download sample safely for deeper analysis


---

## MITRE ATT&CK Quick Reference

- Technique             | ID        | How to Detect                           | Detection Query 
- ----------------------|-----------|-----------------------------------------|----------------
- RDP Brute Force       | T1110.001 | EventID 4625, Logon_Type=10, count >20  | See Section 3 
- PowerShell Abuse      | T1059.001 | EventID 4688, powershell.exe process    | See Section 3 
- Registry Persistence  | T1547.001 | EventID 4657, Run key modification      | See Section 3 
- New Local Account     | T1136.001 | EventID 4720 + 4732 correlation         | See Section 3 
- Log Clearing          | T1070.001 | EventID 1102 or 104                     | See Section 3 
- SMB Lateral Movement  | T1021.002 | EventID 5140, ADMIN$ or C$ access       | See Section 3 
- DNS C2                | T1071.004 | DNS queries longer than 50 characters   | See Section 3 
- Encoded Commands      | T1027     | PowerShell -enc or -EncodedCommand flag | See Section 3 

---

## Threat Intelligence Tools

- Tool              | URL                      | Use Case 
- ------------------|--------------------------|--------------------------------------
- VirusTotal        | virustotal.com           | File, URL, IP, domain reputation 
- AbuseIPDB         | abuseipdb.com            | IP abuse confidence score 
- URLScan.io        | urlscan.io               | Safe URL scanning with screenshot 
- Shodan            | shodan.io                | Internet-facing asset reconnaissance 
- MXToolbox         | mxtoolbox.com            | Email header and DNS analysis 
- Any.run           | any.run                  | Interactive malware sandbox 
- Hybrid Analysis   | hybrid-analysis.com      | Free automated sandbox 
- MalwareBazaar     | bazaar.abuse.ch          | Malware samples database 
- GreyNoise         | greynoise.io             | IP noise vs targeted classification 
- CyberChef         | gchq.github.io/CyberChef | Decode, encode, transform data 
