# soc-analyst-portfolio
SOC Analyst portfolio — incident reports, detection rules, playbooks, and log analysis

## Repository Structure
| Section | Contents |
|---------|---------|
| [Incident Reports](./01-incident-reports/) | Full investigations: RDP Brute Force, Phishing → Malware |
| [Playbooks](./02-playbooks/) | Step-by-step response procedures for common incidents |
| [Splunk SPL Queries](./03-splunk-spl-queries/) | 8 production-ready detection queries with explanations |
| [Threat Intelligence](./04-threat-intelligence/) | IOC tracking, investigation workflow, TI tools reference |
| [Malware & Phishing](./05-malware-phishing-analysis/) | Sandbox reports and phishing header analysis |
| [MITRE ATT&CK](./06-mitre-attack-mapping/) | 2 full attack scenarios mapped to ATT&CK framework |

## Tools & Technologies
| Category | Tools |
|---------|-------|
| **SIEM** | Splunk Enterprise, ELK Stack |
| **Threat Intel** | VirusTotal, AbuseIPDB, URLScan.io, MXToolbox |
| **Sandbox** | Any.run, Hybrid Analysis |
| **Frameworks** | MITRE ATT&CK, NIST SP 800-61, Cyber Kill Chain |
| **OS** | Windows 10/Server, Linux (Ubuntu, Kali) |
| **Network** | Wireshark, tcpdump |
| **Scripting** | PowerShell, Bash |

## Attack Scenarios Covered
| Scenario | MITRE Techniques | Status |
|---------|-----------------|--------|
| RDP Brute Force + Backdoor | T1110.001, T1078, T1136.001, T1543.003 | Full writeup |
| Phishing → Macro → C2 | T1566.001, T1059.001, T1547.001, T1071.004 | Full writeup |
| Log Clearing Detection | T1070.001 | SPL query |
| Lateral Movement via SMB | T1021.002 | SPL query |
| PowerShell Obfuscation | T1059.001, T1027 | SPL query |
| After-Hours Login | T1078 | SPL query |
| DNS Tunneling | T1071.004 | SPL query |

## Skills Demonstrated

- Alert triage and prioritization (L1 SOC workflow)
- Windows Event Log analysis (Event IDs 4624, 4625, 4688, 4720, 1102...)
- SIEM query writing (Splunk SPL)
- Threat intelligence investigation (IP, domain, hash, URL)
- Malware sandbox analysis (Any.run, Hybrid Analysis)
- Phishing email header analysis
- Incident documentation and reporting
- MITRE ATT&CK framework mapping
- Incident response playbook creation

---

## Learning Resources Used

- [TryHackMe — SOC Level 1 Path](https://tryhackme.com/path/outline/soclevel1)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [NIST SP 800-61r2 — Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [Splunk Free Training](https://www.splunk.com/en_us/training/free-courses/overview.html)
- [Blue Team Labs Online](https://blueteamlabs.online)

---

## Connect

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/maksymborysiuk)
