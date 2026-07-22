# Splunk SPL Detection Queries

Production-ready SPL queries for detecting real-world attack techniques.
Each query includes: use case, explanation, and MITRE ATT&CK mapping.

---

## CRITICAL — RDP Brute Force Detection

**Use Case:** Detect mass failed RDP login attempts from a single IP  
**MITRE:** T1110.001  

```
index=windows EventCode=4625 Logon_Type=10
| bucket _time span=5m
| stats count as attempts by _time, Source_Network_Address
| where attempts > 20
| eval Severity="HIGH"
| eval Alert="RDP Brute Force from " + Source_Network_Address
| table _time, Source_Network_Address, attempts, Severity, Alert
| sort -attempts
```

What it does: Groups failed logins into 5-minute windows.
If more than 20 failures come from the same IP → brute force alert.

---

## CRITICAL — Security Log Cleared
Use Case: Detect when an attacker clears Windows Security logs to cover tracks
MITRE: T1070.001

```
index=windows (EventCode=1102 OR EventCode=104)
| eval Severity="CRITICAL"
| eval Alert="Security logs cleared on " + host
| table _time, host, Severity, Alert
| sort -_time
```

What it does: Event 1102 = Security log cleared (Windows).
Event 104 = System log cleared. Both are serious red flags.

---

## HIGH — Office App Spawned Shell
Use Case: Detect macro execution — Word/Excel launching PowerShell or CMD
MITRE: T1059.001, T1566.001

```
index=windows EventCode=4688
| where
  (Parent_Process_Name="winword.exe" AND Process_Name="cmd.exe") OR
  (Parent_Process_Name="excel.exe" AND Process_Name="powershell.exe") OR
  (Parent_Process_Name="outlook.exe" AND Process_Name="wscript.exe") OR
  (Parent_Process_Name="winword.exe" AND Process_Name="powershell.exe")
| eval Severity="HIGH"
| eval Alert=Parent_Process_Name + " spawned " + Process_Name
| table _time, host, Account_Name, Alert, Process_Command_Line
| sort -_time
```

What it does: Legitimate Office apps should NEVER launch shells.
If they do → malicious macro execution is almost certain.

---

## HIGH — New Admin Account Created
Use Case: Detect backdoor account creation — new user added to Administrators
MITRE: T1136.001

```
index=windows (EventCode=4720 OR EventCode=4732)
| eval Event_Type=if(EventCode=4720, "Account Created", "Added to Group")
| stats values(Event_Type) as Events, values(host) as Hosts
        by SAM_Account_Name
| where mvcount(Events) >= 2
| eval Alert="Possible Backdoor Account: " + SAM_Account_Name
```

What it does: Correlates account creation (4720) with group membership
change (4732). If both happen together → backdoor account indicator.

---

## HIGH — Lateral Movement via SMB
Use Case: Detect access to admin shares — a common lateral movement technique
MITRE: T1021.002

```
index=windows EventCode=5140
| where like(Share_Name, "%ADMIN$%") OR
        like(Share_Name, "%C$%") OR
        like(Share_Name, "%IPC$%")
| stats count by Account_Name, Source_Address, Share_Name, host
| where count > 2
| eval Alert="Lateral Movement via SMB: " + Account_Name
| sort -count
```

What it does: Admin shares (ADMIN$, C$) should only be accessed by
authorized admins. Multiple accesses from different hosts = lateral movement.

---

## HIGH — PowerShell Encoded Command
Use Case: Detect PowerShell with base64 encoded commands (common malware trick)
MITRE: T1059.001, T1027

```
index=windows EventCode=4688
| where like(lower(Process_Command_Line), "%-enc%") OR
        like(lower(Process_Command_Line), "%-encodedcommand%") OR
        like(lower(Process_Command_Line), "%frombase64string%")
| eval Severity="HIGH"
| table _time, host, Account_Name, Process_Command_Line
| sort -_time
```

What it does: Attackers encode PowerShell commands in base64 to bypass
security tools and hide what they're actually running.

---

## MEDIUM — After-Hours Login
Use Case: Detect successful logins during unusual hours (midnight to 6AM)
MITRE: T1078

```
index=windows EventCode=4624
| eval hour=tonumber(strftime(_time, "%H"))
| where hour >= 0 AND hour <= 6
| eval Alert="After-hours login at " +
             strftime(_time, "%H:%M") + " by " + Account_Name
| table _time, host, Account_Name, Logon_Type,
        Source_Network_Address, Alert
| sort -_time
```

What it does: Flags legitimate-looking logins that happen at 2AM.
Could be an attacker using stolen credentials when no one is watching.

---

## MEDIUM — DNS Tunneling Detection
Use Case: Detect unusually long DNS queries — possible C2 communication
MITRE: T1071.004

```
index=dns
| eval domain_length=len(query)
| where domain_length > 50
| stats count, values(query) as queries by src_ip, domain_length
| sort -domain_length
| eval Alert="Possible DNS Tunneling from " + src_ip
```

What it does: Normal DNS queries are short (google.com = 10 chars).
Attackers hide data inside DNS queries — they get very long (50+ chars).

---

## SOC Dashboard Overview Query
Use Case: Single query to power a full SOC monitoring dashboard

```
index=windows
  (EventCode=4625 OR EventCode=4624 OR EventCode=4688
   OR EventCode=4720 OR EventCode=1102 OR EventCode=7045)
| eval Event_Type=case(
    EventCode=4625, "❌ Failed Login",
    EventCode=4624, "✅ Successful Login",
    EventCode=4688, "⚙️ Process Created",
    EventCode=4720, "👤 Account Created",
    EventCode=1102, "🗑️ Logs Cleared",
    EventCode=7045, "🔧 New Service",
    true(), "Other"
)
| timechart count by Event_Type span=1h
```

What it does: Creates a time-based chart of all critical security events.
Use this as the main panel in your SOC dashboard.
