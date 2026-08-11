# TryHackMe — Conti (Exchange Server Ransomware Investigation)

**Category:** Defensive Security / SIEM & Log Analysis
**Tooling:** Splunk
**Difficulty:** Medium
**Skills demonstrated:** Sysmon log analysis, Windows event correlation, IIS log analysis, process migration/injection detection, credential dumping detection, web shell identification, ransomware timeline reconstruction

---

## 1. Scenario

Employees reported they could no longer log into Outlook, and the Exchange system administrator was unable to access the Exchange Admin Center. Initial triage revealed ransom note files (`readme.txt`) scattered across the Exchange server's file system.

The task was to use **Splunk**, ingesting Sysmon and IIS logs from the compromised Exchange server, to reconstruct the full attack chain — from initial exploitation of the Exchange server through to ransomware deployment.

## 2. Objectives

1. Locate the ransomware binary and confirm its file-creation event.
2. Recover the ransomware's MD5 hash.
3. Identify where the ransom note was dropped.
4. Identify account creation used for persistence.
5. Trace process migration/injection used by the attacker.
6. Identify the process used to dump credential hashes.
7. Identify the web shell deployed and the command that wrote it to disk.
8. Identify the CVEs exploited to gain initial access.

## 3. Tools

| Tool | Purpose |
|---|---|
| **Splunk** | Central log search, correlation, and field extraction |
| **Sysmon** | Endpoint telemetry (process creation, file creation, remote thread creation, process access) |
| **IIS logs** | Web request telemetry (used to trace the web shell drop) |

## 4. Investigative Workflow

1. Identify the ransomware executable via Sysmon file-creation events (Event ID 11).
2. Pivot on that image path to recover its MD5 hash.
3. Identify all locations the ransom note was written to.
4. Search command-line telemetry for account creation activity.
5. Use Sysmon Event ID 8 (CreateRemoteThread) to trace process migration/injection.
6. Identify LSASS access consistent with credential dumping.
7. Filter IIS logs for POST requests to `.aspx` files to find the dropped web shell.
8. Pivot on the web shell filename to find the command line that wrote it to disk.
9. Cross-reference the exploited CVEs against public threat intelligence on Conti/Exchange intrusions.

## 5. Findings

### 5.1 Ransomware Location

**Splunk query:**
```
EventCode=11
```
Sorting by the `Image` field in Sysmon's file-creation events revealed a `cmd.exe` binary running from an unusual, non-standard location — a strong indicator of a renamed/dropped payload rather than the legitimate system binary.

**Answer:** `C:\Users\Administrator\Documents\cmd.exe`

### 5.2 Sysmon Event ID for File Creation

Sysmon's **Event ID 11 (FileCreate)** logs every file creation/overwrite on the endpoint, which is what surfaced the ransomware binary above.

**Answer:** `11`

### 5.3 MD5 Hash of the Ransomware

**Splunk query:**
```
Image="C:\Users\Administrator\Documents\cmd.exe"
```
Removing the `EventCode=11` filter and inspecting the single matching event's `Hashes`/`MD5` field returned the binary's hash.

**Answer:** `290C7DFB01E50CEA9E19DA81A781AF2C`

### 5.4 File Saved to Multiple Locations

**Splunk query:**
```
Image="C:\Users\Administrator\Documents\cmd.exe" EventCode=11
```
Inspecting the `TargetFilename` field across the returned events showed the same file name written repeatedly across different directories — consistent with a ransom note being dropped into every folder the ransomware touched.

**Answer:** `readme.txt`

### 5.5 Command Used to Add a New User

**Splunk query:**
```
CommandLine=*add*
```
Filtering command-line telemetry for account-management activity revealed a `net user` command creating a new local account for persistent access.

**Answer:** `net user /add securityninja hardToHack123$`

### 5.6 Process Migration (Persistence)

**Splunk query:**
```
EventCode=8
```
Sysmon **Event ID 8 (CreateRemoteThread)** logs when one process creates a thread inside another — a classic process injection/migration technique. Inspecting the `TargetImage` field across the returned events and pivoting into the corresponding event details revealed the source and destination processes of the first migration.

**Answer (migrated process, original process):**
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\wbem\unsecapp.exe`

### 5.7 Process Used to Dump System Hashes

Continuing to review the `EventCode=8` results, a second migration event showed the attacker's process (previously injected into `unsecapp.exe`) subsequently accessing `lsass.exe` — the process that holds credential material in memory on Windows.

**Answer:** `C:\Windows\System32\lsass.exe`

### 5.8 Web Shell Deployed

**Splunk query (IIS logs):**
```
cs_uri_stem=*.aspx* method=POST
```
Filtering IIS logs for POST requests against `.aspx` resources — a common web shell interaction pattern — surfaced a suspicious, randomly-named `.aspx` file under the OWA authentication directory.

**Answer:** `i3gfPctK1c2x.aspx`

### 5.9 Command Line That Wrote the Web Shell

**Splunk query:**
```
CommandLine=*i3gfPctK1c2x.aspx*
```
A single matching event showed the attacker using `attrib.exe` to clear the read-only attribute on the target path immediately before/while writing the web shell into the OWA authentication directory — a directory reachable pre-authentication on a vulnerable Exchange server.

**Answer:**
```
attrib.exe -r \\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx
```

### 5.10 CVEs Leveraged by the Exploit

The initial access hint pointed to external threat-intel research on Conti's exploitation of Exchange/network infrastructure. Correlating the timeframe and behavior with public reporting identified three CVEs used in the intrusion chain.

**Answer (ascending order):** `CVE-2018-13374`, `CVE-2018-13379`, `CVE-2020-0796`

## 6. Attack Chain Summary

```
CVE-2018-13374 / CVE-2018-13379 (Fortinet path traversal / auth bypass)
      │
      ▼
CVE-2020-0796 (SMBGhost — SMBv3 remote code execution)
      │
      ▼
Web shell dropped: i3gfPctK1c2x.aspx  (via attrib.exe, OWA auth directory)
      │
      ▼
Local account created for persistence: securityninja
      │
      ▼
Process migration: unsecapp.exe → powershell.exe
      │
      ▼
Credential access: powershell.exe → lsass.exe (hash dumping)
      │
      ▼
Ransomware dropped as cmd.exe in Administrator\Documents
      │
      ▼
Mass file creation: readme.txt ransom notes across multiple directories
```

## 7. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Exchange server compromised via CVE-2018-13374, CVE-2018-13379, CVE-2020-0796 |
| Persistence | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component: Web Shell | `.aspx` web shell (`i3gfPctK1c2x.aspx`) dropped into the OWA auth directory |
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | `net user /add securityninja hardToHack123$` |
| Defense Evasion / Privilege Escalation | [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Sysmon Event ID 8 (CreateRemoteThread) showing migration into `unsecapp.exe` and later `powershell.exe` |
| Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | `powershell.exe` used post-migration for follow-on actions |
| Execution | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Command and Scripting Interpreter: Windows Command Shell | Ransomware binary disguised as `cmd.exe` |
| Credential Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | Process access to `lsass.exe` to retrieve system hashes |
| Defense Evasion | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) | File and Directory Permissions Modification: Windows File and Directory Permissions Modification | `attrib.exe -r` used to clear read-only protection before dropping the web shell |
| Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Conti ransomware execution and mass `readme.txt` ransom notes across multiple directories |

## 8. OWASP Top 10 Mapping (Web-Facing Root Cause)

Although the bulk of the intrusion is a Windows/endpoint compromise, the **initial foothold** was gained through the exposed, vulnerable Exchange web front end. Mapping that entry point to the OWASP Top 10 (2021) highlights the application-layer root causes:

| OWASP Category | Relevance |
|---|---|
| **A06:2021 – Vulnerable and Outdated Components** | The root cause of initial access: an unpatched Exchange/network stack vulnerable to CVE-2018-13374, CVE-2018-13379, and CVE-2020-0796 |
| **A05:2021 – Security Misconfiguration** | The OWA authentication directory (`.../owa/auth/`) was writable/reachable in a way that allowed a web shell to be planted directly into a pre-authentication path |
| **A01:2021 – Broken Access Control** | A web shell placed under the pre-auth OWA path effectively bypassed the intended authentication boundary, granting the attacker command execution without valid credentials |
| **A03:2021 – Injection** | The `.aspx` web shell itself functions as a remote command injection point, executing arbitrary commands supplied via HTTP requests |
| **A09:2021 – Security Logging and Monitoring Failures** | The compromise was only detected after ransom notes appeared, indicating the exploitation and web shell activity were not alerted on in real time despite being fully visible in IIS/Sysmon logs |

## 9. Key Takeaways

- **Sysmon Event ID 8 is a powerful, underused signal.** CreateRemoteThread events are one of the clearest ways to catch process injection/migration used for persistence and stealth, and chaining two such events revealed the attacker's entire lateral movement from web shell to LSASS.
- **IIS + Sysmon correlation closes the gap between web and host telemetry.** The web shell was invisible in host logs alone; only cross-referencing IIS POST requests with the `attrib.exe` command line tied the web-layer compromise to the endpoint-layer activity.
- **Ransom notes are a lagging indicator, not a leading one.** By the time `readme.txt` files appeared, the attacker had already achieved initial access, persistence, privilege escalation, and credential theft — all of which were logged and detectable well before encryption began.
- **Unpatched, internet-facing Exchange infrastructure remains a top ransomware entry vector.** This intrusion chain mirrors real-world Conti operations, where known, patchable CVEs in edge infrastructure are consistently the first domino.

## 10. Methodology Note

The analytical approach and command/query sequence in this write-up were adapted from a publicly shared methodology for this room; the steps above were independently reproduced and verified against the provided Splunk dataset to arrive at the same results.
