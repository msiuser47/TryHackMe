# REvil Corp — Redline Ransomware Investigation 

**Category:** Digital Forensics & Incident Response (DFIR)
**Platform:** TryHackMe — "REvil Corp"
**Difficulty:** Not specified in source material
**Skills Demonstrated:** Redline host forensics, timeline analysis, file-system artifact review, browser history analysis, ransomware IOC extraction, hash-based malware attribution (VirusTotal)


## 1. Scenario Overview

An employee, **John Coleman**, reported that files on his workstation had been renamed with an unfamiliar extension — a classic ransomware symptom. As the incident responder, the objective was to load the provided **Redline** forensic collection for the host and reconstruct the attack from the ground up: identify the affected user and system, find the malicious binary and its delivery path, determine the scope of file encryption, locate attacker-left artifacts (ransom note, wallpaper change, decoy folders), examine the victim's failed recovery attempt, and finally pivot to VirusTotal to attribute the malware family.

At a high level, the attack chain is a classic **user-executed ransomware** scenario: a binary disguised as a legitimate tool (`WinRAR2021.exe`) was downloaded over HTTP and run by the user, encrypting local files, dropping a ransom note, changing the desktop wallpaper, and leaving decoy/tracking files — after which the user attempted (and failed) to use a downloaded "decryptor" and a ransomware-operator-provided free-decryption URL.

## 2. Tools Used

| Tool | Purpose |
|---|---|
| Redline | Host memory/disk forensic triage — user accounts, file system, timeline, browser history, download history |
| VirusTotal | Multi-engine hash lookup to attribute the malware family/name |
| Windows forensic artifacts (via Redline) | Source data: NTUSER.DAT, timeline events, file metadata (MD5, size, timestamps, attributes) |

## 3. Step-by-Step Walkthrough

### 3.1 Initial Triage — Identifying the User and Host

I opened the **Users** artifact under System Information in Redline and reviewed the local account list. One account, **John Coleman**, stood out: it had a recent login timestamp and membership in both the *Administrators* and *Users* groups, making it the relevant employee account for this case.

[!revilcrop](screenshoots/revil1.png)
> *Shows the Redline System Information panel with the compromised host's machine name and OS build details.*

I then reviewed **System Information → Operating System Information**, which confirmed the workstation was running an outdated, unsupported OS build — a relevant fact for the risk assessment later in this report.

**Findings**

| Question | Answer |
|---|---|
| Compromised employee's full name | John Coleman |
| Operating system of the compromised host | Windows 7 Home Premium 7601 Service Pack 1 |

### 3.2 Identifying the Malicious Executable and Its Delivery

Next, I drilled into the **File System** artifact and expanded John Coleman's user profile. Inside the **Downloads** folder sat an executable, `WinRAR2021.exe`, dated in the same timeframe as the reported incident — an immediate red flag, since a legitimate WinRAR installer would not normally be dropped directly as a standalone executable in a user's Downloads folder without an accompanying installer wizard footprint.

> [!revilcrop](screenshoots/revil2.png)
> *Shows the Redline File System view highlighting `WinRAR2021.exe` inside `C:\Users\John Coleman\Downloads`.*

To trace the delivery vector, I pivoted to the **File Download History** artifact. This showed the binary was pulled from an internal host over plain HTTP, and — importantly — saved to the exact Downloads path already identified, confirming the chain of custody between the download event and the file on disk.

I then returned to the **File System** view and selected the binary directly to pull its file metadata (MD5 hash and size), which are the two most portable IOCs for this artifact.

> [!revilcrop](screenshoots/revil3.png)
> *Shows the Redline file metadata panel with the MD5 hash and 164 KB size for `WinRAR2021.exe`.*

> [!revilcrop](screenshoots/revil5.png)
> *Shows the Redline File Download History entry recording the internal HTTP source URL for the binary.*

**Findings**

| Question | Answer |
|---|---|
| Name of the malicious executable the user opened | `WinRAR2021.exe` |
| Full URL used to download the malicious binary | `hxxp[://]192[.]168[.]75[.]129:4748/Documents/WinRAR2021[.]exe` *(defanged)* |
| MD5 hash of the binary | `890a5f200dfff23165df9e1b088e58f` |
| Size of the binary | 164 KB |

### 3.3 Ransomware Impact — File Encryption and Attacker Artifacts

With the executable confirmed, I reviewed the **File System** artifact again, this time looking at file naming patterns across John Coleman's Desktop. Multiple files (`CreditCardInfo.txt`, `passwords.txt`, `sdl-redline.zip`, etc.) had all been appended with the same unfamiliar suffix, `.t48s39la` — the signature behavior of a ransomware encryption routine renaming files post-encryption.

To scope the blast radius, I switched to the **Timeline** view, filtered to only the `Modified` and `Changed` file-event types (per the room's hint), and searched for the extension string. This returned **48 matches**, giving a concrete count of files touched by the encryption routine.

Still inside the Timeline, I searched for `.bmp` files around the same activity window and found a bitmap dropped into the user's `AppData\Local\Temp` folder — consistent with ransomware families that change the desktop wallpaper to display a ransom message.

**Findings**

| Question | Answer |
|---|---|
| Extension the user's files were renamed to | `.t48s39la` |
| Number of files renamed/changed to that extension | 48 |
| Full path to the wallpaper changed by the attacker | `C:\Users\John Coleman\AppData\Local\Temp\hk8.bmp` |

### 3.4 Ransom Note and Decoy/Tracking Artifacts

Continuing in the Timeline view, I filtered activity to John Coleman's Desktop and searched for `.txt` files, since ransom notes are near-universally dropped as plain text. This surfaced `t48s39la-readme.txt` — a filename that mirrors the encryption extension, confirming it as the attacker's ransom note.

I also noticed a suspicious folder, `Links for United States`, created under the user's `Favorites` directory — not a default Windows folder. Filtering the Timeline to that exact path revealed a dropped file, `GobiernoUSA.gov.url.t48s39la`, which appears to be either a decoy/lure artifact or leftover ransomware tooling (some ransomware families drop `.url` shortcut files as part of their persistence or "proof of activity" routine).

Finally, reviewing the Desktop file listing again, I spotted a hidden, 0-byte file — `d60dff40.lock` — flagged with `Hidden` and `Archive` attributes. Zero-byte `.lock` files like this are commonly used by ransomware as a file-locking/mutex marker during the encryption pass.

**Findings**

| Question | Answer |
|---|---|
| Name of the ransom note left on the Desktop | `t48s39la-readme.txt` |
| File left inside `Favorites\Links for United States` | `GobiernoUSA.gov.url.t48s39la` |
| Hidden 0-byte file created on the Desktop | `d60dff40.lock` |

### 3.5 The Victim's Failed Recovery Attempt

The room's narrative indicated the user tried to self-recover before escalating. Two artifacts confirm this:

First, I found a suspiciously named executable on the Desktop, `d.e.c.r.y.p.tor.exe` — the letter-spaced filename is a common social-engineering/evasion trick to slip past naive string-matching filters (and, in some cases, unsigned/typosquatted "decryptor" scams distributed by the ransomware operators themselves as a secondary monetization or credential-harvesting vector). I pulled its MD5 from the File System metadata.

> [!revilcrop](screenshoots/revil6.png)
> *Shows the Redline File System metadata panel with the MD5 hash for `d.e.c.r.y.p.tor.exe`.*

Second, per the ransom note's instructions, many REvil/Sodinokibi ransom notes include a "free decryption" URL to prove the attacker holds working keys. I filtered **Browser URL History** for HTTP entries and found the user had visited a `decryptor.top` URL with a unique per-victim path parameter — consistent with REvil's known "test decryption" portal pattern.

**Findings**

| Question | Answer |
|---|---|
| MD5 hash of the downloaded decryptor | `f617af8c0d276682fdf528bb3e72560b` |
| Free-decryption URL visited by the user | `http://decryptor.top/644E7C8EFA02FBB7` |

### 3.6 Malware Attribution via VirusTotal

As the final step, I took the MD5 hash of `WinRAR2021.exe` and queried it directly on **VirusTotal** — this was a step I added on top of the base solution to independently verify the family attribution rather than taking it on faith. The sample was flagged as malicious by the large majority of scanning engines, and the aggregated family/threat labels pointed consistently to the same ransomware family under three different naming conventions.

> [!revilcrop](screenshoots/revil4.png)
> *Shows the VirusTotal detection summary for the `WinRAR2021.exe` MD5, with the `sodin` / `sodinokibi` family labels and the "REvil" popular threat label.*

**Findings**

| Question | Answer |
|---|---|
| Three names associated with the malware (alphabetical) | REvil, Sodin, Sodinokibi |

## 4. Attack Chain Summary

```
 User browses to internal HTTP host
              ▼
 Downloads "WinRAR2021.exe" (masquerading as legitimate software)
              ▼
 User executes the binary from Downloads
              ▼
 Ransomware (REvil/Sodinokibi) encrypts local files → .t48s39la extension
              ▼
 Ransom note dropped ("t48s39la-readme.txt") + desktop wallpaper changed (hk8.bmp)
              ▼
 Decoy/tracking artifacts dropped (Favorites\Links for United States, 0-byte .lock marker)
              ▼
 Victim attempts self-recovery:
   ├─ Downloads fake/unofficial "decryptor" (d.e.c.r.y.p.tor.exe) — fails
   └─ Visits attacker-provided "free decryption" proof-of-key URL — fails
              ▼
 Incident escalated → forensic triage via Redline
```

## 5. MITRE ATT&CK Mapping

| Step / Finding | Tactic | Technique ID | Technique Name | Justification |
|---|---|---|---|---|
| Download of `WinRAR2021.exe` from internal HTTP host | Resource Development / Initial Access | T1608 / T1204.002 | Stage Capabilities / User Execution: Malicious File | The payload was staged on an internal host and required the user to manually run the downloaded file |
| User double-clicks `WinRAR2021.exe` | Execution | T1204.002 | User Execution: Malicious File | Ransomware execution required manual user interaction, confirmed via file access/execution timestamps |
| Binary named after legitimate software (WinRAR) | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Filename impersonates a trusted, widely-used utility to lower user suspicion |
| Files renamed with `.t48s39la` extension | Impact | T1486 | Data Encrypted for Impact | Core ransomware behavior — 48 files confirmed encrypted/renamed via Timeline analysis |
| Ransom note `t48s39la-readme.txt` dropped | Impact | T1491.001 | Defacement: Internal Defacement (adjacent) / Ransom Note Delivery | Ransom note left directly on Desktop as the extortion demand delivery mechanism |
| Desktop wallpaper changed to `hk8.bmp` | Impact | T1491.001 | Internal Defacement | Wallpaper replacement is a common REvil/Sodinokibi technique to visually announce the compromise to the victim |
| Hidden 0-byte `.lock` marker file | Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | File was explicitly flagged with the Hidden attribute to reduce casual discovery |
| `.url` decoy file dropped in `Favorites\Links for United States` | Defense Evasion / Collection *(supplementary)* | T1005 *(supplementary)* | Data from Local System *(supplementary)* | ⚠️ *Supplementary analyst annotation* — the exact purpose of this artifact wasn't confirmed by the room; validate against ATT&CK Navigator before formal use |
| User visits `decryptor.top` proof-of-decryption URL | Command and Control *(supplementary)* | T1071.001 *(supplementary)* | Web Protocols *(supplementary)* | ⚠️ *Supplementary annotation* — represents attacker-victim communication over HTTP consistent with REvil's affiliate negotiation portals, not explicitly confirmed as C2 by the room itself |
| Hash-based attribution to REvil/Sodinokibi via VirusTotal | N/A (post-incident analysis) | N/A | N/A | Analytical step, not an adversary technique — included for completeness of the investigative narrative |

## 6. OWASP Applicability

Not applicable. This engagement is a **host-based DFIR/malware-analysis scenario** — there is no web application, injection point, or authentication mechanism in scope; the entire attack chain occurs through a locally downloaded and executed ransomware binary. The OWASP Top 10 framework does not map meaningfully onto this case. A more appropriate reference framework here would be **NIST SP 800-61 (Computer Security Incident Handling Guide)** or a ransomware-specific playbook such as **CISA's #StopRansomware Guide**, both of which address the identification, containment, and recovery phases actually exercised in this room.

## 7. Indicators of Compromise (IOC) Summary

| Type | Indicator |
|---|---|
| File name | `WinRAR2021.exe` |
| File hash (MD5) | `890a5f200dfff23165df9e1b088e58f` |
| File size | 164 KB |
| Delivery URL | `hxxp[://]192[.]168[.]75[.]129:4748/Documents/WinRAR2021[.]exe` *(defanged)* |
| File extension (post-encryption) | `.t48s39la` |
| Ransom note file name | `t48s39la-readme.txt` |
| Wallpaper artifact | `C:\Users\John Coleman\AppData\Local\Temp\hk8.bmp` |
| Decoy file | `GobiernoUSA.gov.url.t48s39la` (in `Favorites\Links for United States`) |
| Hidden marker file | `d60dff40.lock` (0 bytes) |
| Fake decryptor file name | `d.e.c.r.y.p.tor.exe` |
| Fake decryptor hash (MD5) | `f617af8c0d276682fdf528bb3e72560b` |
| Attacker "free decryption" URL | `http://decryptor.top/644E7C8EFA02FBB7` |
| Malware family / threat names | REvil, Sodin, Sodinokibi |
| Affected host | `WIN-HKXQB6M7FTQ` (Windows 7 Home Premium 7601 SP1) |
| Affected user account | John Coleman |

## 8. Key Findings & Risk Summary

| Weakness | Impact | Recommendation |
|---|---|---|
| End-of-life OS (Windows 7 SP1, unsupported since Jan 2020) | No vendor security patches; increases exploitability and reduces effectiveness of modern EDR | Upgrade all endpoints to a supported, actively patched OS |
| User was a local Administrator | Ransomware executed with elevated privileges, maximizing encryption scope and system-level persistence | Enforce least-privilege — standard users should not run with local admin rights day-to-day |
| Executable downloaded and run directly from a browser download without verification | No opportunity for signature/reputation checks before execution | Deploy application allowlisting (e.g., AppLocker/WDAC) and block execution from Downloads/Temp paths |
| Plain HTTP used for binary delivery, even from an "internal" host | No integrity verification of the downloaded file; trivially spoofable/MITM-able | Enforce HTTPS-only internal file distribution and code-signing verification |
| No apparent EDR/AV detection of the ransomware prior to full encryption | Attack ran to completion undetected until user-reported symptoms | Deploy behavior-based EDR with ransomware-specific canary/rollback protections |
| User attempted to use an unofficial "decryptor" found online | Risk of secondary compromise (the fake decryptor itself could be malicious) | Train staff to never download recovery tools independently — escalate to IR/security team immediately |

## 9. Key Takeaways

- Redline's **Timeline** view (filtered by specific field types like `Modified`/`Changed`) is far more efficient for scoping mass file-renaming events than manually browsing the File System tree file-by-file.
- Ransomware artifacts follow a predictable pattern — renamed extension, ransom note, wallpaper change, and often decoy/marker files — and searching for each pattern type systematically (rather than randomly browsing) speeds up triage significantly.
- File metadata (MD5 + size) captured directly from the forensic tool is sufficient to pivot immediately into threat-intel platforms like VirusTotal for family attribution, without needing the raw binary.
- Filenames with unusual character-spacing (e.g., `d.e.c.r.y.p.tor.exe`) are a red flag worth investigating — attackers use this as a lightweight evasion technique against naive string/YARA matching.
- Victims attempting self-service recovery (fake decryptors, attacker-provided "proof" URLs) can inadvertently introduce secondary risk — this is a recurring pattern worth flagging in user security-awareness training.
- Independently verifying a hash against VirusTotal — rather than trusting a reference solution's attribution — is good practice and catches the rare case of stale or incorrect community labels.

## 10. References

- TryHackMe — "REvil Corp" room
- MITRE ATT&CK Framework — https://attack.mitre.org/
- CISA #StopRansomware Guide — https://www.cisa.gov/stopransomware
- NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- VirusTotal — https://www.virustotal.com/
- FireEye/Mandiant Redline — https://fireeye.market/apps/211364
