# Friday Overtime | CTI Investigation 

**Category:** Cyber Threat Intelligence (CTI) / Malware Analysis
**Platform:** TryHackMe
**Difficulty:** Medium
**Skills Demonstrated:** Threat Intel Triage, File Hashing, VirusTotal / Talos Pivoting, OSINT, CyberChef (Defanging), C2 Infrastructure Analysis, MITRE ATT&CK Mapping


## 1. Scenario Overview

An analyst receives an email from a colleague, **Oliver Bennett**, containing a password-protected archive (`samples.zip`) with malware samples for triage. The goal of the room is to:

1. Identify the sender and initial artifact.
2. Extract and hash a malicious DLL sample.
3. Identify the malware family/framework the DLL belongs to.
4. Map the observed technique to **MITRE ATT&CK**.
5. Pivot through OSINT and **VirusTotal** to uncover historical command-and-control (C2) infrastructure.
6. Use **CyberChef** to safely defang IOCs (URLs/IPs) for reporting.
7. Identify a related piece of Android spyware hosted on the same infrastructure.

This simulates a realistic **CTI triage → malware family attribution → infrastructure pivoting** workflow that a SOC/Threat Intel analyst would perform on a real incident.

---

## 2. Tools Used

| Tool | Purpose |
|---|---|
| Terminal (`sha1sum`, `unzip`) | File extraction and hashing |
| VirusTotal | Malware family attribution, IOC pivoting, relations graph |
| Cisco Talos Intelligence | Cross-verification of file reputation |
| CyberChef | Defanging URLs and IP addresses |
| Web/OSINT (ESET WeLiveSecurity) | Threat actor and campaign research |

---

## 3. Step-by-Step Walkthrough

### Task 1 — Who shared the malware samples?

The initial artifact (email/dashboard) discloses the sender's identity in the message metadata/body.

**Finding:** The malware samples were shared by **Oliver Bennett**.

---

### Task 2 — SHA1 hash of `pRsm.dll` inside `samples.zip`

**Steps:**
1. Download the attached `samples.zip`.
2. Extract it using the password supplied in the original email (`Panda321!`).
3. Compute the SHA1 hash of the extracted DLL:
   ```bash
   sha1sum pRsm.dll
   ```

**Finding (SHA1):**
```
9d1ecbbe8637fed0d89fca1af35ea821277ad2e8
```

---

### Task 3 — Which malware framework utilizes these DLLs as add-on modules?

**Steps:**
1. Submit the SHA1 hash to **VirusTotal** and/or **Cisco Talos** for reputation and classification data.
2. Review vendor tags and community comments describing the DLL's role as a plugin/module.

**Finding:** The DLL belongs to the **MgBot** malware framework, a modular malware toolkit associated with the **Evasive Panda** APT group.

---

### Task 4 — Which MITRE ATT&CK Technique is linked to using `pRsm.dll` in this framework?

**Steps:**
1. Perform OSINT research on "MgBot" to locate public threat intelligence reporting.
2. Locate the relevant article: *"Evasive Panda APT group delivers malware via updates for popular Chinese software"* (ESET Research, WeLiveSecurity).
3. Cross-reference the plugin's described functionality (removable/USB media propagation) against the MITRE ATT&CK matrix.

**Finding:** The `pRsm.dll` module corresponds to MITRE ATT&CK technique:

**`T1123` — Audio Capture**

This aligns with ESET's reporting on MgBot's modular plugin design, where individual DLLs provide discrete collection capabilities (e.g., audio recording) that are loaded on demand by the core implant.

*(See Section 4 — MITRE ATT&CK Mapping — for the full technique breakdown.)*

---

### Task 5 — CyberChef defanged URL of the malicious download location first seen on 2020-11-02

**Steps:**
1. Locate the IOC table/timeline in the ESET article, filtering for the date **2020-11-02**.
2. Copy the malicious download URL.
3. Open **CyberChef**, load the **"Defang URL"** recipe, and paste the URL to sanitize it for safe reporting.

**Finding (Defanged URL):**
```
hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe
```

---

### Task 6 — CyberChef defanged IP address of the C2 server first detected on 2020-09-14

**Steps:**
1. Search the ESET article/IOC list for the date **2020-09-14**.
2. Identify the associated C2 IP address from the network session data.
3. Apply CyberChef's **"Defang IP Addresses"** recipe.

**Finding (Defanged IP):**
```
122[.]10[.]90[.]12
```

---

### Task 7 — SHA1 hash of the SpyAgent-family Android spyware hosted on the same IP (Nov 16, 2022)

**Steps:**
1. Pivot on the C2 IP (`122.10.90.12`) inside **VirusTotal**.
2. Navigate to the **"Relations"** tab to view historically resolved/communicating files.
3. Filter for Android-targeting samples dated **2022-11-16** and identify the one attributed to the **SpyAgent** spyware family.
4. Open the file's **"Details"** tab to retrieve its SHA1 hash.

**Finding (SHA1):**
```
1c1fe906e822012f6235fcc53f601d006d15d7be
```

---

## 4. MITRE ATT&CK Mapping

This section consolidates the adversary behaviors identified throughout the investigation into a structured ATT&CK reference, useful for detection engineering and reporting.

| Task / Finding | Tactic | Technique ID | Technique Name | Justification |
|---|---|---|---|---|
| MgBot DLL module (`pRsm.dll`) capability | Collection | **T1123** | Audio Capture | The `pRsm.dll` add-on module provides MgBot's core implant with audio-recording/collection capability, consistent with ESET's description of MgBot's modular plugin architecture. This is the room's validated answer. |
| Malicious downloader URL (update.browser.qq.com) | Command and Control / Resource Development | **T1583.001 / T1584.001** | Acquire Infrastructure: Domains / Compromise Infrastructure: Domains | Threat actor abused a legitimate-looking software update channel to host and distribute a malicious payload. |
| Trojanized software update delivery | Initial Access | **T1195.002** | Supply Chain Compromise: Compromise Software Supply Chain | Evasive Panda distributed MgBot via poisoned update mechanisms for popular Chinese software (per ESET reporting). |
| C2 communication over identified IP | Command and Control | **T1071** | Application Layer Protocol | Malware beacons to a hardcoded C2 IP for command retrieval and data exfiltration. |
| Modular plugin architecture (MgBot) | Persistence / Execution | **T1129** | Shared Modules | MgBot's design relies on loadable DLL "add-on" modules (e.g., `pRsm.dll`) to extend core functionality. |
| SpyAgent Android spyware (same C2 infra) | Collection | **T1429 / T1430** | Audio Capture (Android) / Location Tracking (Android) | SpyAgent-family spyware is known to harvest device audio, SMS, and location data from infected Android hosts. |

> **Note:** ATT&CK technique justifications beyond the room's explicitly validated answer (T1123) are supplementary analyst annotations based on publicly available reporting on Evasive Panda/MgBot and SpyAgent, intended to add depth to the CTI mapping for portfolio purposes. They should be validated against the live ATT&CK Navigator/matrix before use in a formal engagement report.

---

## 5. OWASP Applicability

This engagement is a **malware/threat-intelligence analysis exercise**, not a web application security assessment. As such, the **OWASP Top 10** (which addresses web application vulnerability classes such as Injection, Broken Access Control, etc.) is **not applicable** to this room's scope and has intentionally been omitted from this report.

---

## 6. Indicators of Compromise (IOC) Summary

| Type | Indicator (Defanged) |
|---|---|
| File Hash (SHA1) — MgBot DLL | `9d1ecbbe8637fed0d89fca1af35ea821277ad2e8` |
| File Hash (SHA1) — SpyAgent Android Sample | `1c1fe906e822012f6235fcc53f601d006d15d7be` |
| Malicious URL | `hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe` |
| C2 IP Address | `122[.]10[.]90[.]12` |
| Malware Family | MgBot (Evasive Panda / DaggerFly APT) |
| Related Family | SpyAgent (Android spyware) |

---

## 7. Key Takeaways

- Malware family attribution can often be achieved quickly by cross-referencing file hashes against **VirusTotal** and **Talos** community intelligence rather than performing full static/dynamic analysis from scratch.
- Public threat intelligence reporting (e.g., ESET, Talos, Mandiant) is a critical OSINT resource for confirming ATT&CK technique mappings and historical IOC timelines.
- **VirusTotal's "Relations" graph** is a powerful pivoting tool for uncovering additional malware families sharing the same C2 infrastructure — a technique broadly applicable to real-world infrastructure hunting.
- Defanging IOCs (via **CyberChef**) is a standard and necessary practice before including indicators in any shared threat report, preventing accidental execution/click-through of live malicious artifacts.

---

## 8. References

- ESET Research, *"Evasive Panda APT group delivers malware via updates for popular Chinese software,"* WeLiveSecurity.
- TryHackMe — *Friday Overtime* room.
- MITRE ATT&CK® Framework — [attack.mitre.org](https://attack.mitre.org)
- VirusTotal — [virustotal.com](https://www.virustotal.com)
- CyberChef — [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/)
