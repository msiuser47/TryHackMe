# Investigating Windows 2.0 (Windows Host Compromise & Malware Forensics)

**Category:** Defensive Security / Digital Forensics & Incident Response (DFIR)
**Access Method:** RDP (`xfreerdp`)
**Tooling:** Windows Task Scheduler, Registry Editor, Process Monitor (Procmon), Process Explorer, Process Hacker 2, Loki (IOC/YARA scanner), PowerShell (WMI cmdlets), Sysinternals `strings`, YARA
**Skills demonstrated:** Scheduled task and registry persistence analysis, WMI event subscription (filter/consumer/binding) forensics, process-tree and parent/child analysis, credential-dumping tool identification (Mimikatz), masquerading binary detection, YARA rule authoring to close a detection gap

---

## 1. Scenario

A Windows host was suspected of compromise, with indicators pointing toward credential-dumping activity, scheduled-task-based persistence, and a WMI-based backdoor mechanism. The objective was to reconstruct the full compromise from host artifacts alone — Task Scheduler entries, the registry, live process behavior, and the output of the Loki IOC scanner — culminating in writing a custom YARA rule to detect a malicious binary that the existing tooling had missed entirely.

## 2. Objectives

1. Identify the persistence mechanism(s) used to maintain access on the host.
2. Identify the credential-dumping tool and its exact invocation.
3. Identify the disabled/sabotaged analysis tool and understand how it was being blocked.
4. Reconstruct the WMI event subscription chain (filter → consumer → binding) responsible for the sabotage.
5. Attribute the malicious script to a known, publicly documented attack tool.
6. Correlate live process behavior (Procmon/Process Explorer) with the artifacts found in the registry and WMI.
7. Run Loki to identify additional malicious binaries and dropped tools on the host.
8. Identify a detection gap in Loki's coverage and close it by authoring a custom YARA rule.

## 3. Investigative Methodology

The investigation was carried out in six connected phases, each building on artifacts surfaced in the previous one rather than treating each finding in isolation:

1. **Initial triage** — Task Scheduler and registry review to identify the persistence mechanism.
2. **Analysis environment setup** — identifying which tools were sabotaged and configuring the environment (PATH, file extension visibility) to work around it.
3. **Loki log and WMI analysis** — using Loki's own findings plus PowerShell WMI cmdlets to reconstruct the backdoor's full activation chain.
4. **Process and parent-process tracing** — using Procmon to confirm which processes were behaving maliciously and how.
5. **Deep binary/artifact analysis** — running Loki against the full host and reviewing each flagged binary in detail.
6. **Closing the detection gap** — writing a custom YARA rule for the one binary Loki failed to flag.

## 4. Phase 1 — Initial Triage: Task Scheduler and Registry

Investigation began in **Computer Management → Task Scheduler**, reviewing all scheduled tasks for anything inconsistent with normal system administration. A suspicious task named **"Game Over"** stood out immediately. Reviewing its **Actions** tab revealed that it executed a binary from `C:\TMP` with parameters consistent with **Mimikatz**, specifically a `sekurlsa::LogonPasswords` invocation used to dump credentials from LSASS memory and redirect the output to a file:

```
C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt
```

To determine whether this command had additional persistence beyond the scheduled task itself, **Registry Editor** was opened and searched (`Ctrl+F`) using a distinctive substring from the command. This located a second, independent persistence mechanism in the registry: a logon script configured under the current user's environment key, set to execute the same Mimikatz command automatically at every logon.

**Registry key identified:** `HKCU\Environment\UserInitMprLogonScript`

This confirmed **two parallel, redundant persistence mechanisms** for the same malicious credential-dumping command — a scheduled task and a logon-script registry key — a pattern consistent with an attacker deliberately ensuring survivability even if one mechanism were discovered and removed.

## 5. Phase 2 — Analysis Environment Setup and Tool Sabotage

Before deeper analysis, the Sysinternals Suite (available in the desktop **Tools** folder) was reviewed to identify which analysis utilities were still functional. **Process Monitor (Procmon)** launched normally, but **Process Explorer (`procexp64.exe`)** closed immediately upon launch — a clear sign that something on the host was actively terminating this specific tool to prevent it from being used for investigation.

**Analysis tool confirmed as sabotaged:** `procexp64.exe`

Two environment adjustments were made to streamline the remainder of the investigation:

- The Sysinternals Suite path was added to the system `PATH` environment variable, allowing its tools (e.g., `strings.exe`) to be invoked directly from any command-line location without needing the full path each time.
- **File Explorer** was configured to disable "Hide extensions for known file types," ensuring that any disguised or double-extension files would be visible during manual review.

## 6. Phase 3 — Loki and WMI Analysis: Reconstructing the Backdoor Chain

With `procexp64.exe` confirmed as the sabotaged tool, attention turned to **why** it was being terminated. Loki's most recent log output was reviewed, searching for WMI Query Language (WQL) references (`SELECT *`) to identify any WMI-based event trigger tied to process launches.

**WQL query identified:**
```
SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'
```

This confirmed the mechanism: a **WMI Event Filter** was configured to fire specifically whenever `procexp64.exe` attempted to start — explaining the tool's instant termination and revealing a textbook **WMI event subscription persistence/anti-forensics technique**.

Following this lead into `C:\TMP` located the script responsible for the filter's action, opened for review in PowerShell ISE. Although saved with a `.ps1`-style naming pattern, the actual code inside was not PowerShell — it was **VBScript**, embedded and self-referenced by a variable of the same name within the file, a deliberate obfuscation choice to disguise the true scripting engine at a glance.

**Script language confirmed:** `VBScript`

Reviewing Loki's log further for the event immediately following the WQL match revealed a second, related script reference used as a fallback mechanism, triggered if the primary script failed to execute:

**Secondary script name:** `LaunchBeaconingBackdoor`

Reading the comments embedded within the script disclosed the name of the software company whose boilerplate/sample code appears to have been reused or referenced in building this backdoor:

**Software company referenced:** `Motobit Software`

**Associated websites (from script comments):** `http://www.motobit.com`, `http://motobit.cz`

Searching online using the secondary script's name (`LaunchBeaconingBackdoor`) together with one of these referenced websites surfaced a publicly documented, well-known WMI-based backdoor proof-of-concept matching this exact behavior:

**Attack script identified:** `WMIBackdoor.ps1`

**Location on the local machine:** `C:\TMP`

This single pivot — searching a distinctive internal script name plus an incidentally-referenced third-party domain — was what tied the host's custom-looking artifacts back to a known, published attack tool rather than a fully bespoke implant.

## 7. Phase 4 — Process Tracing: Confirming Live Malicious Behavior

With the WMI/registry persistence mechanisms mapped, the investigation shifted to confirming what these mechanisms actually executed in practice. Reviewing active scheduled tasks alongside the earlier "Game Over" task revealed a second task, disguised under an update-related name and running on a five-minute interval, alongside "Game Over" itself running every two minutes — both launching the same two processes.

**Short-lived processes identified:** `mim.exe`, `powershell.exe`

Using **Procmon**, a filter was applied for these two process names specifically, confirming they spawned and exited repeatedly every few minutes — consistent with brief, low-visibility beaconing or command-execution bursts designed to minimize their footprint and avoid drawing attention from processes that stay resident.

Reviewing the process properties for `mim.exe` in Procmon identified its parent process by PID, which was then cross-referenced against the running process list:

**Parent process identified:** `svchost.exe`

A legitimate system process spawning an unexpected, credential-dumping child process is a strong indicator of either process injection into `svchost.exe` or a scheduled task deliberately configured to launch under a service host context to blend in with normal system activity.

Inspecting the very first recorded event for the first occurrence of these processes in Procmon confirmed the expected starting point of the process lifecycle:

**First operation recorded:** `Process Start`

The **Event** tab for this first occurrence displayed four key data points, each copied into the investigation notes as the baseline reconstruction of what executed and in what context:

**Fields displayed:** `Parent PID`, `Command Line`, `Current Directory`, `Environment`

Reviewing disk-write/rename operations tied to these same processes in Procmon found no distinct process performing unusual disk I/O in this filtered view.

**Result:** `No process` — noted as a signal that this stage of the activity likely operated in memory or via non-disk channels (e.g., named pipes, network) rather than leaving an obvious file-write trail at this specific point.

## 8. Phase 5 — Deep Binary and Artifact Analysis via Loki

**Process Hacker 2** was used as a substitute for the disabled Process Explorer, providing an equivalent Disk tab for monitoring active file operations, and confirming the presence of unnamed ("No process") entries — itself a notable anti-forensics indicator warranting further scrutiny.

Loki's log was reviewed from its initialization block forward to confirm which detection module ran immediately after startup:

**Module after Init:** `WMIScan` — consistent with the WMI-based persistence already identified, confirming Loki's own scan logic was purpose-built to catch exactly this class of technique.

Continuing through Loki's sequential warning output:

- **2nd warning — eventFilter name:** `ProcessStartTrigger`
- **4th warning — class name:** `__FilterToConsumerBinding` (the WMI class that binds an event filter to its consumer, i.e., the mechanism that actually causes the malicious script to execute when the filter condition is met)

Loki's binary-level detections were then reviewed individually:

| Finding | Detail |
|---|---|
| Binary matched by file header (`FIRST_BYTES` = `4D5A9000030000000400000...`) | `nbtscan.exe` |
| Reason 1 description for that alert | `Known Bad / Dual use classics` |
| Binary flagged as **APT Cloaked** | `p.exe` |
| Match strings for that flag | `psexesvc.exe`, `Sysinternals PsExec` — indicating `p.exe` was disguised to imitate PsExec's service component |
| Binary associated with `somethingwindows.dmp` in `C:\TMP` | `schtasks-backdoor.ps1` |
| Encrypted, Trojan-like binary | `xCmd.exe` |
| Binary masquerading as a core Windows process | `C:\Users\Public\svchost.exe` |
| Legitimate path for the real `svchost.exe` | `C:\Windows\System32` |
| Reason 1 description for the masquerading binary | `Stuff running where it normally shouldn't` |
| File in the same folder labeled as a hacktool | `en-US.js` |
| Matched YARA rule | `CACTUSTORCH` |

The **`p.exe` / `psexesvc.exe`** finding is particularly notable: an attacker-controlled binary was deliberately named and internally structured to resemble the legitimate PsExec service component, a technique intended to let malicious lateral-movement or remote-execution activity blend into logs and process lists that administrators associate with routine PsExec usage.

The **`C:\Users\Public\svchost.exe`** finding follows the same masquerading logic at the filename level: reusing the name of a critical, universally-trusted Windows process while placing it in a world-writable, non-system location — a location the legitimate `svchost.exe` would never occupy.

**CACTUSTORCH** is a publicly known payload-generation/execution framework commonly used to launch shellcode via legitimate scripting engines (e.g., JScript/VBScript), which aligns directly with the VBScript-based WMI backdoor identified earlier in the investigation.

## 9. Phase 6 — Closing the Detection Gap: Custom YARA Rule for `mim.exe`

Despite the extensive set of detections above, **`mim.exe`** — the Mimikatz-based credential dumper identified as far back as Phase 1 — **did not appear anywhere in Loki's output**, representing a clear detection gap for one of the most consequential tools on the host.

To close this gap, `mim.exe` (located at `C:\TMP`) was analyzed directly using the Sysinternals `strings` utility, made globally accessible thanks to the earlier `PATH` configuration:

```powershell
strings.exe C:\TMP\mim.exe | findstr <pattern>
```

Output was filtered using `findstr` (which supports basic regular expressions on Windows) to identify distinctive, reliable string markers unique to this binary rather than common, generic substrings that would produce false positives elsewhere on the host.

**Three strings identified to complete the detection rule:**
- `mk.ps1`
- `mk.exe`
- `v2.0.50727` (a .NET Framework runtime version string embedded in the binary)

These three strings were added to the incomplete `test.yar` rule file located in the **Tools\Yara** folder on the desktop. Re-running Loki (or a direct YARA scan) against the host with the completed rule successfully flagged `mim.exe` for the first time, closing the detection gap and completing the investigation.

## 10. Findings Summary

| # | Question Area | Finding |
|---|---|---|
| 1 | Persistence — registry key | `HKCU\Environment\UserInitMprLogonScript` |
| 2 | Sabotaged analysis tool | `procexp64.exe` |
| 3 | WQL query driving the sabotage | `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'` |
| 4 | Script language | VBScript |
| 5 | Fallback/secondary script name | `LaunchBeaconingBackdoor` |
| 6 | Software company referenced in script | Motobit Software |
| 7 | Associated websites | `http://www.motobit.com`, `http://motobit.cz` |
| 8 | Publicly identified attack script | `WMIBackdoor.ps1` |
| 9 | Script location on host | `C:\TMP` |
| 10 | Short-lived processes | `mim.exe`, `powershell.exe` |
| 11 | Parent process | `svchost.exe` |
| 12 | First recorded operation | Process Start |
| 13 | Event tab fields | Parent PID, Command Line, Current Directory, Environment |
| 14 | Unusual disk-writing process | No process |
| 15 | Loki module after Init | WMIScan |
| 16 | 2nd warning — eventFilter name | ProcessStartTrigger |
| 17 | 4th warning — class name | `__FilterToConsumerBinding` |
| 18 | Binary matched by file header | `nbtscan.exe` |
| 19 | Reason 1 for that alert | Known Bad / Dual use classics |
| 20 | APT Cloaked binary | `p.exe` |
| 21 | Match strings for APT Cloaked binary | `psexesvc.exe`, Sysinternals PsExec |
| 22 | Binary tied to `somethingwindows.dmp` | `schtasks-backdoor.ps1` |
| 23 | Encrypted Trojan-like binary | `xCmd.exe` |
| 24 | Masquerading binary full path | `C:\Users\Public\svchost.exe` |
| 25 | Legitimate path for real binary | `C:\Windows\System32` |
| 26 | Reason 1 for masquerading binary | Stuff running where it normally shouldn't |
| 27 | Hacktool-labeled file in same folder | `en-US.js` |
| 28 | Matched YARA rule | CACTUSTORCH |
| 29 | Binary missed by Loki | `mim.exe` |
| 30 | Strings added to close the detection gap | `mk.ps1`, `mk.exe`, `v2.0.50727` |

## 11. Attack Chain Summary

```
Registry logon script + Scheduled task "Game Over" (redundant persistence)
      │
      ▼
mim.exe (Mimikatz) → sekurlsa::LogonPasswords → credentials dumped to C:\TMP\o.txt
      │
      ▼
WMI Event Filter (Win32_ProcessStartTrace on procexp64.exe)
      │
      ▼
__FilterToConsumerBinding → VBScript consumer executes → procexp64.exe killed on launch
      │
      ▼
Fallback consumer: LaunchBeaconingBackdoor → WMIBackdoor.ps1 (C:\TMP)
      │
      ▼
svchost.exe (parent) → mim.exe / powershell.exe spawned every 2–5 minutes (beaconing pattern)
      │
      ▼
Loki scan → multiple additional artifacts identified:
   nbtscan.exe, p.exe (PsExec-masquerading), schtasks-backdoor.ps1,
   xCmd.exe (encrypted trojan), C:\Users\Public\svchost.exe (masquerade),
   en-US.js (CACTUSTORCH-matched hacktool)
      │
      ▼
Detection gap identified: mim.exe not flagged by Loki
      │
      ▼
Manual strings analysis → custom YARA rule completed → gap closed
```

## 12. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Persistence | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | "Game Over" and the disguised update task launching `mim.exe`/`powershell.exe` |
| Persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) *(closest fit — logon-triggered script)* | Boot or Logon Autostart Execution | `HKCU\Environment\UserInitMprLogonScript` executing the Mimikatz command at logon |
| Credential Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | `mim.exe sekurlsa::LogonPasswords` |
| Persistence / Execution | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Event Triggered Execution: WMI Event Subscription | WMI Event Filter on `procexp64.exe` start, bound via `__FilterToConsumerBinding` to a VBScript consumer |
| Defense Evasion | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | `procexp64.exe` terminated automatically via the WMI-triggered script |
| Execution | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Command and Scripting Interpreter: Visual Basic | VBScript-based WMI consumer script |
| Command and Control | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol *(beaconing behavior)* | Repeated, short-lived `mim.exe`/`powershell.exe` execution consistent with periodic beaconing |
| Defense Evasion | [T1055](https://attack.mitre.org/techniques/T1055/) *(possible — parent/child anomaly)* | Process Injection | `svchost.exe` observed as the parent of `mim.exe`/`powershell.exe`, inconsistent with normal service-host behavior |
| Defense Evasion | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name or Location | `p.exe` imitating `psexesvc.exe`, and a malicious `svchost.exe` placed in `C:\Users\Public` |
| Execution | [T1218](https://attack.mitre.org/techniques/T1218/) *(payload delivery via legitimate scripting engines)* | System Binary Proxy Execution | CACTUSTORCH-matched file (`en-US.js`) consistent with shellcode execution via scripting engines |
| Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Presence of `nbtscan.exe`, a NetBIOS network-scanning tool, on the host |
| Defense Evasion | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | `xCmd.exe` identified as encrypted/packed and Trojan-like |

## 13. Key Takeaways

- **Redundant persistence is a strong signal of deliberate, hands-on compromise.** Finding the same malicious command wired into both a scheduled task and a logon-script registry key indicates an attacker actively ensuring survivability, not an opportunistic, single-shot infection.
- **A disabled analysis tool is itself a critical clue, not just an obstacle.** Rather than treating `procexp64.exe`'s failure to launch as a dead end, tracing *why* it failed (via the WMI event filter) was what unlocked the entire backdoor chain.
- **WMI event subscriptions remain a stealthy, underused-by-defenders persistence and defense-evasion mechanism**, precisely because reconstructing them requires actively querying `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` — artifacts many responders never think to check.
- **Automated scanners have blind spots, and closing them is part of the job, not a failure of the tool.** Loki's detection of numerous artifacts did not include the most consequential tool on the host (`mim.exe`); manually deriving unique strings and authoring a targeted YARA rule is exactly the kind of gap-closing work expected of a competent analyst.
- **Masquerading operates at multiple layers simultaneously** — filename (`svchost.exe` in the wrong location), internal strings (`p.exe` mimicking `psexesvc.exe`), and even script authorship (VBScript disguised inside a `.ps1`-styled file) — meaning no single check is sufficient on its own.

## 14. Conclusion

This investigation reconstructed a multi-layered Windows compromise built around two goals: durable credential access via Mimikatz, and durable presence via redundant scheduled-task, registry, and WMI-based persistence — with an active anti-forensics component specifically targeting Process Explorer to slow down investigation. Cross-referencing registry, Task Scheduler, live process behavior (Procmon), and automated scanning (Loki) was necessary at every stage, and the investigation concluded by explicitly identifying and remediating a detection gap in the automated tooling itself, rather than stopping once the initial artifacts were found.


