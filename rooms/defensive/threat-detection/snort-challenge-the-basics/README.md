# Snort Challenge: The Basics (IDS Rule Writing & Traffic Analysis)

**Category:** Defensive Security / Network Intrusion Detection
**Tooling:** Snort (IDS/rule-based packet analysis)
**Skills demonstrated:** Snort rule syntax construction, protocol-aware detection (HTTP, FTP), file-signature/content matching, rule troubleshooting, external rule-set usage against known CVEs (MS17-010/EternalBlue, Log4Shell), log/alert file forensics

---

## 1. Scenario

This room is a hands-on exercise in writing, applying, and troubleshooting Snort Intrusion Detection System (IDS) rules against a series of provided PCAP files. Rather than a single narrative attack chain, each task isolates a distinct detection skill — protocol filtering, content/signature matching, syntax debugging, and applying externally sourced rules against known, high-severity vulnerabilities. The overarching goal was to build practical fluency in translating an investigative question ("did this happen in the traffic?") into a working Snort rule and correctly interpreting the resulting logs.

## 2. Objectives

1. Write protocol-specific detection rules (HTTP, FTP) and interpret packet-level log fields.
2. Use content-based signature matching to identify file types transferred over the network (PNG, GIF, torrent metafiles).
3. Diagnose and correct syntax and logic errors in a series of broken Snort rules.
4. Apply externally provided rule sets to detect exploitation of two real-world, high-severity CVEs (MS17-010/EternalBlue and Log4Shell) and extract IOCs from the resulting alerts.

## 3. Environment Notes

| Item | Default Location |
|---|---|
| Snort log directory | `/var/log/snort` |
| Snort configuration | `/etc/snort/snort.conf` |
| Local rules file | `/etc/snort/rules/local.rules` |

For this room, generated logs and the rules used were kept in the working directory per task rather than the system defaults.

**Core command patterns used throughout:**
```bash
sudo snort -A full -r <file.pcap> -c local.rules -l .   # Analyze a pcap against a ruleset
sudo snort -r <snort.log.file>                            # Read a previously generated log
sudo snort -r <snort.log.file> -n <N>                      # Read up to packet N from the log
cat alert                                                   # View triggered alerts
sudo rm alert <snort.log.file>                              # Clear logs between tasks
```

## 4. Task: HTTP Traffic Detection

**Objective:** detect all TCP port 80 traffic in both directions.

```
alert tcp any 80 <> any any (msg:"TCP port 80 inbound traffic detected"; sid:1000000000001; rev:1)
alert tcp any any <> any 80 (msg:"TCP port 80 outbound traffic detected"; sid:1000000000002; rev:1)
```

The `<>` operator matches traffic in either direction, avoiding the need for two separate directional rules for a bidirectional protocol check.

**Packets detected:** `328`

Reading specific packets from the resulting log with `-n <N>` allowed direct inspection of individual TCP header fields:

| Question | Command | Answer |
|---|---|---|
| Destination address of packet 63 | `snort -r snort.log.* -n 63` | `145.254.160.237` |
| ACK number of packet 64 | `snort -r snort.log.* -n 64` | `0x38AFFFF3` |
| SEQ number of packet 62 | `snort -r snort.log.* -n 62` | `0x38AFFFF3` |
| TTL of packet 65 | `snort -r snort.log.* -n 65` | `128` |
| Source IP of packet 65 | `snort -r snort.log.* -n 65` | `145.254.160.237` |
| Source port of packet 65 | `snort -r snort.log.* -n 65` | `3372` |

This task reinforced that Snort's raw packet log is a full protocol-level record — not just an alert summary — and can answer detailed header-level questions once a matching rule has generated the capture.

## 5. Task: FTP Traffic Detection

**Objective:** detect FTP control-channel traffic and progressively narrow detection to specific authentication outcomes, using FTP reply codes as content signatures.

**All port 21 traffic (both directions):**
```
alert tcp any 21 <> any any (msg:"Outbound ftp traffic detected"; sid:1000000000003; rev:1)
alert tcp any any <> any 21 (msg:"Inbound ftp traffic detected"; sid:1000000000004; rev:1)
```
**Packets detected:** `614`

Reading the resulting log with `strings` and filtering for the `220` banner code (FTP "service ready") revealed the server software in use:

**FTP service identified:** `Microsoft FTP Service`

The remaining sub-questions each mapped a specific FTP reply code to a `content` match, progressively narrowing the population of matched packets from general traffic down to a very specific authentication outcome:

| Detection Goal | FTP Code | Rule (`content` match) | Packets Detected |
|---|---|---|---|
| Failed login attempts | `530` (Not logged in) | `content:"530"` | `41` |
| Successful logins | `230` (User logged in) | `content:"230"` | `1` |
| Valid username, bad/no password | `331` (Username OK, need password) | `content:"331"` | `42` |
| Failed attempts specifically for "Administrator" | `331` + username | `content:"331"; content:"Administrator";` | `7` |

```
alert tcp any any <> any 21 (msg:"Failed ftp login attempt"; content:"530"; sid:1000000000005; rev:1)
alert tcp any any <> any 21 (msg:"Successful ftp login"; content:"230"; sid:1000000000006; rev:1)
alert tcp any any <> any 21 (msg:"Invalid Password"; content:"331"; sid:1000000000007; rev:1)
alert tcp any any <> any 21 (msg:"Invalid Admin Password"; content:"331"; content:"Administrator"; sid:1000000000008; rev:1)
```

This progression illustrates a core IDS-tuning principle: **stacking multiple `content` matches in a single rule narrows detection scope** far more precisely than relying on a single indicator, which is exactly what isolated the 7 failed attempts specifically targeting the `Administrator` account out of 42 total failed-password attempts.

## 6. Task: File-Type Detection via Content Signatures

**Objective:** identify specific file types transferred over the network using their binary/ASCII header signatures, rather than relying on filenames or ports.

**PNG detection** (magic bytes `89 50 4E 47 0D 0A 1A 0A`):
```
alert tcp any any -> any any (msg:"PNG File Detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; depth:8; sid:10000000009)
```
Only one packet matched. Reviewing the log with `strings` identified the authoring software embedded in the file's metadata.

**Software identified:** `Adobe ImageReady`

**GIF detection** (ASCII header `GIF89a`):
```
alert tcp any any -> any any (msg:"GIF File Detected"; content:"GIF89a"; depth:6; sid:10000000010)
```
**Image format confirmed:** `GIF89a` — **Packets detected:** `4`

**Torrent metafile detection** (`.torrent` extension string):
```
alert tcp any any -> any any (msg:"Torrent File Detected"; content:".torrent"; nocase; sid:10000000011)
```
**Packets detected:** `2`

Reviewing this log surfaced further embedded metadata:

| Field | Value |
|---|---|
| Torrent client | `bittorrent` |
| MIME type | `application/x-bittorrent` |
| Hostname (tracker) | `tracker2.torrentbox.com` |

The `depth` option in each rule is a deliberate performance/precision choice — limiting the content search to only the first N bytes of the payload (matching the known header length) avoids false positives from the same byte sequence appearing later in unrelated traffic.

## 7. Task: Troubleshooting Rule Syntax and Logic Errors

This task provided seven broken rule files, each with a distinct defect to diagnose using Snort's own error output (`snort -c local-X.rules -r mx-1.pcap -A console`).

| Rule File | Defect Type | Root Cause | Fix | Packets Detected |
|---|---|---|---|---|
| `local-1.rules` | Syntax | Missing whitespace between `any` and the rule options block `(msg:...)` | Insert a space | `16` |
| `local-2.rules` | Syntax | Missing destination port field for an ICMP rule (ICMP has no ports, but the rule's field structure was still malformed) | `alert icmp any any -> any any (...)` | `68` |
| `local-3.rules` | Logic | Duplicate `sid` values across two rules — Snort requires globally unique rule IDs | Assign unique `sid` values | `87` |
| `local-4.rules` | Syntax + Logic | `msg` option terminated with `:` instead of `;`, plus a duplicate `sid` | Correct punctuation and reassign `sid` | `90` |
| `local-5.rules` | Logic | Use of a nonexistent `<-` directional operator | Replace with the bidirectional `<>` operator | `155` |
| `local-6.rules` | Logic | Case-sensitive `content` match missed lowercase/mixed-case `GET` requests | Add the `nocase` modifier | `2` |
| `local-7.rules` | Logic (missing required option) | Rule lacked the mandatory `msg` option, making its purpose undocumented and its match (an `.html` file signature) uninterpretable | Add a descriptive `msg` field | — |

**Example corrected rules:**
```
alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)
alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)
alert tcp any any <> any 80 (msg: "GET Request Found"; content:"|67 65 74|"; nocase; sid:100001; rev:1;)
alert tcp any any <> any 80 (msg:"html detected"; content:"|2E 68 74 6D 6C|"; sid:100001; rev:1;)
```

This task is a practical demonstration that Snort rule failures fall into two distinct classes — **syntax errors** (which Snort refuses to load and reports directly) and **logic errors** (which Snort loads without complaint but which silently under- or over-match traffic) — and that diagnosing the second category requires understanding the traffic itself, not just the rule grammar.

## 8. Task: External Rules — MS17-010 (EternalBlue)

**Objective:** apply a provided, pre-built rule set to detect exploitation of **MS17-010**, the SMBv1 remote code execution vulnerability exploited by the EternalBlue toolkit (notably used in the WannaCry and NotPetya outbreaks).

```bash
sudo snort -A full -c local.rules -r ms-17-010.pcap
```
**Packets detected:** `25154`

A follow-on custom rule was written to isolate a specific exploitation indicator — the `\IPC$` administrative share, commonly accessed during SMB-based exploitation for null-session/pipe interaction:

```
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:20244225; rev:3;)
```
**Packets detected:** `12`

Reviewing the resulting log with `strings` recovered the exact UNC path targeted:

**Requested path:** `\\192.168.116.138\IPC$`

**CVSS v2 score of MS17-010:** `9.3` (confirmed via external research)

The `flow: to_server, established;` option is worth highlighting — it restricts matching to packets sent toward the server on an already-established TCP session, which meaningfully reduces false positives compared to a stateless content match alone.

## 9. Task: External Rules — Log4j (Log4Shell)

**Objective:** apply a provided rule set to detect exploitation of **Log4Shell (CVE-2021-44228)**, the critical Apache Log4j remote code execution vulnerability triggered via JNDI lookup injection in logged input.

```bash
sudo snort -c local.rules -r log4j.pcap -A full -l .
```
**Packets detected:** `26`

| Question | Method | Answer |
|---|---|---|
| Rules triggered | Review of the alert file | `4` |
| First six digits of triggered rule SIDs | `grep -e sid` against the log | `210037` |

A custom rule was then written to isolate mid-sized payloads consistent with the encoded exploit stage, using the `dsize` option to match packets by payload size range:

```
alert tcp any any -> any any (msg: "Packet payload size between 770 and 855 bytes detected"; dsize:770<>855; sid:1000001;)
```
**Packets detected:** `41`

Reviewing the resulting log with `strings` identified the encoding scheme used to smuggle the second-stage payload:

**Encoding identified:** `Base64`

Cross-referencing the alert file against the known malicious source IP and the `ID` field recovered the corresponding packet's IP identification value:

**IP ID:** `62808`

Decoding the recovered Base64 string surfaced the attacker's actual injected command — the payload retrieved via the classic Log4Shell chain: a crafted string in a logged field (e.g., a `User-Agent` or similar header) triggering a JNDI lookup, which in turn causes the vulnerable application to fetch and execute a remote class/command.

**CVSS v2 score of Log4Shell:** `9.3` (confirmed via external research)

## 10. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Relevance |
|---|---|---|---|
| Reconnaissance / Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | FTP/SMB banner and service enumeration visible in captured traffic |
| Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Repeated FTP `530`/`331` failed-login responses consistent with password guessing against the FTP service |
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Log4Shell (CVE-2021-44228) exploitation traffic detected via external Snort rules |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services | MS17-010/EternalBlue SMB exploitation traffic, including `IPC$` access |
| Command and Control | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Log4Shell JNDI lookup and subsequent payload retrieval over HTTP-based traffic |
| Command and Control | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Data Encoding: Standard Encoding | Base64-encoded command payload identified in the Log4j traffic |

## 11. OWASP Top 10 Mapping (Log4Shell Component)

Since Log4Shell is fundamentally an application-layer vulnerability, a brief OWASP mapping is relevant to that specific task:

| OWASP Category | Relevance |
|---|---|
| **A03:2021 – Injection** | Log4Shell is a textbook injection vulnerability — attacker-controlled input logged by the application triggers a JNDI lookup, leading to remote code execution |
| **A06:2021 – Vulnerable and Outdated Components** | The underlying root cause is the use of a vulnerable, unpatched version of the widely-embedded Log4j logging library |

## 12. Key Takeaways

- **Directional operators matter more than they first appear.** Using `<>` versus `->` versus a two-rule pair changes not just rule count but detection completeness — several of the troubleshooting tasks hinged entirely on this distinction.
- **Content-based signatures generalize well beyond "malware" detection.** The same `content` matching technique used to catch a JNDI exploit string was equally effective at fingerprinting benign file types (PNG, GIF, torrent) purely from header bytes — detection engineering is protocol/format-agnostic at its core.
- **Snort distinguishes syntax failures from logic failures, and only warns you about the first kind.** A rule that loads cleanly can still silently fail to match intended traffic (case sensitivity, wrong operator, missing modifier) — validating detected-packet counts against expectations is essential, not optional.
- **External, community-maintained rule sets are a force multiplier for known CVEs**, but pairing them with a hand-written, narrowly-scoped rule (e.g., isolating `IPC$` or a specific payload size range) is what turns a broad "exploitation detected" alert into an actionable, specific IOC.

## 13. Conclusion

This room built practical fluency across the full Snort rule-writing lifecycle: constructing rules from a detection requirement, reading raw packet logs for forensic detail, debugging both syntax and logic defects, and layering custom rules on top of external, CVE-specific rule sets to extract concrete indicators of compromise from real exploitation traffic (EternalBlue and Log4Shell). The recurring theme is that effective IDS tuning is iterative — broad rules establish that something happened, and progressively narrower `content`/`dsize`/`flow` refinements are what establish exactly what happened and to whom.


