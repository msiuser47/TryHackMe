# TryHackMe — Benign (SIEM Investigation with Splunk)

**Category:** Defensive Security / SOC Level 1 — SIEM
**Tooling:** Splunk (index: `win_eventlogs`)
**Difficulty:** Beginner–Intermediate
**Skills demonstrated:** Windows process-execution log analysis (Event ID 4688), Splunk search construction (`top`, `rare`), impersonation/account-anomaly detection, LOLBIN abuse identification, C2 payload delivery tracing

---

## 1. Scenario

An IDS alert flagged suspicious process execution on a host belonging to the HR department. Follow-up triage identified activity consistent with network reconnaissance tooling and scheduled-task execution, raising suspicion of a broader compromise. Due to limited log collection resources, only **Windows process-creation events (Event ID 4688)** were available, ingested into Splunk under the `win_eventlogs` index.

The environment is organized into three departments, each with known, named users:

| Department | Users |
|---|---|
| IT | James, Moin, Katrina |
| HR | Haroon, Chris, Diana |
| Marketing | Bell, Amelia, Deepak |

The objective was to use Splunk alone — with no additional log sources — to identify the compromised account, the technique used to establish persistence, the delivery mechanism for a malicious payload, and the resulting indicator of compromise.

## 2. Objectives

1. Establish a baseline log volume for the investigation window.
2. Identify an anomalous/impersonating user account hiding among legitimate usernames.
3. Identify which HR user executed scheduled-task activity.
4. Identify which HR user abused a living-off-the-land binary (LOLBIN) to retrieve a payload.
5. Identify the specific LOLBIN, the download source, the execution date, and the resulting artifact.
6. Recover the embedded flag from the delivered payload's hosting page.

## 3. Investigative Workflow

Rather than searching blindly, the investigation was scoped down progressively:

1. Confirm data coverage (volume/date range) before drawing conclusions.
2. Use `UserName` field statistics to surface accounts that don't match the known roster.
3. Narrow to HR-specific hosts/users once the department of interest was confirmed.
4. Pivot on `CommandLine` — first for scheduled-task keywords, then for rare/unusual command patterns — since Event ID 4688 records the exact command executed.
5. Follow the identified C2 URL to recover the final artifact/flag.

This mirrors a standard SOC triage pattern: **scope the data → find the anomaly → pivot on the anomaly → follow the artifact to its outcome.**

## 4. Findings

### 4.1 Log Volume for March 2022

**Splunk query:**
```
index=win_eventlogs
```
With the time range restricted to March 2022, the total event count for that window was confirmed.

**Answer:** `13959`

### 4.2 Imposter Account

**Splunk query:**
```
index=win_eventlogs | top limit=11 UserName
```
The organization's roster contains exactly 10 named users across three departments. Requesting the top 11 values for `UserName` (one more than the expected count) surfaced an eleventh entry that visually mimics a legitimate account through character substitution (a "1" in place of an "i").

**Answer:** `Amel1a`

This is a classic homoglyph/lookalike account technique — designed to blend into `UserName` field listings unless the analyst explicitly checks for more values than expected.

### 4.3 HR User Running Scheduled Tasks

**Splunk query:**
```
index=win_eventlogs schtasks
```
Filtering process-creation events for the `schtasks` keyword returned a small set of matching command lines. Sorting by `CommandLine` isolated a scheduled-task creation command tied to a specific HR account.

**Answer:** `Chris.fort`

### 4.4 HR User Downloading a Payload via LOLBIN

**Splunk query:**
```
index=win_eventlogs HostName="*HR*" | rare limit=20 CommandLine
```
Rather than searching for a specific keyword, this query surfaced the **least common** command lines executed on HR hosts — an effective way to find one-off, anomalous activity that would otherwise be buried among routine process launches. This immediately exposed a command using `certutil.exe` to retrieve a file (`benign.exe`) from an external site, executed under a specific HR user account.

**Answer:** `haroon`

### 4.5 LOLBIN Used to Bypass Security Controls

Identified directly from the command line uncovered in 4.4. `certutil.exe` is a native Windows utility (intended for certificate management) commonly abused to download files, since it is signed, trusted, and rarely restricted by application allow-listing — a textbook **living-off-the-land binary (LOLBIN)**.

**Answer:** `certutil.exe`

### 4.6 Execution Date

Taken from the timestamp of the same `certutil.exe` process-creation event identified above.

**Answer:** `2022-03-04`

### 4.7 Third-Party Hosting Site

The full command line captured in 4.4 revealed the external domain used to stage the payload — a legitimate paste/text-hosting service repurposed to distribute the malicious binary, allowing the download traffic to blend in with normal outbound web activity.

**Answer:** `controlc.com`

### 4.8 File Saved to the Host

Also extracted from the same command line — the local filename the payload was written to on disk after download.

**Answer:** `benign.exe`

### 4.9 Embedded Flag

Retrieving the content hosted at the identified paste-site URL revealed the payload contents, which included an embedded flag pattern matching `THM{...}`.

**Answer:** `THM{KJ&*H^B0}`

### 4.10 Full C2/Delivery URL

The complete URL, combining the domain and its unique path, ties every prior finding (LOLBIN, filename, date, actor) to a single delivery event.

**Answer:** `https://controlc.com/e4d11035`

## 5. Attack Chain Summary

```
Impersonation account created: Amel1a (lookalike of Amelia)
      │
      ▼
HR account "Chris.fort" — scheduled task execution (persistence)
      │
      ▼
HR account "haroon" — certutil.exe abused as a LOLBIN
      │
      ▼
Payload staged on controlc.com (legitimate paste-hosting service)
      │
      ▼
benign.exe downloaded and written to the HR host
      │
      ▼
Payload content recovered → THM{KJ&*H^B0}
```

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Persistence / Initial Access | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Lookalike account `Amel1a` present in `UserName` logs, mimicking the legitimate `Amelia` account |
| Persistence / Execution | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | `schtasks` command executed by `Chris.fort` |
| Defense Evasion | [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | System Binary Proxy Execution: Regsvr32 *(category — LOLBIN abuse)* / [T1105](https://attack.mitre.org/techniques/T1105/) | `certutil.exe` used as a trusted, signed binary to download a payload, evading application controls |
| Command and Control | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | Web Service: Bidirectional Communication | Payload staged on `controlc.com`, a legitimate third-party paste-hosting service used to blend malicious traffic with normal web activity |
| Command and Control / Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | `benign.exe` downloaded and written to disk on the HR host via `certutil.exe` |

*Note: `certutil.exe` abuse for file download does not have its own dedicated LOLBIN sub-technique in ATT&CK; it is most commonly cataloged under T1105 (Ingress Tool Transfer) with T1218 referenced as the broader "signed binary proxy execution" defense-evasion category.*

## 7. Key Takeaways

- **Field-count assumptions catch impersonation.** Knowing the expected number of legitimate accounts (10) and deliberately requesting one more (`top limit=11`) is what exposed the lookalike account — a purely statistical check, not a signature match.
- **`rare` is as valuable as `top`.** While `top` surfaces common/expected activity, `rare` is what exposes single, anomalous command executions buried inside thousands of routine process launches — exactly the kind of needle a LOLBIN abuse case represents.
- **LOLBINs succeed by being trusted, not sophisticated.** `certutil.exe` required no custom tooling or exploit — its abuse relied entirely on being a signed, native utility that security controls are reluctant to block outright.
- **Legitimate web services make convenient C2 infrastructure.** Hosting the payload on a mainstream paste site let the download blend into normal outbound HTTPS traffic, which is why command-line and process telemetry — not network signature detection alone — was what actually exposed this stage.
