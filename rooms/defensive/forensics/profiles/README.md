# Profiles (Linux Memory Forensics)

**Category:** Defensive Security / Digital Forensics
**Difficulty:** Medium
**Skills demonstrated:** Linux memory forensics, Volatility 3, kernel symbol reconstruction, artifact recovery and analysis

---

## 1. Scenario

The incident response team flagged suspicious activity on a Linux database server. A memory dump (`linux.mem`) was collected before the host was taken offline, and the investigation had to rely entirely on that RAM capture — there was no disk image, no live system, and no prior context beyond the raw memory.

The goal was to reconstruct the attacker's actions purely from volatile memory artifacts: credentials exposed in shell history, the malicious payload dropped on the host, the attacker's network endpoint, and any persistence mechanism left behind.

## 2. Objectives

1. Identify the exposed root password.
2. Determine when a sensitive file (`users.db`) was last accessed.
3. Recover and hash the malicious binary executed on the host.
4. Identify the attacker's IP address and port.
5. Locate the cron-based persistence mechanism and recover its contents.

## 3. Tools

| Tool | Purpose |
|---|---|
| **Volatility 3** | Primary memory analysis framework |
| `dwarf2json` | Generates Volatility-compatible debug symbols |
| Ubuntu `dbgsym` packages | Source of kernel debug info (`vmlinux`) matching the target kernel |
| `strings` | Raw string search across the memory image as a fallback/verification method |
| `md5sum` | Hashing the recovered malicious file |

## 4. Preparation: Rebuilding Kernel Symbols

Before any Linux plugin in Volatility 3 will function correctly, it needs debug symbols matching the *exact* kernel of the memory image. Volatility does not ship these by default for every distribution/kernel combination, so they had to be generated manually.

**Target kernel:** `Linux 5.4.0-166-generic`

**Process:**

1. Identify the kernel banner/version from the memory image.
2. Download the matching Ubuntu `dbgsym` package for that kernel build.
3. Extract the uncompressed `vmlinux` from the package.
4. Run `dwarf2json` against `vmlinux` to produce a Volatility-compatible JSON symbol table.
5. Compress the symbol file (`.json.xz`) and place it under Volatility's `symbols/linux` directory.
6. Clear Volatility's cache and re-run a Linux plugin to confirm the symbols resolve correctly.

Only once this step succeeded did the standard Linux plugins (`linux.bash`, `linux.psaux`, `linux.envars`, `linux.sockstat`, `linux.pagecache.*`) return usable output.

## 5. Investigative Workflow

The overall approach followed a standard "memory-only" triage order:

1. Identify kernel version → fix symbols if plugins fail.
2. List running processes and their command-line arguments.
3. Review shell/bash history.
4. Inspect environment variables (session context, e.g. SSH client info).
5. Enumerate network connections.
6. Search the page cache for suspicious or recently touched files.
7. Dump and hash recoverable files.
8. Check for cron-based or other persistence artifacts.

## 6. Findings

### 6.1 Exposed Root Password

```bash
vol -f linux.mem linux.bash.Bash | tee bash.txt
```

Reviewing the recovered bash history revealed a command containing the plaintext root password.

**Answer:** `Ftrccw45PHyq`

### 6.2 Access Time of `users.db`

The same bash history entry that exposed the root password also referenced `users.db`, allowing its approximate access time to be read directly from that history line.

**Answer:** `2023-11-07 03:49:45`

### 6.3 Malicious File and Its MD5 Hash

The bash history showed a `wget` download of a C source file (`shell.c`), which was subsequently compiled into a binary named `pkexecc` and executed. This chain — download, compile, execute — identified `pkexecc` as the malicious payload.

To recover and hash the binary from the page cache:

```bash
mkdir -p dumps

vol -f linux.mem -o dumps linux.pagecache.InodePages \
    --find /home/paco/pkexecc --dump | tee inode_pkexecc.txt

md5sum dumps/inode_*.dmp
```

**Answer:** `0511ccaad402d6d13ce801e1e9136ba2`

### 6.4 Attacker IP and Port

With the malicious IP already visible from the earlier `wget` download activity, the corresponding port was confirmed by cross-referencing active network sockets:

```bash
vol -f linux.mem linux.sockstat.Sockstat | grep "10.0.2.72"
```

**Answer:** `10.0.2.72:1337`

### 6.5 Cronjob File Path and Inode

Searching cached filesystem entries for cron-related paths surfaced the persistence file and its inode number:

```bash
vol -f linux.mem linux.pagecache.Files | grep -iE "cron|crontab|crontabs"
```

**Answer:** `/var/spool/cron/crontabs/root:131127`

### 6.6 Cronjob Contents

The cron file itself was recovered directly from the page cache:

```bash
vol -f linux.mem -o dumps linux.pagecache.InodePages \
    --find /var/spool/cron/crontabs/root --dump
cat dumps/*
```

As a faster cross-check, the same content could be confirmed with a raw string search across the memory image:

```bash
strings -a linux.mem | grep -A3 -B3 "cp /opt/.bashrc"
```

**Answer:** `* * * * * cp /opt/.bashrc /root/.bashrc`

This entry runs every minute, overwriting `/root/.bashrc` with a file from `/opt/`, a low-noise but persistent foothold mechanism.

## 7. Command Reference

| Goal | Command |
|---|---|
| Activate Volatility venv | `source ~/venvs/volatility3/bin/activate` |
| Verify Volatility works | `vol -h` |
| Get kernel version/banner | `vol -f linux.mem banners.Banners` |
| Clear Volatility cache | `vol --clear-cache -f linux.mem linux.psaux.PsAux` |
| List processes + arguments | `vol -f linux.mem linux.psaux.PsAux` |
| Recover bash history | `vol -f linux.mem linux.bash.Bash` |
| Dump environment variables | `vol -f linux.mem linux.envars.Envars` |
| List network sockets | `vol -f linux.mem linux.sockstat.Sockstat` |
| List page cache files | `vol -f linux.mem linux.pagecache.Files` |
| Dump a specific cached file | `vol -f linux.mem -o dumps linux.pagecache.InodePages --find <path> --dump` |
| Recover full cached filesystem | `vol -f linux.mem -o dumps linux.pagecache.RecoverFs` |
| Hash a recovered file | `md5sum <file>` |
| Raw string search | `strings -a linux.mem \| grep -i "<keyword>"` |

## 8. MITRE ATT&CK Mapping

Mapping the recovered artifacts to ATT&CK provides a standardized view of the attacker's tradecraft and makes the write-up easier to compare against other incidents.

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access / Execution | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | Attacker actions reconstructed entirely from bash shell history (`linux.bash.Bash`) |
| Credential Access | [T1552.003](https://attack.mitre.org/techniques/T1552/003/) | Unsecured Credentials: Bash History | Root password `Ftrccw45PHyq` recovered in plaintext from shell history |
| Collection / Discovery | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Access to `users.db`, a local data file containing sensitive records |
| Command and Control | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | `wget` used to pull `shell.c` from the attacker-controlled host |
| Defense Evasion | [T1027.004](https://attack.mitre.org/techniques/T1027/004/) | Obfuscated Files or Information: Compile After Delivery | Source (`shell.c`) transferred and compiled locally into the `pkexecc` binary rather than dropped as a pre-built executable |
| Execution | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Compiled `pkexecc` binary executed on the host |
| Command and Control | [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | Outbound/attacker communication observed on `10.0.2.72:1337`, a non-standard high port |
| Persistence / Scheduled Execution | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Scheduled Task/Job: Cron | Root crontab (`/var/spool/cron/crontabs/root`) modified to run every minute |
| Persistence | [T1546.004](https://attack.mitre.org/techniques/T1546/004/) | Event Triggered Execution: Unix Shell Configuration Modification | Cronjob overwrites `/root/.bashrc` from `/opt/.bashrc` every minute, maintaining a persistent shell backdoor triggered on login |

### Attack Chain Summary (ATT&CK view)

```
T1059.004 (Shell access)
      │
      ▼
T1552.003 (Root password harvested from bash history)
      │
      ▼
T1105 (shell.c downloaded via wget)
      │
      ▼
T1027.004 (Compiled locally → pkexecc)
      │
      ▼
T1204.002 (pkexecc executed)
      │
      ▼
T1571 (C2 contact — 10.0.2.72:1337)
      │
      ▼
T1053.003 + T1546.004 (Cron persistence rewriting .bashrc every minute)
```

## 9. Key Takeaways

- **Symbol accuracy is the gate.** Linux memory forensics with Volatility 3 lives or dies on having correctly matched kernel debug symbols; this is usually the first (and most overlooked) blocker in any real investigation.
- **Bash history is high-value.** A single recovered shell history is often enough to reconstruct the entire attack chain — credential exposure, payload staging, compilation, and execution — in the order it happened.
- **Cross-referencing artifact types builds confidence.** Correlating `bash.Bash`, `psaux.PsAux`, `envars.Envars`, `sockstat.Sockstat`, and `pagecache.*` against each other turns isolated fragments (an IP here, a filename there) into a coherent incident timeline.
- **Page cache recovery works even after the process exits.** Files no longer resident as a running process can often still be reconstructed byte-for-byte straight from cached pages in memory.

## 10. Methodology Note

The analytical approach and command sequence in this write-up were adapted from a publicly shared methodology for this room; the steps above were independently reproduced and verified against the provided memory image to arrive at the same results.
