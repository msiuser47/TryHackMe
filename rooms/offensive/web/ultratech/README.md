# UltraTech 

**Category:** Web Exploitation / Linux Privilege Escalation
**Platform:** TryHackMe
**Difficulty:** Medium
**Skills Demonstrated:** Service Enumeration, Directory Brute-Forcing, Client-Side JS Analysis, OS Command Injection, Hash Cracking, SSH Access, Docker Privilege Escalation (GTFOBins)

---

## Scenario Overview

The target is a server belonging to UltraTech, assessed under a grey-box methodology: the only information provided at the start was the company name and the server's IP address.

The overall attack chain went as follows: port scanning → discovery of a web application on a non-standard port and a REST API on another port → analysis of the site's client-side JavaScript to understand how the API is called → exploitation of an OS command injection flaw in one of the API routes to read a SQLite database → extraction and cracking of a user's password hash → SSH access using the recovered credentials → privilege escalation to root by abusing membership in the `docker` group.

> Note: The IP address shown in some commands changed partway through the engagement because the TryHackMe machine's time limit expired and it had to be redeployed/restarted. Both addresses (<TARGET-IP> and <TARGET-IP>) refer to the same target within the same overall session.

---

## Tools Used

| Tool | Purpose |
|---|---|
| Nmap | Discover open ports and running services, and fingerprint their versions |
| traceroute | Trace the network path to the target |
| FTP client | Attempt anonymous login to the FTP service |
| Gobuster | Enumerate hidden paths and files on both web applications |
| Browser / DevTools | Inspect the site's client-side JavaScript source files |
| hashid | Identify the type of the extracted hash |
| Hashcat | Crack the MD5 hash using the rockyou.txt wordlist |
| SSH | Connect to the server using the recovered credentials |
| Docker | Abuse `docker` group membership to reach the host root filesystem (GTFOBins) |

---

## Step-by-Step Walkthrough

### 1. Initial Port Scan (Nmap)

```
nmap -sC -sV <TARGET-IP>
```

This scan revealed three services:

- **21/tcp** , vsftpd 3.0.5
- **22/tcp** , OpenSSH 8.2p1 (Ubuntu)
- **8081/tcp** , an HTTP service built on Node.js Express, with CORS enabled for several HTTP verbs (HEAD, GET, POST, PUT, DELETE, PATCH) , an early hint that this is a REST API rather than a conventional website.

> ![alt](screenshots/ultratech1.png)
> *Screenshot showing the output of `nmap -sC -sV` and the three discovered ports with service details.*

### 2. Full Port Scan

Running a `-p-` scan uncovered an additional non-standard port:

- **31331/tcp** , Apache httpd 2.4.29 (Ubuntu), hosting the site "UltraTech - The best of technology (AI, FinTech, Big Data)".

This step highlights why relying solely on the default top-1000-port scan is risky: the most important service in this challenge (the company's main website) was running on a non-standard port (31331) and would never have surfaced without a full port sweep.

### 3. Network Path Verification

```
traceroute <TARGET-IP>
```

This was used to confirm the number of hops between the attacker and the target, showing the host sitting directly behind a single gateway with no visible intermediate nodes.

### 4. Anonymous FTP Login Attempt

```
ftp <TARGET-IP>
```

Anonymous login was attempted but failed (`530 Login incorrect`), ruling out this service as a viable entry point and shifting focus to the two web services.

### 5. Directory/File Enumeration (Gobuster)

Gobuster was run against both web services to discover hidden files and directories:

```
gobuster dir -u http://<TARGET-IP>:31331/ -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://<TARGET-IP>:8081/ -w /usr/share/wordlists/dirb/common.txt
```

**Results for port 31331 (main site):** standard static assets (index.html, css/js/images directories, robots.txt), with nothing pointing directly to a vulnerability.

**Results for port 8081 (API):** only two routes were exposed:
- `/auth` (Status 200)
- `/ping` (Status 500)

This confirms that the front-end application relies on exactly two REST API routes, as reflected in the room's reference answer.

> ![alt](screenshots/ultratech2.png)
> *Screenshot showing the discovery of the `auth` and `ping` routes.*

> ![alt](screenshots/ultratech3.png)
> *Screenshot showing the paths and files discovered on the main UltraTech site.*

### 6. Client-Side JavaScript Analysis (api.js)

Browsing the `/js/` directory on port 31331 revealed three files: `api.js`, `app.js`, and `app.min.js`.

Inspecting `api.js` showed that the front-end automatically polls the API every 10 seconds via the following request:

```
http://<host>:8081/ping?ip=<hostname>
```

It also showed that the page's login form submits its data to `http://<host>:8081/auth`.

The critical detail here is that the `ip` parameter in the `/ping` request is built directly from `window.location.hostname` with no visible client-side validation or sanitization , a strong indicator that the backend likely passes this value into an OS-level command (most probably `ping`) in an unsafe way.

### 7. Exploiting the Command Injection

Based on the observation above, an OS command was injected into the `ip` parameter using shell command substitution (backticks):

```
http://<TARGET-IP>:8081/ping?ip=`ls`
```

This succeeded and returned the contents of the current directory on the server, including the filename of a SQLite database. It's worth highlighting a subtle but important technical detail observed during exploitation: it is specifically the backtick character (`` ` ``) that makes the injection work, while a plain single-quote character (`'`) does not get interpreted as a command , the shell only treats backticks as a directive to execute the enclosed command and substitute its output into the string.

Once the filename was known, the following request was made:

```
http://<TARGET-IP>:8081/ping?ip=`cat utech.db.sqlite`
```

The response leaked data extracted from the database, including a username (admin) and a password hash for another user: `f357a0c52799563c7c7b76c1e7543a32`.

> ![alt](screenshots/ultratech4.png)
> *Screenshot showing the successful execution of `ls` via the `ip` parameter on the `/ping` route, and the SQLite database filename appearing in the response.*

> ![alt](screenshots/ultratech5.png)
> *Screenshot showing the database contents leaked in the response, including the password hash.*

### 8. Identifying and Cracking the Hash

`hashid` was used to identify the hash type:

```
hashid -m f357a0c52799563c7c7b76c1e7543a32
```

Among several candidate algorithms (all sharing the same 32-character hex length), MD5 was flagged as the most likely.

The hash was then run through Hashcat against the rockyou.txt wordlist, assuming MD5:

```
hashcat -m 0 -a 0 'f357a0c52799563c7c7b76c1e7543a32' /usr/share/wordlists/rockyou.txt --force
```

The hash was cracked in under 5 seconds:

**Hash:** `f357a0c52799563c7c7b76c1e7543a32`
**Password:** `n100906`

> ![alt](screenshots/ultratech6.png)
> *Screenshot showing the "Cracked" status and the recovered password `n100906` next to the hash.*

### 9. SSH Access and Privilege Escalation

With credentials extracted from the database, several likely usernames were tried (`Mr00t`, `root`) without success, until the login succeeded with the username `r00t` and password `n100906`.

Checking identity and group membership:

```
id
```

```
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

Membership in the **docker** group is the pivotal weakness here: any user in this group effectively has root-equivalent privileges on the host system, because the Docker daemon itself runs as root, and a privileged container can be used to access the host's entire root filesystem.

Checking GTFOBins for Docker privilege escalation, the standard suggested command was tried:

```
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

This particular command did not work in this environment (most likely because the `alpine` image wasn't available locally or couldn't be pulled). After adjusting the base image, the following command succeeded in achieving the same goal:

```
docker run -v /:/mnt --rm -it bash chroot /mnt sh
```

This command spins up a new container, mounts the entire host filesystem (`/`) into `/mnt` with full read/write access, and then runs `chroot` to change the process's effective root to that path , resulting in a shell that effectively runs as root on the host system itself, rather than inside an isolated container environment.

### 10. Accessing Root's Data

With a root-level shell obtained, the `/root` directory was accessed and inspected:

```
ls -la
```

Among the listed files, the `.ssh` directory was opened, and the private key was read:

```
cat id_rsa
```

A full RSA private key was returned, beginning with:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBA...
```

This confirms full compromise of the server, culminating in access to root's own SSH private key.

---

## Attack Chain Summary

```
Port Scanning (Nmap)
        ▼
Discovery of a website on port 31331 and a REST API on port 8081
        ▼
Analysis of api.js → discovery of the /ping?ip= route
        ▼
Exploitation of Command Injection → reading the SQLite database
        ▼
Extraction of an MD5 hash and cracking it via Hashcat (rockyou.txt)
        ▼
SSH login as user r00t
        ▼
Discovery of docker group membership
        ▼
Privilege escalation via chroot inside a Docker container mounting the host root
        ▼
Full compromise + reading root's private SSH key
```

---

## MITRE ATT&CK Mapping

Several distinct adversary behaviors were observed during this assessment and can be mapped as follows:

- Port and service scanning via Nmap falls under **Active Scanning (Reconnaissance)**.
- Hidden-path enumeration via Gobuster and analysis of client-side JavaScript files fall under **Gather Victim Application/Website Information**.
- Exploiting the command injection flaw via the `ip` parameter in `/ping` represents **Exploit Public-Facing Application** under the **Initial Access** tactic, with the resulting command execution falling under **Command and Scripting Interpreter (Unix Shell)**.
- Extracting credentials from an unprotected SQLite database falls under **Credentials from Password Stores / Unsecured Credentials**.
- Cracking the hash via Hashcat and the rockyou.txt wordlist represents **Brute Force: Password Cracking**.
- Using the recovered credentials to authenticate over SSH falls under **Valid Accounts**, representing effective initial access to the server itself.
- Abusing `docker` group membership to run a fully privileged container for privilege escalation falls under **Exploitation for Privilege Escalation**, and broadly under **Abuse Elevation Control Mechanism**, since no Docker-specific sub-technique is formally defined in every version of the framework.
- Accessing root's SSH private key falls under **Unsecured Credentials: Private Keys**, representing the final **Persistence/Full Compromise** objective.

> Analyst note: some of these mappings (particularly around Docker privilege escalation) are supplementary analytical annotations added by the report author and are not explicitly stated in the original solution source. They should be validated against the live ATT&CK Navigator before being used in any formal deliverable.

---

## OWASP Top 10 Applicability

Since the primary entry point in this assessment was a command injection vulnerability in a REST API belonging to a web application (UltraTech), the OWASP Top 10 is directly applicable:

| OWASP Category | Relevance to this Engagement |
|---|---|
| A03:2021 – Injection | The central vulnerability of the entire engagement; the user-controlled `ip` value was passed directly into an OS-level command with no sanitization or encoding, enabling arbitrary shell command execution (Command Injection). |
| A02:2021 – Cryptographic Failures | Passwords were stored using MD5, an outdated algorithm that is fast to brute-force compared to purpose-built password hashing algorithms such as bcrypt or argon2. |
| A05:2021 – Security Misconfiguration | The SQLite database file was accessible from within the application's execution context, and an application-level user was granted membership in the OS-level `docker` group , a misconfiguration that extends beyond the application itself into the infrastructure layer. |
| A07:2021 – Identification and Authentication Failures | Weak passwords were used that could be cracked via a common wordlist (rockyou.txt) in a matter of seconds. |

---

## Key Findings & Risk Summary

| Weakness | Impact | Recommendation |
|---|---|---|
| Command injection via the `ip` parameter on `/ping` | Arbitrary command execution on the server, and exfiltration of sensitive data from the filesystem | Strictly validate and sanitize all user input; avoid passing user-controlled input directly into OS-level calls; use safe libraries for network operations instead of invoking shell commands directly |
| Passwords stored as MD5 | Passwords can be cracked very quickly using precomputed wordlists | Use purpose-built password hashing algorithms such as bcrypt or argon2 with an appropriate salt |
| Application user granted `docker` group membership | Immediate privilege escalation from a regular user to full root on the host system | Avoid granting application users membership in the `docker` group unless absolutely necessary; consider safer alternatives such as Rootless Docker or properly configured AppArmor/Seccomp policies |
| SQLite database readable via the execution vulnerability | Full disclosure of user credentials | Restrict access permissions on database files, and avoid storing password hashes in locations reachable from externally exploitable execution paths |

---

## Key Takeaways

- A full port scan (`-p-`) is essential every time; relying on the default scan alone would have completely hidden the most important service in this challenge.
- Analyzing a front-end application's client-side JavaScript often reveals precise details about how API requests are constructed , this is exactly what led directly to the vulnerability here.
- The difference between backtick characters (`` ` ``) and a plain single quote (`'`) may look trivial, but it is often the difference between a successful command injection exploit and a failed one.
- A user's membership in the `docker` group is effectively equivalent to full root privileges on the host system, and this common misconfiguration should always be checked right after obtaining any initial foothold (via `id` and `groups`).
- When a standard GTFOBins command fails (e.g., using the `alpine` image), it's worth trying alternative base images (such as `bash`) before assuming the technique isn't viable.
- Documenting every command and its output as you go makes writing a professional report afterward much easier, and demonstrates a clear methodology to anyone reviewing the work.

---

## References

- UltraTech room on TryHackMe , by Lp1 (fenrir.pro)
- MITRE ATT&CK Framework , https://attack.mitre.org
- OWASP Top 10 (2021) , https://owasp.org/Top10/
- GTFOBins , Docker , https://gtfobins.github.io/gtfobins/docker/
- Nmap , https://nmap.org
- Gobuster , https://github.com/OJ/gobuster
- Hashcat , https://hashcat.net/hashcat/
