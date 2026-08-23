# Snort Challenge: Live Attacks (Real-Time Detection & Blocking)

**Category:** Defensive Security / Network Intrusion Prevention
**Tooling:** Snort (sniffer mode, IDS console mode, and inline IPS mode)
**Skills demonstrated:** Live traffic capture and analysis, anomaly identification from raw packet logs, Snort rule authoring for active blocking (not just alerting), inline IPS deployment (AFPACKET/`-Q`), real-time attack mitigation validation

---

## 1. Scenario

Unlike a static-pcap rule-writing exercise, this room required responding to **two live, ongoing attacks** against a running system in real time. In each scenario, the objective was to capture live traffic with Snort in sniffer mode, identify the anomalous activity from the raw packet stream, author a targeted Snort rule, and then run Snort in **inline IPS mode** to actively drop the malicious traffic. Successfully blocking each attack for a sustained period (at least one minute) triggered the appearance of a flag file on the desktop — providing immediate, practical confirmation that the mitigation worked, not just that a rule matched.

## 2. Objectives

1. Capture live network traffic and identify an active brute-force attack, including its source, targeted service, and port.
2. Author and validate a Snort rule to block the brute-force traffic in IPS mode.
3. Capture live traffic and identify a persistent outbound connection consistent with a reverse shell, including its port and the offensive tool commonly associated with it.
4. Author and validate a Snort rule to block the reverse shell traffic in IPS mode.

## 3. Methodology

Both scenarios followed the same operational pattern, reflecting a realistic detection-to-prevention workflow:

1. **Capture** — run Snort in sniffer mode against live traffic to obtain a representative sample.
2. **Analyze** — read the resulting log verbosely (`-X`) to inspect full packet contents, and use `grep` to isolate suspicious repeated ports/services.
3. **Author** — write a targeted `drop` rule (not merely `alert`) matching the identified protocol/port.
4. **Validate in IDS mode** — test the rule with `-A console` to confirm it fires as expected without side effects.
5. **Deploy in IPS mode** — run Snort inline (`-Q`, AFPACKET) with `-A full` to actively drop matching traffic and confirm the attack stops.

## 4. Scenario 1 — SSH Brute-Force Attack

### 4.1 Live Capture

Traffic was captured in sniffer mode for a short observation window:

```bash
sudo snort -v -l .
```
The capture was stopped with `Ctrl+C` once sufficient traffic had been recorded, generating a timestamped log file under `snort.log.<timestamp>`.

### 4.2 Anomaly Identification

The log was read in verbose/full-packet mode:

```bash
sudo snort -r snort.log.<timestamp> -X
```

Reviewing the traffic, port **22** appeared repeatedly as both source and destination across a high volume of connections — a pattern inconsistent with normal, sparse SSH usage and suggestive of automated, repeated authentication attempts. This was confirmed by filtering the log directly:

```bash
sudo snort -r snort.log.<timestamp> -X | grep :22
sudo snort -r snort.log.<timestamp> -X | grep -i ssh
```

Narrowing further with a packet-count limit isolated the specific traffic pattern used to confirm the finding:

```bash
sudo snort -r snort.log.<timestamp> -X -n 30
```

**Service under attack:** `SSH`
**Protocol/port used:** `TCP/22`

The high frequency of repeated connection attempts to a single authentication service on its standard port, without the intervening activity expected from a normal interactive session, is the classic network-level signature of a brute-force attack.

### 4.3 Rule Authoring

The local rules file was edited directly:

```bash
sudo gedit /etc/snort/rules/local.rules
```

A rule was written using the **`drop`** action (rather than `alert`), since the objective was active prevention, not passive detection:

```
drop tcp any any -> any 22 (msg:"SSH Brute Force Attack Blocked"; sid:100001; rev:1;)
```

### 4.4 Deployment in IPS Mode

The rule was first validated in console/IDS mode to confirm correct matching, then deployed inline to actively enforce the drop action against live traffic:

```bash
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full
```

Running Snort inline between the two configured interfaces (`eth0:eth1`) allowed it to intercept and drop matching packets in real time rather than passively observing a mirrored feed. After the rule remained active and effectively blocked the brute-force traffic for approximately one minute, the flag file appeared on the desktop, confirming successful mitigation.

**Flag:** `THM{81b7fef657f8aaa6e4e200d616738254}`

## 5. Scenario 2 — Reverse Shell (Outbound C2) Detection

### 5.1 Live Capture

With the inbound threat resolved, attention shifted to outbound traffic — a deliberate pivot reflecting a realistic incident-response principle: stopping unauthorized inbound access does not address adversaries who may already have an established foothold. The same sniffer-mode capture process was repeated:

```bash
sudo snort -v -l .
sudo snort -r snort.log.<timestamp> -X
```

### 5.2 Anomaly Identification

Reviewing the captured traffic revealed a **persistent connection using port 4444** as both the source and destination across repeated packets — a pattern distinct from typical short-lived, request/response web or file-sharing traffic, and consistent with an established, long-lived command-and-control channel.

**Protocol/port used:** `TCP/4444`

A brief search confirmed the strong association between this specific port and a widely-used exploitation/post-exploitation framework, since 4444 has long served as its conventional default listener port.

**Associated tool:** `Metasploit` (its default `multi/handler` listener port)

### 5.3 Rule Authoring

The local rules file was again edited to add a targeted drop rule for this port:

```
drop tcp any any -> any 4444 (msg:"Reverse Shell Traffic Blocked"; sid:100001; rev:1;)
```

### 5.4 Deployment in IPS Mode

The same inline deployment process was used to actively enforce the block:

```bash
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full
```

Once the outbound connection on port 4444 was suppressed for the required duration, the corresponding flag file appeared on the desktop.

**Flag:** `THM{0ead8c494861079b1b74ec2380d2cd24}`

## 6. Comparative Summary

| Aspect | Scenario 1 — Brute Force | Scenario 2 — Reverse Shell |
|---|---|---|
| Traffic direction | Inbound | Outbound |
| Target port | 22 (SSH) | 4444 (Metasploit default) |
| Underlying behavior | Repeated authentication attempts | Persistent C2 channel |
| Detection cue | High-frequency repeated connections to a standard service port | Long-lived, low-variation session on a non-standard port |
| Snort rule action | `drop` | `drop` |
| Mitigation validation | Flag appears after ~1 minute of sustained blocking | Flag appears after ~1 minute of sustained blocking |

## 7. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Repeated, high-frequency connection attempts to TCP/22 (SSH) |
| Initial Access | [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | SSH targeted as the exposed remote-access service under attack |
| Command and Control | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Persistent outbound session on TCP/4444 consistent with an established C2/reverse-shell channel |
| Command and Control / Tooling | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software *(closest category — commodity C2 tooling)* | Traffic pattern strongly associated with Metasploit's default handler port |

## 8. Key Takeaways

- **Inline IPS mode is operationally different from IDS mode, and the room enforces that distinction.** Writing a correct `drop` rule is necessary but not sufficient — the rule only has real effect once Snort is run inline (`-Q`, AFPACKET) between the monitored interfaces, which is what the flag-generation mechanic in this room specifically validates.
- **Port-based anomaly detection is still highly effective for commodity attacks.** Neither scenario required deep packet payload inspection — the repeated, sustained use of a single port (22 or 4444) in an unusual traffic pattern was, by itself, enough to identify and characterize both attacks.
- **Outbound traffic deserves equal attention to inbound traffic.** The room's own scenario framing makes this explicit: blocking brute-force attempts at the perimeter says nothing about adversaries who may already be inside, which is why the second scenario deliberately pivoted to egress monitoring.
- **Default tool ports remain a durable detection signal.** Metasploit's long-standing default use of port 4444 for its handler is well known enough that its mere presence in unexplained persistent outbound traffic is a strong, actionable indicator on its own.

## 9. Conclusion

This room moved beyond static rule-writing into active, real-time network defense: identifying two distinct classes of live attack — an inbound brute-force attempt and an outbound reverse-shell/C2 channel — purely from traffic pattern analysis, then authoring and deploying inline Snort rules that measurably stopped each attack. The exercise reinforces that effective network defense is a closed loop: detect, characterize, write a precise rule, and validate that the rule actually changes the outcome in production (inline) rather than only in a passive alerting mode.


