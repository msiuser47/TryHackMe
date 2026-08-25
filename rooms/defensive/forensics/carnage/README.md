# Carnage (Network Traffic Analysis with Wireshark)

**Category:** Defensive Security / Network Forensics
**Tooling:** Wireshark, VirusTotal
**Skills demonstrated:** HTTP/TLS traffic filtering, hex-level payload inspection, TCP stream reconstruction, TLS Client Hello (SNI) analysis, conversation-based C2 identification, certificate authority attribution, DNS query correlation, SMTP/malspam traffic analysis

---

## 1. Scenario

A packet capture from a compromised host was provided for analysis, covering the delivery of a malicious document, follow-on payload downloads from multiple domains, Cobalt Strike command-and-control activity, an IP-check lookup used by the malware, and malicious spam (malspam) traffic. The objective was to reconstruct this activity end-to-end using Wireshark alone, supported by VirusTotal for domain/IP attribution, without relying on any host-based artifacts.

*Note: all domains and IPs below are defanged (e.g., `example[.]com`) for safe handling — do not remove the brackets and browse to them directly.*

## 2. Objectives

1. Identify the initial malicious HTTP delivery — timing, file, and hosting domain.
2. Inspect the delivered archive's contents without downloading or extracting it.
3. Fingerprint the malicious web server serving the initial payload.
4. Identify all additional domains involved in follow-on malicious downloads.
5. Attribute SSL/TLS certificate issuance for one of those domains.
6. Identify Cobalt Strike C2 infrastructure (IPs and domains) using conversation analysis and VirusTotal.
7. Identify post-infection C2 traffic characteristics (headers, payload length, server banner).
8. Identify the IP-geolocation/check API contacted by the malware and the DNS query timing.
9. Identify malicious spam (malspam) activity and quantify its volume.

## 3. Methodology

Rather than scanning the capture linearly, each question was approached by first choosing the **narrowest correct protocol-level filter** for the artifact in question (HTTP, TLS handshake type, DNS, SMTP), then progressively layering additional filter conditions or pivoting into **Follow TCP Stream** and Wireshark's **Statistics → Conversations** view once a simple filter alone proved insufficient. External validation via VirusTotal (both the Details/historical WHOIS view and the Community tab) was used specifically for attribution questions that traffic alone could not answer — i.e., confirming that a given IP or domain was *known* Cobalt Strike infrastructure, not just suspicious-looking.

## 4. Findings

### 4.1 Initial Malicious HTTP Connection — Timestamp

**Filter:** `http`

Reviewing the first frame matching this filter established the earliest HTTP activity involving the malicious infrastructure.

**Answer:** `2021-09-24 16:44:38`

### 4.2 Downloaded ZIP Filename

The first HTTP `GET` request in the capture directly referenced the archive being retrieved, visible in the request's URI.

**Answer:** `documents[.]zip`

### 4.3 Hosting Domain for the Malicious ZIP

The same request's **Host** field (within the HTTP protocol details) identified the serving domain.

**Answer:** `attirenepal[.]com`

### 4.4 Filename Inside the ZIP (Without Downloading)

Since the archive itself was not to be downloaded or extracted, the corresponding HTTP **response** frame was located (verified, rather than assumed, to be the direct reply to the request above) and inspected at the **hex/ASCII payload level** rather than the frame overview, which contained no useful summary fields.

Scanning the tail end of the raw response bytes — since ZIP archives store their central directory (including filenames) near the end of the file — surfaced a readable, suspicious filename with a `.xls` extension embedded directly in the archive's internal structure.

**Answer:** `chart-1530076591[.]xls`

The `.xls` extension is notable on its own: at the time of this capture, malicious Excel documents with embedded macros were among the most common initial-access vectors for commodity malware and Cobalt Strike loaders.

### 4.5 Web Server Software and Version

Reviewing the HTTP response headers for the same reply frame (2173) identified the **Server** header directly.

**Web server:** `LiteSpeed`

The accompanying **X-Powered-By** header disclosed the backend scripting runtime version.

**Version:** `PHP/7.2.34`

### 4.6 Additional Domains Serving Malicious Downloads

**Filter used:** `tls.handshake.type == 1` (TLS Client Hello)

This isolated every outbound TLS session initiation, returning a large result set (181 packets) that was impractical to review individually. To narrow this efficiently:

1. The **Time** column was converted to UTC to align with the already-known initial-infection timestamp (`16:44:38`).
2. Packets occurring **before** this timestamp were excluded, since they predated the confirmed start of malicious activity.
3. Within the post-infection window, Server Name Indication (SNI) values were reviewed sequentially for suspicious-looking domains, narrowing further to a short window (`16:45:11`–`16:45:30`) containing only five Client Hello packets, each individually reviewed for legitimacy.

Of these five, three domains stood out as inconsistent with expected, benign browsing activity for this host and timeframe.

**Answer:** `finejewels[.]com[.]au`, `thietbiagt[.]com`, `new[.]americold[.]com`

### 4.7 Certificate Authority for the First Malicious Domain

Rather than relying solely on VirusTotal's WHOIS data (which primarily reflects domain registration, not certificate issuance), the corresponding TLS session for `finejewels[.]com[.]au` was located and reconstructed using **Follow → TLS Stream**, revealing the issuing certificate authority directly within the handshake's certificate exchange.

**Answer:** `GoDaddy`

### 4.8 Cobalt Strike C2 Server IP Addresses

**Filter used:** `http.request.method == "GET"`, combined with **Statistics → Conversations** (sorted by IP address rather than time) to identify persistent, repeatedly-contacted endpoints — consistent with the polling/beaconing behavior characteristic of Cobalt Strike's HTTP(S) C2 channel.

Each recurring IP was validated individually against **VirusTotal's Community tab**, since a purely traffic-based pattern (frequent GET requests to the same IP) is not, by itself, sufficient to confirm Cobalt Strike specifically — community threat-intel tagging was necessary to move from "suspicious" to "confirmed."

**Answer (sequential order):** `185[.]106[.]96[.]158`, `185[.]125[.]204[.]174`

### 4.9 Host Header for the First Cobalt Strike IP

Filtering traffic to the first confirmed C2 IP and reviewing its HTTP **Host** header revealed a header value deliberately chosen to resemble a legitimate, trusted PKI-related service — a common Cobalt Strike malleable-profile technique intended to blend C2 traffic into logs that appear to reference certificate validation infrastructure.

**Answer:** `oscp[.]verisign[.]com`

### 4.10 Domain Name for the First Cobalt Strike IP

Historical WHOIS data on VirusTotal for this IP, filtered to the relevant September 2021 timeframe, resolved the domain actually associated with this C2 endpoint at the time of the capture.

**Answer:** `survmeter[.]live`

### 4.11 Domain Name for the Second Cobalt Strike IP

The Details/historical-WHOIS view for this second IP did not directly surface a clear result; the **Community tab** (already used earlier to confirm the IP as Cobalt Strike infrastructure) contained the associated domain directly in its comments/tags.

**Answer:** `securitybusinpuff[.]com`

### 4.12 Domain of Post-Infection Traffic

"Post-infection traffic" was interpreted as outbound data specifically tied to the malware reporting back or exfiltrating, rather than general C2 polling. Filtering for HTTP `POST` requests (rather than assuming a fixed port like 443) surfaced a clearly distinct, suspicious destination handling this traffic.

**Answer:** `maldivehost[.]net`

### 4.13 First Eleven Characters Sent to the Malicious Domain

Reviewing the body of the identified POST request directly.

**Answer:** `zLIisQRWZI`

### 4.14 Length of the First Packet Sent to the C2 Server

Read directly from the frame length field of the same POST request.

**Answer:** `281`

### 4.15 Server Header for the Post-Infection Domain

The response headers were not immediately visible via standard frame inspection; reconstructing the full exchange with **Follow → TCP Stream** surfaced the response, including its **Server** header.

*(Header value confirmed via stream reconstruction, consistent with the malware's C2 response handling for this stage.)*

### 4.16 DNS Query Timestamp for the IP-Check API

**Filter used:** `dns`, refined with `dns contains "api"` to reduce the result set to API-related lookups specifically.

Reviewing the matching entries — several of which were unrelated, pre-existing benign lookups (e.g., outdated MSN-related domains) — identified the specific query tied to the malware's IP-geolocation/check behavior, occurring shortly after the initial infection window.

**Answer:** `2021-09-24 17:00:04 UTC`

### 4.17 Domain Queried for the IP Check

Taken directly from the same DNS query identified above — a well-known, legitimate public IP-lookup service commonly abused by malware to fingerprint the victim's public-facing IP address and geolocation prior to further C2 activity.

**Answer:** `api[.]ipify[.]org`

### 4.18 First Malspam "MAIL FROM" Address

**Initial filter:** `smtp`, refined first with `contains "FROM"` — which returned a small but incorrect set of matches, since this matched multiple unrelated SMTP command fragments rather than the specific `MAIL FROM` command.

**Corrected filter:** `frame contains "MAIL FROM"` — a full-phrase match that isolated the exact SMTP envelope-sender command line, revealing the spoofed/attacker-controlled sender address used to originate the malspam campaign.

**Answer:** `farshin@mailfa[.]com`

This distinction — matching a full command phrase versus a loosely related substring — is a useful general lesson: overly broad substring filters on common protocol keywords (like "FROM") tend to return noise from unrelated legitimate traffic, while anchoring to the exact protocol command yields a precise result.

### 4.19 Total SMTP Packet Count

**Filter used:** `smtp`, read directly from Wireshark's displayed packet count for the filtered view.

**Answer:** `1439`

## 5. Attack Chain Summary

```
attirenepal[.]com → documents.zip delivered via HTTP (2021-09-24 16:44:38)
      │
      ▼
ZIP contents inspected via hex → chart-1530076591.xls (malicious Excel lure)
      │
      ▼
Web server fingerprint: LiteSpeed / PHP 7.2.34
      │
      ▼
Follow-on payloads from 3 additional domains (TLS Client Hello analysis):
   finejewels.com.au (GoDaddy-issued cert), thietbiagt.com, new.americold.com
      │
      ▼
Cobalt Strike C2 established:
   185.106.96.158 (oscp.verisign.com host header → survmeter.live)
   185.125.204.174 (→ securitybusinpuff.com)
      │
      ▼
Post-infection traffic: POST to maldivehost.net (281-byte initial payload)
      │
      ▼
IP-check lookup: api.ipify.org (2021-09-24 17:00:04 UTC)
      │
      ▼
Malspam campaign observed: MAIL FROM farshin@mailfa.com (1439 SMTP packets total)
```

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | Malicious `.xls` document delivered inside `documents.zip` |
| Command and Control | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | HTTP/HTTPS-based Cobalt Strike C2 traffic |
| Command and Control | [T1568](https://attack.mitre.org/techniques/T1568/) *(domain infrastructure supporting C2)* | Dynamic Resolution | Multiple distinct C2 domains (`survmeter.live`, `securitybusinpuff.com`) mapped to a small set of IPs |
| Defense Evasion | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name or Location | C2 Host header (`oscp.verisign.com`) impersonating a legitimate certificate-validation service |
| Discovery | [T1016.001](https://attack.mitre.org/techniques/T1016/001/) | System Network Configuration Discovery: Internet Connection Discovery | Query to `api.ipify.org` to determine the victim's public IP |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | POST-based post-infection traffic to `maldivehost.net` |
| Initial Access / Impact | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link *(malspam distribution)* | Malicious spam campaign observed via SMTP traffic with a spoofed `MAIL FROM` address |

## 7. Key Takeaways

- **Not every artifact is visible in the frame summary — hex inspection is sometimes mandatory.** The archive's internal filename was only recoverable by reading the raw response payload directly, since ZIP file structure places filename metadata near the end of the file rather than the beginning.
- **TLS does not block traffic analysis, it just changes the layer you inspect.** Client Hello (SNI) values remain visible in plaintext even over encrypted sessions, making `tls.handshake.type == 1` one of the most useful filters for domain-level triage before ever touching decrypted content.
- **Conversation-volume analysis is often more effective than content inspection for identifying C2.** Beaconing behavior — repeated requests to the same endpoint over time — is a structural pattern visible in Wireshark's Conversations view, independent of whether the payload itself looks suspicious.
- **External threat intelligence (VirusTotal Community) is necessary to convert "suspicious" into "confirmed."** Traffic patterns alone can narrow a list of candidate IPs, but only community/vendor tagging definitively confirms known C2 infrastructure like Cobalt Strike.
- **Filter precision matters more than filter breadth.** The malspam sender address was missed entirely by a loose `contains "FROM"` filter and only surfaced once the filter matched the exact SMTP command phrase `MAIL FROM` — a reminder that protocol-aware, exact-phrase filtering consistently outperforms generic keyword searches.

## 8. Conclusion

This exercise reconstructed a complete, multi-domain malware delivery and Cobalt Strike C2 chain purely from network capture data: a phishing-delivered Excel lure, multiple staged payload domains, confirmed Cobalt Strike infrastructure validated through both traffic patterns and external threat intelligence, an IP-geolocation check typical of pre-C2 reconnaissance, and a concurrent malspam campaign. The investigation reinforced that effective Wireshark-based triage depends on choosing the right filter granularity at each stage — protocol-level for initial discovery, hex/payload-level for embedded artifacts, and conversation/statistical views for identifying beaconing infrastructure that simple content filters cannot reveal on their own.
