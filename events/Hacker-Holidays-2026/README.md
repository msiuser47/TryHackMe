<div align="center">

# 🏝️ TryHackMe: Hacker Holidays 2026: *The Byte Lotus*

### Writeups, Analysis & Screenshots for a 14-Challenge Security Advent Event

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Hacker%20Holidays%202026-red?style=for-the-badge&logo=tryhackme&logoColor=white)](https://tryhackme.com)
[![Status](https://img.shields.io/badge/Progress-14%2F14%20Completed-brightgreen?style=for-the-badge&logo=checkmarx&logoColor=white)](#-challenge-matrix)
[![Challenges](https://img.shields.io/badge/Challenges-14-blue?style=flat-square)](#-challenge-matrix)
[![Difficulty](https://img.shields.io/badge/Difficulty-Very%20Easy%20→%20Hard-orange?style=flat-square)](#-challenge-matrix)
[![Topics](https://img.shields.io/badge/Topics-OSINT%20%7C%20Web%20%7C%20API%20%7C%20AI%20Security%20%7C%20Forensics%20%7C%20Boot2Root-informational?style=flat-square)](#-focus-areas)
[![Made with](https://img.shields.io/badge/Written%20in-Markdown-lightgrey?style=flat-square&logo=markdown)](#)
[![License](https://img.shields.io/badge/License-Educational%20Use-yellow?style=flat-square)](#-disclaimer)

*A themed island resort. A hidden data-exfiltration ring. Fourteen days of hacking.*


</div>

---

## 📖 About This Project

This Directory documents my complete, independently-written walkthroughs and technical analysis for **TryHackMe's Hacker Holidays 2026: The Byte Lotus** — a 14-day festive CTF-style event set at a fictional luxury resort. Each day introduced a standalone challenge spanning a realistic range of attack surfaces: AI agents, cloud infrastructure, web applications, APIs, and forensic artifacts.

Rather than posting raw flags, every writeup follows a consistent, professional structure — **Overview → Analysis → Root Cause → Exploitation → Remediation** — mirroring the format used in real-world penetration test reports.

> 🏆 **Result:** 14/14 challenges completed, spanning Very Easy → Hard difficulty.

---

## 💡 Why This Collection Matters

Recruiters and technical reviewers can use this Directory to evaluate:

| What You'll See | What It Demonstrates |
|---|---|
| Structured root-cause analysis in every writeup | Ability to communicate findings clearly — a core pentest reporting skill |
| Coverage across 6 distinct security domains | Breadth: not a one-trick specialist |
| Chained, multi-stage exploitation (e.g. Day 11, Day 14) | Ability to think in attack chains, not isolated bugs |
| Remediation guidance alongside every exploit | A defensive mindset, not just "break things" |
| Clean, consistent Markdown + version control | Documentation discipline and Git literacy |

---

## 🎯 Focus Areas

| Domain | Description |
|---|---|
| 🕵️ **OSINT** | Social media reconnaissance, metadata harvesting, public information correlation |
| 🌐 **Web Exploitation** | SSTI, NoSQL injection, Zip Slip, exposed `.git` repos, unsafe deserialization |
| 🔌 **API Hacking** | Business logic flaws, race conditions, broken authorization |
| 🤖 **AI in Security** | Prompt injection, role manipulation, indirect prompt injection, insecure tool-output handling |
| ☁️ **Cloud Security** | AWS IAM misconfigurations, Azure Storage/Key Vault abuse, managed identity trust chains |
| 🧬 **Digital Forensics** | PCAP analysis, malware triage, WMI persistence, DPAPI credential recovery |
| 🔓 **Boot2Root** | Multi-stage initial access → privilege escalation chains |

---

## 🗂️ Challenge Matrix

| Day | Challenge Title | Category | Difficulty | Writeup | Screenshots |
|:---:|---|---|:---:|:---:|:---:|
| 01 | The Concierge Knows Too Much | AI Security | 🟢 Very Easy | [📄 Writeup](./Challenges/day-01-The-Concierge-Knows-Too-Much.md) | [🖼️ View](./Screenshots/Challenge1/) |
| 02 | Room 404 | Web Security | 🟢 Very Easy | [📄 Writeup](./Challenges/day-02-room-404.md) | [🖼️ View](./Screenshots/Challenge2/) |
| 03 | Complimentary | Cloud Security (AWS) | 🟡 Easy | [📄 Writeup](./Challenges/day-03-complimentary.md) | [🖼️ View](./Screenshots/Challenge3/) |
| 04 | Packed Light | Network Forensics | 🟡 Easy | [📄 Writeup](./Challenges/day-04-Packed-Light.md) | [🖼️ View](./Screenshots/Challenge4/) |
| 05 | Beach Bar | Boot2Root / Web | 🟡 Easy | [📄 Writeup](./Challenges/day-05-beach-bar.md) | [🖼️ View](./Screenshots/Challenge5/) |
| 06 | Overheard at Breakfast | OSINT | 🟡 Easy | [📄 Writeup](./Challenges/day-06-overheard-at-breakfast.md) | [🖼️ View](./Screenshots/Challenge6/) |
| 07 | Do Not Disturb | Boot2Root / Web Security | 🟠 Medium | [📄 Writeup](./Challenges/day-07-do-not-disturb.md) | [🖼️ View](./Screenshots/Challenge7/) |
| 08 | Towel on the Sunbed | Web Exploitation / API Abuse | 🟠 Medium | [📄 Writeup](./Challenges/day-08-towel-on-the-sunbed.md) | [🖼️ View](./Screenshots/Challenge8/) |
| 09 | CryptoCabana | Cloud Security (Azure) | 🟠 Medium | [📄 Writeup](./Challenges/day-09-cryptocabana.md) | [🖼️ View](./Screenshots/Challenge9/) |
| 10 | The Hollow Shell | Web | 🟠 Medium | [📄 Writeup](./Challenges/day-10-thehollowshell.md) | [🖼️ View](./Screenshots/Challenge10/) |
| 11 | Infinity Pool | Boot2Root | 🟠 Medium | [📄 Writeup](./Challenges/day-11-InfinityPool.md) | [🖼️ View](./Screenshots/Challenge11/) |
| 12 | After Hours | Forensics | 🟠 Medium | [📄 Writeup](./Challenges/day-12-afterhours.md) | [🖼️ View](./Screenshots/Challenge12/) |
| 13 | The Guestbook | AI Security | 🟠 Medium | [📄 Writeup](./Challenges/day-13-theguestbook.md) | [🖼️ View](./Screenshots/Challenge13/) |
| 14 | Management Wants a Word | Forensics | 🔴 Hard | [📄 Writeup](./Challenges/day-14-managementwantsaword.md) | [🖼️ View](./Screenshots/Challenge14/) |

**Legend:** 🟢 Very Easy · 🟡 Easy · 🟠 Medium · 🔴 Hard

---

## 🌳 Directory Structure

```
Hacker-Holidays-2026-The-Byte-Lotus/
│
├── 📁 Challenges/
│   ├── day-01-the-concierge-knows-too-much.md
│   ├── day-02-room-404.md
│   ├── day-03-complimentary.md
│   ├── day-04-packed-light.md
│   ├── day-05-beach-bar.md
│   ├── day-06-overheard-at-breakfast.md
│   ├── day-07-do-not-disturb.md
│   ├── day-08-towel-on-the-sunbed.md
│   ├── day-09-cryptocabana.md
│   ├── day-10-the-hollow-shell.md
│   ├── day-11-infinity-pool.md
│   ├── day-12-after-hours.md
│   ├── day-13-the-guestbook.md
│   └── day-14-management-wants-a-word.md
│
├── 📁 Screenshots/
│   ├── Challenge1/
│   ├── Challenge2/
│   ├── Challenge3/
│   ├── Challenge4/
│   ├── Challenge5/
│   ├── Challenge6/
│   ├── Challenge7/
│   ├── Challenge8/
│   ├── Challenge9/
│   ├── Challenge10/
│   ├── Challenge11/
│   ├── Challenge12/
│   ├── Challenge13/
│   └── Challenge14/
│
└── 📄 README.md
```

---

## 🧠 Key Takeaways

Working through all 14 days reinforced technical skills across a wide spread of offensive security domains:

- **🕵️ OSINT Tradecraft** — Correlating fragments of information across social media posts, public profiles, and casual conversation leaks to reconstruct a bigger picture (`Day 6`), reinforcing that human-layer reconnaissance is often the fastest path to a foothold.
- **🤖 AI Prompt Injection & LLM Abuse** — Manipulating an AI agent's trust model through unverified identity claims and role manipulation (`Day 1`), and chaining indirect prompt injection with insecure tool-output handling to achieve unintended actions (`Day 13`) — a growing and increasingly critical class of vulnerability in AI-integrated systems.
- **🌐 Web & API Penetration Testing** — Exploiting exposed `.git` repositories, NoSQL injection, Server-Side Template Injection (SSTI), Zip Slip path traversal leading to RCE, and race conditions in business logic/API workflows (`Days 2, 7, 8, 10`).
- **☁️ Cloud Misconfiguration Analysis** — Abusing overly permissive AWS IAM policies and pivoting through Azure Storage, Key Vault, and Managed Identity trust relationships to escalate access (`Days 3, 9`).
- **🧬 Digital Forensics & Incident Response** — Performing PCAP traffic analysis and malware triage to trace data exfiltration (`Day 4`), analyzing fileless WMI persistence with reflective .NET assembly loading (`Day 12`), and recovering DPAPI-protected credentials to defeat encrypted volume protection (`Day 14`).
- **🔓 Privilege Escalation & Boot2Root Methodology** — Chaining OS command injection and unsafe YAML deserialization from initial foothold through to full privilege escalation on multi-stage boxes (`Days 5, 11`).
- **📝 Structured Reporting** — Practicing clear, reproducible documentation of root cause, exploitation steps, and remediation — a core skill for real-world penetration testing engagements and professional writeups.

---

## 🚀 Usage Guidelines

This section is organized for easy navigation and reference:

1. **Browse by day** — Use the [Challenge Matrix](#-challenge-matrix) above to jump directly to any writeup or its corresponding screenshots.
2. **Reading a writeup** — Each file in `Challenges/` follows a consistent structure: `Overview → Challenge Analysis → Root Cause → Exploitation Steps → Remediation/Takeaways`.
3. **Screenshots** — Supporting visual evidence for each challenge lives in its matching `Screenshots/ChallengeN/` folder, referenced inline within the corresponding writeup.
4. **Using this as a learning reference** — If you're attempting the event yourself, it's recommended to try each challenge independently before consulting these writeups, to get the most value out of the learning process.
5. **Contributions / Corrections** — Found an inaccuracy or have a cleaner approach to a challenge? Feel free to open an issue or pull request.

---

## ⚠️ Disclaimer

> This Directory is intended **strictly for educational and informational purposes**.
>
> All content documents activity performed within **TryHackMe's Hacker Holidays 2026** event — a legal, sanctioned, and intentionally vulnerable environment designed for security training. All systems, applications, and data referenced (including "The Byte Lotus" resort, its staff, and associated narrative elements) are **entirely fictional**.
>
> The techniques, tools, and methodologies described here should **never** be applied to systems, networks, or applications without **explicit, written authorization** from their owner. Unauthorized access to computer systems is illegal under laws such as the Computer Fraud and Abuse Act (CFAA) and equivalent legislation worldwide.
>
> The author assumes **no responsibility or liability** for any misuse of the information contained in this Directory. Use this knowledge responsibly, ethically, and only within legal boundaries — such as authorized labs, CTFs, and platforms like TryHackMe or HackTheBox.

---

