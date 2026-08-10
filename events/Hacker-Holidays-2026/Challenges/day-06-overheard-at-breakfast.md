# Challenge 6: Overheard at Breakfast

## Overview

| Field | Value |
|---|---|
| **Platform** | TryHackMe |
| **Event** | Hacker Holidays 2026 |
| **Category** | OSINT |
| **Difficulty** | Easy |
| **Challenge Type** | Open Source Intelligence (OSINT) |

---

## Objective

Analyze a captured conversation between two people, extract clues leading to a hidden account, and obtain the flag.

---

## Reconnaissance and Analysis

While reading the conversation, it became clear that it contained information that seemed ordinary but included several indicators exploitable in an OSINT investigation.

![Challenge 6](../Screenshots/Challenge6/Overheard-at-Breakfast1.png)

The key observations were:

- A clearly visible email address belonging to the target:
  ```
  lambobytelotushotel@gmail.com
  ```
- The person stated that they don't use social media much.
- A very important hint in the statement:
  > *I used to use this free tool that let me upload my profile and link other media accounts... Started with a G.*

  This hint pointed to a service starting with the letter **G**, used to link different accounts.

After analyzing the hint, it was concluded that the service in question was **Gravatar**, since it relies on an email address to build a profile and link a user's various accounts.

### Tools Used

- Browser
- Gravatar service
- Linux Terminal
- `md5sum`
- `base64`

### Rationale for the Next Step

The presence of the email address, combined with the clear reference to a service starting with "G," made **Gravatar** the most likely candidate. The next step was therefore to compute the MD5 hash of the email address to access the associated profile.

---

## Root Cause

This challenge does not rely on a traditional security vulnerability, but rather on **information disclosure** resulting from sharing personal data that can be leveraged in OSINT investigations.

The issue arose due to:

- Sharing a real email address.
- Referencing the Gravatar service.
- Gravatar's reliance on the MD5 hash of an email address to grant access to the associated profile once the email is known.

This type of information allows an attacker to access data that was not meant to be easily discoverable.

---

## Discovery Process

The solution path was identified by carefully analyzing the conversation rather than through random searching. The indicators that led to the solution were:

- A complete email address.
- A mention of a free service starting with "G."
- A description of the service as one that links social media accounts.

The following steps were then carried out:

1. Extract the email address.
2. Compute its MD5 hash.
3. Use the MD5 hash to access the Gravatar profile page.
4. Review the data present within the profile.

These steps were successful, and an encoded string was found within the profile.

---

## Exploitation Steps

### Step 1 — Computing the MD5 Hash of the Email Address

```
echo -n "lambobytelotushotel@gmail.com" | md5sum
```

![Challenge 6](../Screenshots/Challenge6/Overheard-at-Breakfast2.png)

**Reason:** Gravatar relies on the MD5 hash of an email address to determine which profile to display.

### Step 2 — Accessing the Gravatar Profile

The following URL was opened:

```
https://gravatar.com/<MD5_HASH>
```

replacing `<MD5_HASH>` with the value obtained in the previous step.

**Result:** Access was gained to the profile of the user **"Lambo."**

### Step 3 — Extracting the Encoded Text

The following string was found within the profile:

```
VEhNe1MzY3JlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9
```

### Step 4 — Decoding the Base64 String

```
echo 'VEhNe1MzY3JlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9' | base64 -d
```

![Challenge 6](../Screenshots/Challenge6/Overheard-at-Breakfast3.png)

**Result:**
```
THM{*****}
```

---

## Result

Access was gained to the user's hidden profile via Gravatar. An encoded Base64 string was extracted from the profile, and after decoding it, the flag was obtained:

```
THM{*****}
```

The challenge did not require:

- Obtaining a shell.
- Performing remote code execution.
- Privilege escalation.

The objective was to conduct a successful OSINT investigation to locate the hidden account and extract the flag.

---

## Mitigation

To reduce the risk of this type of information disclosure, the following measures can be applied:

- Avoid sharing a real email address in public conversations.
- Use a separate email address for public-facing services.
- Review Gravatar privacy settings and remove unnecessary information.
- Avoid linking different personal accounts through a public service unless necessary.
- Use profile pictures or accounts that do not rely on a primary email address.
- Periodically review one's digital footprint to reduce the amount of information available to attackers.

---

## Lessons Learned

- Learned the importance of carefully analyzing text and not overlooking any clue within a challenge.
- Learned how the Gravatar service works and its reliance on the MD5 hash of an email address.
- Learned how to use Linux commands such as `md5sum` and `base64` during OSINT investigations.
- Realized that simple information, such as an email address, can lead to the disclosure of profiles and other accounts.
- Learned that successful OSINT investigations often depend on connecting several small pieces of evidence to reach the final target.

---

## References

- [Gravatar service documentation on how profiles are generated using email addresses.](https://docs.gravatar.com/sdk/profiles/)

