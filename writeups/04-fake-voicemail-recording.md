# Phishing Analysis: Fake Voicemail "New Recording" Notification

## Summary
- **Verdict:** Malicious
- **Phishing type:** Fake voicemail/recording lure (generic "Support" sender, no brand)
- **Sample source:** Nazario phishing corpus, phishing-2021
- **Date of email:** 20 Jan 2021

## Email Header Analysis
| Field | Value | Notes |
|---|---|---|
| Subject | New Recording [13913670] | Generic lure with a fake reference number |
| From (display) | "Support" <info@baliyev[.]com> | Generic name, unrelated domain |
| To | jose@monkey.org | Single named recipient |
| Return-Path | info@baliyev[.]com | Same as From |
| Originating host | ec2-3-90-164-29.compute-1.amazonaws.com | Amazon cloud server |
| Originating IP | 3.90.164.29 | AWS us-east-1 |
| Relay | linuxhosting.cloudinhost[.]com (138.201.18.59) | Hosting provider mail server, Exim 4.93 |
| DKIM signer | xn--scherenhebebhnen-uzb[.]com | Different from the From domain, punycode (internationalized) domain |
| Message-ID | ...@baliyev[.]com | |
| Date | 20 Jan 2021 08:21:25 +0000 | |

## Body Analysis
- The email is HTML with embedded inline images (app download icons) to look like a real voicemail service.
- Voicemail-style emails in the same sample link to a page on a free Firebase hosting address: hxxps://mayaadri-an32[.]web[.]app/mkasiwas.html#jose@monkey.org
- The victim's email address is placed after the # so the fake page looks personalized.
- The link was extracted from the same sample file, and may come from a sibling email in the same campaign rather than this exact message. The page was not visited.

## Social Engineering Tactics
- Curiosity: a recording is waiting for you
- Urgency: a time limit on the message link
- Authority: generic "Support" sender
- Fake reference number [13913670] to look like a ticket

## Key Findings
- No brand is impersonated, the lure relies on curiosity alone.
- The From domain (baliyev.com) is unrelated, and the DKIM signature comes from a different domain.
- The mail came from an Amazon cloud server through a hosting provider, the same pattern as writeups 02 and 03.
- The same email appears three times in the sample, so it was sent in bulk.

## Indicators of Compromise
| Type | Value (defanged) | Source |
|---|---|---|
| IP | 3.90.164.29 | First Received header (AWS) |
| IP | 138.201.18.59 | Relay (shared hosting, block with care) |
| Domain | baliyev[.]com | From and Return-Path |
| Domain | xn--scherenhebebhnen-uzb[.]com | DKIM signer |
| Email | info@baliyev[.]com | From |
| Hostname | linuxhosting.cloudinhost[.]com | Received header |
| Subject | New Recording [13913670] | Subject header |
| URL | hxxps://mayaadri-an32[.]web[.]app/mkasiwas.html | Body link in voicemail-style emails (free Firebase hosting) |

## MITRE ATT&CK Mapping
- T1566.002 Phishing: Spearphishing Link
- T1204.001 User Execution: Malicious Link
- T1036 Masquerading

## Recommended Response
- Block the sender domain, the DKIM domain and the originating IP.
- Search mail logs for the subject pattern "New Recording [" followed by digits and purge matches.
- Warn users about unexpected voicemail or recording notifications.
- If a user clicked the link, reset their password and check for unusual sign-ins.

## Detection Idea
Alert when the DKIM signing domain does not match the From domain and the subject matches voicemail or recording keywords. Also alert on messages with a generic "Support" display name from a domain with no history in your mail logs.