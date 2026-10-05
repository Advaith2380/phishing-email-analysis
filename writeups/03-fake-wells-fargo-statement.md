# Phishing Analysis: Fake Wells Fargo Monthly Statement

## Summary
- **Verdict:** Malicious
- **Phishing type:** Credential harvesting with a lookalike domain
- **Brand impersonated:** Wells Fargo
- **Sample source:** Nazario phishing corpus, phishing-2021
- **Date of email:** 3 Feb 2021

## Email Header Analysis
| Field | Value | Notes |
|---|---|---|
| Subject | Your Wells Fargo monthly statement is available. | Routine-looking lure, encoded in the raw header |
| From (display) | "Wellsfargo." <info@cargoholdinc[.]com> | Display name says Wells Fargo, domain is unrelated |
| To | Recipients <info@cargoholdinc[.]com> | Same address as From, real victims hidden (BCC) |
| Return-Path | info@cargoholdinc[.]com | Not a Wells Fargo domain |
| Reply-To | reply-...@mail.wellsfrgo[.]com | Lookalike domain: "wellsfrgo" is missing the "a" |
| Authenticated sender | admin@acaciasinvest[.]co[.]mz | Real mailbox used to send, likely compromised or abused |
| Originating IP | 198.46.81.9 (ecres155.servconfig.com) | Hosting provider server |
| First hop | ec2-3-226-255-163.compute-1.amazonaws.com [3.226.255.163] | Amazon cloud server |
| HELO name | EC2AMAZ-NTI22NP.ec2.internal | Default Windows cloud server name, a throwaway machine |
| Relay chain | ecres155.servconfig.com, then se4-iad1.servconfig.com (173.231.241.34), then the victim's mail server | Hosting provider mail servers |
| Authentication-Results | auth=pass for servconfig.com | Passes only for the attacker's own hosting account, says nothing about Wells Fargo |
| Date | Wed, 03 Feb 2021 11:16:06 +0000 | |

## Body Analysis
- The email contains login forms that point to a script called login.php, which means stolen data goes to a server the attacker controls.
- The page text mentions wellsfargo.com, but that is only decoration to make the code look real.
- The body was reviewed only briefly in this writeup, and the final destination of the form was not visited.

## Social Engineering Tactics
- Routine lure: "your monthly statement is available"
- Brand impersonation using the bank name and styling
- Lookalike domain in the Reply-To header
- Sloppy detail: trailing full stop in the display name "Wellsfargo."

## Key Findings
- The sender domain (cargoholdinc.com) has no connection to Wells Fargo.
- The Reply-To uses a misspelled domain (wellsfrgo.com), a typosquat.
- The email was sent from an Amazon cloud server through a hosting provider, using a different authenticated mailbox than the From address.
- Authentication shows "pass", but only for the attacker's own account. A pass does not mean the email is legitimate.
- Same pattern as writeup 02: To equals From, a cloud server with a default EC2AMAZ hostname, and an authenticated mailbox from an unrelated company.

## Indicators of Compromise
| Type | Value (defanged) | Source |
|---|---|---|
| IP | 198.46.81.9 | X-Originating-IP |
| IP | 3.226.255.163 | First Received header (AWS) |
| IP | 173.231.241.34 | Relay (shared hosting, block with care) |
| Domain | wellsfrgo[.]com | Reply-To (typosquat) |
| Domain | cargoholdinc[.]com | From and Return-Path |
| Email | info@cargoholdinc[.]com | From |
| Email | admin@acaciasinvest[.]co[.]mz | X-Authenticated-Sender |
| Hostname | ecres155.servconfig[.]com | Received header |
| HELO | EC2AMAZ-NTI22NP | Received header |
| Subject | Your Wells Fargo monthly statement is available. | Subject header |

## MITRE ATT&CK Mapping
- T1566 Phishing
- T1036 Masquerading (impersonating Wells Fargo)
- T1583.001 Acquire Infrastructure: Domains (lookalike domain)
- T1589.001 Gather Victim Identity Information: Credentials

## Recommended Response
- Quarantine mail where the display name contains "Wells Fargo" or "Wellsfargo" but the sender domain is not wellsfargo.com.
- Block the domains wellsfrgo.com and cargoholdinc.com, and the sender account.
- Search mail logs for the subject and purge matches.
- Tell users to check the sender domain, not just the display name.
- If any user entered credentials, reset their password and review the account for unusual activity.

## Detection Idea
Alert when the Reply-To domain differs from the From domain and either one is a close misspelling of a known brand. Also alert on display names containing a bank brand with a non-matching sender domain.


