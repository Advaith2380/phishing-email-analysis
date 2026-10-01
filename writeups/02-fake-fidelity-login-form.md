# Phishing Analysis: Fake Fidelity "Service Suspension" Login Form

## Summary
- **Verdict:** Malicious
- **Phishing type:** Credential harvesting (login form embedded in the email body)
- **Brand impersonated:** Fidelity Investments
- **Sample source:** Nazario phishing corpus, phishing-2021
- **Date of email:** 27 Jan 2021

## Email Header Analysis
| Field | Value | Notes |
|---|---|---|
| Subject | Service Suspension Notification. | Fear lure: your service will be suspended |
| From (display) | "Fidelity Investments." <bcornett@pacific[.]net> | Display name says Fidelity, the address is unrelated to Fidelity |
| To | Recipients <bcornett@pacific[.]net> | Fake placeholder, real victims were hidden (BCC) |
| Return-Path | bcornett@pacific[.]net | Same unrelated address |
| Authenticated sender | smtpfox-r7b6q@alternavida[.]com[.]mx | Real account used to send, different from the From address, likely a compromised or abused mailbox |
| Originating host | ec2-13-232-241-52.ap-south-1.compute.amazonaws.com | Amazon cloud server, not Fidelity or pacific.net |
| Originating IP | 13.232.241.52 | AWS ap-south-1 (Mumbai) |
| HELO name | EC2AMAZ-N86J32E | Default Windows cloud server name, a throwaway machine |
| Relay | ded3192.inmotionhosting.com (144.208.68.91) | Hosting provider mail server, Exim 4.93 |
| Date | Wed, 27 Jan 2021 16:57:27 +0000 | |

## Body Analysis
- The email contains a full fake login form, not a link to a login page.
- Fields requested: **Email Address, Email Password, Mobile Number**, with an "Update Account" button.
- Fidelity never asks for an email password, so the purpose is to steal email credentials and a phone number.
- Fidelity branding and styling were copied. The CSS also references the font "Wells Fargo Sans", which suggests the kit was reused from a fake Wells Fargo email.
- Many links (Register Now, FAQ, Online Security) have junk values such as "dhwjbwkjdbkjw", so they go nowhere and only make the page look real.
- The form submit destination was not extracted in this analysis.

## Social Engineering Tactics
- Fear: "Service Suspension Notification"
- Authority: bank branding and a realistic layout
- Convenience: the victim does not have to click out, the form is right in the email
- Trailing full stop in the display name "Fidelity Investments." (sloppy detail)

## Key Findings
- The From domain (pacific.net) has no connection to Fidelity.
- The mail was sent from a cloud server (AWS) through a hosting provider, with a different authenticated sender than the From address.
- To and From are the same address, a common trick to hide the real recipients.
- The email asks for credentials directly inside the message.

## Indicators of Compromise
| Type | Value (defanged) | Source |
|---|---|---|
| IP | 13.232.241.52 | First Received header (AWS) |
| IP | 144.208.68.91 | Relay (InMotion Hosting, shared host, block with care) |
| Hostname | ec2-13-232-241-52.ap-south-1.compute.amazonaws[.]com | Received header |
| Email | bcornett@pacific[.]net | From and Return-Path |
| Email | smtpfox-r7b6q@alternavida[.]com[.]mx | X-Authenticated-Sender |
| Subject | Service Suspension Notification. | Subject header |
| HELO | EC2AMAZ-N86J32E | Received header |

## MITRE ATT&CK Mapping
- T1566 Phishing
- T1036 Masquerading (impersonating Fidelity)
- T1589.001 Gather Victim Identity Information: Credentials

## Recommended Response
- Quarantine mail where the display name contains "Fidelity" but the sender domain is not fidelity.com.
- Block the originating IP and the authenticated sender account.
- Search mail logs for the subject "Service Suspension Notification" and purge matches.
- Tell users that real banks never ask for an email password inside an email.
- If any user submitted the form, reset their email password and review the mailbox for forwarding rules.

## Detection Idea
Alert on inbound mail where the display name matches a known brand (Fidelity, Wells Fargo, DocuSign) and the sender domain does not match the brand's real domain. Also alert on HTML emails containing password input fields.