\# Phishing Analysis: Fake FedEx Shipment Notification



\## Summary

\- \*\*Verdict:\*\* Malicious

\- \*\*Phishing type:\*\* Brand impersonation with a payment lure (fake FedEx "unpaid handling fee")

\- \*\*Sample source:\*\* Nazario phishing corpus, phishing-2021

\- \*\*Date of email:\*\* 8 Jan 2021



\## Email Header Analysis

| Field | Value | Notes |

|---|---|---|

| From | shipment@fedex.com | Claimed sender, easy to fake |

| Return-Path | bounces+...@sendgrid.net | Real bounce address is SendGrid, not FedEx |

| Originating IP | 167.89.100.244 | SendGrid mail server |

| Received (earlier hop) | from fedex.com (unknown) | Claimed name could not be verified |

| DKIM signer | sendgrid.net | Signed by SendGrid, not fedex.com |

| Message-ID | ...@fedex.com | Faked to look like FedEx |

| Subject (decoded) | FedEx Shipment Notification 384789299 | Base64 encoded in the raw header |



\## Body and URL Analysis

| Item | Value (defanged) | Notes |

|---|---|---|

| Displayed link text | hxxps:/fedex\[.]com/en-fr/tracking/domestic/cost-shipping/384789299 | Looks like FedEx, has a malformed single slash |

| Real link (href) | hxxps://u15559054\[.]ct\[.]sendgrid\[.]net/ls/click?upn=... | SendGrid click-tracking redirect, final destination hidden in the encoded parameter |

| Tracking pixel | hxxps://u15559054\[.]ct\[.]sendgrid\[.]net/wf/open?upn=... | 1x1 image, tells the sender the email was opened |



The final destination was not visited, because this was static analysis only.



\## Social Engineering Tactics

\- Urgency: 48 hours to recover the package

\- Fear and money: package "returned", handling fee of 6,53 USD

\- Generic greeting: "Dear Customer"

\- Poor grammar and odd formatting

\- Real FedEx logo hotlinked from fedex.com to look genuine



\## Key Findings

\- The email claims to be from fedex.com but was sent through SendGrid, a bulk email service.

\- The visible link text does not match the real link target.

\- The attacker abused a trusted email provider, so the sending IP is not obviously bad.

\- The plain-text part is almost empty, and only the HTML part has content.

\- The subject was Base64 encoded.



\## Indicators of Compromise

| Type | Value (defanged) | Source |

|---|---|---|

| IP | 167.89.100.244 | Received header (SendGrid, do not block, abused service) |

| Email | shipment@fedex.com | From header (spoofed) |

| Subject | FedEx Shipment Notification 384789299 | Subject header |

| URL | hxxps://u15559054\[.]ct\[.]sendgrid\[.]net/ls/click | HTML body link |

| Tracking ID | 384789299 | Subject and fake URL |



\## MITRE ATT\&CK Mapping

\- T1566.002 Phishing: Spearphishing Link

\- T1204.001 User Execution: Malicious Link



\## Recommended Response

\- Quarantine emails where the From domain is fedex.com but the sender is not FedEx infrastructure.

\- Search mail logs for the same subject pattern and the SendGrid click-tracking URL, and purge matches.

\- Warn users about fake shipment and fee notifications.

\- Do not block sendgrid.net itself, because it is a legitimate service.



\## Detection Idea

Alert on mail where the From domain is fedex.com and SPF or DMARC does not pass for fedex.com. Also alert on subjects matching "FedEx Shipment Notification" followed by digits.

