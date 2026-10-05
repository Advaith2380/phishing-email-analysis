\# Phishing Email Analysis



SOC-style investigations of real phishing emails. Each writeup covers header analysis, body and URL review, indicator extraction (IOCs), MITRE ATT\&CK mapping, a recommended response, and a detection idea.



All samples come from the public Nazario phishing corpus (phishing-2021), published for research.



\## Writeups



| # | Title | Type | Verdict |

|---|---|---|---|

| 01 | \[Fake FedEx shipment](writeups/01-fake-fedex-shipment.md) | Brand impersonation, payment lure | Malicious |

| 02 | \[Fake Fidelity login form](writeups/02-fake-fidelity-login-form.md) | Credential harvesting (form inside the email) | Malicious |

| 03 | \[Fake Wells Fargo statement](writeups/03-fake-wells-fargo-statement.md) | Credential harvesting, lookalike domain | Malicious |

| 04 | \[Fake voicemail recording](writeups/04-fake-voicemail-recording.md) | Voicemail lure, link to a free-hosting page | Malicious |



\## Patterns Seen Across the Samples



\- \*\*Display name vs real sender:\*\* the visible name says FedEx, Fidelity or Wells Fargo, but the sending domain has no connection to the brand.

\- \*\*Abused trusted infrastructure:\*\* the FedEx email went through SendGrid, so the sending IP looked clean. Several others came from Amazon cloud servers with default Windows hostnames (EC2AMAZ-...) through hosting providers.

\- \*\*Lookalike domains:\*\* the Wells Fargo email used a misspelled Reply-To domain (wellsfrgo.com).

\- \*\*Authentication can pass and still be malicious:\*\* SPF, DKIM or SMTP auth passed, but only for the attacker's own account or hosting provider, not for the impersonated brand.

\- \*\*Hidden recipients:\*\* in writeups 02 and 03, To and From are the same address, which hides the real victims in BCC.

\- \*\*Link hiding:\*\* tracking redirects (writeup 01) and free hosting pages (writeup 04) hide the real destination.

\- \*\*Pressure tactics:\*\* urgency, fear and money (48-hour deadline, service suspension, handling fee).



\## MITRE ATT\&CK Techniques Referenced



| ID | Technique |

|---|---|

| T1566 / T1566.002 | Phishing / Phishing: Spearphishing Link |

| T1204.001 | User Execution: Malicious Link |

| T1036 | Masquerading |

| T1583.001 | Acquire Infrastructure: Domains |

| T1589.001 | Gather Victim Identity Information: Credentials |



\## Method



1\. Read the raw headers: From, Return-Path, Reply-To, Received chain, DKIM signer, authentication results.

2\. Compare the claimed sender with the real sending path.

3\. Review the body: links, forms, hidden content, tracking pixels.

4\. Extract indicators and defang them (hxxps://, \[.]).

5\. Map to MITRE ATT\&CK and write a response and a detection idea.



Static analysis only. No links were opened and nothing was detonated.



\## Tools



PowerShell (extracting emails from the mbox file), CyberChef (Base64 decoding), VirusTotal, urlscan.io, MXToolbox / Google Admin Toolbox Messageheader.



\## Safety Notes



\- Raw samples are never committed. The `samples/` folder is in `.gitignore`.

\- All URLs, domains and addresses in the writeups are defanged.

\- A few details were not verified: form submit destinations were not fully extracted, and the voicemail link may come from a sibling email in the same campaign. Each writeup states these limits.



\## Repository Layout



\- `writeups/` : one markdown file per analyzed email, plus `\_template.md`

\- `samples/` : local only, ignored by Git

\- `README.md` : this file



\## Template



New writeups start from \[writeups/\_template.md](writeups/\_template.md).



\## Related



See my \[soc-detection-lab](https://github.com/Advaith2380/soc-detection-lab) repository for Sigma detection rules and SOC incident writeups.

