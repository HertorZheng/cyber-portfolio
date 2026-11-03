# TShark Challenge I: Teamwork (TryHackMe)

_A hands-on blue team packet analysis project using TShark to extract IOCs and validate them with VirusTotal._

---

## Table of Contents
- [Project Summary](#project-summary)
- [Skills Demonstrated](#skills-demonstrated)
- [Investigation Process](#investigation-process)
  - [Stage 1: Enumerate Contacted Domains (DNS)](#stage-1-enumerate-contacted-domains-dns)
  - [Stage 2: Reconstruct the Full Malicious URL (HTTP)](#stage-2-reconstruct-the-full-malicious-url-http)
  - [Stage 3: VirusTotal Enrichment & First-Seen](#stage-3-virustotal-enrichment--first-seen)
  - [Stage 4: Identify Brand Impersonation](#stage-4-identify-brand-impersonation)
  - [Stage 5: Resolve Malicious IP (Passive DNS)](#stage-5-resolve-malicious-ip-passive-dns)
  - [Stage 6: Extract Email Indicators (No Parsed SMTP)](#stage-6-extract-email-indicators-no-parsed-smtp)
- [IOCs (Defanged)](#iocs-defanged)
- [Detections](#detections)
  - [Sigma (Web/Proxy Logs)](#sigma-webproxy-logs)
  - [Suricata (Network IDS)](#suricata-network-ids)
- [Lessons Learned](#lessons-learned)
- [What I’d Improve Next Time](#what-id-improve-next-time)

---

## Project Summary
**Goal:** Investigate `teamwork.pcap` to identify a suspicious domain/URL reported by threat research, enrich with VirusTotal, and produce actionable indicators and detections.

**Outcome:** Extracted the phishing URL, mapped it to **PayPal impersonation**, identified its **IP**, and recovered an **email address** associated with activity in the capture. Noted a realistic intel discrepancy between historical VirusTotal “first submission” and the live database today.

---

## Skills Demonstrated
- Network forensics with **TShark** (DNS/HTTP filtering, field extraction)
- Threat intel enrichment (**VirusTotal**)
- IOC management & defanging for safe reporting
- Detection engineering (Sigma / Suricata)
- Clear documentation of methodology and caveats

---

## Investigation Process

### Stage 1: Enumerate Contacted Domains (DNS)
List unique DNS queries from the PCAP:
```bash
tshark -r teamwork.pcap -Y dns -T fields -e dns.qry.name | sort -u
```
**Findings (examples):**
- `toolbarqueries.google.com`
- `wittyserver.hsd1.md.comcast.net`
- `www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com`  ⟵ **suspicious**

---

### Stage 2: Reconstruct the Full Malicious URL (HTTP)
Pull host + URI from HTTP requests to build the full URL:
```bash
tshark -r teamwork.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```
> Combine `http.host` and `http.request.uri` → **Full URL**  
> `http://www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com/<path-if-any>`

_Defanged (final used in the room):_  
`hxxp[:]//www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com`

---

### Stage 3: VirusTotal Enrichment & First-Seen
- Search **the full URL** in VirusTotal (URL object, not just the base domain).
- **Reality check:** VT is dynamic. My live lookup showed a recent first-seen, but the lab expects the historical one.

**Answer used (historical, matches room key):**  
`17 Apr 2017 22:52:53 UTC`

> _Note_: In 2024, VT may show your own submission time as “first seen” if the specific URL object aged out. I documented both values and why they differ.

---

### Stage 4: Identify Brand Impersonation
The label `paypal.com` at the **left** of a longer hostname is a classic phishing trick. The **registered domain** is `timeseaways.com`.

**Service impersonated:** **PayPal**

---

### Stage 5: Resolve Malicious IP (Passive DNS)
From VT **Relations** (Passive DNS) or from DNS A answers in PCAP:
```bash
tshark -r teamwork.pcap -Y "dns.a" -T fields -e dns.qry.name -e dns.a
```
**IP observed:** `184.154.127.226` → defanged: `184[.]154[.]127[.]226`

---

### Stage 6: Extract Email Indicators (No Parsed SMTP)
The PCAP didn’t expose parsed `smtp.mailfrom/rcptto` fields (likely no cleartext SMTP). Fallback to printable strings/email patterns:

```bash
# Quick and dirty string scan
strings teamwork.pcap | grep -iE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

# Or with tshark payload/text lines
tshark -r teamwork.pcap -T fields -e data-text-lines   | grep -iE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
```

**Email recovered:** `johnny5alive@gmail.com`  
**Defanged:** `johnny5alive[at]gmail[.]com`

---

## IOCs (Defanged)

| Type  | Indicator |
|------|-----------|
| URL  | `hxxp[:]//www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com` |
| Domain | `www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com` |
| IP   | `184[.]154[.]127[.]226` |
| Email | `johnny5alive[at]gmail[.]com` |
| Brand | **PayPal** (impersonation) |
| VT First-Seen (historical) | `17 Apr 2017 22:52:53 UTC` |

---

## Detections

### Sigma (Web/Proxy Logs)
Alert when `Host` header contains a high-value brand but **is not** an actual brand domain.
```yaml
title: Brand Impersonation in Host Header (Non-Canonical Domain)
id: web_brand_impersonation_host_not_paypal
status: experimental
logsource:
  product: webserver
  category: webserver
detection:
  sel:
    cs-host|contains: 'paypal.com'
  filter_legit:
    cs-host|endswith: '.paypal.com'
  condition: sel and not filter_legit
level: medium
tags:
  - attack.t1566.002
```

### Suricata (Network IDS)
```suricata
alert http any any -> any any (
  msg:"Phish: PayPal brand in Host not under paypal.com";
  http.host; content:"paypal.com"; nocase;
  http.host; pcre:!"\.paypal\.com$";
  classtype:trojan-activity; sid:42000421; rev:1;
)
```

---

## Lessons Learned
- **CLI > GUI** for fast IOC extraction at scale (TShark fields + UNIX pipes).
- VT **URL object vs domain object** can show different “first-seen” times; always document context.
- If protocol parsers fail (e.g., SMTP over TLS), fall back to **payload string searches** for emails/creds.
- Defang everything in reports to avoid accidental clicks/executions.

---

## What I’d Improve Next Time
- Generate **Zeek** logs from the PCAP (`zeek -Cr teamwork.pcap`) for richer pivots (dns.log/http.log).
- Automate enrichment (hash/domain/IP → VT API) and IOC CSV export.
- Add brand-spoofing detection to a home lab proxy and simulate alerts.
