# CISA Known Exploited Vulnerabilities (KEV) Catalog Reference

This reference details the role of the Cybersecurity and Infrastructure Security Agency (CISA) KEV catalog in enterprise vulnerability prioritization and how `vuln-scan-prioritizer` utilizes it to eliminate scan noise.

---

## 1. Why KEV Overrides Static CVSS

Vulnerability databases contain over 240,000 published CVEs. However, empirical threat research by CISA and EPSS (Exploit Prediction Scoring System) reveals that **fewer than 4% of published CVEs are ever exploited in the wild**.

Relying solely on CVSS base scores causes security teams to spend thousands of hours patching theoretical CVSS 9.8 vulnerabilities on non-exposed internal machines while ignoring CVSS 7.5 vulnerabilities (such as HTTP/2 Rapid Reset or VPN perimeter flaws) that are being actively weaponized by ransomware syndicates.

`vuln-scan-prioritizer` incorporates KEV indicators as the highest priority tier:
- If a vulnerability is listed in the CISA KEV catalog, it automatically receives a **+3.0 score boost**.
- If that vulnerability is also located on an internet-facing host, it immediately escalates to **Wave 1 (Emergency 24-Hour SLA)** regardless of its initial scanner base severity rating.

---

## 2. Default Embedded KEV Signatures

`vuln-scan-prioritizer` includes embedded threat signatures for high-impact enterprise perimeter vulnerabilities:

| CVE | Vulnerability Name / Component | Typical Port | Ransomware / Active Exploitation |
| :--- | :--- | :--- | :--- |
| `CVE-2021-44228` | Apache Log4j2 JNDI RCE (Log4Shell) | 8080, 8443 | Widespread active exploitation |
| `CVE-2020-1472` | Microsoft Netlogon EoP (Zerologon) | 445 | Active Domain Controller takeover |
| `CVE-2023-44487` | HTTP/2 Rapid Reset Stream Cancellation | 443, 8443 | Record DDoS campaigns |
| `CVE-2024-21413` | Microsoft Outlook MonikerLink NTLM Leak | 445, 443 | Targeted enterprise credential theft |
| `CVE-2022-22965` | VMware / Spring Framework RCE (Spring4Shell) | 8080 | Active botnet and shell drops |
| `CVE-2023-38545` | cURL / libcurl SOCKS5 Heap Buffer Overflow | 443 | High-impact memory corruption |
| `CVE-2023-27997` | FortiOS SSL-VPN Pre-Auth RCE | 443, 10443 | State-sponsored perimeter breach |
| `CVE-2023-34362` | Progress Software MOVEit Transfer SQLi | 443 | Cl0p ransomware mass exfiltration |
| `CVE-2024-3400` | Palo Alto PAN-OS Command Injection | 443 | Threat actor zero-day campaigns |
| `CVE-2017-0144` | Microsoft SMBv1 Remote Code Execution (EternalBlue) | 445 | WannaCry / NotPetya worm campaigns |

---

## 3. Loading Custom / Live KEV Feeds

To ingest daily updated CISA KEV feeds, download the official CISA JSON catalog (`known_exploited_vulnerabilities.json`) and pass it to `vuln_prioritizer.py`:

```bash
# Ingest live CISA KEV feed
python scripts/vuln_prioritizer.py -i scan_export.csv --kev-file known_exploited_vulnerabilities.json
```
