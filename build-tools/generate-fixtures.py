#!/usr/bin/env python3
"""
Synthetic Fixture Generator for vuln-scan-prioritizer.
Generates multi-scanner CSV scan reports (Nessus, OpenVAS, Qualys, Rapid7)
using 100% synthetic RFC 5737 / RFC 3849 test IP blocks and mock hostnames.
Complies with Rule 7 (Zero-Emoji) and Rule 9 (Obvious Synthetic Mock Identifiers).
"""

import csv
import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

# 1. Tenable Nessus Enterprise Scan Export
def generate_nessus_fixture():
    nessus_path = FIXTURES_DIR / "fixture-nessus-enterprise-scan.csv"
    headers = [
        "Plugin ID", "CVE", "CVSS v3.0 Base Score", "Risk", "Host", 
        "Protocol", "Port", "Name", "Synopsis", "Description", "Solution", "Plugin Output"
    ]
    rows = [
        [
            "150123", "CVE-2023-44487", "7.5", "High", "synthetic-dmz-web-01.corp.example.com",
            "tcp", "443", "HTTP/2 Rapid Reset Vulnerability",
            "The remote web server is vulnerable to HTTP/2 Rapid Reset Denial of Service.",
            "An attacker can exploit HTTP/2 stream reset frames to cause resource exhaustion.",
            "Upgrade web server daemon to current patched release or disable HTTP/2 stream processing.",
            "HTTP/2 enabled on port 443 with rapid stream reset support detected."
        ],
        [
            "150124", "CVE-2023-44487", "7.5", "High", "synthetic-dmz-web-01.corp.example.com",
            "tcp", "8443", "HTTP/2 Rapid Reset Vulnerability",
            "The remote web server is vulnerable to HTTP/2 Rapid Reset Denial of Service.",
            "An attacker can exploit HTTP/2 stream reset frames to cause resource exhaustion.",
            "Upgrade web server daemon to current patched release or disable HTTP/2 stream processing.",
            "HTTP/2 enabled on port 8443 with rapid stream reset support detected."
        ],
        [
            "160450", "CVE-2023-38606", "9.8", "Critical", "synthetic-db-cluster-01.corp.example.com",
            "tcp", "5432", "PostgreSQL Buffer Overflow via Malformed Query",
            "The remote PostgreSQL database engine allows remote memory corruption.",
            "Unauthenticated remote code execution via buffer boundary failure.",
            "Apply PostgreSQL maintenance update 15.4 or higher.",
            "PostgreSQL version 15.2 detected on tcp/5432."
        ],
        [
            "170889", "CVE-2024-21413", "9.8", "Critical", "synthetic-app-internal-02.corp.example.com",
            "tcp", "445", "Microsoft Outlook / SMB NTLM Credential Reflection (MonikerLink)",
            "Remote attackers can bypass Protected View and leak NTLM hashes.",
            "Sending a specially crafted file: link triggers NTLM credential relay.",
            "Apply Microsoft security bulletin patch KB5034763.",
            "Unpatched SMB client configuration detected on port 445."
        ],
        [
            "140221", "CVE-2021-44228", "10.0", "Critical", "synthetic-dmz-gateway-01.corp.example.com",
            "tcp", "8080", "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
            "The remote Java application is vulnerable to unauthenticated remote code execution.",
            "Apache Log4j2 JNDI message lookup parsing allows external code loading.",
            "Upgrade Log4j to version 2.17.1 or remove JndiLookup.class from classpath.",
            "Vulnerable Log4j core jar 2.14.1 found in application archive."
        ],
        [
            "102401", "CVE-2022-22965", "9.8", "Critical", "synthetic-dmz-gateway-01.corp.example.com",
            "tcp", "8080", "Spring Framework Class Loader Access (Spring4Shell)",
            "Spring Framework RCE via Data Binding parameter manipulation.",
            "A Spring MVC or WebFlux application on JDK 9+ allows class loader binding.",
            "Upgrade Spring Framework to 5.3.18 or 5.2.20.",
            "Spring Framework 5.3.15 detected."
        ],
        [
            "100010", "", "", "None", "synthetic-dmz-web-01.corp.example.com",
            "tcp", "80", "Hypertext Transfer Protocol (HTTP) Service Detection",
            "An HTTP service is running on the remote host.",
            "Informational detection of web service.",
            "None required for informational finding.",
            "HTTP/1.1 200 OK returned."
        ],
        [
            "100011", "", "", "None", "synthetic-db-cluster-01.corp.example.com",
            "tcp", "22", "OpenSSH Server Service Banner",
            "An SSH server service is active on the host.",
            "Service discovery banner.",
            "None required.",
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        ],
        [
            "155230", "CVE-2022-0778", "7.5", "High", "synthetic-edge-vpn-01.corp.example.com",
            "tcp", "1194", "OpenSSL BN_mod_sqrt Infinite Loop Denial of Service",
            "Parsing malformed certificates triggers an infinite loop.",
            "Adversaries can trigger remote denial of service via invalid elliptic curve params.",
            "Upgrade OpenSSL package to version 1.1.1n or 3.0.2.",
            "OpenSSL 1.1.1f detected."
        ],
        [
            "155231", "CVE-2022-0778", "7.5", "High", "synthetic-edge-vpn-01.corp.example.com",
            "tcp", "443", "OpenSSL BN_mod_sqrt Infinite Loop Denial of Service",
            "Parsing malformed certificates triggers an infinite loop.",
            "Adversaries can trigger remote denial of service via invalid elliptic curve params.",
            "Upgrade OpenSSL package to version 1.1.1n or 3.0.2.",
            "OpenSSL 1.1.1f detected."
        ],
        [
            "180102", "CVE-2023-38545", "9.8", "Critical", "synthetic-dmz-web-01.corp.example.com",
            "tcp", "443", "cURL SOCKS5 Heap Buffer Overflow",
            "A heap-based buffer overflow flaw in the SOCKS5 proxy handshake.",
            "Hostnames longer than 255 bytes trigger heap corruption.",
            "Upgrade curl package to 8.4.0 or later.",
            "libcurl 8.2.1 detected in runtime container."
        ]
    ]

    with open(nessus_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"Generated Nessus fixture: {nessus_path} ({len(rows)} rows)")

# 2. Greenbone OpenVAS / GVM Export
def generate_openvas_fixture():
    openvas_path = FIXTURES_DIR / "fixture-openvas-infrastructure-scan.csv"
    headers = [
        "NVT OID", "CVEs", "Severity", "Host", "Port", 
        "NVT Name", "Summary", "Solution", "Vulnerability Insight"
    ]
    rows = [
        [
            "1.3.6.1.4.1.25623.1.0.147890", "CVE-2023-44487", "7.5", "192.0.2.15", "443/tcp",
            "HTTP/2 Rapid Reset Advisory",
            "Web server vulnerable to rapid stream cancellation DoS.",
            "Update nginx or apache to current patched release.",
            "CISA KEV item actively exploited in widespread DDoS campaigns."
        ],
        [
            "1.3.6.1.4.1.25623.1.0.147891", "CVE-2021-44228", "10.0", "192.0.2.20", "8080/tcp",
            "Apache Log4j Log4Shell Remote Code Execution",
            "Critical unauthenticated JNDI code execution.",
            "Update log4j package to 2.17.1 or newer.",
            "Public weaponized exploit available. CISA KEV listing."
        ],
        [
            "1.3.6.1.4.1.25623.1.0.147892", "CVE-2022-22965", "9.8", "192.0.2.20", "8080/tcp",
            "Spring Framework ClassLoader Vulnerability (Spring4Shell)",
            "Remote attackers can execute arbitrary code on Tomcat container.",
            "Upgrade Spring Core to version 5.3.18 or 5.2.20.",
            "Public exploit proof-of-concept verified."
        ],
        [
            "1.3.6.1.4.1.25623.1.0.147893", "CVE-2020-1472", "10.0", "192.0.2.50", "445/tcp",
            "Microsoft Netlogon Elevation of Privilege (Zerologon)",
            "Unauthenticated Netlogon cryptographic flaw allows Domain Controller takeover.",
            "Apply Microsoft KB4557222 and enforce secure RPC channel.",
            "Actively weaponized CISA KEV catalog entry."
        ],
        [
            "1.3.6.1.4.1.25623.1.0.147894", "CVE-2023-38545", "9.8", "192.0.2.15", "443/tcp",
            "cURL SOCKS5 Heap Buffer Overflow",
            "Buffer overflow when resolving hostnames through SOCKS5 proxy.",
            "Upgrade libcurl3 to 8.4.0.",
            "High impact memory corruption."
        ],
        [
            "1.3.6.1.4.1.25623.1.0.147895", "", "0.0", "192.0.2.15", "80/tcp",
            "Web Server Version Reporting",
            "Web server discloses version string in HTTP headers.",
            "Configure ServerTokens Prod in configuration file.",
            "Informational observation only."
        ]
    ]

    with open(openvas_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"Generated OpenVAS fixture: {openvas_path} ({len(rows)} rows)")

# 3. Qualys VMDR Export
def generate_qualys_fixture():
    qualys_path = FIXTURES_DIR / "fixture-qualys-vmdr-scan.csv"
    headers = [
        "QID", "CVE ID", "CVSS3 Base", "Severity", "IP", "DNS", 
        "Port", "Protocol", "Title", "Solution", "Results"
    ]
    rows = [
        [
            "378912", "CVE-2024-21413", "9.8", "5", "198.51.100.12", "synthetic-exchange-01.corp.example.com",
            "443", "TCP", "Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)",
            "Apply official vendor patch KB5034763 released in February 2024 security update.",
            "Vulnerable Exchange/Outlook integration detected on port 443."
        ],
        [
            "378913", "CVE-2023-44487", "7.5", "4", "198.51.100.12", "synthetic-exchange-01.corp.example.com",
            "443", "TCP", "HTTP/2 Rapid Reset Stream Cancellation Exhaustion",
            "Update frontend IIS / HTTP.sys or reverse proxy modules.",
            "HTTP/2 negotiated with RST_STREAM vulnerability present."
        ],
        [
            "378914", "CVE-2023-38606", "9.8", "5", "198.51.100.45", "synthetic-db-stage-01.corp.example.com",
            "5432", "TCP", "PostgreSQL Backend Memory Corruption Vulnerability",
            "Upgrade database cluster binaries to latest maintenance release.",
            "PostgreSQL 15.2 detected."
        ],
        [
            "378915", "CVE-2021-44228", "10.0", "5", "198.51.100.60", "synthetic-ops-monitor-01.corp.example.com",
            "8443", "TCP", "Apache Log4j JNDI Remote Code Execution Flaw",
            "Deploy Log4j 2.17.1 update across Java classpath.",
            "Vulnerable log4j-core-2.14.0.jar detected."
        ],
        [
            "10050", "", "", "1", "198.51.100.12", "synthetic-exchange-01.corp.example.com",
            "80", "TCP", "HTTP Server Banner Detection",
            "No remediation required for informational telemetry.",
            "Microsoft-IIS/10.0 detected."
        ]
    ]

    with open(qualys_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"Generated Qualys fixture: {qualys_path} ({len(rows)} rows)")

# 4. Rapid7 Nexpose Export
def generate_rapid7_fixture():
    rapid7_path = FIXTURES_DIR / "fixture-rapid7-nexpose-scan.csv"
    headers = [
        "Vulnerability ID", "CVEs", "CVSS Score", "Severity", "Asset IP Address", 
        "Asset Hostname", "Service Port", "Service Protocol", "Vulnerability Title", "Fix"
    ]
    rows = [
        [
            "cve-2020-1472", "CVE-2020-1472", "10.0", "Critical", "203.0.113.10",
            "synthetic-ad-dc-01.corp.example.com", "445", "tcp",
            "Netlogon Elevation of Privilege Vulnerability (Zerologon)",
            "Install security update KB4557222 and verify Domain Controller secure RPC settings."
        ],
        [
            "cve-2023-44487", "CVE-2023-44487", "7.5", "High", "203.0.113.25",
            "synthetic-web-portal-01.corp.example.com", "443", "tcp",
            "HTTP/2 Rapid Reset Denial of Service",
            "Patch nginx package to version 1.25.3 or apply rate limiting."
        ],
        [
            "cve-2021-44228", "CVE-2021-44228", "10.0", "Critical", "203.0.113.25",
            "synthetic-web-portal-01.corp.example.com", "8080", "tcp",
            "Apache Log4j RCE via JNDI Injection",
            "Upgrade log4j dependency to 2.17.1 or later."
        ],
        [
            "info-tls-10", "", "0.0", "Informational", "203.0.113.25",
            "synthetic-web-portal-01.corp.example.com", "443", "tcp",
            "TLS 1.0 / 1.1 Deprecation Notice",
            "Disable TLS 1.0 and 1.1 in web server configuration."
        ]
    ]

    with open(rapid7_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"Generated Rapid7 fixture: {rapid7_path} ({len(rows)} rows)")

# 5. CISA KEV Catalog Reference Fixture
def generate_cisa_kev_fixture():
    kev_path = FIXTURES_DIR / "fixture-cisa-kev.json"
    kev_data = {
        "title": "CISA Known Exploited Vulnerabilities Catalog (Synthetic Subset)",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j2 JNDI Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 contains an insecure JNDI lookup vulnerability leading to remote code execution.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known"
            },
            {
                "cveID": "CVE-2020-1472",
                "vendorProject": "Microsoft",
                "product": "Windows Server",
                "vulnerabilityName": "Microsoft Netlogon Cryptographic Bypass (Zerologon)",
                "dateAdded": "2021-11-03",
                "shortDescription": "Flaw in MS-NRPC allows unauthenticated attacker to obtain domain administrator rights.",
                "requiredAction": "Apply vendor security updates.",
                "dueDate": "2021-11-17",
                "knownRansomwareCampaignUse": "Known"
            },
            {
                "cveID": "CVE-2023-44487",
                "vendorProject": "Multiple Vendors",
                "product": "HTTP/2 Protocol",
                "vulnerabilityName": "HTTP/2 Rapid Reset Denial-of-Service Vulnerability",
                "dateAdded": "2023-10-10",
                "shortDescription": "HTTP/2 protocol allows stream cancellation abuse triggering high CPU and DoS conditions.",
                "requiredAction": "Apply patches or mitigate HTTP/2 stream cancellations.",
                "dueDate": "2023-10-31",
                "knownRansomwareCampaignUse": "Unknown"
            },
            {
                "cveID": "CVE-2024-21413",
                "vendorProject": "Microsoft",
                "product": "Outlook",
                "vulnerabilityName": "Microsoft Outlook Remote Code Execution Vulnerability",
                "dateAdded": "2024-02-15",
                "shortDescription": "Parsing of specially crafted URLs allows unauthenticated remote attackers to bypass Protected View.",
                "requiredAction": "Apply vendor patches.",
                "dueDate": "2024-02-29",
                "knownRansomwareCampaignUse": "Known"
            },
            {
                "cveID": "CVE-2022-22965",
                "vendorProject": "VMware",
                "product": "Spring Framework",
                "vulnerabilityName": "Spring Framework Remote Code Execution (Spring4Shell)",
                "dateAdded": "2022-04-04",
                "shortDescription": "Data binding parameter vulnerability leading to remote code execution.",
                "requiredAction": "Apply vendor patches.",
                "dueDate": "2022-04-25",
                "knownRansomwareCampaignUse": "Known"
            }
        ]
    }
    with open(kev_path, "w", encoding="utf-8") as f:
        json.dump(kev_data, f, indent=2)
    print(f"Generated CISA KEV fixture: {kev_path} ({len(kev_data['vulnerabilities'])} entries)")

if __name__ == "__main__":
    generate_nessus_fixture()
    generate_openvas_fixture()
    generate_qualys_fixture()
    generate_rapid7_fixture()
    generate_cisa_kev_fixture()
    print("All synthetic scan fixtures generated successfully.")
