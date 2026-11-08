# Scanner Column Mapping Matrix

This reference documents how `vuln-scan-prioritizer` maps and normalizes heterogenous CSV column headers across leading vulnerability management platforms into a unified analytical finding schema.

---

## 1. Unified Schema Definitions

Each scanner CSV row is ingested and converted into an internal `Finding` model:

| Internal Field | Type | Description |
| :--- | :--- | :--- |
| `finding_id` | String | Scanner unique identifier (Plugin ID, QID, NVT OID, or Vuln ID) |
| `cves` | List[String] | Extracted and normalized CVE identifiers (`CVE-YYYY-NNNN+`) |
| `cvss_base` | Float | Normalized CVSS v3.x score (0.0 to 10.0) |
| `raw_severity` | String | Qualitative scanner risk rating (Critical, High, Medium, Low, None) |
| `host` | String | Fully qualified domain name (FQDN) or IP address of the target |
| `port` | String | Service port number (e.g., `443`, `8080`) or `0` for host-level |
| `protocol` | String | Transport protocol (`tcp`, `udp`) |
| `title` | String | Vulnerability synopsis, title, or advisory headline |
| `solution` | String | Remediation advisory, vendor fix guidance, or package upgrade instructions |
| `remediation_package` | String | Deduplication cluster target (e.g., `OpenSSL Cryptographic Library`, `Apache Log4j2 Library`) |

---

## 2. Multi-Scanner Column Mapping

The engine applies case-insensitive, fuzzy header discovery to match varying export templates:

| Internal Field | Tenable Nessus | Greenbone OpenVAS / GVM | Qualys VMDR | Rapid7 Nexpose / InsightVM |
| :--- | :--- | :--- | :--- | :--- |
| **Identifier** | `Plugin ID`, `ID` | `NVT OID`, `OID` | `QID`, `ID` | `Vulnerability ID`, `ID` |
| **CVE Number** | `CVE`, `CVEs` | `CVEs`, `CVE` | `CVE ID`, `CVE` | `CVEs`, `CVE` |
| **CVSS Base** | `CVSS v3.0 Base Score`, `CVSS` | `Severity`, `CVSS Score` | `CVSS3 Base`, `CVSS Base` | `CVSS Score`, `CVSS` |
| **Severity** | `Risk`, `Severity` | `Severity`, `Threat` | `Severity`, `Risk` | `Severity`, `Risk` |
| **Target Host** | `Host`, `IP`, `DNS` | `Host`, `IP` | `DNS`, `IP`, `Host` | `Asset Hostname`, `Asset IP Address` |
| **Port / Proto** | `Port`, `Protocol` | `Port` (parses `443/tcp`) | `Port`, `Protocol` | `Service Port`, `Service Protocol` |
| **Vulnerability Title** | `Name`, `Synopsis` | `NVT Name`, `Name` | `Title`, `Name` | `Vulnerability Title`, `Title` |
| **Remediation Fix** | `Solution`, `Remediation` | `Solution` | `Solution` | `Fix`, `Solution` |
| **Details / Evidence** | `Description`, `Plugin Output` | `Summary`, `Vulnerability Insight` | `Results`, `Diagnosis` | `Description`, `Summary` |

---

## 3. Qualitative Severity Normalization

When a scan report omits numerical CVSS base scores, `vuln-scan-prioritizer` maps qualitative text or numeric levels to standard CVSS equivalents:

| Qualitative Scanner Label | Numeric Level | Normalized CVSS Equivalent | Default SLA Tier |
| :--- | :---: | :---: | :--- |
| **Critical** | `5` | `9.5` | Wave 2 (Urgent 7d) or Wave 1 if Exploit exists |
| **High** | `4` | `7.5` | Wave 3 (Standard 30d) or Wave 2 if External |
| **Medium** | `3` | `5.0` | Wave 3 (Standard 30d) |
| **Low** | `2` | `2.5` | Wave 4 (Backlog / Info) |
| **None / Informational** | `1` or `0` | `0.0` | Wave 4 (Backlog / Info) |
