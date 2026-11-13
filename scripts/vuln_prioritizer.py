#!/usr/bin/env python3
"""
Enterprise Vulnerability Scan Prioritizer and Deduplication Engine.
Ingests raw CSV scan reports from Tenable Nessus, Greenbone OpenVAS, Qualys VMDR,
and Rapid7 Nexpose. Deduplicates findings by patchable package/solution, applies
contextual risk scoring (CVSS + CISA KEV + Exploit + Exposure), and generates
a 4-wave remediation schedule with ITSM patch tickets.

Zero third-party dependencies. Complies with Rule 3, Rule 4 (Sanitization),
and Rule 7 (Zero-Emoji Enterprise Tone).
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Shared residual sanitization pass (vendored: scripts/sanitizer.py).
# Runs last, after this skill's domain-specific masking, so that every skill in
# the library enforces an identical credential/PII floor. See
# tests/sanitizer_conformance_test.py for the contract this must satisfy.
# ---------------------------------------------------------------------------
try:
    from sanitizer import residual_scrub as _residual_scrub
except ImportError:  # pragma: no cover - direct execution from another cwd
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from sanitizer import residual_scrub as _residual_scrub


# Increase CSV field size limit to support massive vulnerability scanner outputs (e.g., 50MB+ plugin outputs)
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2147483647)

# Built-in High-Impact CISA Known Exploited Vulnerabilities (KEV) Catalog Subset
DEFAULT_KEV_CVES: Set[str] = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2020-1472",   # Zerologon
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2024-21413",  # Outlook MonikerLink
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2023-38545",  # cURL SOCKS5 Overflow
    "CVE-2023-27997",  # FortiOS SSL-VPN RCE
    "CVE-2023-34362",  # MOVEit Transfer SQLi
    "CVE-2023-22515",  # Confluence Data Center Broken Access
    "CVE-2023-46805",  # Ivanti Connect Secure Auth Bypass
    "CVE-2024-1709",   # ConnectWise ScreenConnect Auth Bypass
    "CVE-2024-3400",   # Palo Alto PAN-OS Command Injection
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2017-0144",   # EternalBlue
    "CVE-2019-0708",   # BlueKeep
}

# Known weaponized public exploit indicators (Metasploit, Exploit-DB, PoC in wild)
DEFAULT_EXPLOIT_CVES: Set[str] = DEFAULT_KEV_CVES.union({
    "CVE-2023-38606",
    "CVE-2022-0778",
    "CVE-2021-26855",  # ProxyLogon
    "CVE-2021-34473",  # ProxyShell
})


@dataclass
class Finding:
    """Represents a normalized vulnerability finding from any supported scanner."""
    scanner: str
    finding_id: str
    cves: List[str]
    cvss_base: float
    raw_severity: str
    host: str
    port: str
    protocol: str
    title: str
    solution: str
    description: str = ""
    is_kev: bool = False
    has_exploit: bool = False
    is_external: bool = False
    is_critical_asset: bool = False
    composite_score: float = 0.0
    wave: str = "Wave 3 (Standard 30d)"
    remediation_package: str = ""


@dataclass
class DeduplicatedRemediationGroup:
    """Group of findings on an asset sharing identical remediation package/solution."""
    host: str
    remediation_package: str
    solution: str
    findings_count: int
    affected_ports: List[str]
    cves: List[str]
    max_cvss: float
    max_composite_score: float
    highest_wave: str
    has_kev: bool
    has_exploit: bool
    titles: List[str]


class TelemetrySanitizer:
    """Client-side data sanitization adhering to Rule 4."""
    def __init__(self, salt: str = "enterprise-audit-salt"):
        self.salt = salt
        self._ip_cache: Dict[str, str] = {}
        self._host_cache: Dict[str, str] = {}
        self._ip_counter = 1

    def sanitize_ip(self, ip: str) -> str:
        """Replaces real IP with RFC 5737 test network address (192.0.2.x)."""
        if not ip or ip.strip() == "":
            return ip
        ip_clean = ip.strip()
        if ip_clean not in self._ip_cache:
            self._ip_cache[ip_clean] = f"192.0.2.{self._ip_counter % 250 + 1}"
            self._ip_counter += 1
        return self._ip_cache[ip_clean]

    def sanitize_host(self, host: str) -> str:
        """Masks internal hostnames into deterministic synthetic identifiers."""
        if not host or host.strip() == "":
            return host
        host_clean = host.strip()
        # If it looks like an IP, sanitize as IP
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_clean):
            return self.sanitize_ip(host_clean)
        
        if host_clean not in self._host_cache:
            h = hashlib.sha256((host_clean + self.salt).encode("utf-8")).hexdigest()[:8]
            self._host_cache[host_clean] = f"host-{h}.corp.example.com"
        return self._host_cache[host_clean]

    def sanitize_text(self, text: str) -> str:
        """Sanitizes text strings (titles, solutions) by stripping internal domains/IPs and bidi overrides."""
        if not text:
            return ""
        # Strip dangerous bidirectional unicode characters and zero-width spaces
        text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]", "", text)
        # Replace IPv4 addresses
        text = re.sub(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "192.0.2.10",
            text
        )
        text = _residual_scrub(text)
        return text


class ScannerDetector:
    """Detects scanner CSV dialect from header names."""
    @staticmethod
    def detect_format(headers: List[str]) -> str:
        h_norm = [h.strip().lower() for h in headers]
        h_set = set(h_norm)
        
        if "plugin id" in h_set or ("risk" in h_set and "synopsis" in h_set):
            return "nessus"
        if "nvt oid" in h_set or "nvt name" in h_set or ("severity" in h_set and "cves" in h_set and "summary" in h_set):
            return "openvas"
        if "qid" in h_set or ("cvss3 base" in h_set and "title" in h_set and "solution" in h_set):
            return "qualys"
        if "vulnerability id" in h_set or "asset ip address" in h_set or "fix" in h_set:
            return "rapid7"
        
        # Generic heuristic
        if any("cve" in h for h in h_norm) and any("host" in h or "ip" in h for h in h_norm):
            return "generic"
        return "unknown"


class ScannerParser:
    """Parses multi-scanner CSVs into standardized Finding objects."""
    def __init__(self, sanitizer: Optional[TelemetrySanitizer] = None):
        self.sanitizer = sanitizer

    def parse_file(self, filepath: Path) -> Tuple[str, List[Finding]]:
        if not filepath.exists():
            raise FileNotFoundError(f"Scanner CSV file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.reader(f)
            headers = []
            for row in reader:
                if row and any(cell.strip() for cell in row):
                    headers = row
                    break
            
            if not headers:
                raise ValueError("CSV file contains no readable headers.")

        format_detected = ScannerDetector.detect_format(headers)
        findings: List[Finding] = []

        with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
            dict_reader = csv.DictReader(f)
            for row in dict_reader:
                if not any(v.strip() for v in row.values() if v):
                    continue
                finding = self._parse_row(format_detected, row)
                if finding:
                    findings.append(finding)

        return format_detected, findings

    def _parse_row(self, scanner: str, row: Dict[str, str]) -> Optional[Finding]:
        # Case-insensitive row lookup helper
        norm_row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items() if k}

        def get_field(candidates: List[str], default: str = "") -> str:
            for c in candidates:
                if c.lower() in norm_row:
                    return norm_row[c.lower()]
            return default

        finding_id = ""
        cve_raw = ""
        cvss_str = ""
        raw_sev = ""
        host = ""
        port = ""
        protocol = "tcp"
        title = ""
        solution = ""
        description = ""

        if scanner == "nessus":
            finding_id = get_field(["plugin id", "id"])
            cve_raw = get_field(["cve", "cves"])
            cvss_str = get_field(["cvss v3.0 base score", "cvss v3 base score", "cvss", "cvss3"])
            raw_sev = get_field(["risk", "severity"])
            host = get_field(["host", "ip", "dns"])
            port = get_field(["port"], "0")
            protocol = get_field(["protocol"], "tcp")
            title = get_field(["name", "synopsis", "title"])
            solution = get_field(["solution", "remediation"])
            description = get_field(["description", "synopsis"])

        elif scanner == "openvas":
            finding_id = get_field(["nvt oid", "oid", "id"])
            cve_raw = get_field(["cves", "cve"])
            cvss_str = get_field(["severity", "cvss", "cvss score"])
            raw_sev = get_field(["severity", "threat"])
            host = get_field(["host", "ip"])
            port_raw = get_field(["port"], "0")
            if "/" in port_raw:
                parts = port_raw.split("/")
                if parts[0].isdigit():
                    port = parts[0]
                    protocol = parts[1] if len(parts) > 1 else "tcp"
                elif len(parts) > 1 and parts[1].isdigit():
                    port = parts[1]
                    protocol = parts[0]
                else:
                    port = parts[0]
            else:
                port = port_raw
            title = get_field(["nvt name", "name", "title"])
            solution = get_field(["solution", "remediation"])
            description = get_field(["summary", "vulnerability insight", "description"])

        elif scanner == "qualys":
            finding_id = get_field(["qid", "id"])
            cve_raw = get_field(["cve id", "cve", "cves"])
            cvss_str = get_field(["cvss3 base", "cvss base", "cvss3", "cvss"])
            raw_sev = get_field(["severity", "risk"])
            host = get_field(["dns", "ip", "host"])
            if not host:
                host = get_field(["ip"])
            port = get_field(["port"], "0")
            protocol = get_field(["protocol"], "tcp")
            title = get_field(["title", "name"])
            solution = get_field(["solution", "remediation"])
            description = get_field(["results", "diagnosis", "threat"])

        elif scanner == "rapid7":
            finding_id = get_field(["vulnerability id", "id"])
            cve_raw = get_field(["cves", "cve"])
            cvss_str = get_field(["cvss score", "cvss", "cvss3"])
            raw_sev = get_field(["severity", "risk"])
            host = get_field(["asset hostname", "asset ip address", "host", "ip"])
            port = get_field(["service port", "port"], "0")
            protocol = get_field(["service protocol", "protocol"], "tcp")
            title = get_field(["vulnerability title", "title", "name"])
            solution = get_field(["fix", "solution"])
            description = get_field(["description", "summary"])

        else:  # Generic fallback
            finding_id = get_field(["id", "finding id", "vulnerability id", "plugin id"], "GENERIC-001")
            cve_raw = get_field(["cve", "cves", "cve id"])
            cvss_str = get_field(["cvss", "cvss3", "cvss score", "cvss base score", "severity score"])
            raw_sev = get_field(["severity", "risk", "priority"], "Medium")
            host = get_field(["host", "hostname", "ip", "asset", "target"], "unknown-host")
            port = get_field(["port"], "0")
            protocol = get_field(["protocol"], "tcp")
            title = get_field(["title", "name", "vulnerability", "synopsis"], "Unnamed Vulnerability")
            solution = get_field(["solution", "fix", "remediation"], "Apply vendor security updates.")
            description = get_field(["description", "summary", "details"], "")

        # Extract and normalize CVEs
        cve_list = self._extract_cves(cve_raw + " " + title + " " + description)

        # Parse CVSS score
        cvss_score = self._parse_cvss(cvss_str, raw_sev)

        # Apply sanitization if active
        if self.sanitizer:
            host = self.sanitizer.sanitize_host(host)
            title = self.sanitizer.sanitize_text(title)
            solution = self.sanitizer.sanitize_text(solution)
            description = self.sanitizer.sanitize_text(description)

        # Package / Solution normalization for deduplication
        package_name = self._extract_remediation_package(title, solution)

        return Finding(
            scanner=scanner,
            finding_id=finding_id,
            cves=cve_list,
            cvss_base=cvss_score,
            raw_severity=raw_sev,
            host=host,
            port=port,
            protocol=protocol.lower(),
            title=title,
            solution=solution,
            description=description,
            remediation_package=package_name
        )

    def _extract_cves(self, text: str) -> List[str]:
        if not text:
            return []
        matches = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)
        # Unique and uppercase
        seen = set()
        result = []
        for m in matches:
            u = m.upper()
            if u not in seen:
                seen.add(u)
                result.append(u)
        return result

    def _parse_cvss(self, cvss_str: str, raw_sev: str) -> float:
        if cvss_str:
            try:
                # Support European comma decimal separator (e.g., "9,8" -> "9.8")
                clean_str = cvss_str.strip().replace(",", ".")
                match = re.search(r"(-?\d+(\.\d+)?)", clean_str)
                if match:
                    score = float(match.group(1))
                    # Clamp valid CVSS to range [0.0, 10.0]
                    return max(0.0, min(10.0, score))
            except (ValueError, TypeError):
                pass

        # Qualitative fallback mapping
        sev_lower = raw_sev.lower().strip()
        if "critical" in sev_lower or sev_lower == "5":
            return 9.5
        elif "high" in sev_lower or sev_lower == "4":
            return 7.5
        elif "medium" in sev_lower or sev_lower == "3":
            return 5.0
        elif "low" in sev_lower or sev_lower == "2":
            return 2.5
        elif "none" in sev_lower or "info" in sev_lower or sev_lower in ["1", "0"]:
            return 0.0
        return 4.0

    def _extract_remediation_package(self, title: str, solution: str) -> str:
        """Identifies root package / daemon for deduplication."""
        text = (title + " " + solution).lower()
        
        known_components = [
            ("log4j", "Apache Log4j2 Library"),
            ("openssl", "OpenSSL Cryptographic Library"),
            ("spring", "Spring Framework"),
            ("postgresql", "PostgreSQL Database Server"),
            ("mysql", "MySQL Database Server"),
            ("nginx", "Nginx HTTP Server"),
            ("apache", "Apache HTTP Server"),
            ("http/2", "HTTP/2 Web Server Stack"),
            ("curl", "cURL / libcurl"),
            ("openssh", "OpenSSH Server"),
            ("exchange", "Microsoft Exchange Server"),
            ("outlook", "Microsoft Office / Outlook"),
            ("netlogon", "Windows Netlogon Service (Zerologon)"),
            ("active directory", "Active Directory Domain Services"),
            ("smb", "Server Message Block (SMB/Samba)"),
            ("sudo", "Linux Sudo Binary"),
            ("kernel", "Linux Operating System Kernel"),
            ("windows", "Microsoft Windows Operating System"),
        ]

        for keyword, pkg_name in known_components:
            if keyword in text:
                return pkg_name

        # Fallback to sanitized first 4 words of solution or title
        first_line = solution.strip().split("\n")[0] if solution else title
        words = re.findall(r"[A-Za-z0-9_-]+", first_line)
        if words:
            return " ".join(words[:4]).title()
        return "Generic Component Patch"


class PrioritizationEngine:
    """Calculates contextual risk scores and partitions findings into SLA waves."""
    def __init__(
        self,
        kev_cves: Optional[Set[str]] = None,
        exploit_cves: Optional[Set[str]] = None,
        target_exposure: str = "hybrid",
        critical_assets: Optional[List[str]] = None
    ):
        self.kev_cves = kev_cves if kev_cves is not None else DEFAULT_KEV_CVES
        self.exploit_cves = exploit_cves if exploit_cves is not None else DEFAULT_EXPLOIT_CVES
        self.target_exposure = target_exposure.lower()
        self.critical_assets = [a.lower().strip() for a in (critical_assets or [])]

    def evaluate_findings(self, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            # Check CISA KEV
            f.is_kev = any(cve in self.kev_cves for cve in f.cves)
            
            # Check Public Exploit
            f.has_exploit = f.is_kev or any(cve in self.exploit_cves for cve in f.cves)

            # Check Exposure
            host_lower = f.host.lower()
            if self.target_exposure == "external":
                f.is_external = True
            elif self.target_exposure == "internal":
                f.is_external = False
            else:  # Hybrid: determine based on naming/port heuristics
                dmz_indicators = ["dmz", "edge", "vpn", "gateway", "ext", "portal", "web", "public", "exchange"]
                f.is_external = any(ind in host_lower for ind in dmz_indicators) or f.port in ["80", "443", "8443", "1194", "500"]

            # Check Asset Criticality
            crit_indicators = ["dc", "db", "prod", "cluster", "core", "ad", "exchange", "master"]
            f.is_critical_asset = (
                any(ca in host_lower for ca in self.critical_assets) or
                any(crit in host_lower for crit in crit_indicators)
            )

            # Calculate Composite Risk Score:
            # Base (0-10) + KEV (+3.0) + Exploit (+2.0 if not already KEV) + External (+2.0) + Critical (+1.0)
            score = f.cvss_base
            if f.is_kev:
                score += 3.0
            elif f.has_exploit:
                score += 2.0

            if f.is_external:
                score += 2.0

            if f.is_critical_asset:
                score += 1.0

            f.composite_score = round(score, 1)

            # Partition into 4 Remediation Waves
            if (f.is_kev and (f.is_external or f.is_critical_asset)) or f.composite_score >= 12.0:
                f.wave = "Wave 1 (Emergency 24h)"
            elif f.composite_score >= 9.0 or (f.cvss_base >= 9.0 and f.is_external):
                f.wave = "Wave 2 (Urgent 7d)"
            elif f.composite_score >= 5.0 or f.cvss_base >= 4.0:
                f.wave = "Wave 3 (Standard 30d)"
            else:
                f.wave = "Wave 4 (Backlog / Info)"

        # Sort descending by composite score, then CVSS base
        findings.sort(key=lambda x: (x.composite_score, x.cvss_base), reverse=True)
        return findings

    def deduplicate(self, findings: List[Finding]) -> List[DeduplicatedRemediationGroup]:
        """Consolidates findings on each host sharing identical remediation package."""
        groups: Dict[Tuple[str, str], List[Finding]] = {}
        for f in findings:
            key = (f.host, f.remediation_package)
            if key not in groups:
                groups[key] = []
            groups[key].append(f)

        dedup_list: List[DeduplicatedRemediationGroup] = []
        for (host, pkg), flist in groups.items():
            all_cves = []
            seen_cves = set()
            for f in flist:
                for c in f.cves:
                    if c not in seen_cves:
                        seen_cves.add(c)
                        all_cves.append(c)

            def port_sort_key(p: str) -> Tuple[int, str]:
                m = re.search(r"\d+", p)
                return (int(m.group(0)) if m else 999999, p)

            ports = sorted(list(set(f.port for f in flist if f.port and f.port != "0")), key=port_sort_key)
            max_cvss = max(f.cvss_base for f in flist)
            max_comp = max(f.composite_score for f in flist)
            has_kev = any(f.is_kev for f in flist)
            has_exploit = any(f.has_exploit for f in flist)
            
            # Highest wave determination
            wave_hierarchy = [
                "Wave 1 (Emergency 24h)",
                "Wave 2 (Urgent 7d)",
                "Wave 3 (Standard 30d)",
                "Wave 4 (Backlog / Info)"
            ]
            highest_wave = "Wave 4 (Backlog / Info)"
            for w in wave_hierarchy:
                if any(f.wave == w for f in flist):
                    highest_wave = w
                    break

            solutions = [f.solution for f in flist if f.solution]
            primary_solution = solutions[0] if solutions else "Apply relevant vendor patch."

            titles = list(dict.fromkeys([f.title for f in flist if f.title]))

            dedup_list.append(DeduplicatedRemediationGroup(
                host=host,
                remediation_package=pkg,
                solution=primary_solution,
                findings_count=len(flist),
                affected_ports=ports,
                cves=all_cves,
                max_cvss=max_cvss,
                max_composite_score=max_comp,
                highest_wave=highest_wave,
                has_kev=has_kev,
                has_exploit=has_exploit,
                titles=titles
            ))

        # Sort deduplicated packages by max composite score
        dedup_list.sort(key=lambda x: (x.max_composite_score, x.max_cvss), reverse=True)
        return dedup_list


class ReportFormatter:
    """Generates console tables, Markdown summaries, CSV matrices, and ITSM tickets."""
    
    @staticmethod
    def format_console_summary(
        scanner: str,
        total_raw: int,
        dedup_groups: List[DeduplicatedRemediationGroup],
        findings: List[Finding]
    ) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY SCAN PRIORITIZATION & REMEDIATION REPORT")
        lines.append("=" * 80)
        lines.append(f"Scanner Dialect Detected : {scanner.upper()}")
        lines.append(f"Total Raw CSV Rows       : {total_raw}")
        lines.append(f"Unified Patch Bundles    : {len(dedup_groups)}")
        
        reduction = ((total_raw - len(dedup_groups)) / total_raw * 100) if total_raw > 0 else 0.0
        lines.append(f"Deduplication Efficiency : {reduction:.1f}% reduction in ticket fatigue")
        lines.append("-" * 80)

        # Wave breakdown counts
        wave_counts = {
            "Wave 1 (Emergency 24h)": 0,
            "Wave 2 (Urgent 7d)": 0,
            "Wave 3 (Standard 30d)": 0,
            "Wave 4 (Backlog / Info)": 0,
        }
        for g in dedup_groups:
            wave_counts[g.highest_wave] = wave_counts.get(g.highest_wave, 0) + 1

        lines.append("REMEDIATION SLA WAVES (UNIFIED ACTION BUNDLES):")
        for wave, count in wave_counts.items():
            lines.append(f"  * {wave:<25} : {count:>4} action bundle(s)")
        lines.append("-" * 80)

        # Top 10 Action Items
        lines.append(f"{'PRIORITY':<8} {'WAVE':<16} {'SCORE':<7} {'KEV':<5} {'TARGET HOST':<28} {'PACKAGE / SOLUTION'}")
        lines.append("-" * 80)
        for idx, g in enumerate(dedup_groups[:10], 1):
            kev_flag = "YES" if g.has_kev else "NO"
            short_wave = g.highest_wave.split(" (")[0]
            short_host = g.host[:27]
            short_pkg = g.remediation_package[:25]
            lines.append(f"#{idx:<7} {short_wave:<16} {g.max_composite_score:<7.1f} {kev_flag:<5} {short_host:<28} {short_pkg}")

        lines.append("=" * 80)
        return "\n".join(lines)

    @staticmethod
    def generate_markdown_report(
        scanner: str,
        total_raw: int,
        dedup_groups: List[DeduplicatedRemediationGroup],
        findings: List[Finding]
    ) -> str:
        reduction = ((total_raw - len(dedup_groups)) / total_raw * 100) if total_raw > 0 else 0.0
        
        md = []
        md.append("# Vulnerability Scan Prioritization & Remediation Assessment")
        md.append("")
        md.append("Deterministic, exploit-aware triage and deduplication report generated by `vuln-scan-prioritizer`.")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 1. Executive Metrics & Noise Reduction")
        md.append("")
        md.append("| Metric | Value | Operational Impact |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Scanner Format** | `{scanner.upper()}` | Autodetected native column schema |")
        md.append(f"| **Raw Scanner Rows** | **{total_raw:,}** | Total findings reported before deduplication |")
        md.append(f"| **Consolidated Patch Bundles** | **{len(dedup_groups):,}** | Actionable packages requiring sysadmin attention |")
        md.append(f"| **Noise Suppression Ratio** | **{reduction:.1f}%** | Saved engineer hours eliminating duplicate tickets |")
        
        kev_count = sum(1 for g in dedup_groups if g.has_kev)
        md.append(f"| **Active In-The-Wild Exploits (CISA KEV)** | **{kev_count}** | Immediate threat to perimeter integrity |")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 2. Remediation SLA Waves")
        md.append("")

        wave_buckets: Dict[str, List[DeduplicatedRemediationGroup]] = {
            "Wave 1 (Emergency 24h)": [],
            "Wave 2 (Urgent 7d)": [],
            "Wave 3 (Standard 30d)": [],
            "Wave 4 (Backlog / Info)": [],
        }
        for g in dedup_groups:
            wave_buckets[g.highest_wave].append(g)

        for wave_name, group_list in wave_buckets.items():
            md.append(f"### {wave_name} ({len(group_list)} Action Bundles)")
            if not group_list:
                md.append("No findings currently scheduled in this SLA tier.")
                md.append("")
                continue

            md.append("| Target Host | Remediation Package | CVEs | Max CVSS | Composite | Ports |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for g in group_list[:15]:
                cve_str = ", ".join(g.cves[:3]) + ("..." if len(g.cves) > 3 else "")
                if not cve_str:
                    cve_str = "N/A"
                port_str = ", ".join(g.affected_ports[:4]) if g.affected_ports else "Host-level"
                md.append(f"| `{g.host}` | **{g.remediation_package}** | `{cve_str}` | {g.max_cvss:.1f} | **{g.max_composite_score:.1f}** | {port_str} |")
            md.append("")

        md.append("---")
        md.append("")
        md.append("## 3. Top Prioritized Remediation Action Plans")
        md.append("")
        for idx, g in enumerate(dedup_groups[:5], 1):
            md.append(f"### Action Item #{idx}: {g.remediation_package} on `{g.host}`")
            md.append(f"- **Remediation SLA:** {g.highest_wave}")
            md.append(f"- **Composite Priority Score:** **{g.max_composite_score:.1f}** (Base CVSS: {g.max_cvss:.1f})")
            md.append(f"- **CISA Known Exploited Vulnerability:** {'**YES (Actively Exploited)**' if g.has_kev else 'No'}")
            md.append(f"- **Associated CVEs:** {', '.join(g.cves) if g.cves else 'None'}")
            md.append(f"- **Affected Ports / Services:** {', '.join(g.affected_ports) if g.affected_ports else 'Host Service'}")
            md.append(f"- **Vendor Recommended Fix:** {g.solution}")
            md.append("")

        return "\n".join(md)

    @staticmethod
    def generate_itsm_tickets(dedup_groups: List[DeduplicatedRemediationGroup]) -> str:
        """Produces copy-paste ticket text for Jira, ServiceNow, or Remedy."""
        out = []
        out.append("# ITSM Remediation Patch Tickets (Jira / ServiceNow Ready)")
        out.append("")
        for idx, g in enumerate(dedup_groups, 1):
            priority_map = {
                "Wave 1 (Emergency 24h)": "P1 - Critical / Blocker",
                "Wave 2 (Urgent 7d)": "P2 - High",
                "Wave 3 (Standard 30d)": "P3 - Medium",
                "Wave 4 (Backlog / Info)": "P4 - Low"
            }
            itsm_priority = priority_map.get(g.highest_wave, "P3 - Medium")
            
            cve_str = ", ".join(g.cves) if g.cves else "None"
            port_str = ", ".join(g.affected_ports) if g.affected_ports else "Host-level"

            out.append(f"## TICKET-{idx:03d}: [SecOps Patch] {g.remediation_package} on {g.host}")
            out.append(f"**Priority:** {itsm_priority}")
            out.append(f"**Target Host:** {g.host}")
            out.append(f"**Remediation SLA Wave:** {g.highest_wave}")
            out.append(f"**Composite Risk Score:** {g.max_composite_score:.1f} (Base CVSS: {g.max_cvss:.1f})")
            out.append(f"**CISA KEV Active Exploit:** {'YES' if g.has_kev else 'NO'}")
            out.append(f"**Associated CVEs:** {cve_str}")
            out.append(f"**Affected Ports:** {port_str}")
            out.append(f"**Consolidated Finding Count:** {g.findings_count} raw scanner alerts")
            out.append("")
            out.append("**Remediation Description & Action Required:**")
            out.append(f"{g.solution}")
            out.append("")
            out.append("**Verification Command:**")
            out.append("Verify package version after deployment and schedule rescan to confirm resolution.")
            out.append("-" * 60)
            out.append("")

        return "\n".join(out)

    @staticmethod
    def export_csv(dedup_groups: List[DeduplicatedRemediationGroup], output_path: Path):
        headers = [
            "Target Host", "Remediation Package", "SLA Wave", "Composite Score",
            "Max CVSS", "CISA KEV", "Public Exploit", "Raw Finding Count",
            "Affected Ports", "Associated CVEs", "Recommended Solution"
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for g in dedup_groups:
                writer.writerow([
                    g.host,
                    g.remediation_package,
                    g.highest_wave,
                    f"{g.max_composite_score:.1f}",
                    f"{g.max_cvss:.1f}",
                    "YES" if g.has_kev else "NO",
                    "YES" if g.has_exploit else "NO",
                    g.findings_count,
                    ";".join(g.affected_ports),
                    ";".join(g.cves),
                    g.solution.replace("\n", " ")
                ])


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enterprise Vulnerability Scan Prioritizer and Deduplication Engine."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        type=Path,
        help="Path to raw vulnerability scanner CSV export (Nessus, OpenVAS, Qualys, Rapid7)."
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Optional path to output Markdown assessment report."
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="Optional path to output prioritized deduplicated CSV matrix."
    )
    parser.add_argument(
        "--generate-tickets",
        type=Path,
        default=None,
        help="Optional path to export ITSM patch tickets in Markdown format."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON summary directly to stdout for automated agent consumption."
    )
    parser.add_argument(
        "--target-exposure",
        choices=["external", "internal", "hybrid"],
        default="hybrid",
        help="Network asset exposure model (default: hybrid)."
    )
    parser.add_argument(
        "--critical-assets",
        nargs="*",
        default=[],
        help="List of high-value hostnames or subnets to boost asset criticality."
    )
    parser.add_argument(
        "--kev-file",
        type=Path,
        default=None,
        help="Optional external JSON file with supplemental CISA KEV entries."
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help="Enable client-side SHA-256 and RFC 5737 data sanitization (Rule 4)."
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    sanitizer = TelemetrySanitizer() if args.sanitize else None
    parser = ScannerParser(sanitizer=sanitizer)

    try:
        format_detected, findings = parser.parse_file(args.input)
    except Exception as exc:
        print(f"Error reading scanner CSV: {exc}", file=sys.stderr)
        sys.exit(1)

    if not findings:
        print("No valid vulnerability findings discovered in CSV.", file=sys.stderr)
        sys.exit(0)

    # Load custom KEV file if provided
    custom_kev = None
    if args.kev_file and args.kev_file.exists():
        try:
            with open(args.kev_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                custom_kev = set()
                if "vulnerabilities" in data:
                    for v in data["vulnerabilities"]:
                        if "cveID" in v:
                            custom_kev.add(v["cveID"].strip().upper())
        except Exception as exc:
            print(f"Warning: Failed to load external KEV file: {exc}", file=sys.stderr)

    # Initialize Engine
    engine = PrioritizationEngine(
        kev_cves=custom_kev,
        target_exposure=args.target_exposure,
        critical_assets=args.critical_assets
    )

    scored_findings = engine.evaluate_findings(findings)
    dedup_groups = engine.deduplicate(scored_findings)

    # Handle outputs
    if args.json:
        summary_payload = {
            "scanner": format_detected,
            "raw_findings_count": len(findings),
            "consolidated_bundles_count": len(dedup_groups),
            "deduplication_reduction_percent": round(
                ((len(findings) - len(dedup_groups)) / len(findings) * 100), 1
            ),
            "bundles": [
                {
                    "host": g.host,
                    "remediation_package": g.remediation_package,
                    "highest_wave": g.highest_wave,
                    "composite_score": g.max_composite_score,
                    "cvss_base": g.max_cvss,
                    "has_kev": g.has_kev,
                    "has_exploit": g.has_exploit,
                    "cves": g.cves,
                    "affected_ports": g.affected_ports,
                    "findings_count": g.findings_count,
                    "solution": g.solution
                }
                for g in dedup_groups
            ]
        }
        print(json.dumps(summary_payload, indent=2))
        return

    # Console output
    console_text = ReportFormatter.format_console_summary(
        format_detected, len(findings), dedup_groups, scored_findings
    )
    print(console_text)

    # File outputs
    if args.output:
        md_text = ReportFormatter.generate_markdown_report(
            format_detected, len(findings), dedup_groups, scored_findings
        )
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md_text)
        print(f"Markdown assessment report written to: {args.output}")

    if args.output_csv:
        ReportFormatter.export_csv(dedup_groups, args.output_csv)
        print(f"Prioritized CSV matrix exported to: {args.output_csv}")

    if args.generate_tickets:
        tickets_text = ReportFormatter.generate_itsm_tickets(dedup_groups)
        with open(args.generate_tickets, "w", encoding="utf-8") as f:
            f.write(tickets_text)
        print(f"ITSM patch tickets written to: {args.generate_tickets}")


if __name__ == "__main__":
    main()

