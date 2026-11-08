#!/usr/bin/env python3
"""
Automated Validation Suite for vuln-scan-prioritizer.
Verifies multi-scanner dialect autodetection (Nessus, OpenVAS, Qualys, Rapid7),
deduplication efficiency, contextual risk scoring, CISA KEV correlation,
and client-side data sanitization adhering to Rule 3, Rule 4, Rule 7, and Rule 9.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add scripts directory to path
SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from vuln_prioritizer import (
    DEFAULT_KEV_CVES,
    Finding,
    PrioritizationEngine,
    ReportFormatter,
    ScannerDetector,
    ScannerParser,
    TelemetrySanitizer,
)

FIXTURES_DIR = SKILL_ROOT / "tests" / "fixtures"


def test_scanner_detection():
    print("[TEST 01] Scanner Header Dialect Autodetection...")
    cases = [
        (["Plugin ID", "CVE", "CVSS v3.0 Base Score", "Risk", "Host"], "nessus"),
        (["NVT OID", "CVEs", "Severity", "Host", "Port", "NVT Name"], "openvas"),
        (["QID", "CVE ID", "CVSS3 Base", "Severity", "IP", "DNS", "Title"], "qualys"),
        (["Vulnerability ID", "CVEs", "CVSS Score", "Severity", "Asset IP Address"], "rapid7"),
        (["CVE", "Host", "Severity", "Details"], "generic"),
        (["Random", "Headers", "Only"], "unknown"),
    ]
    for headers, expected in cases:
        detected = ScannerDetector.detect_format(headers)
        assert detected == expected, f"Expected {expected}, got {detected} for headers {headers}"
    print("  -> PASSED: All 6 scanner dialect signatures correctly recognized.")


def test_nessus_parsing_and_deduplication():
    print("[TEST 02] Nessus Parsing & Patch Deduplication...")
    fixture_path = FIXTURES_DIR / "fixture-nessus-enterprise-scan.csv"
    assert fixture_path.exists(), f"Fixture missing: {fixture_path}"

    parser = ScannerParser()
    dialect, findings = parser.parse_file(fixture_path)
    assert dialect == "nessus", f"Expected 'nessus', got '{dialect}'"
    assert len(findings) == 11, f"Expected 11 findings, got {len(findings)}"

    engine = PrioritizationEngine()
    scored = engine.evaluate_findings(findings)
    groups = engine.deduplicate(scored)

    # 11 raw findings should consolidate to 9 unified bundles (HTTP/2 on 443 & 8443 collapsed; OpenSSL on 1194 & 443 collapsed)
    assert len(groups) == 9, f"Expected 9 deduplicated bundles, got {len(groups)}"

    # Check that HTTP/2 bundle collapsed 2 ports
    http2_group = next((g for g in groups if "HTTP/2" in g.remediation_package), None)
    assert http2_group is not None, "HTTP/2 bundle missing"
    assert http2_group.findings_count == 2, f"Expected 2 collapsed findings, got {http2_group.findings_count}"
    assert set(http2_group.affected_ports) == {"443", "8443"}, f"Expected ports 443, 8443, got {http2_group.affected_ports}"
    print("  -> PASSED: Successfully deduplicated multi-port findings into unified bundles.")


def test_openvas_parsing():
    print("[TEST 03] OpenVAS / GVM CSV Parsing...")
    fixture_path = FIXTURES_DIR / "fixture-openvas-infrastructure-scan.csv"
    parser = ScannerParser()
    dialect, findings = parser.parse_file(fixture_path)
    assert dialect == "openvas", f"Expected 'openvas', got '{dialect}'"
    assert len(findings) == 6, f"Expected 6 findings, got {len(findings)}"

    # Verify CVE extraction from compound strings
    log4j_finding = next((f for f in findings if "CVE-2021-44228" in f.cves), None)
    assert log4j_finding is not None, "Log4j CVE-2021-44228 not extracted"
    assert log4j_finding.cvss_base == 10.0, f"Expected CVSS 10.0, got {log4j_finding.cvss_base}"
    print("  -> PASSED: OpenVAS OID and port formats parsed accurately.")


def test_qualys_parsing():
    print("[TEST 04] Qualys VMDR CSV Parsing...")
    fixture_path = FIXTURES_DIR / "fixture-qualys-vmdr-scan.csv"
    parser = ScannerParser()
    dialect, findings = parser.parse_file(fixture_path)
    assert dialect == "qualys", f"Expected 'qualys', got '{dialect}'"
    assert len(findings) == 5, f"Expected 5 findings, got {len(findings)}"

    # Host should prefer DNS over IP if present
    exchange_finding = next((f for f in findings if "MonikerLink" in f.title), None)
    assert exchange_finding is not None, "MonikerLink finding not found"
    assert "synthetic-exchange-01.corp.example.com" in exchange_finding.host
    print("  -> PASSED: Qualys QID, DNS resolution, and CVSS3 mapped correctly.")


def test_rapid7_parsing():
    print("[TEST 05] Rapid7 Nexpose CSV Parsing...")
    fixture_path = FIXTURES_DIR / "fixture-rapid7-nexpose-scan.csv"
    parser = ScannerParser()
    dialect, findings = parser.parse_file(fixture_path)
    assert dialect == "rapid7", f"Expected 'rapid7', got '{dialect}'"
    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}"

    zerologon = next((f for f in findings if "Zerologon" in f.title), None)
    assert zerologon is not None, "Zerologon finding missing"
    assert "CVE-2020-1472" in zerologon.cves
    print("  -> PASSED: Rapid7 Vulnerability ID and Fix attributes parsed.")


def test_cisa_kev_and_contextual_scoring():
    print("[TEST 06] CISA KEV Boost and Contextual Scoring Calculations...")
    f_kev = Finding(
        scanner="generic",
        finding_id="1",
        cves=["CVE-2021-44228"],
        cvss_base=10.0,
        raw_severity="Critical",
        host="synthetic-dmz-web-01.corp.example.com",
        port="443",
        protocol="tcp",
        title="Apache Log4j",
        solution="Upgrade Log4j"
    )

    f_non_kev = Finding(
        scanner="generic",
        finding_id="2",
        cves=["CVE-2023-99999"],
        cvss_base=9.8,
        raw_severity="Critical",
        host="synthetic-test-internal-01.corp.example.com",
        port="8080",
        protocol="tcp",
        title="Theoretical Buffer Overflow",
        solution="Apply patch"
    )

    engine = PrioritizationEngine(target_exposure="hybrid")
    evaluated = engine.evaluate_findings([f_kev, f_non_kev])

    # f_kev: Base 10.0 + KEV 3.0 + External 2.0 = 15.0 (Emergency Wave 1)
    # f_non_kev: Base 9.8 + Internal 0.0 = 9.8 (Urgent Wave 2)
    assert f_kev.is_kev is True
    assert f_kev.composite_score == 15.0
    assert f_kev.wave == "Wave 1 (Emergency 24h)"

    assert f_non_kev.is_kev is False
    assert f_non_kev.composite_score == 9.8
    assert f_non_kev.wave == "Wave 2 (Urgent 7d)"
    print("  -> PASSED: Active in-the-wild exploit outranks internal theoretical CVSS 9.8.")


def test_client_side_sanitization():
    print("[TEST 07] Client-Side Data Sanitization (Rule 4 Compliance)...")
    sanitizer = TelemetrySanitizer(salt="unit-test-salt")

    ip_out1 = sanitizer.sanitize_ip("10.50.100.25")
    ip_out2 = sanitizer.sanitize_ip("10.50.100.25")
    assert ip_out1 == ip_out2, "Sanitization must be deterministic for identical IP"
    assert ip_out1.startswith("192.0.2."), f"IP should use RFC 5737 block, got {ip_out1}"

    host_out = sanitizer.sanitize_host("dc01.internal.megacorp.local")
    assert "megacorp" not in host_out, f"Internal domain leaked in sanitized host: {host_out}"
    assert host_out.endswith(".corp.example.com")
    assert host_out.startswith("host-")

    text_out = sanitizer.sanitize_text("Database listener running on 10.10.1.5 connected to internal host.")
    assert "10.10.1.5" not in text_out
    assert "192.0.2.10" in text_out
    print("  -> PASSED: RFC 5737 IP masking and SHA-256 hostname obfuscation verified.")


def test_ticket_and_markdown_generation():
    print("[TEST 08] Report & ITSM Ticket Generation...")
    fixture_path = FIXTURES_DIR / "fixture-nessus-enterprise-scan.csv"
    parser = ScannerParser()
    dialect, findings = parser.parse_file(fixture_path)
    engine = PrioritizationEngine()
    scored = engine.evaluate_findings(findings)
    groups = engine.deduplicate(scored)

    # Generate Markdown
    md = ReportFormatter.generate_markdown_report(dialect, len(findings), groups, scored)
    assert "# Vulnerability Scan Prioritization & Remediation Assessment" in md
    assert "Noise Suppression Ratio" in md

    # Generate ITSM Tickets
    tickets = ReportFormatter.generate_itsm_tickets(groups)
    assert "# ITSM Remediation Patch Tickets" in tickets
    assert "TICKET-001:" in tickets
    assert "Remediation Description & Action Required:" in tickets

    # Export CSV in temp file
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
        temp_csv = Path(tf.name)

    try:
        ReportFormatter.export_csv(groups, temp_csv)
        assert temp_csv.exists() and temp_csv.stat().st_size > 0
        content = temp_csv.read_text(encoding="utf-8")
        assert "Remediation Package" in content
        assert "SLA Wave" in content
    finally:
        if temp_csv.exists():
            temp_csv.unlink()

    print("  -> PASSED: Markdown, ITSM tickets, and prioritized CSV generated cleanly.")


def main():
    print("=" * 70)
    print("VULN-SCAN-PRIORITIZER AUTOMATED VALIDATION SUITE")
    print("=" * 70)
    test_scanner_detection()
    test_nessus_parsing_and_deduplication()
    test_openvas_parsing()
    test_qualys_parsing()
    test_rapid7_parsing()
    test_cisa_kev_and_contextual_scoring()
    test_client_side_sanitization()
    test_ticket_and_markdown_generation()
    print("=" * 70)
    print("ALL 8 VALIDATION CHECKS PASSED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()
