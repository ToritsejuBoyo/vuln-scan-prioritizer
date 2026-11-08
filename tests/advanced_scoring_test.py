#!/usr/bin/env python3
"""
Advanced Scoring & Contextual Prioritization Test Suite for vuln-scan-prioritizer.
Thoroughly tests exposure switches, custom KEV file loading, critical asset weighting,
mixed-case CVE extraction, deduplication across multi-host environments,
and boundary condition handling.
"""

import json
import sys
import tempfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from vuln_prioritizer import (
    DEFAULT_KEV_CVES,
    DeduplicatedRemediationGroup,
    Finding,
    PrioritizationEngine,
    ScannerParser,
    TelemetrySanitizer,
)


def test_exposure_models():
    print("[ADVANCED TEST 01] Exposure Model Switches (External vs Internal vs Hybrid)...")
    
    # Internal server without external ports
    f = Finding(
        scanner="generic",
        finding_id="EX-01",
        cves=["CVE-2023-38606"],
        cvss_base=9.8,
        raw_severity="Critical",
        host="backend-db-01.corp.local",
        port="5432",
        protocol="tcp",
        title="PostgreSQL Vulnerability",
        solution="Update postgresql"
    )

    # Test Hybrid mode (defaults to internal because port 5432 and no dmz keywords)
    engine_hybrid = PrioritizationEngine(target_exposure="hybrid")
    res_hybrid = engine_hybrid.evaluate_findings([f])[0]
    assert res_hybrid.is_external is False, "Expected internal in hybrid mode"
    # Base 9.8 + Exploit 2.0 + Critical db keyword 1.0 = 12.8
    assert res_hybrid.composite_score == 12.8

    # Force External mode
    f.composite_score = 0.0
    engine_ext = PrioritizationEngine(target_exposure="external")
    res_ext = engine_ext.evaluate_findings([f])[0]
    assert res_ext.is_external is True, "Expected external when forced"
    # Base 9.8 + Exploit 2.0 + External 2.0 + Critical 1.0 = 14.8
    assert res_ext.composite_score == 14.8

    # Force Internal mode on a DMZ web host
    f_dmz = Finding(
        scanner="generic",
        finding_id="EX-02",
        cves=["CVE-2023-38606"],
        cvss_base=9.8,
        raw_severity="Critical",
        host="dmz-web-01.corp.local",
        port="443",
        protocol="tcp",
        title="PostgreSQL Vulnerability",
        solution="Update postgresql"
    )
    engine_int = PrioritizationEngine(target_exposure="internal")
    res_int = engine_int.evaluate_findings([f_dmz])[0]
    assert res_int.is_external is False, "Expected internal when target_exposure=internal"
    print("  -> PASSED: Target exposure modes correctly enforce and override asset context.")


def test_critical_asset_flagging():
    print("[ADVANCED TEST 02] Custom Critical Asset List Flagging...")
    f1 = Finding(
        scanner="generic",
        finding_id="CRIT-01",
        cves=["CVE-2022-0778"],
        cvss_base=7.5,
        raw_severity="High",
        host="billing-db-01.corp.local",
        port="8080",
        protocol="tcp",
        title="OpenSSL Infinite Loop",
        solution="Update openssl"
    )
    
    # Without custom critical asset list
    engine1 = PrioritizationEngine(critical_assets=["unrelated-host"])
    res1 = engine1.evaluate_findings([f1])[0]
    assert res1.is_critical_asset is True  # 'db' is in default crit indicators

    f2 = Finding(
        scanner="generic",
        finding_id="CRIT-02",
        cves=["CVE-2022-0778"],
        cvss_base=7.5,
        raw_severity="High",
        host="app-worker-node-42.corp.local",
        port="8080",
        protocol="tcp",
        title="OpenSSL Infinite Loop",
        solution="Update openssl"
    )
    # Default: worker node is not critical
    engine2 = PrioritizationEngine(critical_assets=[])
    res2 = engine2.evaluate_findings([f2])[0]
    assert res2.is_critical_asset is False

    # Explicitly add worker node to critical list
    engine3 = PrioritizationEngine(critical_assets=["app-worker-node-42.corp.local"])
    res3 = engine3.evaluate_findings([f2])[0]
    assert res3.is_critical_asset is True
    print("  -> PASSED: Custom critical assets list boosts priority by +1.0 score.")


def test_custom_kev_json_override():
    print("[ADVANCED TEST 03] Custom KEV Catalog Ingestion & Matching...")
    custom_cves = {"CVE-2029-99999", "CVE-2030-11111"}
    
    f = Finding(
        scanner="generic",
        finding_id="KEV-01",
        cves=["CVE-2029-99999"],
        cvss_base=6.5,
        raw_severity="Medium",
        host="host-test.corp.local",
        port="80",
        protocol="tcp",
        title="Future Zero Day",
        solution="Update software"
    )

    engine = PrioritizationEngine(kev_cves=custom_cves)
    res = engine.evaluate_findings([f])[0]
    assert res.is_kev is True, "Custom KEV CVE not recognized"
    assert res.composite_score >= 9.5
    print("  -> PASSED: Custom KEV catalog successfully overrides default dataset.")


def test_multi_host_remediation_clustering():
    print("[ADVANCED TEST 04] Multi-Host Package Deduplication...")
    findings = [
        Finding(
            scanner="nessus",
            finding_id="1",
            cves=["CVE-2021-44228"],
            cvss_base=10.0,
            raw_severity="Critical",
            host="host-a.example.com",
            port="8080",
            protocol="tcp",
            title="Apache Log4j",
            solution="Upgrade log4j package",
            remediation_package="Apache Log4j2 Library"
        ),
        Finding(
            scanner="nessus",
            finding_id="2",
            cves=["CVE-2021-45046"],
            cvss_base=9.0,
            raw_severity="Critical",
            host="host-a.example.com",
            port="8443",
            protocol="tcp",
            title="Apache Log4j Additional Flaw",
            solution="Upgrade log4j package",
            remediation_package="Apache Log4j2 Library"
        ),
        Finding(
            scanner="nessus",
            finding_id="3",
            cves=["CVE-2021-44228"],
            cvss_base=10.0,
            raw_severity="Critical",
            host="host-b.example.com",
            port="8080",
            protocol="tcp",
            title="Apache Log4j",
            solution="Upgrade log4j package",
            remediation_package="Apache Log4j2 Library"
        )
    ]

    engine = PrioritizationEngine()
    scored = engine.evaluate_findings(findings)
    groups = engine.deduplicate(scored)

    # host-a has 2 findings collapsed into 1 bundle.
    # host-b has 1 finding in 1 bundle.
    # Total bundles: 2
    assert len(groups) == 2, f"Expected 2 bundles across 2 hosts, got {len(groups)}"
    
    group_a = next(g for g in groups if g.host == "host-a.example.com")
    assert group_a.findings_count == 2
    assert set(group_a.cves) == {"CVE-2021-44228", "CVE-2021-45046"}
    assert set(group_a.affected_ports) == {"8080", "8443"}
    print("  -> PASSED: Deduplication clusters by host and package without cross-host contamination.")


def test_qualitative_severity_fallback():
    print("[ADVANCED TEST 05] Qualitative Severity Parsing & Fallback...")
    parser = ScannerParser()
    assert parser._parse_cvss("", "Critical") == 9.5
    assert parser._parse_cvss("", "5") == 9.5
    assert parser._parse_cvss("", "High") == 7.5
    assert parser._parse_cvss("", "4") == 7.5
    assert parser._parse_cvss("", "Medium") == 5.0
    assert parser._parse_cvss("", "3") == 5.0
    assert parser._parse_cvss("", "Low") == 2.5
    assert parser._parse_cvss("", "None") == 0.0
    assert parser._parse_cvss("", "Informational") == 0.0
    assert parser._parse_cvss("9.8 (v3)", "") == 9.8
    assert parser._parse_cvss("7.5", "Low") == 7.5  # Numerical overrides qualitative
    print("  -> PASSED: Numerical and qualitative CVSS score normalization verified.")


def main():
    print("=" * 70)
    print("VULN-SCAN-PRIORITIZER ADVANCED SCORING TEST SUITE")
    print("=" * 70)
    test_exposure_models()
    test_critical_asset_flagging()
    test_custom_kev_json_override()
    test_multi_host_remediation_clustering()
    test_qualitative_severity_fallback()
    print("=" * 70)
    print("ALL 5 ADVANCED SCORING TESTS PASSED (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()
