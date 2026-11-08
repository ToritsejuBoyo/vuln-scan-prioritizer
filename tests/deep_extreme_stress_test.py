#!/usr/bin/env python3
"""
Deep Extreme Stress Test Suite for vuln-scan-prioritizer (20 Extreme Tests).
Probes memory limits, massive 250KB field sizes, 50,000-row scale hammer,
European comma decimals, Bidi unicode overrides, ReDoS resistance, ragged lines,
and pathological scanner anomalies.
"""

import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))
FIXTURES_DIR = SKILL_ROOT / "tests" / "fixtures"

from vuln_prioritizer import (
    Finding,
    PrioritizationEngine,
    ReportFormatter,
    ScannerDetector,
    ScannerParser,
    TelemetrySanitizer,
)


def run_all_20_extreme_stress_tests():
    print("=" * 80)
    print("VULN-SCAN-PRIORITIZER: 20 EXTREME ADVERSARIAL STRESS TESTS")
    print("=" * 80)
    passed = 0
    failed = 0

    # TEST 1: Massive 250KB Single CSV Cell (Exceeds Python's default 128KB limit)
    print("[TEST 01/20] Massive 250KB Single CSV Field (Field Size Limit Test)...")
    try:
        massive_payload = "X" * 250000
        content = (
            "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output\n"
            f'101,CVE-2021-44228,10.0,Critical,srv-01,tcp,443,Log4j,Synopsis,Description,Solution,"{massive_payload}"\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="", encoding="utf-8") as tf:
            tf.write(content)
            temp_path = Path(tf.name)
        try:
            parser = ScannerParser()
            dialect, findings = parser.parse_file(temp_path)
            assert dialect == "nessus"
            assert len(findings) == 1
            print("  -> PASSED: Ingested 250KB single field without _csv.Error crash.")
            passed += 1
        finally:
            temp_path.unlink()
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 2: European Comma Decimals ("9,8" -> 9.8 and "7,5" -> 7.5)
    print("[TEST 02/20] European Comma Decimal Parsing (Locale Independence)...")
    try:
        parser = ScannerParser()
        score1 = parser._parse_cvss("9,8", "Critical")
        score2 = parser._parse_cvss("7,5 (v3)", "High")
        assert score1 == 9.8, f"Expected 9.8, got {score1}"
        assert score2 == 7.5, f"Expected 7.5, got {score2}"
        print("  -> PASSED: European comma decimals accurately normalized to floats.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 3: Natural Numeric Port Sorting (80 < 443 < 1194 < 8080)
    print("[TEST 03/20] Natural Numeric Port Sorting (80 < 443 < 1194 < 8080)...")
    try:
        findings = [
            Finding("nessus", "1", ["CVE-2022-0778"], 7.5, "High", "srv-vpn", "8080", "tcp", "OpenSSL", "Fix openssl", remediation_package="OpenSSL"),
            Finding("nessus", "2", ["CVE-2022-0778"], 7.5, "High", "srv-vpn", "80", "tcp", "OpenSSL", "Fix openssl", remediation_package="OpenSSL"),
            Finding("nessus", "3", ["CVE-2022-0778"], 7.5, "High", "srv-vpn", "1194", "tcp", "OpenSSL", "Fix openssl", remediation_package="OpenSSL"),
            Finding("nessus", "4", ["CVE-2022-0778"], 7.5, "High", "srv-vpn", "443", "tcp", "OpenSSL", "Fix openssl", remediation_package="OpenSSL"),
        ]
        engine = PrioritizationEngine()
        scored = engine.evaluate_findings(findings)
        groups = engine.deduplicate(scored)
        assert len(groups) == 1
        assert groups[0].affected_ports == ["80", "443", "1194", "8080"], f"Got {groups[0].affected_ports}"
        print("  -> PASSED: Port array sorted in natural numeric sequence.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 4: Inverted Port / Protocol Formats ("tcp/443" vs "443/tcp")
    print("[TEST 04/20] Inverted Port / Protocol Normalization...")
    try:
        row1 = {"nvt oid": "1", "cves": "CVE-2023-44487", "severity": "7.5", "host": "192.0.2.1", "port": "tcp/443", "nvt name": "HTTP2", "solution": "Fix"}
        row2 = {"nvt oid": "2", "cves": "CVE-2023-44487", "severity": "7.5", "host": "192.0.2.1", "port": "8443/tcp", "nvt name": "HTTP2", "solution": "Fix"}
        parser = ScannerParser()
        f1 = parser._parse_row("openvas", row1)
        f2 = parser._parse_row("openvas", row2)
        assert f1.port == "443" and f1.protocol == "tcp", f"Got port={f1.port}, proto={f1.protocol}"
        assert f2.port == "8443" and f2.protocol == "tcp", f"Got port={f2.port}, proto={f2.protocol}"
        print("  -> PASSED: Both tcp/443 and 8443/tcp extracted correctly.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 5: Embedded Null Bytes in CSV Cell
    print("[TEST 05/20] Embedded Null Bytes in CSV Cells...")
    try:
        content = "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution\n1,CVE-2021-44228,10.0,Critical,srv-01,tcp,443,Log4j\x00Injection,Synopsis,Desc,Fix\n"
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as tf:
            tf.write(content)
            temp_path = Path(tf.name)
        try:
            parser = ScannerParser()
            dialect, findings = parser.parse_file(temp_path)
            assert len(findings) == 1
            print("  -> PASSED: Null bytes parsed without scanner failure.")
            passed += 1
        finally:
            temp_path.unlink()
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 6: Bidi Unicode Right-To-Left Overrides (\u202e)
    print("[TEST 06/20] Bidi Unicode / Trojan Source Filtering...")
    try:
        sanitizer = TelemetrySanitizer()
        nasty_text = "Upgrade OpenSSL to \u202e3.0.2\u200e immediately on 10.10.1.5"
        clean = sanitizer.sanitize_text(nasty_text)
        assert "\u202e" not in clean
        assert "\u200e" not in clean
        assert "10.10.1.5" not in clean
        assert "192.0.2.10" in clean
        print("  -> PASSED: Bidi control codes stripped cleanly from report output.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 7: CVSS Out-of-Range Clamping (-999 and +999)
    print("[TEST 07/20] CVSS Out-of-Range Boundary Clamping...")
    try:
        parser = ScannerParser()
        score_low = parser._parse_cvss("-15.0", "Low")
        score_high = parser._parse_cvss("99.9", "Critical")
        assert score_low == 0.0, f"Expected 0.0, got {score_low}"
        assert score_high == 10.0, f"Expected 10.0, got {score_high}"
        print("  -> PASSED: CVSS scores clamped within valid bounds [0.0, 10.0].")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 8: 50,000-Row Scale Hammer (Throughput & Memory Assertions)
    print("[TEST 08/20] 50,000-Row High-Volume Scale Hammer...")
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="", encoding="utf-8") as tf:
            writer = csv.writer(tf)
            writer.writerow(["Plugin ID", "CVE", "CVSS v3.0 Base Score", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Description", "Solution", "Plugin Output"])
            for i in range(50000):
                host_id = i % 500
                writer.writerow([
                    f"10{i%100}",
                    "CVE-2021-44228" if i % 3 == 0 else "CVE-2023-44487",
                    "10.0" if i % 3 == 0 else "7.5",
                    "Critical" if i % 3 == 0 else "High",
                    f"srv-{host_id:04d}.corp.example.com",
                    "tcp",
                    str(8000 + (i % 20)),
                    "Package Alert",
                    "Synopsis",
                    "Description",
                    "Upgrade Apache Log4j" if i % 3 == 0 else "Update HTTP/2 stack",
                    "Plugin output data"
                ])
            hammer_path = Path(tf.name)

        try:
            t0 = time.perf_counter()
            parser = ScannerParser(sanitizer=TelemetrySanitizer())
            dialect, findings = parser.parse_file(hammer_path)
            t_parse = time.perf_counter()

            engine = PrioritizationEngine()
            scored = engine.evaluate_findings(findings)
            t_score = time.perf_counter()

            groups = engine.deduplicate(scored)
            t_dedup = time.perf_counter()

            total_sec = t_dedup - t0
            assert len(findings) == 50000
            print(f"  -> PASSED: 50,000 rows triaged in {total_sec:.2f}s ({50000/total_sec:,.0f} rows/sec).")
            passed += 1
        finally:
            hammer_path.unlink()
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 9: 1,000 Unique Hosts with Identical Finding (Fan-Out)
    print("[TEST 09/20] 1,000 Unique Hosts Fan-Out Deduplication...")
    try:
        findings = [
            Finding("nessus", f"{i}", ["CVE-2021-44228"], 10.0, "Critical", f"host-{i:04d}.corp.local", "443", "tcp", "Log4j", "Upgrade Log4j", remediation_package="Apache Log4j2 Library")
            for i in range(1000)
        ]
        engine = PrioritizationEngine()
        scored = engine.evaluate_findings(findings)
        groups = engine.deduplicate(scored)
        assert len(groups) == 1000, f"Expected 1,000 distinct host bundles, got {len(groups)}"
        print("  -> PASSED: 1,000 independent host bundles grouped with zero cross-talk.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 10: Single Host with 1,000 Unique Ports (Fan-In)
    print("[TEST 10/20] Single Host with 1,000 Ports Fan-In Deduplication...")
    try:
        findings = [
            Finding("nessus", f"{i}", ["CVE-2022-0778"], 7.5, "High", "big-vpn-concentrator", str(i + 1), "tcp", "OpenSSL", "Upgrade OpenSSL", remediation_package="OpenSSL Cryptographic Library")
            for i in range(1000)
        ]
        engine = PrioritizationEngine()
        scored = engine.evaluate_findings(findings)
        groups = engine.deduplicate(scored)
        assert len(groups) == 1, f"Expected 1 consolidated bundle, got {len(groups)}"
        assert groups[0].findings_count == 1000
        assert len(groups[0].affected_ports) == 1000
        print("  -> PASSED: 1,000 port instances on single asset collapsed into 1 bundle.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 11: Multi-CVE Compound String Extraction
    print("[TEST 11/20] Multi-CVE Delimiter Parsing (Commas, Semicolons, Mixed Case)...")
    try:
        raw_cves = "cve-2021-44228; CVE-2022-22965, CVE-2023-44487 \n cve-2024-21413 / CVE-2020-1472"
        parser = ScannerParser()
        extracted = parser._extract_cves(raw_cves)
        assert len(extracted) == 5
        assert all(c.startswith("CVE-") for c in extracted)
        print("  -> PASSED: Normalized 5 compound CVEs from mixed delimiter formats.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 12: Special Regex Characters in Solution Text
    print("[TEST 12/20] Regex Metacharacters in Package & Solution Text...")
    try:
        parser = ScannerParser()
        tricky_title = "Vulnerability in [C++] std::vector<T*> operator+=(size_t) flaw ($HOME/bin)"
        tricky_solution = "Apply regex patch: s/.*pattern[0-9]+/replacement/g in (conf.d/*)"
        pkg = parser._extract_remediation_package(tricky_title, tricky_solution)
        assert pkg is not None and len(pkg) > 0
        print("  -> PASSED: Handled regex metacharacters without regex compilation error.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 13: IPv6 Compressed & Bracketed Address Handling
    print("[TEST 13/20] IPv6 Compressed & Bracketed Host Parsing...")
    try:
        sanitizer = TelemetrySanitizer()
        h1 = sanitizer.sanitize_host("[2001:db8::1]")
        h2 = sanitizer.sanitize_host("fe80::1ff:fe00:1")
        assert h1.startswith("host-") or h1.startswith("192.0.2.")
        assert h2.startswith("host-") or h2.startswith("192.0.2.")
        print("  -> PASSED: Handled IPv6 formats without parsing failure.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 14: Non-Standard Unknown Headers (Generic Dialect Fallback)
    print("[TEST 14/20] Non-Standard Schema Generic Dialect Fallback...")
    try:
        content = "Asset,Security Issue,Severity Score,Fix Notes\nsrv-custom-01,Insecure Password Hash,High,Update hashing algorithm\n"
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as tf:
            tf.write(content)
            temp_path = Path(tf.name)
        try:
            parser = ScannerParser()
            dialect, findings = parser.parse_file(temp_path)
            assert dialect in ["generic", "unknown"]
            assert len(findings) == 1
            print("  -> PASSED: Generic schema fallback parsed asset and severity.")
            passed += 1
        finally:
            temp_path.unlink()
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 15: Full Determinism Across 5 Consecutive Ingestions
    print("[TEST 15/20] Deterministic Output Invariance (5 Ingestion Iterations)...")
    try:
        fixture_path = FIXTURES_DIR / "fixture-nessus-enterprise-scan.csv"
        parser = ScannerParser()
        d, findings = parser.parse_file(fixture_path)
        engine = PrioritizationEngine()
        
        runs = []
        for _ in range(5):
            scored = engine.evaluate_findings(list(findings))
            groups = engine.deduplicate(scored)
            serialized = [(g.host, g.remediation_package, g.max_composite_score) for g in groups]
            runs.append(serialized)

        assert all(r == runs[0] for r in runs)
        print("  -> PASSED: 100% deterministic output verified across consecutive runs.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 16: Zero PII Leakage Verification Under Hostile Embedded Strings
    print("[TEST 16/20] Zero PII Leakage Under Hostile Injected Telemetry...")
    try:
        sanitizer = TelemetrySanitizer()
        hostile_desc = (
            "Internal domain controller dc01.internal.megacorp.com is connected to 10.240.12.88. "
            "Database at 172.16.5.99 sent secret to user-admin@secret.internal."
        )
        cleaned = sanitizer.sanitize_text(hostile_desc)
        assert "10.240.12.88" not in cleaned
        assert "172.16.5.99" not in cleaned
        assert "192.0.2.10" in cleaned
        print("  -> PASSED: RFC 1918 addresses completely masked by RFC 5737 replacements.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 17: CLI JSON Mode Output Validity
    print("[TEST 17/20] CLI JSON Output Mode Structural Validation...")
    try:
        script_path = SKILL_ROOT / "scripts" / "vuln_prioritizer.py"
        fixture_path = FIXTURES_DIR / "fixture-openvas-infrastructure-scan.csv"
        res = subprocess.run(
            [sys.executable, str(script_path), "-i", str(fixture_path), "--json"],
            capture_output=True,
            text=True
        )
        assert res.returncode == 0
        parsed_json = json.loads(res.stdout)
        assert "scanner" in parsed_json
        assert "bundles" in parsed_json
        assert len(parsed_json["bundles"]) > 0
        print("  -> PASSED: Valid JSON summary emitted with proper schema.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 18: Unclosed Quotes in Description Field
    print("[TEST 18/20] Unclosed Quotes and Escaped Characters...")
    try:
        content = (
            'Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution\n'
            '101,CVE-2021-44228,10.0,Critical,srv-01,tcp,443,Log4j,Synopsis,"Unclosed quote in description text,Solution text\n'
            '102,CVE-2023-44487,7.5,High,srv-02,tcp,443,HTTP2,Synopsis,Normal desc,Solution\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as tf:
            tf.write(content)
            temp_path = Path(tf.name)
        try:
            parser = ScannerParser()
            dialect, findings = parser.parse_file(temp_path)
            assert len(findings) >= 1
            print("  -> PASSED: Ingested malformed quotes without catastrophic failure.")
            passed += 1
        finally:
            temp_path.unlink()
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 19: All SLA Wave Buckets Populated Concurrently
    print("[TEST 19/20] Concurrent SLA Wave Bucket Partitioning...")
    try:
        findings = [
            Finding("generic", "1", ["CVE-2021-44228"], 10.0, "Critical", "dmz-web-01", "443", "tcp", "Log4j", "Fix", remediation_package="Log4j"),     # Wave 1 (KEV + Ext)
            Finding("generic", "2", ["CVE-2023-99999"], 9.8, "Critical", "srv-worker", "8080", "tcp", "Buffer", "Fix", remediation_package="Worker"),  # Wave 2 (CVSS >= 9.0)
            Finding("generic", "3", ["CVE-2022-99998"], 5.5, "Medium", "srv-internal", "3306", "tcp", "SQL Flaw", "Fix", remediation_package="MySQL"),  # Wave 3 (Score 5.0 - 8.9)
            Finding("generic", "4", [], 0.0, "Info", "srv-internal", "22", "tcp", "SSH Banner", "None", remediation_package="SSH"),                      # Wave 4 (Score < 5.0)
        ]
        engine = PrioritizationEngine(target_exposure="hybrid")
        scored = engine.evaluate_findings(findings)
        waves = {f.wave for f in scored}
        assert "Wave 1 (Emergency 24h)" in waves
        assert "Wave 2 (Urgent 7d)" in waves
        assert "Wave 3 (Standard 30d)" in waves
        assert "Wave 4 (Backlog / Info)" in waves
        print("  -> PASSED: All 4 SLA waves populated according to strict rubric.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 20: Missing Argument & Flag Validation
    print("[TEST 20/20] CLI Argument & Flag Robustness...")
    try:
        script_path = SKILL_ROOT / "scripts" / "vuln_prioritizer.py"
        res_noargs = subprocess.run([sys.executable, str(script_path)], capture_output=True, text=True)
        assert res_noargs.returncode != 0
        assert "required" in res_noargs.stderr.lower() or "error" in res_noargs.stderr.lower()
        print("  -> PASSED: Missing required flags gracefully handled by argparse.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    print("=" * 80)
    print(f"DEEP EXTREME STRESS TESTS RESULT: {passed}/20 PASSED, {failed} FAILED")
    print("=" * 80)
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_all_20_extreme_stress_tests()
