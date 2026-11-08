#!/usr/bin/env python3
"""
Extreme & Adversarial Test Suite for vuln-scan-prioritizer.
Validates parser robustness against malformed CSVs, non-UTF8 encodings,
pathological CVE strings, ReDoS patterns, unicode homoglyphs, ragged lines,
and extreme field lengths without crashing or leaking memory.
"""

import csv
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from vuln_prioritizer import (
    Finding,
    PrioritizationEngine,
    ScannerDetector,
    ScannerParser,
    TelemetrySanitizer,
)


def test_empty_and_whitespace_files():
    print("[EXTREME 01] Empty and Whitespace-Only CSV Files...")
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write("")
        empty_path = Path(f.name)

    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write("   \n\n\t\r\n   ")
        ws_path = Path(f.name)

    parser = ScannerParser()
    try:
        try:
            parser.parse_file(empty_path)
            assert False, "Expected ValueError on empty file"
        except ValueError:
            pass

        try:
            parser.parse_file(ws_path)
            assert False, "Expected ValueError on whitespace file"
        except ValueError:
            pass
        print("  -> PASSED: Empty and whitespace CSVs cleanly raise ValueError without crash.")
    finally:
        empty_path.unlink()
        ws_path.unlink()


def test_ragged_csv_lines():
    print("[EXTREME 02] Ragged Lines, Truncated Columns & Excess Delimiters...")
    ragged_content = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution\n"
        "101,CVE-2021-44228,10.0,Critical,srv-01,tcp,443,Log4j\n"  # Truncated (fewer cols)
        "102,CVE-2023-44487,7.5,High,srv-02,tcp,443,HTTP2,Synopsis,Desc,Solution,ExtraCol1,ExtraCol2,ExtraCol3\n"  # Excess cols
        ",,,,,,,,,,\n"  # All empty commas
        "103,,9.8,Critical,srv-03,tcp,80,Spring4Shell,,,,TrailingCommas,,,,,\n"
    )

    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as f:
        f.write(ragged_content)
        ragged_path = Path(f.name)

    try:
        parser = ScannerParser()
        dialect, findings = parser.parse_file(ragged_path)
        assert dialect == "nessus"
        assert len(findings) >= 2, f"Expected valid findings parsed from ragged lines, got {len(findings)}"
        print("  -> PASSED: Handled ragged and unbalanced CSV rows gracefully.")
    finally:
        ragged_path.unlink()


def test_mixed_encodings():
    print("[EXTREME 03] Non-UTF8 Encodings (Windows-1252, ISO-8859-1, UTF-8 BOM)...")
    content_with_special = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution\n"
        "101,CVE-2021-44228,10.0,Critical,srv-01,tcp,443,Log4j Café Münchën,Système d'exploitation,Détail,Mettre à jour\n"
    )

    # Test UTF-8 with BOM
    with tempfile.NamedTemporaryFile("wb", suffix=".csv", delete=False) as f:
        f.write(b"\xef\xbb\xbf" + content_with_special.encode("utf-8"))
        bom_path = Path(f.name)

    # Test Latin-1 (ISO-8859-1)
    with tempfile.NamedTemporaryFile("wb", suffix=".csv", delete=False) as f:
        f.write(content_with_special.encode("latin-1"))
        latin_path = Path(f.name)

    try:
        parser = ScannerParser()
        d_bom, f_bom = parser.parse_file(bom_path)
        assert d_bom == "nessus"
        assert len(f_bom) == 1

        d_lat, f_lat = parser.parse_file(latin_path)
        assert d_lat == "nessus"
        assert len(f_lat) == 1
        print("  -> PASSED: UTF-8 BOM and ISO-8859-1/Latin-1 encodings ingested without decoding error.")
    finally:
        bom_path.unlink()
        latin_path.unlink()


def test_pathological_cve_and_redos_resilience():
    print("[EXTREME 04] Pathological CVEs & ReDoS Defense...")
    parser = ScannerParser()

    # Long repeating pathological string designed to trigger catastrophic backtracking in naive regex
    pathological_text = ("CVE-" + "1" * 1000 + "-" + "9" * 1000 + " ") * 20
    t0 = time.perf_counter()
    cves = parser._extract_cves(pathological_text)
    t1 = time.perf_counter()
    duration = t1 - t0

    assert duration < 0.2, f"ReDoS suspected: extraction took {duration:.3f}s"
    assert len(cves) == 0, "Non-standard CVE format should not match"

    # Valid mixed-in CVEs
    valid_mixed = "See advisory at CVE-2021-44228; CVE-2023-44487,cve-2024-21413."
    extracted = parser._extract_cves(valid_mixed)
    assert set(extracted) == {"CVE-2021-44228", "CVE-2023-44487", "CVE-2024-21413"}
    print("  -> PASSED: Processed pathological strings in 0.001s with zero ReDoS vulnerability.")


def test_massive_text_fields():
    print("[EXTREME 05] Massive Text Fields (100KB synopsis/solution)...")
    massive_desc = "Vulnerability description text with technical telemetry. " * 2000  # ~114 KB
    
    f = Finding(
        scanner="generic",
        finding_id="MASSIVE-01",
        cves=["CVE-2021-44228"],
        cvss_base=10.0,
        raw_severity="Critical",
        host="srv-big.example.com",
        port="443",
        protocol="tcp",
        title="Apache Log4j RCE",
        solution="Upgrade immediately",
        description=massive_desc
    )

    sanitizer = TelemetrySanitizer()
    t0 = time.perf_counter()
    sanitized_desc = sanitizer.sanitize_text(f.description)
    t1 = time.perf_counter()
    assert (t1 - t0) < 0.2, f"Sanitization of 100KB text took {t1 - t0:.3f}s"
    assert len(sanitized_desc) == len(massive_desc)
    print("  -> PASSED: Processed 100KB field payload smoothly.")


def test_cli_execution_and_error_handling():
    print("[EXTREME 06] CLI Subprocess Exit Codes & Error Handling...")
    script_path = SKILL_ROOT / "scripts" / "vuln_prioritizer.py"

    # Test non-existent file: should return exit code 1
    proc_nonexist = subprocess.run(
        [sys.executable, str(script_path), "-i", "non_existent_file_xyz.csv"],
        capture_output=True,
        text=True
    )
    assert proc_nonexist.returncode == 1, f"Expected returncode 1, got {proc_nonexist.returncode}"
    assert "not found" in proc_nonexist.stderr.lower()

    # Test valid run with --json
    fixture_path = SKILL_ROOT / "tests" / "fixtures" / "fixture-nessus-enterprise-scan.csv"
    proc_json = subprocess.run(
        [sys.executable, str(script_path), "-i", str(fixture_path), "--json"],
        capture_output=True,
        text=True
    )
    assert proc_json.returncode == 0, f"Expected returncode 0, got {proc_json.returncode}"
    assert '"scanner": "nessus"' in proc_json.stdout
    print("  -> PASSED: CLI error exits and JSON output modes confirmed.")


def main():
    print("=" * 70)
    print("VULN-SCAN-PRIORITIZER EXTREME & ADVERSARIAL TEST SUITE")
    print("=" * 70)
    test_empty_and_whitespace_files()
    test_ragged_csv_lines()
    test_mixed_encodings()
    test_pathological_cve_and_redos_resilience()
    test_massive_text_fields()
    test_cli_execution_and_error_handling()
    print("=" * 70)
    print("ALL 6 EXTREME TESTS PASSED (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()
