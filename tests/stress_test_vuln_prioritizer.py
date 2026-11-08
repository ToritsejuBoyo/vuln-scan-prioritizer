#!/usr/bin/env python3
"""
Stress & High-Volume Benchmark Suite for vuln-scan-prioritizer.
Generates and triages 10,000 synthetic vulnerability scanner rows across 500 hosts.
Asserts end-to-end ingestion, parsing, scoring, and deduplication finish in under 3.0 seconds.
"""

import csv
import sys
import tempfile
import time
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from vuln_prioritizer import (
    PrioritizationEngine,
    ReportFormatter,
    ScannerParser,
    TelemetrySanitizer,
)


def generate_large_nessus_csv(target_path: Path, row_count: int = 10000):
    headers = [
        "Plugin ID", "CVE", "CVSS v3.0 Base Score", "Risk", "Host",
        "Protocol", "Port", "Name", "Synopsis", "Description", "Solution", "Plugin Output"
    ]
    
    # 10 repeating vulnerability templates
    templates = [
        ("101", "CVE-2021-44228", "10.0", "Critical", "Apache Log4j RCE", "Upgrade log4j package to 2.17.1"),
        ("102", "CVE-2023-44487", "7.5", "High", "HTTP/2 Rapid Reset DoS", "Apply HTTP/2 rate limit patch"),
        ("103", "CVE-2022-0778", "7.5", "High", "OpenSSL Infinite Loop", "Upgrade OpenSSL to 1.1.1n"),
        ("104", "CVE-2024-21413", "9.8", "Critical", "Outlook MonikerLink NTLM", "Install KB5034763"),
        ("105", "CVE-2023-38606", "9.8", "Critical", "PostgreSQL Buffer Overflow", "Update postgresql-15 package"),
        ("106", "CVE-2023-38545", "9.8", "Critical", "cURL SOCKS5 Overflow", "Upgrade libcurl to 8.4.0"),
        ("107", "CVE-2022-22965", "9.8", "Critical", "Spring4Shell RCE", "Upgrade Spring Framework"),
        ("108", "CVE-2020-1472", "10.0", "Critical", "Zerologon Netlogon Bypass", "Apply KB4557222"),
        ("109", "", "0.0", "None", "OpenSSH Banner Detection", "Informational only"),
        ("110", "", "3.1", "Low", "TCP Timestamp Response", "Disable TCP timestamps in sysctl"),
    ]

    ports = ["22", "80", "443", "445", "1194", "3389", "5432", "8080", "8443", "9090"]

    with open(target_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for i in range(row_count):
            tpl = templates[i % len(templates)]
            host_idx = (i // 10) % 500 + 1
            port = ports[i % len(ports)]
            host = f"synthetic-srv-{host_idx:03d}.corp.example.com"
            writer.writerow([
                f"{tpl[0]}{i % 50}",
                tpl[1],
                tpl[2],
                tpl[3],
                host,
                "tcp",
                port,
                tpl[4],
                f"Synopsis for {tpl[4]} on port {port}",
                f"Detailed description of {tpl[4]}",
                tpl[5],
                f"Scanner output evidence for finding {i}"
            ])


def run_benchmark():
    print("=" * 70)
    print("VULN-SCAN-PRIORITIZER STRESS & HIGH-VOLUME BENCHMARK (10,000 ROWS)")
    print("=" * 70)

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
        temp_csv = Path(tf.name)

    try:
        print("[STEP 1] Generating 10,000-row synthetic Nessus CSV scan export...")
        t0_gen = time.perf_counter()
        generate_large_nessus_csv(temp_csv, 10000)
        t1_gen = time.perf_counter()
        file_size_mb = temp_csv.stat().st_size / (1024 * 1024)
        print(f"  -> Generated {file_size_mb:.2f} MB CSV in {t1_gen - t0_gen:.3f}s")

        print("[STEP 2] Parsing 10,000 rows with client-side sanitization enabled...")
        sanitizer = TelemetrySanitizer(salt="stress-benchmark-salt")
        parser = ScannerParser(sanitizer=sanitizer)
        t0_parse = time.perf_counter()
        dialect, findings = parser.parse_file(temp_csv)
        t1_parse = time.perf_counter()
        parse_duration = t1_parse - t0_parse
        print(f"  -> Parsed {len(findings):,} findings ({dialect.upper()}) in {parse_duration:.3f}s")
        assert len(findings) == 10000, f"Expected 10,000 findings, got {len(findings)}"

        print("[STEP 3] Prioritization, contextual risk scoring, and SLA wave partitioning...")
        engine = PrioritizationEngine(target_exposure="hybrid")
        t0_score = time.perf_counter()
        scored_findings = engine.evaluate_findings(findings)
        t1_score = time.perf_counter()
        score_duration = t1_score - t0_score
        print(f"  -> Scored {len(scored_findings):,} findings in {score_duration:.3f}s")

        print("[STEP 4] Deduplication and unified remediation package grouping...")
        t0_dedup = time.perf_counter()
        groups = engine.deduplicate(scored_findings)
        t1_dedup = time.perf_counter()
        dedup_duration = t1_dedup - t0_dedup
        print(f"  -> Consolidated into {len(groups):,} unified patch bundles in {dedup_duration:.3f}s")

        reduction_percent = (10000 - len(groups)) / 10000 * 100
        print(f"  -> Noise reduction ratio: {reduction_percent:.1f}%")
        assert reduction_percent > 40.0, f"Expected > 40% deduplication, got {reduction_percent:.1f}%"

        total_proc_time = parse_duration + score_duration + dedup_duration
        print("-" * 70)
        print(f"TOTAL ENGINE EXECUTION TIME: {total_proc_time:.3f}s")
        print(f"THROUGHPUT: {10000 / total_proc_time:,.0f} findings/second")
        print("-" * 70)

        # Assert SLA: Must finish 10,000 rows under 3.0 seconds
        assert total_proc_time < 3.0, f"Benchmark exceeded 3.0s limit: {total_proc_time:.3f}s"
        print("PERFORMANCE BENCHMARK PASSED: Under 3.0s execution SLA met.")

    finally:
        if temp_csv.exists():
            temp_csv.unlink()

    print("=" * 70)
    print("STRESS TEST COMPLETED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
