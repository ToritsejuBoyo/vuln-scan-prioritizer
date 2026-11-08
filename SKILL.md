---
name: vuln-scan-prioritizer
description: Triage, deduplicate, and prioritize vulnerability scanner CSV exports (Nessus, OpenVAS, Qualys, Rapid7) into actionable 4-wave remediation schedules and ITSM patch tickets.
---

# Vulnerability Scan Prioritizer (`vuln-scan-prioritizer`)

A deterministic, offline security operations skill that transforms raw, noisy vulnerability scanner CSV exports into an exploit-aware, prioritized remediation roadmap. Autodetects scanner column schemas, collapses redundant multi-port findings into unified patch bundles, correlates active in-the-wild weaponized exploits (CISA KEV), and enforces client-side data sanitization.

---

## Capabilities & Key Workflows

1. **Multi-Scanner Column Autodetection:**
   - Ingests exports from **Tenable Nessus**, **Greenbone OpenVAS / GVM**, **Qualys VMDR**, and **Rapid7 Nexpose / InsightVM** without requiring pre-formatting or manual column mapping.
   - Fallback heuristic handles generic vulnerability CSV schemas.

2. **Deduplication by Remediation Package:**
   - Standard scanners produce duplicate line items for every open port and network protocol.
   - The engine identifies common remediation components (e.g., OpenSSL, Log4j, Linux Kernel, Windows Netlogon) and aggregates multi-port alerts into a single unified patch action per host.

3. **Contextual Risk Scoring:**
   - Overcomes static CVSS score blind spots by factoring in real-world exploit availability and environment exposure:
     $$\text{Composite Score} = \text{CVSS}_{\text{Base}} + W_{\text{KEV}} (+3.0) + W_{\text{Exploit}} (+2.0) + W_{\text{Exposure}} (+2.0) + W_{\text{Criticality}} (+1.0)$$
   - Automatically prioritizes lower-CVSS actively exploited perimeter flaws over theoretical internal vulnerabilities.

4. **Remediation SLA Waves:**
   - **Wave 1 (Emergency - 24h):** Actively weaponized exploits (CISA KEV) on perimeter or critical assets.
   - **Wave 2 (Urgent - 7d):** Critical base severity ($\ge 9.0$) or high exposure without known public exploit.
   - **Wave 3 (Standard - 30d):** Medium-to-high internal infrastructure findings resolved during normal patch cycles.
   - **Wave 4 (Backlog / Info):** Low severity items, banner observations, and informational discoveries.

5. **Client-Side Data Sanitization (Rule 4):**
   - Automated `--sanitize` mode masks internal IPv4/IPv6 addresses into RFC 5737 test network blocks (`192.0.2.x`), hashes internal hostnames into `host-xxxx.corp.example.com`, and scrubs corporate domain suffixes.

6. **Automated ITSM Ticket & Report Generation:**
   - Produces executive Markdown assessments, prioritized CSV matrices, and pre-formatted Jira/ServiceNow patch tickets.

---

## Command Reference

### Basic Analysis (Console Report)
```bash
python scripts/vuln_prioritizer.py -i scan_export.csv
```

### Full Enterprise Triage with Sanitization & Artifact Generation
```bash
python scripts/vuln_prioritizer.py \
  -i scan_export.csv \
  --sanitize \
  --target-exposure hybrid \
  -o assessment_report.md \
  --output-csv prioritized_patches.csv \
  --generate-tickets itsm_tickets.md
```

### Force External Exposure (Perimeter Audit)
```bash
python scripts/vuln_prioritizer.py \
  -i dmz_nessus_scan.csv \
  --target-exposure external \
  --sanitize
```

### Ingest Custom or Live CISA KEV Feed
```bash
python scripts/vuln_prioritizer.py \
  -i scan_export.csv \
  --kev-file known_exploited_vulnerabilities.json
```

### Programmatic JSON Mode for Autonomous Agent Integration
```bash
python scripts/vuln_prioritizer.py -i scan_export.csv --json
```

---

## Integration with Agent Workflows

When an AI agent is tasked with reviewing infrastructure security scans:
1. Run `vuln_prioritizer.py -i <scan.csv> --sanitize --json` to inspect prioritized findings programmatically.
2. Review Wave 1 (Emergency) bundles to identify immediate perimeter risks.
3. Present the executive summary table and ticket copy to human security engineers for change management sign-off.
