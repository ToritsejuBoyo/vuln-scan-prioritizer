# Contextual Risk Scoring Rubric

This reference defines the mathematical scoring model and SLA tiering heuristics utilized by `vuln-scan-prioritizer` to contextualize static scanner severity scores into operational remediation waves.

---

## 1. The Contextual Composite Score Formula

Static CVSS scores evaluate vulnerabilities in a theoretical vacuum. `vuln-scan-prioritizer` incorporates threat intelligence (active weaponization) and infrastructure context (network exposure and asset importance) into a composite priority score:

$$\text{Composite Risk Score} = \text{CVSS}_{\text{Base}} + W_{\text{KEV}} + W_{\text{Exploit}} + W_{\text{Exposure}} + W_{\text{Criticality}}$$

### Weight Breakdown

| Parameter | Weight / Points | Condition | Justification |
| :--- | :---: | :--- | :--- |
| **$\text{CVSS}_{\text{Base}}$** | `0.0` - `10.0` | Ingested from scanner | Standard baseline metric measuring intrinsic vulnerability difficulty and impact. |
| **$W_{\text{KEV}}$** | `+3.0` | Present in CISA KEV Catalog | Confirmed active, ongoing exploitation in the wild by threat actors. |
| **$W_{\text{Exploit}}$** | `+2.0` | Public functional PoC / weaponized exploit (if not KEV) | Low barrier to entry; trivial for script kiddies and opportunistic automated bots. |
| **$W_{\text{Exposure}}$** | `+2.0` | Internet-facing host, DMZ, VPN, or public web service | Accessible from untrusted public networks without perimeter authentication barriers. |
| **$W_{\text{Criticality}}$** | `+1.0` | Core infrastructure (Active Directory, primary database, cluster master) | High business blast radius; potential for lateral movement or total enterprise compromise. |

---

## 2. Remediation SLA Waves

Findings and deduplicated patch bundles are partitioned into four operational waves:

### Wave 1: Emergency Remediation (24-Hour SLA)
- **Qualification Criteria:**
  - Active CISA KEV catalog item present on an internet-facing asset or critical infrastructure host.
  - Or Composite Risk Score $\ge 12.0$.
- **Operational Action:** Immediate out-of-band change request (Emergency RFC). Patch deployment within 24 hours.

### Wave 2: Urgent Remediation (7-Day SLA)
- **Qualification Criteria:**
  - Base CVSS $\ge 9.0$ on internet-facing assets without confirmed active in-the-wild exploitation.
  - Or Composite Risk Score between $9.0$ and $11.9$.
- **Operational Action:** Expedited maintenance window. Engineering testing and rollout within 7 calendar days.

### Wave 3: Standard Remediation (30-Day SLA)
- **Qualification Criteria:**
  - Medium-to-High vulnerabilities (Base CVSS $\ge 4.0$ or Composite Risk Score between $5.0$ and $8.9$) located on internal, isolated networks.
- **Operational Action:** Scheduled within monthly routine enterprise patching cycle (Patch Tuesday + test cadence).

### Wave 4: Backlog / Informational (Quarterly / Discretionary)
- **Qualification Criteria:**
  - Low severity issues, informational banners, service discoveries, or Composite Risk Score $< 5.0$.
- **Operational Action:** Addressed during scheduled OS lifecycle upgrades or hardware refresh cycles.
