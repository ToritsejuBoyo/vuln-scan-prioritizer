# ITSM Patch Ticket Specification (Template)

Pre-formatted structure for integration with Jira Service Management, ServiceNow Change Management, BMC Remedy, or Azure DevOps Boards.

---

### Ticket Summary
`[SecOps Patch] {{REMEDIATION_PACKAGE}} on {{TARGET_HOST}}`

### Field Attributes
- **Issue Type:** Patch Deployment / Vulnerability Remediation
- **Priority:** {{ITSM_PRIORITY}} (P1 Critical, P2 High, P3 Medium, P4 Low)
- **Component / CI:** `{{TARGET_HOST}}`
- **SLA Remediation Wave:** {{REMEDIATION_WAVE}}
- **Risk Score:** Composite {{COMPOSITE_SCORE}} (Base CVSS: {{CVSS_BASE}})
- **CISA KEV Exploit Status:** {{CISA_KEV_STATUS}}

### Affected Endpoints
- **Target Host:** `{{TARGET_HOST}}`
- **Impacted Network Ports:** `{{AFFECTED_PORTS}}`
- **Associated CVE Identifiers:** `{{ASSOCIATED_CVES}}`
- **Consolidated Alert Count:** {{FINDINGS_COUNT}} scanner findings collapsed

### Actionable Remediation Instructions
```text
{{VENDOR_RECOMMENDED_SOLUTION}}
```

### Change Verification & Rollback Procedure
1. **Pre-flight Check:** Verify running daemon state and backup configuration files.
2. **Execution:** Apply official vendor patch or package upgrade via standard enterprise configuration management (Ansible, SCCM, Intune, Puppet).
3. **Post-validation:** Query software version via command line and verify daemon listening on specified ports.
4. **Rollback Plan:** Revert to previous snapshot or package version if service fails health check.
