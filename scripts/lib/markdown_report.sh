#!/bin/bash
# shellcheck source=/dev/null
# shellcheck disable=SC2154
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Security Scanner - Markdown Report Generator (LLM-optimized)
# ══════════════════════════════════════════════════════════════════════════════
#
# Generates a structured Markdown report designed for LLM consumption:
# - YAML frontmatter with metadata
# - Clear hierarchical structure
# - Grouped findings by severity
# - Actionable recommendations format
# ══════════════════════════════════════════════════════════════════════════════

#######################################
# Generate YAML frontmatter for LLM context
# Globals:
#   target, scan_id, mode
#   critical, high, medium, low, info, total
# Arguments:
#   None
# Outputs:
#   YAML frontmatter to stdout
#######################################
generate_markdown_frontmatter() {
    cat << EOF
---
type: security_scan_report
version: "1.0"
generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
scan:
  id: "$scan_id"
  target: "$target"
  mode: "$mode"
summary:
  critical: $critical
  high: $high
  medium: $medium
  low: $low
  info: $info
  total: $total
tools_used:
  - nuclei
  - zap
  - testssl
  - nikto
  - ffuf
---

EOF
}

#######################################
# Generate executive summary section
# Globals:
#   target, critical, high, medium, low, info, total
# Arguments:
#   None
# Outputs:
#   Executive summary markdown to stdout
#######################################
generate_markdown_summary() {
    local risk_level="LOW"
    if [ "$critical" -gt 0 ]; then
        risk_level="CRITICAL"
    elif [ "$high" -gt 0 ]; then
        risk_level="HIGH"
    elif [ "$medium" -gt 0 ]; then
        risk_level="MEDIUM"
    fi

    cat << EOF
# Security Scan Report

## Executive Summary

**Target:** \`$target\`
**Overall Risk Level:** **$risk_level**
**Total Findings:** $total

### Severity Distribution

| Severity | Count | Priority |
|----------|-------|----------|
| 🔴 Critical | $critical | Immediate action required |
| 🟠 High | $high | Address within 24-48 hours |
| 🟡 Medium | $medium | Address within 1-2 weeks |
| 🟢 Low | $low | Address in next release cycle |
| 🔵 Info | $info | Review and document |

EOF
}

#######################################
# Generate findings section grouped by severity
# Globals:
#   findings_list
# Arguments:
#   None
# Outputs:
#   Findings markdown to stdout
#######################################
generate_markdown_findings() {
    echo "## Detailed Findings"
    echo ""

    # Process each severity level
    local severities=("critical" "high" "medium" "low" "info")
    local severity_labels=("Critical" "High" "Medium" "Low" "Informational")
    local severity_icons=("🔴" "🟠" "🟡" "🟢" "🔵")

    for i in "${!severities[@]}"; do
        local sev="${severities[$i]}"
        local label="${severity_labels[$i]}"
        local icon="${severity_icons[$i]}"
        local count=0
        local findings_output=""

        # Collect findings for this severity
        for finding in "${findings_list[@]}"; do
            IFS='|' read -r _f_icon f_severity f_tool f_name f_description <<< "$finding"
            local normalized_sev
            normalized_sev=$(echo "$f_severity" | tr '[:upper:]' '[:lower:]')

            if [ "$normalized_sev" = "$sev" ]; then
                ((count++))
                findings_output+="### $count. $f_name

- **Tool:** \`$f_tool\`
- **Severity:** $label
- **Details:** $f_description

"
            fi
        done

        # Only output section if there are findings
        if [ "$count" -gt 0 ]; then
            echo "---"
            echo ""
            echo "## $icon $label Findings ($count)"
            echo ""
            echo "$findings_output"
        fi
    done
}

#######################################
# Generate recommendations section for LLM analysis
# Globals:
#   critical, high, medium
# Arguments:
#   None
# Outputs:
#   Recommendations markdown to stdout
#######################################
generate_markdown_recommendations() {
    cat << 'EOF'
---

## Recommended Actions

### Immediate Priority (Critical/High)

EOF

    if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ]; then
        cat << 'EOF'
1. **Triage critical findings** - Review and validate each critical/high finding
2. **Implement fixes** - Apply patches or configuration changes
3. **Verify remediation** - Re-scan to confirm fixes are effective

EOF
    else
        echo "_No critical or high severity findings require immediate action._"
        echo ""
    fi

    cat << 'EOF'
### Short-term Priority (Medium)

EOF

    if [ "$medium" -gt 0 ]; then
        cat << 'EOF'
1. **Schedule remediation** - Plan fixes for the next sprint/release
2. **Document exceptions** - If a finding cannot be fixed, document the risk acceptance
3. **Implement compensating controls** - Add monitoring or additional security layers

EOF
    else
        echo "_No medium severity findings require short-term action._"
        echo ""
    fi

    cat << 'EOF'
### Continuous Improvement

- Review informational findings for security hardening opportunities
- Update security baselines based on scan results
- Schedule regular security scans to track progress

EOF
}

#######################################
# Generate LLM instruction footer
# Arguments:
#   None
# Outputs:
#   LLM instructions markdown to stdout
#######################################
generate_markdown_llm_instructions() {
    cat << 'EOF'
---

## LLM Analysis Instructions

When analyzing this report, consider the following:

1. **Context:** This is an automated security scan of a web application/infrastructure
2. **False Positives:** Some findings may be false positives - validate before taking action
3. **Business Context:** Consider the criticality of the target system when prioritizing
4. **Remediation:** Provide specific, actionable remediation steps for each finding type
5. **Risk Assessment:** Evaluate the real-world exploitability of each finding

### Suggested Analysis Tasks

- Summarize the overall security posture
- Identify the top 3 most critical issues to address
- Suggest a prioritized remediation plan
- Identify any patterns or systemic issues across findings
- Recommend additional security testing if gaps are identified

EOF
}

#######################################
# Generate complete Markdown report
# Globals:
#   OUTPUT_DIR, findings_list
#   critical, high, medium, low, info, total
#   target, scan_id, mode
# Arguments:
#   None
# Outputs:
#   Creates report.md file
#######################################
generate_markdown_report() {
    local report_file="$OUTPUT_DIR/report.md"

    {
        generate_markdown_frontmatter
        generate_markdown_summary
        generate_markdown_findings
        generate_markdown_recommendations
        generate_markdown_llm_instructions
    } > "$report_file"
}
