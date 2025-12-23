#!/bin/bash
# shellcheck source=/dev/null
# shellcheck disable=SC2154
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Security Scanner - JSON Report Generator
# ══════════════════════════════════════════════════════════════════════════════

#######################################
# Generate JSON report
# Globals:
#   OUTPUT_DIR, SCANS_DIR, findings_list
#   critical, high, medium, low, info, total
#   target, scan_id, mode
# Arguments:
#   None
# Outputs:
#   Creates report.json file
#######################################
generate_json_report() {
    local report_file="$OUTPUT_DIR/report.json"

    # Build findings JSON array
    local findings_json="["
    local first=true

    for finding in "${findings_list[@]}"; do
        IFS='|' read -r _icon severity tool name description <<< "$finding"

        [ "$first" = true ] && first=false || findings_json+=","

        local escaped_desc escaped_name
        escaped_desc=$(escape_json "$description")
        escaped_name=$(escape_json "$name")

        findings_json+="{\"severity\":\"$severity\",\"tool\":\"$tool\",\"name\":\"$escaped_name\",\"description\":\"$escaped_desc\"}"
    done
    findings_json+="]"

    # Write JSON report
    cat > "$report_file" << EOF
{
    "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "scan_id": "$scan_id",
    "target": "$target",
    "mode": "$mode",
    "summary": {
        "critical": $critical,
        "high": $high,
        "medium": $medium,
        "low": $low,
        "info": $info,
        "total": $total
    },
    "findings": $findings_json,
    "files": {
        "scans": $(list_files_json "$SCANS_DIR"),
        "logs": $(list_files_json "$OUTPUT_DIR/logs")
    }
}
EOF
}
