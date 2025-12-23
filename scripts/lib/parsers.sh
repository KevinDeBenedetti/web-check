#!/bin/bash
# shellcheck source=/dev/null
# shellcheck disable=SC2154
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Security Scanner - Parsers Library
# Individual parsers for each security tool output
# ══════════════════════════════════════════════════════════════════════════════

#######################################
# Parse Nuclei JSONL output
# Globals:
#   SCANS_DIR, critical, high, medium, low, info, findings_list
# Arguments:
#   None
# Outputs:
#   Updates global counters and findings_list array
#######################################
parse_nuclei() {
    local file="$SCANS_DIR/nuclei.json"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing Nuclei results..."

    local count=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue

        local severity template matched
        severity=$(echo "$line" | grep -oE '"severity"\s*:\s*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"' | tr '[:upper:]' '[:lower:]')
        template=$(echo "$line" | grep -oE '"template-id"\s*:\s*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
        matched=$(echo "$line" | grep -oE '"matched-at"\s*:\s*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')

        case "$severity" in
            critical) ((critical++)); add_finding "🔴" "CRITICAL" "Nuclei" "$template" "$matched" ;;
            high)     ((high++));     add_finding "🟠" "HIGH" "Nuclei" "$template" "$matched" ;;
            medium)   ((medium++));   add_finding "🟡" "MEDIUM" "Nuclei" "$template" "$matched" ;;
            low)      ((low++));      add_finding "🟢" "LOW" "Nuclei" "$template" "$matched" ;;
            info)     ((info++));     add_finding "🔵" "INFO" "Nuclei" "$template" "$matched" ;;
        esac
        ((count++))
    done < "$file"

    log_info "   └── Found $count findings"
}

#######################################
# Parse ZAP JSON output
# Globals:
#   SCANS_DIR, critical, high, medium, low, info, findings_list
# Arguments:
#   None
#######################################
parse_zap() {
    local file="$SCANS_DIR/zap.json"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing ZAP results..."

    local zap_critical zap_high zap_medium zap_low zap_info
    zap_critical=$(grep -cE '"riskcode"\s*:\s*"4"' "$file" 2>/dev/null) || zap_critical=0
    zap_high=$(grep -cE '"riskcode"\s*:\s*"3"' "$file" 2>/dev/null) || zap_high=0
    zap_medium=$(grep -cE '"riskcode"\s*:\s*"2"' "$file" 2>/dev/null) || zap_medium=0
    zap_low=$(grep -cE '"riskcode"\s*:\s*"1"' "$file" 2>/dev/null) || zap_low=0
    zap_info=$(grep -cE '"riskcode"\s*:\s*"0"' "$file" 2>/dev/null) || zap_info=0

    critical=$((critical + zap_critical))
    high=$((high + zap_high))
    medium=$((medium + zap_medium))
    low=$((low + zap_low))
    info=$((info + zap_info))

    # Extract detailed alerts with jq
    if command -v jq &> /dev/null; then
        while IFS= read -r alert; do
            [ -n "$alert" ] && findings_list+=("$alert")
        done < <(jq -r '.site[]?.alerts[]? |
            (if .riskcode == "3" then "🟠|HIGH|ZAP"
             elif .riskcode == "2" then "🟡|MEDIUM|ZAP"
             elif .riskcode == "1" then "🟢|LOW|ZAP"
             else "🔵|INFO|ZAP" end) + "|" + .alert + "|" + (.instances[0]?.uri // "N/A")' "$file" 2>/dev/null)
    fi

    local total=$((zap_critical + zap_high + zap_medium + zap_low + zap_info))
    log_info "   └── Found $total alerts"
}

#######################################
# Parse testssl.sh JSON output
# Globals:
#   SCANS_DIR, critical, high, medium, low, info, findings_list
# Arguments:
#   None
#######################################
parse_testssl() {
    local file="$SCANS_DIR/testssl.json"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing testssl.sh results..."

    local ts_critical ts_high ts_medium ts_low ts_info
    ts_critical=$(grep -ciE '"severity"\s*:\s*"CRITICAL"' "$file" 2>/dev/null) || ts_critical=0
    ts_high=$(grep -ciE '"severity"\s*:\s*"HIGH"' "$file" 2>/dev/null) || ts_high=0
    ts_medium=$(grep -ciE '"severity"\s*:\s*"(MEDIUM|WARN)"' "$file" 2>/dev/null) || ts_medium=0
    ts_low=$(grep -ciE '"severity"\s*:\s*"LOW"' "$file" 2>/dev/null) || ts_low=0
    ts_info=$(grep -ciE '"severity"\s*:\s*"(INFO|OK)"' "$file" 2>/dev/null) || ts_info=0

    critical=$((critical + ts_critical))
    high=$((high + ts_high))
    medium=$((medium + ts_medium))
    low=$((low + ts_low))
    info=$((info + ts_info))

    # Extract findings with jq
    if command -v jq &> /dev/null; then
        while IFS='|' read -r sev id finding; do
            case "$sev" in
                CRITICAL) add_finding "🔴" "CRITICAL" "testssl" "$id" "$finding" ;;
                HIGH)     add_finding "🟠" "HIGH" "testssl" "$id" "$finding" ;;
                MEDIUM|WARN) add_finding "🟡" "MEDIUM" "testssl" "$id" "$finding" ;;
                LOW)      add_finding "🟢" "LOW" "testssl" "$id" "$finding" ;;
            esac
        done < <(jq -r '.[] | select(.severity == "CRITICAL" or .severity == "HIGH" or .severity == "MEDIUM" or .severity == "WARN" or .severity == "LOW") | "\(.severity)|\(.id)|\(.finding)"' "$file" 2>/dev/null)
    fi

    local issues=$((ts_critical + ts_high + ts_medium + ts_low))
    log_info "   └── Found $issues issues (+ $ts_info info)"
}

#######################################
# Parse Nikto HTML output
# Globals:
#   SCANS_DIR, high, medium, low, info, findings_list
# Arguments:
#   None
#######################################
parse_nikto() {
    local file="$SCANS_DIR/nikto.html"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing Nikto results..."

    local nikto_findings nikto_high nikto_medium nikto_info nikto_low
    nikto_findings=$(grep -c '<td class="column-head">Description</td>' "$file" 2>/dev/null) || nikto_findings=0

    # Classify by pattern matching
    nikto_high=$(grep -ciE '(SQL injection|XSS|Remote File|command injection|directory traversal|RCE)' "$file" 2>/dev/null) || nikto_high=0
    nikto_medium=$(grep -ciE '(X-Frame-Options|X-Content-Type|X-XSS-Protection|Content-Security-Policy|Strict-Transport)' "$file" 2>/dev/null) || nikto_medium=0
    nikto_info=$(grep -ciE '(Server:.*[0-9]|retrieved|appears to be|uncommon header)' "$file" 2>/dev/null) || nikto_info=0

    nikto_low=$((nikto_findings - nikto_high - nikto_medium - nikto_info))
    [ $nikto_low -lt 0 ] && nikto_low=0

    high=$((high + nikto_high))
    medium=$((medium + nikto_medium))
    low=$((low + nikto_low))
    info=$((info + nikto_info))

    # Extract descriptions
    while IFS= read -r desc; do
        desc=$(echo "$desc" | sed 's/&quot;/"/g; s/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g' | head -c 200)
        [ -z "$desc" ] && continue

        if echo "$desc" | grep -qiE '(SQL injection|XSS|Remote File|command injection)'; then
            add_finding "🟠" "HIGH" "Nikto" "vulnerability" "$desc"
        elif echo "$desc" | grep -qiE '(X-Frame-Options|X-Content-Type|X-XSS-Protection)'; then
            add_finding "🟡" "MEDIUM" "Nikto" "missing-header" "$desc"
        else
            add_finding "🔵" "INFO" "Nikto" "check" "$desc"
        fi
    done < <(grep -A1 'Description</td>' "$file" 2>/dev/null | grep '<td>' | sed 's/.*<td>\([^<]*\)<\/td>.*/\1/' | head -30)

    log_info "   └── Found $nikto_findings findings"
}

#######################################
# Parse ffuf JSON output
# Globals:
#   SCANS_DIR, high, medium, info, findings_list
# Arguments:
#   None
#######################################
parse_ffuf() {
    local file="$SCANS_DIR/ffuf.json"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing ffuf results..."

    local ffuf_high=0 ffuf_medium=0 ffuf_info=0

    if command -v jq &> /dev/null; then
        local ffuf_403 ffuf_401 ffuf_200 ffuf_301
        ffuf_403=$(jq '[.results[]? | select(.status == 403)] | length' "$file" 2>/dev/null) || ffuf_403=0
        ffuf_401=$(jq '[.results[]? | select(.status == 401)] | length' "$file" 2>/dev/null) || ffuf_401=0
        ffuf_200=$(jq '[.results[]? | select(.status == 200)] | length' "$file" 2>/dev/null) || ffuf_200=0
        ffuf_301=$(jq '[.results[]? | select(.status == 301 or .status == 302)] | length' "$file" 2>/dev/null) || ffuf_301=0

        ffuf_medium=$((ffuf_403 + ffuf_401))
        ffuf_info=$((ffuf_200 + ffuf_301))

        # Extract URLs
        while IFS= read -r result; do
            local url status input
            url=$(echo "$result" | jq -r '.url' 2>/dev/null)
            status=$(echo "$result" | jq -r '.status' 2>/dev/null)
            input=$(echo "$result" | jq -r '.input.FUZZ' 2>/dev/null)

            if [ "$status" = "403" ] || [ "$status" = "401" ]; then
                add_finding "🟡" "MEDIUM" "ffuf" "$input" "$url (Status: $status - Potential sensitive file)"
            elif [ "$status" = "200" ]; then
                if echo "$input" | grep -qiE '(config|admin|backup|\.env|passwd|wp-config|\.git)'; then
                    add_finding "🟠" "HIGH" "ffuf" "$input" "$url (Status: $status - Sensitive file exposed)"
                    ((ffuf_high++))
                else
                    add_finding "🔵" "INFO" "ffuf" "$input" "$url (Status: $status)"
                fi
            fi
        done < <(jq -c '.results[]?' "$file" 2>/dev/null)
    else
        ffuf_info=$(grep -c '"status":' "$file" 2>/dev/null) || ffuf_info=0
    fi

    high=$((high + ffuf_high))
    medium=$((medium + ffuf_medium))
    info=$((info + ffuf_info))

    local total=$((ffuf_high + ffuf_medium + ffuf_info))
    log_info "   └── Found $total discoveries"
}

#######################################
# Run all parsers
# Globals:
#   All parser globals
# Arguments:
#   None
#######################################
run_all_parsers() {
    parse_nuclei
    parse_zap
    parse_testssl
    parse_nikto
    parse_ffuf
}
