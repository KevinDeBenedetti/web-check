#!/bin/bash
# shellcheck source=/dev/null
# shellcheck disable=SC2154
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Parsers Library
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
# Notes:
#   - HTTP 429 (rate limiting) is a security feature, not a vulnerability
#   - Downgrades false positives to INFO level
#######################################
parse_testssl() {
    local file="$SCANS_DIR/testssl.json"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing testssl.sh results..."

    local ts_critical=0 ts_high=0 ts_medium=0 ts_low=0 ts_info=0
    local ts_false_positives=0

    # Extract findings with jq for better filtering
    if command -v jq &> /dev/null; then
        while IFS='|' read -r sev id finding; do
            # Skip empty lines
            [ -z "$sev" ] && continue

            # Filter out false positives
            # HTTP 429 = Rate limiting is a security FEATURE, not a vulnerability
            if [[ "$id" == "HTTP_status_code" ]] && [[ "$finding" == *"429"* ]]; then
                ((ts_false_positives++))
                add_finding "🔵" "INFO" "testssl" "$id" "$finding (Rate limiting active - this is good!)"
                ((ts_info++))
                continue
            fi

            case "$sev" in
                CRITICAL)
                    add_finding "🔴" "CRITICAL" "testssl" "$id" "$finding"
                    ((ts_critical++))
                    ;;
                HIGH)
                    add_finding "🟠" "HIGH" "testssl" "$id" "$finding"
                    ((ts_high++))
                    ;;
                MEDIUM|WARN)
                    add_finding "🟡" "MEDIUM" "testssl" "$id" "$finding"
                    ((ts_medium++))
                    ;;
                LOW)
                    add_finding "🟢" "LOW" "testssl" "$id" "$finding"
                    ((ts_low++))
                    ;;
                INFO|OK)
                    # Add INFO findings to the list (limited display in report)
                    add_finding "🔵" "INFO" "testssl" "$id" "$finding"
                    ((ts_info++))
                    ;;
            esac
        done < <(jq -r '.[] | select(.severity) | "\(.severity)|\(.id)|\(.finding)"' "$file" 2>/dev/null)
    else
        # Fallback without jq (less accurate)
        ts_critical=$(grep -ciE '"severity"\s*:\s*"CRITICAL"' "$file" 2>/dev/null) || ts_critical=0
        ts_high=$(grep -ciE '"severity"\s*:\s*"HIGH"' "$file" 2>/dev/null) || ts_high=0
        ts_medium=$(grep -ciE '"severity"\s*:\s*"(MEDIUM|WARN)"' "$file" 2>/dev/null) || ts_medium=0
        ts_low=$(grep -ciE '"severity"\s*:\s*"LOW"' "$file" 2>/dev/null) || ts_low=0
        ts_info=$(grep -ciE '"severity"\s*:\s*"(INFO|OK)"' "$file" 2>/dev/null) || ts_info=0
    fi

    critical=$((critical + ts_critical))
    high=$((high + ts_high))
    medium=$((medium + ts_medium))
    low=$((low + ts_low))
    info=$((info + ts_info))

    local issues=$((ts_critical + ts_high + ts_medium + ts_low))
    if [ $ts_false_positives -gt 0 ]; then
        log_info "   └── Found $issues issues (+ $ts_info info, $ts_false_positives false positives filtered)"
    else
        log_info "   └── Found $issues issues (+ $ts_info info)"
    fi
}

#######################################
# Parse Nikto HTML output
# Globals:
#   SCANS_DIR, high, medium, low, info, findings_list
# Arguments:
#   None
# Notes:
#   - Missing X-XSS-Protection header is MEDIUM (not HIGH - it's just a missing header)
#   - Actual XSS/SQLi vulnerabilities are HIGH
#   - Server version disclosure and uncommon headers are INFO
#   - ORDER MATTERS: Check INFO patterns FIRST to avoid false HIGH classification
#######################################
parse_nikto() {
    local file="$SCANS_DIR/nikto.html"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing Nikto results..."

    local nikto_high=0 nikto_medium=0 nikto_info=0 nikto_low=0

    # Extract and classify descriptions
    while IFS= read -r desc; do
        desc=$(echo "$desc" | sed 's/&quot;/"/g; s/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g' | head -c 200)
        [ -z "$desc" ] && continue

        # IMPORTANT: Check INFO patterns FIRST (uncommon headers, version info)
        # These should NOT be escalated to HIGH/MEDIUM
        if echo "$desc" | grep -qiE '(uncommon header|retrieved x-|Server:|appears to be|version|Allowed HTTP)'; then
            add_finding "🔵" "INFO" "Nikto" "info-disclosure" "$desc"
            ((nikto_info++))
        # HIGH: Actual vulnerabilities (not just missing headers)
        elif echo "$desc" | grep -qiE '(SQL injection|Remote File Inclusion|command injection|directory traversal|RCE|Local File Inclusion|XXE|SSRF|file upload|backdoor|shell)'; then
            add_finding "🟠" "HIGH" "Nikto" "vulnerability" "$desc"
            ((nikto_high++))
        # MEDIUM: Missing security headers
        elif echo "$desc" | grep -qiE '(X-Frame-Options|X-Content-Type|X-XSS-Protection|Content-Security-Policy|Strict-Transport|anti-clickjacking|Expect-CT|header is not|not defined|not set|not present|not offered)'; then
            add_finding "🟡" "MEDIUM" "Nikto" "missing-header" "$desc"
            ((nikto_medium++))
        # Everything else is INFO
        else
            add_finding "🔵" "INFO" "Nikto" "check" "$desc"
            ((nikto_info++))
        fi
    done < <(grep -A1 'Description</td>' "$file" 2>/dev/null | grep '<td>' | sed 's/.*<td>\([^<]*\)<\/td>.*/\1/' | head -50)

    high=$((high + nikto_high))
    medium=$((medium + nikto_medium))
    low=$((low + nikto_low))
    info=$((info + nikto_info))

    local total=$((nikto_high + nikto_medium + nikto_low + nikto_info))
    log_info "   └── Found $total findings (High: $nikto_high, Medium: $nikto_medium, Info: $nikto_info)"
}

#######################################
# Parse ffuf JSON output
# Globals:
#   SCANS_DIR, high, medium, info, findings_list
# Arguments:
#   None
# Notes:
#   - 403/401 responses are NOT vulnerabilities (server is correctly blocking)
#   - Only 200 responses to sensitive files are actual findings
#   - Entries starting with # (wordlist comments) are ignored
#######################################
parse_ffuf() {
    local file="$SCANS_DIR/ffuf.json"
    [ ! -f "$file" ] || [ ! -s "$file" ] && return 0

    log_info "📊 Parsing ffuf results..."

    local ffuf_high=0 ffuf_medium=0 ffuf_info=0
    local ffuf_protected=0  # Count of properly protected resources (403/401)

    if command -v jq &> /dev/null; then
        local ffuf_200 ffuf_301
        ffuf_200=$(jq '[.results[]? | select(.status == 200)] | length' "$file" 2>/dev/null) || ffuf_200=0
        ffuf_301=$(jq '[.results[]? | select(.status == 301 or .status == 302)] | length' "$file" 2>/dev/null) || ffuf_301=0

        # Extract URLs - only process actual findings, not protected resources
        while IFS= read -r result; do
            local url status input
            url=$(echo "$result" | jq -r '.url' 2>/dev/null)
            status=$(echo "$result" | jq -r '.status' 2>/dev/null)
            input=$(echo "$result" | jq -r '.input.FUZZ' 2>/dev/null)

            # Skip wordlist comments (lines starting with #)
            if [[ "$input" == \#* ]]; then
                continue
            fi

            # 403/401 = Server is correctly protecting the resource - NOT a vulnerability
            if [ "$status" = "403" ] || [ "$status" = "401" ]; then
                ((ffuf_protected++))
                # Optionally log as INFO for visibility (commented out to reduce noise)
                # add_finding "🔵" "INFO" "ffuf" "$input" "$url (Status: $status - Protected)"
            elif [ "$status" = "200" ]; then
                # Only 200 responses are potential issues
                if echo "$input" | grep -qiE '(config|admin|backup|\.env|passwd|wp-config|\.git|\.svn|\.htaccess|\.htpasswd|phpinfo|server-status)'; then
                    add_finding "🟠" "HIGH" "ffuf" "$input" "$url (Status: $status - Sensitive file exposed!)"
                    ((ffuf_high++))
                elif echo "$input" | grep -qiE '(api|swagger|graphql|debug|console|phpmyadmin)'; then
                    add_finding "🟡" "MEDIUM" "ffuf" "$input" "$url (Status: $status - Potentially sensitive endpoint)"
                    ((ffuf_medium++))
                else
                    add_finding "🔵" "INFO" "ffuf" "$input" "$url (Status: $status - Discovered)"
                    ((ffuf_info++))
                fi
            elif [ "$status" = "301" ] || [ "$status" = "302" ]; then
                # Redirects might be interesting but are informational
                add_finding "🔵" "INFO" "ffuf" "$input" "$url (Status: $status - Redirect)"
                ((ffuf_info++))
            fi
        done < <(jq -c '.results[]?' "$file" 2>/dev/null)
    else
        ffuf_info=$(grep -c '"status":' "$file" 2>/dev/null) || ffuf_info=0
    fi

    high=$((high + ffuf_high))
    medium=$((medium + ffuf_medium))
    info=$((info + ffuf_info))

    local total=$((ffuf_high + ffuf_medium + ffuf_info))
    log_info "   └── Found $total actual discoveries ($ffuf_protected resources correctly protected)"
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
