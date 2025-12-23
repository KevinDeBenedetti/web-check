#!/bin/bash
# shellcheck source=/dev/null
# shellcheck disable=SC2154
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Security Scanner - Utility Functions
# Common helper functions for report generation
# ══════════════════════════════════════════════════════════════════════════════

# Terminal colors
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_NC='\033[0m'

#######################################
# Log info message
# Arguments:
#   $1 - Message to log
#######################################
log_info() {
    echo -e "${COLOR_BLUE}$1${COLOR_NC}"
}

#######################################
# Log success message
# Arguments:
#   $1 - Message to log
#######################################
log_success() {
    echo -e "${COLOR_GREEN}$1${COLOR_NC}"
}

#######################################
# Log warning message
# Arguments:
#   $1 - Message to log
#######################################
log_warn() {
    echo -e "${COLOR_YELLOW}$1${COLOR_NC}"
}

#######################################
# Log error message
# Arguments:
#   $1 - Message to log
#######################################
log_error() {
    echo -e "${COLOR_RED}$1${COLOR_NC}" >&2
}

#######################################
# Add finding to the global findings list
# Globals:
#   findings_list
# Arguments:
#   $1 - Icon (emoji)
#   $2 - Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
#   $3 - Tool name
#   $4 - Finding name/id
#   $5 - Description
#######################################
add_finding() {
    local icon="$1"
    local severity="$2"
    local tool="$3"
    local name="$4"
    local description="$5"
    findings_list+=("${icon}|${severity}|${tool}|${name}|${description}")
}

#######################################
# Read metadata from JSON file
# Globals:
#   OUTPUT_DIR, target, scan_id, mode, started_at, ended_at
# Arguments:
#   None
#######################################
read_metadata() {
    local metadata_file="$OUTPUT_DIR/metadata.json"

    target="N/A"
    scan_id="N/A"
    mode="N/A"
    started_at="N/A"
    ended_at="N/A"

    [ ! -f "$metadata_file" ] && return 0

    if command -v jq &> /dev/null; then
        target=$(jq -r '.target // "N/A"' "$metadata_file" 2>/dev/null)
        scan_id=$(jq -r '.scan_id // "N/A"' "$metadata_file" 2>/dev/null)
        mode=$(jq -r '.mode // "N/A"' "$metadata_file" 2>/dev/null)
        # shellcheck disable=SC2034  # Reserved for future use
        started_at=$(jq -r '.started_at // "N/A"' "$metadata_file" 2>/dev/null)
        # shellcheck disable=SC2034  # Reserved for future use
        ended_at=$(jq -r '.ended_at // "N/A"' "$metadata_file" 2>/dev/null)
    else
        target=$(sed -n 's/.*"target"\s*:\s*"\([^"]*\)".*/\1/p' "$metadata_file" | head -1)
        scan_id=$(sed -n 's/.*"scan_id"\s*:\s*"\([^"]*\)".*/\1/p' "$metadata_file" | head -1)
        mode=$(sed -n 's/.*"mode"\s*:\s*"\([^"]*\)".*/\1/p' "$metadata_file" | head -1)
        [ -z "$target" ] && target="N/A"
        [ -z "$scan_id" ] && scan_id="N/A"
        [ -z "$mode" ] && mode="N/A"
    fi
}

#######################################
# Escape string for JSON
# Arguments:
#   $1 - String to escape
# Outputs:
#   Escaped string
#######################################
escape_json() {
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

#######################################
# Escape string for HTML
# Arguments:
#   $1 - String to escape
# Outputs:
#   Escaped string
#######################################
escape_html() {
    echo "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

#######################################
# Print summary banner
# Globals:
#   critical, high, medium, low, info
# Arguments:
#   None
#######################################
print_summary() {
    echo ""
    log_success "════════════════════════════════════════════════════════════════"
    log_success "  Summary: $critical Critical | $high High | $medium Medium | $low Low | $info Info"
    log_success "════════════════════════════════════════════════════════════════"
    echo ""
}

#######################################
# List files in directory as JSON array
# Arguments:
#   $1 - Directory path
# Outputs:
#   JSON array of filenames
#######################################
list_files_json() {
    local dir="$1"
    if command -v jq &> /dev/null && [[ -d "$dir" ]]; then
        find "$dir" -maxdepth 1 -type f -exec basename {} \; 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0))' 2>/dev/null || echo '[]'
    else
        echo '[]'
    fi
}
