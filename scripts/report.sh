#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Security Scanner - Report Generator v3.0 (Modular)
# ══════════════════════════════════════════════════════════════════════════════
#
# This script generates HTML and JSON reports from security scan results.
# It uses a modular architecture with separate library files for:
#   - utils.sh       : Common utilities (logging, escaping, helpers)
#   - parsers.sh     : Tool-specific parsers (nuclei, zap, testssl, nikto, ffuf)
#   - html_report.sh : HTML report generation
#   - json_report.sh : JSON report generation
#
# Usage: ./report.sh <scan_output_directory>
#
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

# Global counters for severity levels
critical=0
high=0
medium=0
low=0
info=0
# shellcheck disable=SC2034  # Used in sourced modules
total=0

# Global array to store all findings
# shellcheck disable=SC2034  # Used in sourced modules
findings_list=()

# Metadata variables
target=""
scan_id=""
mode=""

# Directory paths (set in main)
OUTPUT_DIR=""
SCANS_DIR=""

# ══════════════════════════════════════════════════════════════════════════════
# Load Library Modules
# ══════════════════════════════════════════════════════════════════════════════

#######################################
# Load all required library modules
# Globals:
#   LIB_DIR
# Arguments:
#   None
# Returns:
#   1 if any module is missing
#######################################
load_modules() {
    local modules=("utils.sh" "parsers.sh" "html_report.sh" "json_report.sh" "markdown_report.sh")

    for module in "${modules[@]}"; do
        local module_path="$LIB_DIR/$module"
        if [[ -f "$module_path" ]]; then
            # shellcheck source=/dev/null
            source "$module_path"
        else
            echo "❌ Error: Missing module $module_path" >&2
            return 1
        fi
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ══════════════════════════════════════════════════════════════════════════════

#######################################
# Display usage information
# Arguments:
#   None
# Outputs:
#   Usage text to stdout
#######################################
usage() {
    cat << EOF
Usage: $(basename "$0") <scan_output_directory>

Generate HTML and JSON reports from security scan results.

Arguments:
    scan_output_directory    Path to scan output (e.g., outputs/20251223-184827)

Example:
    $(basename "$0") outputs/20251223-184827

Output files:
    <scan_dir>/report.html   - Interactive HTML report with filtering
    <scan_dir>/report.json   - Machine-readable JSON report
EOF
}

#######################################
# Validate command line arguments and directories
# Arguments:
#   $1 - scan output directory path
# Globals:
#   OUTPUT_DIR, SCANS_DIR (set by this function)
# Returns:
#   1 if validation fails
#######################################
validate_arguments() {
    if [[ $# -lt 1 ]]; then
        usage
        return 1
    fi

    OUTPUT_DIR="$1"
    SCANS_DIR="$OUTPUT_DIR/scans"

    if [[ ! -d "$OUTPUT_DIR" ]]; then
        log_error "Directory not found: $OUTPUT_DIR"
        return 1
    fi

    if [[ ! -d "$SCANS_DIR" ]]; then
        log_error "Scans directory not found: $SCANS_DIR"
        return 1
    fi
}

#######################################
# Main function - orchestrates report generation
# Arguments:
#   $@ - command line arguments
# Returns:
#   0 on success, 1 on failure
#######################################
main() {
    # Load library modules first
    if ! load_modules; then
        echo "❌ Failed to load modules" >&2
        exit 1
    fi

    # Validate arguments
    if ! validate_arguments "$@"; then
        exit 1
    fi

    log_info "Starting report generation..."
    log_info "Output directory: $OUTPUT_DIR"

    # Read metadata
    read_metadata
    log_info "Target: $target | Mode: $mode | Scan ID: $scan_id"

    # Run all parsers
    log_info "Parsing scan results..."
    run_all_parsers

    # Calculate total (used in sourced report generators)
    # shellcheck disable=SC2034
    total=$((critical + high + medium + low + info))

    # Print summary
    print_summary

    # Generate reports (Markdown first for HTML embedding)
    log_info "Generating Markdown report (LLM-optimized)..."
    generate_markdown_report
    log_success "Markdown report: $OUTPUT_DIR/report.md"

    log_info "Generating HTML report..."
    generate_html_report
    log_success "HTML report: $OUTPUT_DIR/report.html"

    log_info "Generating JSON report..."
    generate_json_report
    log_success "JSON report: $OUTPUT_DIR/report.json"

    log_success "Report generation complete!"
    return 0
}

# Run main function with all arguments
main "$@"
