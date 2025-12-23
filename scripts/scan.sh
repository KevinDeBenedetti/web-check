#!/bin/bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Variables
# ══════════════════════════════════════════════════════════════════════════════
TARGET="$1"
OUTPUT_DIR="$2"
MODE="${3:-full}"
TOOLS="${4:-}"

# Uniform subdirectories
SCANS_DIR="$OUTPUT_DIR/scans"
LOGS_DIR="$OUTPUT_DIR/logs"
OUTPUT_BASE="$(dirname "$OUTPUT_DIR")"

# Create directory structure
mkdir -p "$SCANS_DIR" "$LOGS_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ══════════════════════════════════════════════════════════════════════════════
# Determine which tools to use
# ══════════════════════════════════════════════════════════════════════════════
case "$MODE" in
    full)
        tools_to_run="zap nuclei nikto testssl ffuf"
        ;;
    quick)
        tools_to_run="nuclei nikto"
        ;;
    custom)
        tools_to_run="${TOOLS//,/ }"
        ;;
esac

read -ra tools_array <<< "$tools_to_run"
total_tools=${#tools_array[@]}
current_tool=0

# ══════════════════════════════════════════════════════════════════════════════
# Utility functions
# ══════════════════════════════════════════════════════════════════════════════

show_progress() {
    local current=$1
    local total=$2
    local tool_name=$3
    local percent=$((current * 100 / total))
    local filled=$((percent / 5))
    local empty=$((20 - filled))

    local bar=""
    for ((i=0; i<filled; i++)); do bar+="━"; done
    for ((i=0; i<empty; i++)); do bar+="─"; done

    local icon="⏳"
    [ $percent -eq 100 ] && icon="✅"
    [ $percent -ge 75 ] && [ $percent -lt 100 ] && icon="🔥"
    [ $percent -ge 50 ] && [ $percent -lt 75 ] && icon="⚡"
    [ $percent -ge 25 ] && [ $percent -lt 50 ] && icon="🔄"

    echo -e "${CYAN}──────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${icon} ${BOLD}PROGRESS${NC}  ${BOLD}${percent}%${NC}  ${GREEN}[${bar}]${NC}  ${current}/${total}"
    echo -e "  🔧 Tool: ${YELLOW}${BOLD}${tool_name}${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────────${NC}"
}

format_time() {
    local seconds=$1
    printf "%dm %02ds" $((seconds / 60)) $((seconds % 60))
}

SPINNER_PID=""
start_spinner() {
    local msg="${1:-Loading...}"
    local bars=("[■□□□□]" "[■■□□□]" "[■■■□□]" "[■■■■□]" "[■■■■■]" "[□■■■■]" "[□□■■■]" "[□□□■■]" "[□□□□■]" "[□□□□□]")
    (
        local i=0
        while true; do
            echo -ne "\r\033[K   ${CYAN}${BOLD}${bars[$((i % 10))]}${NC} ${YELLOW}${msg}${NC}"
            sleep 0.15
            ((i++))
        done
    ) &
    SPINNER_PID=$!
}

stop_spinner() {
    if [ -n "$SPINNER_PID" ]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
    fi
    SPINNER_PID=""
    echo -ne "\r\033[K"
}

trap 'stop_spinner; exit 1' INT TERM

# ══════════════════════════════════════════════════════════════════════════════
# Run a scan (uniform for all tools)
# ══════════════════════════════════════════════════════════════════════════════
run_scan() {
    local tool=$1
    local log_file="$LOGS_DIR/${tool}.log"

    echo -e "   ${CYAN}↳ Starting ${tool}...${NC}"

    case $tool in
        zap)
            start_spinner "${BOLD}ZAP${NC} DAST analysis..."
            docker exec security-scanner-zap \
                zap-baseline.py -t "$TARGET" \
                -r "/zap/wrk/zap.html" \
                -J "/zap/wrk/zap.json" \
                -I > "$log_file" 2>&1 || true
            # Copier les résultats ZAP dans le bon dossier
            mv "$OUTPUT_BASE/zap.html" "$SCANS_DIR/" 2>/dev/null || true
            mv "$OUTPUT_BASE/zap.json" "$SCANS_DIR/" 2>/dev/null || true
            stop_spinner
            ;;
        nuclei)
            start_spinner "${BOLD}Nuclei${NC} scan CVE..."
            docker exec security-scanner-nuclei \
                nuclei -u "$TARGET" -severity critical,high,medium \
                -jsonl -o "/output/nuclei.json" > "$log_file" 2>&1 || true
            mv "$OUTPUT_BASE/nuclei.json" "$SCANS_DIR/" 2>/dev/null || true
            stop_spinner
            ;;
        nikto)
            start_spinner "${BOLD}Nikto${NC} web server scan..."
            docker exec security-scanner-nikto \
                perl /nikto/nikto.pl -h "$TARGET" \
                -output "/output/nikto.html" -Format html > "$log_file" 2>&1 || true
            mv "$OUTPUT_BASE/nikto.html" "$SCANS_DIR/" 2>/dev/null || true
            # Nikto crée parfois des fichiers avec timestamp
            mv "$OUTPUT_BASE"/nikto*.html "$SCANS_DIR/" 2>/dev/null || true
            stop_spinner
            ;;
        testssl)
            local domain
            domain=$(echo "$TARGET" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
            start_spinner "${BOLD}testssl${NC} SSL/TLS analysis..."
            docker exec security-scanner-testssl \
                /home/testssl/testssl.sh --jsonfile "/output/testssl.json" "$domain" > "$log_file" 2>&1 || true
            mv "$OUTPUT_BASE/testssl.json" "$SCANS_DIR/" 2>/dev/null || true
            stop_spinner
            ;;
        ffuf)
            start_spinner "${BOLD}ffuf${NC} fuzzing..."
            docker exec security-scanner-ffuf \
                ffuf -u "$TARGET/FUZZ" -w /wordlists/common.txt \
                -mc 200,201,301,302,401,403 \
                -o "/output/ffuf.json" -of json -s > "$log_file" 2>&1 || true
            mv "$OUTPUT_BASE/ffuf.json" "$SCANS_DIR/" 2>/dev/null || true
            stop_spinner
            ;;
    esac

    echo -e "   ${GREEN}✓${NC} ${tool} completed - Log: ${CYAN}$log_file${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Create metadata
# ══════════════════════════════════════════════════════════════════════════════
create_metadata() {
    cat > "$OUTPUT_DIR/metadata.json" << EOF
{
    "scan_id": "$(basename "$OUTPUT_DIR")",
    "target": "$TARGET",
    "mode": "$MODE",
    "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [$(echo "$tools_to_run" | sed 's/ /", "/g' | sed 's/^/"/' | sed 's/$/"/')],
    "total_tools": $total_tools
}
EOF
}

# ══════════════════════════════════════════════════════════════════════════════
# Display header
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "   ${BOLD}🔒  S E C U R I T Y   S C A N N E R   S U I T E${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "   🎯 ${BOLD}Target:${NC}  ${CYAN}${TARGET}${NC}"
echo -e "   📦 ${BOLD}Mode:${NC}    ${YELLOW}${MODE}${NC}"
echo -e "   🔧 ${BOLD}Tools:${NC}  ${GREEN}${total_tools} selected${NC}"
echo -e "   📁 ${BOLD}Output:${NC}  ${CYAN}${OUTPUT_DIR}${NC}"
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"

# Create metadata
create_metadata

START_TIME=$(date +%s)

# ══════════════════════════════════════════════════════════════════════════════
# Execute scans
# ══════════════════════════════════════════════════════════════════════════════
for tool in $tools_to_run; do
    ((current_tool++))
    TOOL_START=$(date +%s)

    echo ""
    show_progress "$current_tool" "$total_tools" "$tool"
    echo ""

    run_scan "$tool"

    TOOL_END=$(date +%s)
    echo -e "   ⏱️  Duration: $(format_time $((TOOL_END - TOOL_START)))"
    echo ""
done

# ══════════════════════════════════════════════════════════════════════════════
# Clean up orphan files at the outputs root
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}📥 Cleaning up...${NC}"
# Déplacer tout fichier orphelin vers le dossier scans
for f in "$OUTPUT_BASE"/*.json "$OUTPUT_BASE"/*.html "$OUTPUT_BASE"/*.yaml; do
    [ -f "$f" ] && mv "$f" "$SCANS_DIR/" 2>/dev/null || true
done

# ══════════════════════════════════════════════════════════════════════════════
# Generate report
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}📊 Generating HTML report...${NC}"
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/report.sh" ]; then
    bash "$SCRIPT_DIR/report.sh" "$OUTPUT_DIR" 2>/dev/null || true
fi

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# Update metadata with duration
if command -v jq &> /dev/null && [ -f "$OUTPUT_DIR/metadata.json" ]; then
    tmp=$(mktemp)
    jq --arg ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson duration "$TOTAL_DURATION" \
       '. + {ended_at: $ended, duration_seconds: $duration}' \
       "$OUTPUT_DIR/metadata.json" > "$tmp" 2>/dev/null && mv "$tmp" "$OUTPUT_DIR/metadata.json"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Final summary
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "   ${BOLD}✅  S C A N   C O M P L E T E${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "   ⏱️  ${BOLD}Duration:${NC}   $(format_time $TOTAL_DURATION)"
echo -e "   🔧 ${BOLD}Tools:${NC}  ${total_tools}"
echo ""
echo -e "   ${BOLD}📁 Results structure:${NC}"
echo -e "   ${OUTPUT_DIR}/"
echo -e "   ├── scans/        (raw results)"
find "$SCANS_DIR" -maxdepth 1 -type f -exec basename {} \; 2>/dev/null | while read -r f; do echo -e "   │   └── $f"; done
echo -e "   ├── logs/         (execution logs)"
find "$LOGS_DIR" -maxdepth 1 -type f -exec basename {} \; 2>/dev/null | while read -r f; do echo -e "   │   └── $f"; done
echo -e "   ├── report.html   (consolidated report)"
echo -e "   └── metadata.json"
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"

# Ouvrir le rapport
REPORT_FILE="$OUTPUT_DIR/report.html"
if [ -f "$REPORT_FILE" ]; then
    echo -e "${CYAN}🌐 Opening report...${NC}"
    open "$REPORT_FILE" 2>/dev/null || xdg-open "$REPORT_FILE" 2>/dev/null || \
        echo -e "${YELLOW}💡 Open: ${CYAN}${REPORT_FILE}${NC}"
fi
echo ""
