#!/bin/bash
# shellcheck source=/dev/null
# shellcheck disable=SC2154
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Security Scanner - HTML Report Generator
# ══════════════════════════════════════════════════════════════════════════════

#######################################
# Generate HTML header and CSS styles
# Arguments:
#   $1 - scan_id
# Outputs:
#   HTML header string to stdout
#######################################
generate_html_header() {
    local scan_id="$1"
    cat << 'HEADER_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
HEADER_EOF
    echo "    <title>Security Report - $scan_id</title>"
    cat << 'STYLE_EOF'
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        h2 { font-size: 1.5rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
        .meta { color: var(--text-muted); margin-bottom: 2rem; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }
        .stat-value { font-size: 2.5rem; font-weight: bold; }
        .stat-label { color: var(--text-muted); text-transform: uppercase; font-size: 0.8rem; }
        .critical { color: var(--critical); }
        .high { color: var(--high); }
        .medium { color: var(--medium); }
        .low { color: var(--low); }
        .info { color: var(--info); }
        table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: var(--bg-card); color: var(--text-muted); text-transform: uppercase; font-size: 0.8rem; }
        tr:hover { background: rgba(255,255,255,0.03); }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(248,81,73,0.2); color: var(--critical); }
        .badge-high { background: rgba(240,136,62,0.2); color: var(--high); }
        .badge-medium { background: rgba(210,153,34,0.2); color: var(--medium); }
        .badge-low { background: rgba(63,185,80,0.2); color: var(--low); }
        .badge-info { background: rgba(88,166,255,0.2); color: var(--info); }
        .filters { margin-bottom: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .filter-btn {
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn:hover { border-color: var(--text-muted); }
        .filter-btn.active { background: var(--info); color: var(--bg-dark); border-color: var(--info); }
        .finding-row { transition: opacity 0.2s; }
        .finding-row.hidden { display: none; }
        .header-actions { display: flex; gap: 0.5rem; margin-top: 1rem; }
        .action-btn {
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.9rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }
        .action-btn:hover { border-color: var(--info); color: var(--info); }
        .action-btn.copied { background: var(--low); color: var(--bg-dark); border-color: var(--low); }
        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--bg-card);
            border: 1px solid var(--low);
            color: var(--low);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            opacity: 0;
            transform: translateY(1rem);
            transition: all 0.3s;
            z-index: 1000;
        }
        .toast.show { opacity: 1; transform: translateY(0); }
        #markdown-content { display: none; }
        footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="container">
STYLE_EOF
}

#######################################
# Generate summary statistics section
# Globals:
#   critical, high, medium, low, info, total
# Arguments:
#   None
# Outputs:
#   HTML stats section to stdout
#######################################
generate_html_stats() {
    cat << EOF
        <h2>📊 Summary</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-value critical">$critical</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value high">$high</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat">
                <div class="stat-value medium">$medium</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat">
                <div class="stat-value low">$low</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat">
                <div class="stat-value info">$info</div>
                <div class="stat-label">Info</div>
            </div>
            <div class="stat">
                <div class="stat-value">$total</div>
                <div class="stat-label">Total</div>
            </div>
        </div>
EOF
}

#######################################
# Generate findings table header with filters
# Arguments:
#   None
# Outputs:
#   HTML filter buttons and table header to stdout
#######################################
generate_findings_table_header() {
    cat << 'EOF'
        <h2>🔍 Vulnerability Details</h2>
        <div class="filters">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="critical">Critical</button>
            <button class="filter-btn" data-filter="high">High</button>
            <button class="filter-btn" data-filter="medium">Medium</button>
            <button class="filter-btn" data-filter="low">Low</button>
            <button class="filter-btn" data-filter="info">Info</button>
        </div>
        <table id="findings-table">
            <thead>
                <tr>
                    <th style="width: 40px"></th>
                    <th style="width: 100px">Severity</th>
                    <th style="width: 100px">Tool</th>
                    <th style="width: 200px">Name</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
EOF
}

#######################################
# Generate a single finding row
# Arguments:
#   $1 - icon
#   $2 - severity (lowercase)
#   $3 - tool name
#   $4 - finding name
#   $5 - description
# Outputs:
#   HTML table row to stdout
#######################################
generate_finding_row() {
    local icon="$1"
    local severity="$2"
    local tool="$3"
    local name="$4"
    local description="$5"

    # Normalize severity to lowercase for CSS classes and filters
    severity=$(echo "$severity" | tr '[:upper:]' '[:lower:]')

    local escaped_name escaped_desc
    escaped_name=$(escape_html "$name")
    escaped_desc=$(escape_html "$description")

    cat << EOF
                <tr class="finding-row" data-severity="$severity">
                    <td>$icon</td>
                    <td><span class="badge badge-$severity">$severity</span></td>
                    <td>$tool</td>
                    <td>$escaped_name</td>
                    <td>$escaped_desc</td>
                </tr>
EOF
}

#######################################
# Generate HTML footer with JavaScript
# Arguments:
#   None
# Outputs:
#   HTML footer with filter script to stdout
#######################################
generate_html_footer() {
    cat << 'FOOTER_EOF'
            </tbody>
        </table>
        <footer>
            <p>🔒 Security Scanner Report - Generated automatically</p>
        </footer>
        <div class="toast" id="toast">✅ Markdown copied to clipboard!</div>
    </div>
FOOTER_EOF

    # Embed markdown content
    echo '    <pre id="markdown-content">'
    if [[ -f "$OUTPUT_DIR/report.md" ]]; then
        # Escape HTML entities in markdown content
        sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$OUTPUT_DIR/report.md"
    fi
    echo '</pre>'

    cat << 'SCRIPT_EOF'
    <script>
        // Filter functionality
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const filter = btn.dataset.filter;
                document.querySelectorAll('.finding-row').forEach(row => {
                    if (filter === 'all' || row.dataset.severity === filter) {
                        row.classList.remove('hidden');
                    } else {
                        row.classList.add('hidden');
                    }
                });
            });
        });

        // Copy markdown functionality
        async function copyMarkdown() {
            const content = document.getElementById('markdown-content').textContent;
            const btn = document.getElementById('copy-md-btn');
            const toast = document.getElementById('toast');

            try {
                await navigator.clipboard.writeText(content);
                btn.classList.add('copied');
                btn.innerHTML = '✅ Copied!';
                toast.classList.add('show');

                setTimeout(() => {
                    btn.classList.remove('copied');
                    btn.innerHTML = '📋 Copy Markdown (LLM)';
                    toast.classList.remove('show');
                }, 2000);
            } catch (err) {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = content;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);

                btn.innerHTML = '✅ Copied!';
                setTimeout(() => btn.innerHTML = '📋 Copy Markdown (LLM)', 2000);
            }
        }
    </script>
</body>
</html>
SCRIPT_EOF
}

#######################################
# Generate complete HTML report
# Globals:
#   OUTPUT_DIR, findings_list
#   critical, high, medium, low, info, total
#   target, scan_id, mode
# Arguments:
#   None
# Outputs:
#   Creates report.html file
#######################################
generate_html_report() {
    local report_file="$OUTPUT_DIR/report.html"

    {
        generate_html_header "$scan_id"

        # Title and meta info
        cat << EOF
        <h1>🛡️ Security Scan Report</h1>
        <p class="meta">
            <strong>Target:</strong> $target |
            <strong>Mode:</strong> $mode |
            <strong>Scan ID:</strong> $scan_id |
            <strong>Date:</strong> $(date '+%Y-%m-%d %H:%M:%S')
        </p>
        <div class="header-actions">
            <button class="action-btn" id="copy-md-btn" onclick="copyMarkdown()">
                📋 Copy Markdown (LLM)
            </button>
            <a class="action-btn" href="report.md" download>
                ⬇️ Download Markdown
            </a>
            <a class="action-btn" href="report.json" download>
                ⬇️ Download JSON
            </a>
        </div>
EOF

        generate_html_stats
        generate_findings_table_header

        # Generate all finding rows
        for finding in "${findings_list[@]}"; do
            IFS='|' read -r icon severity tool name description <<< "$finding"
            generate_finding_row "$icon" "$severity" "$tool" "$name" "$description"
        done

        generate_html_footer

    } > "$report_file"
}
