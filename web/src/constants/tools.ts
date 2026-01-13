/**
 * Tool definitions and configurations
 */

import type { ScanTool, ToolInfo } from "../types/api";

export const TOOL_INFO: Record<ScanTool, ToolInfo> = {
  nuclei: {
    id: "nuclei",
    name: "Nuclei",
    description: "CVE and vulnerability scanning with community templates",
    category: "quick",
    defaultTimeout: 300,
    icon: "🎯",
  },
  nikto: {
    id: "nikto",
    name: "Nikto",
    description: "Web server scanning for misconfigurations",
    category: "quick",
    defaultTimeout: 600,
    icon: "🕷️",
  },
  zap: {
    id: "zap",
    name: "OWASP ZAP",
    description: "Comprehensive security scan (XSS, SQLi, etc.)",
    category: "deep",
    defaultTimeout: 900,
    icon: "⚡",
  },
  testssl: {
    id: "testssl",
    name: "SSLyze",
    description: "SSL/TLS analysis and cryptographic configuration",
    category: "deep",
    defaultTimeout: 300,
    icon: "🔒",
  },
  ffuf: {
    id: "ffuf",
    name: "FFUF",
    description: "Directory and hidden file fuzzing",
    category: "security",
    defaultTimeout: 600,
    icon: "🔍",
  },
  sqlmap: {
    id: "sqlmap",
    name: "SQLMap",
    description: "Automated SQL injection testing",
    category: "security",
    defaultTimeout: 900,
    icon: "💉",
  },
  wapiti: {
    id: "wapiti",
    name: "Wapiti",
    description: "Web vulnerability scanner (XSS, injection, etc.)",
    category: "security",
    defaultTimeout: 600,
    icon: "🕸️",
  },
  xsstrike: {
    id: "xsstrike",
    name: "XSStrike",
    description: "Advanced XSS vulnerability detection",
    category: "security",
    defaultTimeout: 300,
    icon: "⚔️",
  },
};

export const AVAILABLE_TOOLS: ToolInfo[] = Object.values(TOOL_INFO);

export const TOOL_CATEGORIES = {
  quick: {
    name: "Quick Scan",
    description: "Fast scans for initial assessment",
    color: "green",
  },
  deep: {
    name: "Deep Analysis",
    description: "Detailed analysis with in-depth testing",
    color: "blue",
  },
  security: {
    name: "Advanced Security",
    description: "Specialized security tests",
    color: "purple",
  },
} as const;

export const FULL_SCAN_CONFIG = {
  timeout: 3600, // 1 hour
  tools: Object.keys(TOOL_INFO) as ScanTool[],
  name: "Full Scan",
  description: "Executes all available scanning tools",
};
