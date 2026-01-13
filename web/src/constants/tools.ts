/**
 * Tool definitions and configurations
 */

import type { ScanTool, ToolInfo } from "../types/api";

export const TOOL_INFO: Record<ScanTool, ToolInfo> = {
  nuclei: {
    id: "nuclei",
    name: "Nuclei",
    description: "Scan CVE et vulnérabilités avec templates communautaires",
    category: "quick",
    defaultTimeout: 300,
    icon: "🎯",
  },
  nikto: {
    id: "nikto",
    name: "Nikto",
    description: "Scan serveur web pour misconfigurations",
    category: "quick",
    defaultTimeout: 600,
    icon: "🕷️",
  },
  zap: {
    id: "zap",
    name: "OWASP ZAP",
    description: "Scan sécurité complet (XSS, SQLi, etc.)",
    category: "deep",
    defaultTimeout: 900,
    icon: "⚡",
  },
  testssl: {
    id: "testssl",
    name: "SSLyze",
    description: "Analyse SSL/TLS et configuration cryptographique",
    category: "deep",
    defaultTimeout: 300,
    icon: "🔒",
  },
  ffuf: {
    id: "ffuf",
    name: "FFUF",
    description: "Fuzzing directories et fichiers cachés",
    category: "security",
    defaultTimeout: 600,
    icon: "🔍",
  },
  sqlmap: {
    id: "sqlmap",
    name: "SQLMap",
    description: "Test automatisé d'injection SQL",
    category: "security",
    defaultTimeout: 900,
    icon: "💉",
  },
  wapiti: {
    id: "wapiti",
    name: "Wapiti",
    description: "Scanner de vulnérabilités web (XSS, injection, etc.)",
    category: "security",
    defaultTimeout: 600,
    icon: "🕸️",
  },
  xsstrike: {
    id: "xsstrike",
    name: "XSStrike",
    description: "Détection avancée de vulnérabilités XSS",
    category: "security",
    defaultTimeout: 300,
    icon: "⚔️",
  },
};

export const AVAILABLE_TOOLS: ToolInfo[] = Object.values(TOOL_INFO);

export const TOOL_CATEGORIES = {
  quick: {
    name: "Scan Rapide",
    description: "Scans rapides pour une évaluation initiale",
    color: "green",
  },
  deep: {
    name: "Analyse Approfondie",
    description: "Analyse détaillée avec tests en profondeur",
    color: "blue",
  },
  security: {
    name: "Sécurité Avancée",
    description: "Tests de sécurité spécialisés",
    color: "purple",
  },
} as const;

export const FULL_SCAN_CONFIG = {
  timeout: 3600, // 1 heure
  tools: Object.keys(TOOL_INFO) as ScanTool[],
  name: "Full Scan",
  description: "Exécute tous les outils de scan disponibles",
};
