// Types based on Pydantic API models
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "success" | "error" | "timeout" | "running";
export type ScanCategory = "quick" | "deep" | "security";

export type ScanTool = "nuclei" | "nikto" | "zap" | "testssl" | "ffuf" | "sqlmap" | "wapiti" | "xsstrike";

export interface Finding {
  severity: Severity;
  title: string;
  description: string;
  reference?: string;
  cve?: string;
  cvss_score?: number;
}

export interface CheckResult {
  module: string;
  category: ScanCategory;
  target: string;
  timestamp: string;
  duration_ms: number;
  status: ScanStatus;
  data?: Record<string, any>;
  findings: Finding[];
  error?: string;
}

export interface ScanRequest {
  target: string;
  modules: string[];
  timeout: number;
}

export interface ScanResponse {
  scan_id: string;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  results: CheckResult[];
}

export interface ToolInfo {
  id: ScanTool;
  name: string;
  description: string;
  category: ScanCategory;
  defaultTimeout: number;
  icon: string;
}
