// Mirrors the Pydantic models in apps/api/models.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "success" | "error" | "timeout" | "running";
export type ScanCategory = "quick" | "deep" | "security";
export type ServiceState = "running" | "stopped" | "missing" | "unknown";

export interface Finding {
  severity: Severity;
  title: string;
  description: string;
  reference: string | null;
  cve: string | null;
  cvss_score: number | null;
  remediation: string | null;
}

export interface CheckResult {
  module: string;
  category: ScanCategory;
  target: string;
  timestamp: string;
  duration_ms: number;
  status: ScanStatus;
  data: Record<string, unknown> | null;
  findings: Finding[];
  error: string | null;
}

export type SeverityCounts = Record<Severity, number>;

export interface ScanResponse {
  scan_id: string;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  modules: string[] | null;
  score: number | null;
  severity_counts: Partial<SeverityCounts>;
  results: CheckResult[];
}

export interface ScanRequest {
  target: string;
  modules?: string[];
  profile?: string;
  timeout: number;
}

export interface AggregatedFinding extends Finding {
  id: string;
  sources: string[];
}

export interface ScanSummary {
  scan_id: string;
  target: string;
  status: ScanStatus;
  started_at: string;
  score: number;
  severity_counts: SeverityCounts;
}

export interface ScanFindings {
  summary: ScanSummary;
  findings: AggregatedFinding[];
}

export interface ScanComparison {
  base: ScanSummary;
  head: ScanSummary;
  score_delta: number;
  new: AggregatedFinding[];
  fixed: AggregatedFinding[];
  unchanged: AggregatedFinding[];
}

export interface ModuleInfo {
  id: string;
  name: string;
  description: string;
  category: ScanCategory;
  intrusive: boolean;
  default_timeout: number;
}

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  modules: string[];
}

export interface Catalog {
  modules: ModuleInfo[];
  profiles: ScanProfile[];
  default_profile: string;
}

export interface ScopeRules {
  rules: string[];
  source: string;
}

export interface ScopeCheckResult {
  target: string;
  hostname: string | null;
  allowed: boolean;
  matched_rule: string | null;
}

export interface ServiceStatus {
  id: string;
  name: string;
  role: string;
  container: string | null;
  image: string | null;
  state: ServiceState;
  compose_profile: string | null;
}

export type LogType =
  | "connected"
  | "info"
  | "success"
  | "warning"
  | "error"
  | "docker"
  | "complete";

export interface LogEntry {
  timestamp: string;
  scan_id?: string;
  type: LogType;
  message: string;
  event?: "module_started" | "module_completed";
  module?: string;
  modules?: string[];
  findings_count?: number;
  status?: ScanStatus;
  duration_ms?: number;
}

export type ExportFormat = "json" | "markdown" | "sarif";
