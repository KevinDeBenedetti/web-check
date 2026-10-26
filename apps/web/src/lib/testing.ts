import type { CheckResult, Finding, ScanResponse, Severity } from "../api/types";

export function makeFinding(title: string, severity: Severity = "medium"): Finding {
  return {
    severity,
    title,
    description: `${title} description`,
    reference: null,
    cve: null,
    cvss_score: null,
    remediation: null,
  };
}

export function makeResult(module: string, findings: Finding[]): CheckResult {
  return {
    module,
    category: "quick",
    target: "https://example.com",
    timestamp: "2026-10-26T10:00:00Z",
    duration_ms: 1000,
    status: "success",
    data: null,
    findings,
    error: null,
  };
}

export function makeScan(overrides: Partial<ScanResponse> = {}): ScanResponse {
  return {
    scan_id: "20261026-100000-aaaa",
    target: "https://example.com",
    status: "success",
    started_at: "2026-10-26T10:00:00Z",
    completed_at: "2026-10-26T10:05:00Z",
    modules: ["headers"],
    score: 90,
    severity_counts: {},
    results: [],
    ...overrides,
  };
}
