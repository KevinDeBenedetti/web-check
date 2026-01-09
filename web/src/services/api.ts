import axios from "axios";
import type { CheckResult, ScanRequest, ScanResponse } from "../types/api";

const api = axios.create({
  baseURL: "/api",
  headers: {
    "Content-Type": "application/json",
  },
});

// Quick scans
export const quickScans = {
  nuclei: (url: string, timeout: number = 300): Promise<CheckResult> =>
    api.get("/quick/nuclei", { params: { url, timeout } }).then((res) => res.data),

  nikto: (url: string, timeout: number = 600): Promise<CheckResult> =>
    api.get("/quick/nikto", { params: { url, timeout } }).then((res) => res.data),

  dns: (domain: string): Promise<CheckResult> =>
    api.get("/quick/dns", { params: { domain } }).then((res) => res.data),
};

// Deep scans
export const deepScans = {
  fullScan: (url: string, timeout: number = 900): Promise<CheckResult> =>
    api.get("/deep/full", { params: { url, timeout } }).then((res) => res.data),
};

// Security scans
export const securityScans = {
  zap: (url: string, timeout: number = 900): Promise<CheckResult> =>
    api.get("/security/zap", { params: { url, timeout } }).then((res) => res.data),
};

// Scan management
export const scans = {
  start: (request: ScanRequest): Promise<ScanResponse> =>
    api.post("/scans/start", request).then((res) => res.data),

  get: (scanId: string): Promise<ScanResponse> =>
    api.get(`/scans/${scanId}`).then((res) => res.data),

  list: (): Promise<ScanResponse[]> => api.get("/scans").then((res) => res.data),

  delete: (scanId: string): Promise<void> => api.delete(`/scans/${scanId}`).then((res) => res.data),
};

// Health check
export const health = {
  check: (): Promise<{ status: string; timestamp: string }> =>
    api.get("/health").then((res) => res.data),
};

export default api;
