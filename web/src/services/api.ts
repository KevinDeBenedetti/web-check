import axios from "axios";
import type { CheckResult, ScanRequest, ScanResponse, ScanTool } from "../types/api";

const api = axios.create({
  baseURL: "/api",
  headers: {
    "Content-Type": "application/json",
  },
});

// Log des erreurs pour debug
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error("API Error:", {
      url: error.config?.url,
      method: error.config?.method,
      status: error.response?.status,
      data: error.response?.data,
      message: error.message,
    });
    return Promise.reject(error);
  }
);

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
  zap: (url: string, timeout: number = 900): Promise<CheckResult> =>
    api.get("/deep/zap", { params: { url, timeout } }).then((res) => res.data),

  testssl: (url: string, timeout: number = 300): Promise<CheckResult> =>
    api.get("/deep/sslyze", { params: { url, timeout } }).then((res) => res.data),
};

// Security scans
export const securityScans = {
  ffuf: (
    url: string,
    timeout: number = 600,
    wordlist: string = "common.txt"
  ): Promise<CheckResult> =>
    api.get("/security/ffuf", { params: { url, timeout, wordlist } }).then((res) => res.data),

  sqlmap: (url: string, timeout: number = 900): Promise<CheckResult> =>
    api.get("/security/sqlmap", { params: { url, timeout } }).then((res) => res.data),
};

// Run multiple scans
export const runMultipleScans = async (
  url: string,
  tools: ScanTool[],
  timeout: number
): Promise<CheckResult[]> => {
  const scanPromises = tools.map((tool) => {
    switch (tool) {
      case "nuclei":
        return quickScans.nuclei(url, timeout);
      case "nikto":
        return quickScans.nikto(url, timeout);
      case "zap":
        return deepScans.zap(url, timeout);
      case "testssl":
        return deepScans.testssl(url, timeout);
      case "ffuf":
        return securityScans.ffuf(url, timeout);
      case "sqlmap":
        return securityScans.sqlmap(url, timeout);
      default:
        throw new Error(`Unknown tool: ${tool}`);
    }
  });

  return Promise.allSettled(scanPromises).then((results) =>
    results.map((result, index) => {
      if (result.status === "fulfilled") {
        return result.value;
      } else {
        return {
          module: tools[index],
          category: "quick" as const,
          target: url,
          timestamp: new Date().toISOString(),
          duration_ms: 0,
          status: "error" as const,
          findings: [],
          error: result.reason?.message || "Unknown error",
        };
      }
    })
  );
};

// Scan management
export const scans = {
  start: (request: ScanRequest): Promise<ScanResponse> =>
    api.post("/scans/start", request).then((res) => res.data),

  get: (scanId: string): Promise<ScanResponse> =>
    api.get(`/scans/${scanId}`).then((res) => res.data),

  list: (): Promise<ScanResponse[]> => api.get("/scans").then((res) => res.data),

  delete: (scanId: string): Promise<void> => api.delete(`/scans/${scanId}`).then((res) => res.data),

  streamLogs: (scanId: string): string => {
    const baseURL = api.defaults.baseURL || "/api";
    return `${baseURL}/scans/${scanId}/logs`;
  },
};

// Health check
export const health = {
  check: (): Promise<{ status: string; timestamp: string }> =>
    api.get("/health").then((res) => res.data),
};

export default api;
