import type {
  Catalog,
  ExportFormat,
  ScanComparison,
  ScanFindings,
  ScanRequest,
  ScanResponse,
  ScopeCheckResult,
  ScopeRules,
  ServiceStatus,
} from "./types";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function describeError(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const { detail } = body as { detail: unknown };
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((item) => (item && typeof item === "object" && "msg" in item ? String(item.msg) : ""))
        .filter(Boolean)
        .join(", ");
    }
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
  } catch {
    throw new ApiError(0, "API injoignable. Vérifiez que `docker compose up` tourne.");
  }

  if (!response.ok) {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = undefined;
    }
    throw new ApiError(response.status, describeError(body, `Erreur ${response.status}`));
  }
  return (await response.json()) as T;
}

const id = (value: string) => encodeURIComponent(value);

export const api = {
  health: () => request<{ status: string }>("/health"),
  listScans: () => request<ScanResponse[]>("/scans"),
  getScan: (scanId: string) => request<ScanResponse>(`/scans/${id(scanId)}`),
  getFindings: (scanId: string) => request<ScanFindings>(`/scans/${id(scanId)}/findings`),
  compare: (baseId: string, headId: string) =>
    request<ScanComparison>(`/scans/${id(baseId)}/compare/${id(headId)}`),
  startScan: (body: ScanRequest) =>
    request<ScanResponse>("/scans/start", { method: "POST", body: JSON.stringify(body) }),
  catalog: () => request<Catalog>("/catalog"),
  scope: () => request<ScopeRules>("/scope"),
  checkScope: (target: string) =>
    request<ScopeCheckResult>("/scope/check", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),
  services: () => request<ServiceStatus[]>("/services"),
};

export const exportUrl = (scanId: string, format: ExportFormat) =>
  `/api/scans/${id(scanId)}/export?format=${format}`;

export const logsUrl = (scanId: string) => `/api/scans/${id(scanId)}/logs`;
