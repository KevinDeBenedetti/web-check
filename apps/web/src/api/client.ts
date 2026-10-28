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
import { filenameFromDisposition } from "../lib/url";

const API_KEY_STORAGE = "web-check.apiKey";

/** API key kept in this browser (Settings page); empty when the API is unauthenticated. */
export function getApiKey(): string {
  try {
    return window.localStorage.getItem(API_KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(value: string): void {
  try {
    if (value) window.localStorage.setItem(API_KEY_STORAGE, value);
    else window.localStorage.removeItem(API_KEY_STORAGE);
  } catch {
    // Private mode or storage disabled: the key only lives for this page load.
  }
}

/** Headers for a raw `fetch` to the API: the key travels in X-API-Key, never in the URL. */
export function authHeaders(): Record<string, string> {
  const key = getApiKey();
  return key ? { "X-API-Key": key } : {};
}

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
        ...authHeaders(),
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
    if (response.status === 401) {
      throw new ApiError(
        401,
        getApiKey()
          ? "Clé API refusée : vérifiez-la dans Réglages (elle doit être égale à API_KEY)."
          : "L’API exige une clé (API_KEY) : renseignez-la dans Réglages.",
      );
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

/** Download a report through fetch (so the API key header is sent), then save it. */
export async function downloadExport(scanId: string, format: ExportFormat): Promise<void> {
  const response = await fetch(exportUrl(scanId, format), { headers: authHeaders() });
  if (!response.ok) {
    throw new ApiError(response.status, response.status === 401 ? "Clé API refusée." : `Erreur ${response.status}`);
  }
  const blob = await response.blob();
  const name =
    filenameFromDisposition(response.headers.get("content-disposition")) ?? `web-check-${scanId}.${format}`;
  const href = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = href;
  link.download = name;
  link.click();
  URL.revokeObjectURL(href);
}

export const isNotFound = (error: Error | undefined): boolean =>
  error instanceof ApiError && error.status === 404;
