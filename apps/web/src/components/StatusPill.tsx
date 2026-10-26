import type { ScanStatus, ServiceState } from "../api/types";
import { SERVICE_STATE_LABELS, STATUS_LABELS } from "../lib/labels";

const STATUS_TONE: Record<ScanStatus, string> = {
  running: "info",
  success: "ok",
  error: "bad",
  timeout: "warn",
};

const SERVICE_TONE: Record<ServiceState, string> = {
  running: "ok",
  stopped: "neutral",
  missing: "warn",
  unknown: "neutral",
};

export function StatusPill({ status, partial }: { status: ScanStatus; partial?: boolean }) {
  if (partial && status === "success") {
    return <span className="pill pill--warn">Échec partiel</span>;
  }
  return <span className={`pill pill--${STATUS_TONE[status]}`}>{STATUS_LABELS[status]}</span>;
}

export function ServicePill({ state }: { state: ServiceState }) {
  return (
    <span className={`pill pill--${SERVICE_TONE[state]}`}>
      <span className="pill__dot" aria-hidden="true" />
      {SERVICE_STATE_LABELS[state]}
    </span>
  );
}
