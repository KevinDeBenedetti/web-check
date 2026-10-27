import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router";
import { api, isNotFound } from "../api/client";
import type { CheckResult, LogEntry, ScanResponse } from "../api/types";
import { EmptyState, ErrorNotice, Loading } from "../components/Feedback";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { SeverityBadge } from "../components/Severity";
import { StatusPill } from "../components/StatusPill";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useNow } from "../hooks/useNow";
import { useResource } from "../hooks/useResource";
import { type StreamState, useScanLogs } from "../hooks/useScanLogs";
import { dedupeFindings } from "../lib/findings";
import { formatDateTime, formatDuration, formatTime, hostnameOf } from "../lib/format";
import { canonicalModule, moduleEngine, moduleLabel } from "../lib/labels";
import { scanProgress } from "../lib/sites";

type StepState = "done" | "failed" | "running" | "pending";

interface Step {
  module: string;
  state: StepState;
  detail: string;
  duration: string;
}

function buildSteps(scan: ScanResponse): Step[] {
  const results = new Map<string, CheckResult>(
    scan.results.map((result) => [canonicalModule(result.module), result]),
  );
  let runningAssigned = false;
  return (scan.modules ?? []).map((module) => {
    const result = results.get(module);
    if (result) {
      const ok = result.status === "success";
      return {
        module,
        state: ok ? "done" : "failed",
        detail: ok
          ? `${result.findings.length} problème${result.findings.length > 1 ? "s" : ""}`
          : (result.error ?? `statut ${result.status}`),
        duration: formatDuration(result.duration_ms),
      };
    }
    // Modules run in order: the first one without a result is the current one.
    const state: StepState = scan.status === "running" && !runningAssigned ? "running" : "pending";
    runningAssigned ||= state === "running";
    return { module, state, detail: moduleEngine(module), duration: "—" };
  });
}

const STEP_ICON: Record<StepState, { name: "checkCircle" | "alert" | "activity" | "minus"; label: string }> = {
  done: { name: "checkCircle", label: "Terminé" },
  failed: { name: "alert", label: "En échec" },
  running: { name: "activity", label: "En cours" },
  pending: { name: "minus", label: "En attente" },
};

type LogFilter = "all" | "warning" | "error";

const FILTERS: { id: LogFilter; label: string }[] = [
  { id: "all", label: "Tout" },
  { id: "warning", label: "Alertes" },
  { id: "error", label: "Erreurs" },
];

const LEVEL_LABELS: Partial<Record<LogEntry["type"], string>> = {
  info: "INFO",
  docker: "INFO",
  success: "OK",
  warning: "ALERTE",
  error: "ERREUR",
  complete: "FIN",
};

function LogConsole({
  entries,
  state,
  onReconnect,
}: {
  entries: LogEntry[];
  state: StreamState;
  onReconnect: () => void;
}) {
  const [filter, setFilter] = useState<LogFilter>("all");
  const [follow, setFollow] = useState(true);
  const bodyRef = useRef<HTMLDivElement>(null);
  const shown = entries.filter((entry) => filter === "all" || entry.type === filter);

  useEffect(() => {
    const body = bodyRef.current;
    if (follow && body) body.scrollTop = body.scrollHeight;
  }, [shown.length, follow]);

  return (
    <section className="console" aria-labelledby="log-title">
      <div className="console__header">
        <h2 id="log-title" className="console__title">
          Journal
        </h2>
        <div className="chips chips--dark" role="group" aria-label="Filtrer le journal">
          {FILTERS.map((item) => (
            <button
              key={item.id}
              type="button"
              className="chip"
              aria-pressed={filter === item.id}
              onClick={() => setFilter(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>
      <div
        ref={bodyRef}
        className="console__body"
        role="log"
        aria-live="polite"
        onScroll={(event) => {
          const el = event.currentTarget;
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
        }}
      >
        {shown.length === 0 && <p className="console__empty">En attente des premiers messages…</p>}
        {shown.map((entry, index) => (
          <div key={`${entry.timestamp}-${index}`} className={`log log--${entry.type}`}>
            <span className="log__time">{formatTime(entry.timestamp)}</span>
            <span className="log__level">{LEVEL_LABELS[entry.type] ?? entry.type.toUpperCase()}</span>
            <span className="log__source">{entry.module ?? "scan"}</span>
            <span className="log__message">{entry.message}</span>
          </div>
        ))}
      </div>
      <div className="console__footer">
        <span>
          {shown.length} ligne{shown.length > 1 ? "s" : ""}
          {follow ? " · défilement automatique" : ""}
        </span>
        {state === "closed" && (
          <button type="button" className="btn btn--ghost-dark btn--small" onClick={onReconnect}>
            Connexion perdue — reconnecter
          </button>
        )}
        {state === "connecting" && <span>Connexion…</span>}
      </div>
    </section>
  );
}

function LiveView({ scan, reload }: { scan: ScanResponse; reload: () => void }) {
  const running = scan.status === "running";
  const logs = useScanLogs(scan.scan_id, running);
  const now = useNow(1000, running);
  const steps = useMemo(() => buildSteps(scan), [scan]);
  const findings = useMemo(() => dedupeFindings(scan.results), [scan.results]);
  const progress = Math.round(scanProgress(scan) * 100);
  const end = scan.completed_at ? new Date(scan.completed_at) : now;
  const elapsed = Math.max(0, end.getTime() - new Date(scan.started_at).getTime());
  const current = steps.find((step) => step.state === "running");

  // Refresh the scan as soon as the stream reports a finished module or the end.
  const lastEvent = logs.entries[logs.entries.length - 1];
  useEffect(() => {
    if (lastEvent?.event === "module_completed" || lastEvent?.type === "complete") reload();
  }, [lastEvent, reload]);

  return (
    <>
      <PageHeader
        title={hostnameOf(scan.target)}
        mono
        back={{ to: "/", label: "Tableau de bord" }}
        subtitle={
          <>
            <StatusPill status={scan.status} /> Démarré le {formatDateTime(scan.started_at)} ·{" "}
            <span className="mono">{scan.scan_id}</span>
          </>
        }
        actions={
          <Link to={`/scans/${scan.scan_id}`} className="btn btn--dark">
            {running ? "Rapport partiel" : "Voir le rapport"}
          </Link>
        }
      />

      {!running && (
        <div className="notice notice--ok" role="status">
          <Icon name="checkCircle" />
          <span className="notice__text">
            Scan terminé en {formatDuration(elapsed)}. Score {scan.score ?? "—"} / 100.
          </span>
          <Link to={`/scans/${scan.scan_id}`} className="btn btn--secondary btn--small">
            Ouvrir le rapport
          </Link>
        </div>
      )}

      <section className="card stack-sm" aria-label="Progression">
        <div className="row-between small">
          <span>
            <span className="strong">
              {scan.results.length} sur {steps.length} modules
            </span>
            {current && ` · ${moduleLabel(current.module)} (${moduleEngine(current.module)})`}
          </span>
          <span className="muted">
            écoulé <span className="mono strong-text">{formatDuration(elapsed)}</span>
          </span>
        </div>
        <div
          className="progress progress--large"
          role="progressbar"
          aria-label="Progression du scan"
          aria-valuenow={progress}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div className="progress__bar" style={{ width: `${progress}%` }} />
        </div>
      </section>

      <div className="split">
        <section className="card split__aside" aria-labelledby="steps-title">
          <h2 id="steps-title" className="card__title">
            Étapes
          </h2>
          <ol className="steps">
            {steps.map((step) => (
              <li key={step.module} className={`step step--${step.state}`}>
                <span className="step__icon">
                  <Icon
                    name={STEP_ICON[step.state].name}
                    size={20}
                    strokeWidth={2}
                    label={STEP_ICON[step.state].label}
                  />
                </span>
                <span className="step__text">
                  <span className="step__title">{moduleLabel(step.module)}</span>
                  <span className="step__detail">{step.detail}</span>
                </span>
                <span className="step__time mono">{step.duration}</span>
              </li>
            ))}
          </ol>
        </section>

        <div className="split__main stack">
          {running || logs.entries.length > 0 ? (
            <LogConsole entries={logs.entries} state={logs.state} onReconnect={logs.reconnect} />
          ) : null}

          <section className="card" aria-labelledby="first-title">
            <div className="card__heading-row">
              <h2 id="first-title" className="card__title">
                {running ? "Premiers résultats" : "Résultats"}
              </h2>
              <Link to={`/scans/${scan.scan_id}`} className="small">
                Voir les {findings.length}
              </Link>
            </div>
            {findings.length === 0 ? (
              <p className="muted small">
                {running ? "Aucun problème pour l’instant." : "Aucun problème détecté."}
              </p>
            ) : (
              <ul className="list">
                {findings.slice(0, 6).map((finding) => (
                  <li key={finding.key} className="list__item">
                    <SeverityBadge severity={finding.severity} />
                    <span className="list__main strong">{finding.title}</span>
                    <span className="muted small mono nowrap">
                      {finding.sources.map((source) => moduleEngine(source)).join(", ")}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </>
  );
}

export function LiveScanPage() {
  const { scanId = "" } = useParams();
  const [running, setRunning] = useState(true);
  const scan = useResource(() => api.getScan(scanId), [scanId], running ? 4000 : undefined);

  useEffect(() => {
    if (scan.data) setRunning(scan.data.status === "running");
  }, [scan.data]);
  useDocumentTitle(scan.data ? `Scan ${hostnameOf(scan.data.target)}` : "Scan en cours");

  if (scan.error) {
    return isNotFound(scan.error) ? (
      <EmptyState title="Scan introuvable" action={{ to: "/scans", label: "Voir l’historique" }} />
    ) : (
      <ErrorNotice error={scan.error} onRetry={scan.reload} />
    );
  }
  if (!scan.data) return <Loading />;
  return <LiveView scan={scan.data} reload={scan.reload} />;
}
