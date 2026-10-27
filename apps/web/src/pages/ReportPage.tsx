import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { api, exportUrl, isNotFound } from "../api/client";
import type { AggregatedFinding, ExportFormat, ScanResponse, Severity } from "../api/types";
import { CodeBlock } from "../components/CopyButton";
import { EmptyState, ErrorNotice, Loading } from "../components/Feedback";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { ScoreRing } from "../components/Score";
import { SeverityBadge } from "../components/Severity";
import { StatusPill } from "../components/StatusPill";
import { useCopy } from "../hooks/useCopy";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useResource } from "../hooks/useResource";
import { findingToMarkdown } from "../lib/findings";
import { formatDateTime, formatDuration, hostnameOf, plural } from "../lib/format";
import {
  SCORE_BAND_LABELS,
  SEVERITIES,
  SEVERITY_LABELS,
  canonicalModule,
  moduleEngine,
  moduleLabel,
  scoreBand,
} from "../lib/labels";

const EXPORTS: { format: ExportFormat; label: string }[] = [
  { format: "markdown", label: "Markdown" },
  { format: "json", label: "JSON" },
  { format: "sarif", label: "SARIF" },
];

function previousScan(scans: ScanResponse[] | undefined, scan: ScanResponse) {
  return scans?.find(
    (candidate) =>
      candidate.target === scan.target &&
      candidate.status !== "running" &&
      candidate.started_at < scan.started_at,
  );
}

function Summary({ scan, previous }: { scan: ScanResponse; previous: ScanResponse | undefined }) {
  const score = scan.score ?? 0;
  const delta = previous?.score != null ? score - previous.score : undefined;
  return (
    <section className="card summary-card" aria-label="Synthèse">
      <div className="summary-card__score">
        <ScoreRing score={score} />
        <div className="stack-xs">
          <span className="muted small">Score global</span>
          <span className="strong large">{SCORE_BAND_LABELS[scoreBand(score)]}</span>
          {delta !== undefined && previous && (
            <span className={delta >= 0 ? "small delta delta--up" : "small delta delta--down"}>
              {delta >= 0 ? "+" : ""}
              {delta} pts depuis le {formatDateTime(previous.started_at)}
            </span>
          )}
          {scan.status === "running" && <span className="small muted">Scan en cours : score partiel</span>}
        </div>
      </div>
      <div className="sev-tiles">
        {SEVERITIES.map((severity) => (
          <div key={severity} className={`sev-tile sev--${severity}`}>
            <span className="sev-tile__count">{scan.severity_counts[severity] ?? 0}</span>
            <span className="sev-tile__label">{SEVERITY_LABELS[severity]}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ModulesTable({ scan }: { scan: ScanResponse }) {
  const done = new Set(scan.results.map((result) => canonicalModule(result.module)));
  const waiting = (scan.modules ?? []).filter((module) => !done.has(module));
  return (
    <section className="card card--flush" aria-labelledby="modules-title">
      <div className="card__header">
        <h2 id="modules-title" className="card__title">
          Modules
        </h2>
        <span className="muted small">
          {plural(scan.results.length, "module exécuté", "modules exécutés")}
        </span>
      </div>
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Module</th>
              <th scope="col">Statut</th>
              <th scope="col">Durée</th>
              <th scope="col">Problèmes</th>
              <th scope="col">Détail</th>
            </tr>
          </thead>
          <tbody>
            {scan.results.map((result) => (
              <tr key={result.module}>
                <td>
                  <span className="strong">{moduleLabel(result.module)}</span>
                  <span className="muted small block mono">{moduleEngine(result.module)}</span>
                </td>
                <td>
                  <StatusPill status={result.status} />
                </td>
                <td className="mono">{formatDuration(result.duration_ms)}</td>
                <td>{result.findings.length}</td>
                <td className="muted small break">{result.error ?? "—"}</td>
              </tr>
            ))}
            {waiting.map((module) => (
              <tr key={module}>
                <td>
                  <span className="strong">{moduleLabel(module)}</span>
                  <span className="muted small block mono">{moduleEngine(module)}</span>
                </td>
                <td>
                  <span className="pill pill--neutral">En attente</span>
                </td>
                <td className="mono">—</td>
                <td>—</td>
                <td className="muted small">—</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FindingDetail({ finding, target }: { finding: AggregatedFinding; target: string }) {
  const { copied, copy } = useCopy();
  return (
    <article className="card detail" aria-labelledby="detail-title">
      <div className="stack-xs">
        <div className="row-wrap">
          <SeverityBadge severity={finding.severity} />
          <span className="small muted">
            Sources : {finding.sources.map((source) => moduleEngine(source)).join(", ")}
          </span>
          {finding.cve && <span className="tag mono">{finding.cve}</span>}
          {finding.cvss_score != null && <span className="tag mono">CVSS {finding.cvss_score.toFixed(1)}</span>}
        </div>
        <h2 id="detail-title" className="detail__title">
          {finding.title}
        </h2>
      </div>

      <div className="stack-xs">
        <h3 className="eyebrow">Constat</h3>
        <p className="detail__text">{finding.description}</p>
      </div>

      <div className="stack-xs">
        <h3 className="eyebrow">Correction</h3>
        {finding.remediation ? (
          <CodeBlock code={finding.remediation} copyLabel="Copier la correction" />
        ) : (
          <p className="muted small">
            Le module n’a pas proposé de correction. Consultez la référence ci-dessous.
          </p>
        )}
        {finding.reference && (
          <p className="small">
            Référence :{" "}
            <a href={finding.reference} target="_blank" rel="noreferrer noopener" className="break">
              {finding.reference}
              <Icon name="external" size={14} />
            </a>
          </p>
        )}
      </div>

      <div className="row-wrap detail__actions">
        <button
          type="button"
          className="btn btn--secondary"
          onClick={() => void copy(findingToMarkdown(finding, target))}
        >
          <Icon name={copied ? "check" : "copy"} size={16} />
          {copied ? "Copié" : "Copier pour un ticket"}
        </button>
      </div>
    </article>
  );
}

function Findings({ findings, target }: { findings: AggregatedFinding[]; target: string }) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string>();

  const shown = findings.filter(
    (finding) =>
      (severity === "all" || finding.severity === severity) &&
      `${finding.title} ${finding.sources.join(" ")}`.toLowerCase().includes(query.trim().toLowerCase()),
  );
  const selected = shown.find((finding) => finding.id === selectedId) ?? shown[0];
  const counts = useMemo(() => {
    const result: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) result[finding.severity] += 1;
    return result;
  }, [findings]);

  if (findings.length === 0) {
    return (
      <div className="card">
        <EmptyState title="Aucun problème détecté">
          Les modules exécutés n’ont rien signalé. Pensez à vérifier les modules en échec plus haut.
        </EmptyState>
      </div>
    );
  }

  return (
    <div className="split split--findings">
      <section className="card card--flush split__main" aria-labelledby="findings-title">
        <div className="card__header card__header--stack">
          <div className="row-between">
            <h2 id="findings-title" className="card__title">
              Problèmes
            </h2>
            <span className="muted small">dédoublonnés entre modules</span>
          </div>
          <div className="chips" role="group" aria-label="Filtrer par gravité">
            <button type="button" className="chip" aria-pressed={severity === "all"} onClick={() => setSeverity("all")}>
              Tous <span className="mono">{findings.length}</span>
            </button>
            {SEVERITIES.filter((value) => counts[value] > 0).map((value) => (
              <button
                key={value}
                type="button"
                className="chip"
                aria-pressed={severity === value}
                onClick={() => setSeverity(value)}
              >
                {SEVERITY_LABELS[value]} <span className="mono">{counts[value]}</span>
              </button>
            ))}
          </div>
          <div className="search search--full">
            <Icon name="search" size={16} />
            <label htmlFor="finding-search" className="sr-only">
              Rechercher un problème
            </label>
            <input
              id="finding-search"
              type="search"
              className="search__input"
              placeholder="Rechercher…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
        </div>
        <ul className="finding-list">
          {shown.map((finding) => (
            <li key={finding.id}>
              <button
                type="button"
                className="finding-row"
                aria-current={finding.id === selected?.id ? "true" : undefined}
                onClick={() => setSelectedId(finding.id)}
              >
                <SeverityBadge severity={finding.severity} />
                <span className="finding-row__text">
                  <span className="finding-row__title">{finding.title}</span>
                  <span className="finding-row__meta mono">
                    {finding.sources.map((source) => moduleEngine(source)).join(", ")}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
        {shown.length === 0 && <p className="table-empty">Aucun problème ne correspond au filtre.</p>}
      </section>
      <div className="split__aside split__aside--wide">
        {selected && <FindingDetail finding={selected} target={target} />}
      </div>
    </div>
  );
}

export function ReportPage() {
  const { scanId = "" } = useParams();
  const [running, setRunning] = useState(false);
  const refreshMs = running ? 5000 : undefined;
  const scan = useResource(() => api.getScan(scanId), [scanId], refreshMs);
  const findings = useResource(() => api.getFindings(scanId), [scanId], refreshMs);
  const scans = useResource(api.listScans, []);

  useEffect(() => {
    setRunning(scan.data?.status === "running");
  }, [scan.data]);
  useDocumentTitle(scan.data ? `Rapport ${hostnameOf(scan.data.target)}` : "Rapport");

  if (scan.error) {
    return isNotFound(scan.error) ? (
      <EmptyState title="Scan introuvable" action={{ to: "/scans", label: "Voir l’historique" }} />
    ) : (
      <ErrorNotice error={scan.error} onRetry={scan.reload} />
    );
  }
  if (!scan.data) return <Loading />;

  const current = scan.data;
  const previous = previousScan(scans.data, current);
  const duration = current.completed_at
    ? formatDuration(new Date(current.completed_at).getTime() - new Date(current.started_at).getTime())
    : undefined;

  return (
    <>
      <PageHeader
        title={hostnameOf(current.target)}
        mono
        back={{ to: "/scans", label: "Historique" }}
        subtitle={
          <>
            <StatusPill status={current.status} /> {formatDateTime(current.started_at)}
            {duration && ` · ${duration}`} · {plural(current.modules?.length ?? 0, "module")} ·{" "}
            <span className="mono">{current.scan_id}</span>
          </>
        }
        actions={
          <>
            {running && (
              <Link to={`/scans/${current.scan_id}/live`} className="btn btn--secondary">
                <Icon name="activity" size={16} />
                Suivre
              </Link>
            )}
            {previous && (
              <Link
                to={`/compare?base=${previous.scan_id}&head=${current.scan_id}`}
                className="btn btn--secondary"
              >
                <Icon name="compare" size={16} />
                Comparer au précédent
              </Link>
            )}
            <Link to={`/scans/new?target=${encodeURIComponent(current.target)}`} className="btn btn--secondary">
              <Icon name="refresh" size={16} />
              Relancer
            </Link>
            <div className="btn-group" role="group" aria-label="Exporter le rapport">
              <span className="btn-group__label">
                <Icon name="download" size={16} />
                Exporter
              </span>
              {EXPORTS.map((item) => (
                <a key={item.format} href={exportUrl(current.scan_id, item.format)} className="btn-group__item" download>
                  {item.label}
                </a>
              ))}
            </div>
          </>
        }
      />
      <Summary scan={current} previous={previous} />
      <ModulesTable scan={current} />
      {findings.error && <ErrorNotice error={findings.error} onRetry={findings.reload} />}
      {findings.loading && <Loading label="Chargement des problèmes…" />}
      {findings.data && <Findings findings={findings.data.findings} target={current.target} />}
    </>
  );
}
