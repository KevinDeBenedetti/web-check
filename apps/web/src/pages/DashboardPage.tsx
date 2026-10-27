import { useMemo, useState } from "react";
import { Link } from "react-router";
import { api } from "../api/client";
import type { ScanResponse } from "../api/types";
import { EmptyState, ErrorNotice, Loading } from "../components/Feedback";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { ScoreValue, Sparkline } from "../components/Score";
import {
  SeverityBadge,
  SeverityBar,
  SeverityLegend,
  severityShortText,
} from "../components/Severity";
import { StatusPill } from "../components/StatusPill";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useResource } from "../hooks/useResource";
import { formatRelative, hostnameOf, plural } from "../lib/format";
import { moduleLabel } from "../lib/labels";
import { groupScansBySite, recurringFindings, scanProgress, type SiteSummary } from "../lib/sites";

const DAY_MS = 86_400_000;

function totalFindings(scan: ScanResponse | undefined): number {
  if (!scan) return 0;
  const { critical = 0, high = 0, medium = 0, low = 0 } = scan.severity_counts;
  return critical + high + medium + low;
}

function isPartial(scan: ScanResponse): boolean {
  return scan.results.some((result) => result.status !== "success");
}

function RunningBanner({ scan, others }: { scan: ScanResponse; others: number }) {
  const progress = Math.round(scanProgress(scan) * 100);
  const total = scan.modules?.length ?? 0;
  const next = scan.modules?.[scan.results.length];
  return (
    <section className="card banner" aria-label="Scan en cours">
      <div className="banner__text">
        <span className="pulse" aria-hidden="true" />
        <div>
          <p className="strong">Scan en cours — {hostnameOf(scan.target)}</p>
          <p className="muted small">
            {scan.results.length} module{scan.results.length > 1 ? "s" : ""} terminé
            {scan.results.length > 1 ? "s" : ""} sur {total}
            {next ? ` · ${moduleLabel(next)}` : ""}
            {others > 0 && (
              <>
                {" · "}
                <Link to="/scans?status=running">
                  {others > 1 ? `${others} autres scans en cours` : "un autre scan en cours"}
                </Link>
              </>
            )}
          </p>
        </div>
      </div>
      <div className="banner__progress">
        <div
          className="progress"
          role="progressbar"
          aria-label="Progression du scan"
          aria-valuenow={progress}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div className="progress__bar" style={{ width: `${progress}%` }} />
        </div>
        <span className="mono small">{progress} %</span>
      </div>
      <Link to={`/scans/${scan.scan_id}/live`} className="btn btn--secondary">
        Suivre le scan
      </Link>
    </section>
  );
}

function Kpis({ sites, scans }: { sites: SiteSummary[]; scans: ScanResponse[] }) {
  const scored = sites.filter((site) => site.latest?.score != null);
  const average = scored.length
    ? Math.round(scored.reduce((sum, site) => sum + (site.latest?.score ?? 0), 0) / scored.length)
    : null;
  const open = sites.reduce((sum, site) => sum + totalFindings(site.latest), 0);
  const critical = sites.reduce((sum, site) => sum + (site.latest?.severity_counts.critical ?? 0), 0);
  const since = Date.now() - 30 * DAY_MS;
  const recent = scans.filter((scan) => new Date(scan.started_at).getTime() >= since).length;

  return (
    <section className="kpis" aria-label="Indicateurs">
      <div className="card kpi">
        <span className="kpi__label">Score moyen</span>
        <span className="kpi__value">
          <ScoreValue score={average} />
          <span className="kpi__unit">/ 100</span>
        </span>
        <span className="kpi__hint">sur le dernier scan de chaque site</span>
      </div>
      <div className="card kpi">
        <span className="kpi__label">Problèmes ouverts</span>
        <span className="kpi__value">{open}</span>
        <span className={critical ? "kpi__hint kpi__hint--bad" : "kpi__hint"}>
          {critical ? `${plural(critical, "critique")} à traiter` : "aucun critique"}
        </span>
      </div>
      <div className="card kpi">
        <span className="kpi__label">Sites suivis</span>
        <span className="kpi__value">{sites.length}</span>
        <span className="kpi__hint">{plural(scans.length, "scan")} au total</span>
      </div>
      <div className="card kpi">
        <span className="kpi__label">Scans sur 30 jours</span>
        <span className="kpi__value">{recent}</span>
        <span className="kpi__hint">lancés depuis l’API, la CLI ou l’interface</span>
      </div>
    </section>
  );
}

function SitesTable({ sites }: { sites: SiteSummary[] }) {
  const [query, setQuery] = useState("");
  const shown = sites.filter((site) => site.host.toLowerCase().includes(query.trim().toLowerCase()));

  return (
    <section className="card card--flush" aria-labelledby="sites-title">
      <div className="card__header">
        <h2 id="sites-title" className="card__title">
          Sites suivis
        </h2>
        <div className="search">
          <Icon name="search" size={16} />
          <label htmlFor="site-search" className="sr-only">
            Filtrer les sites
          </label>
          <input
            id="site-search"
            type="search"
            className="search__input"
            placeholder="Filtrer les sites…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
      </div>
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Site</th>
              <th scope="col">Score</th>
              <th scope="col">Problèmes</th>
              <th scope="col">Évolution</th>
              <th scope="col">Dernier scan</th>
              <th scope="col">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.map((site) => (
              <tr key={site.host}>
                <td>
                  {site.latest ? (
                    <Link to={`/scans/${site.latest.scan_id}`} className="mono strong link-plain">
                      {site.host}
                    </Link>
                  ) : (
                    <span className="mono strong">{site.host}</span>
                  )}
                  {site.running && (
                    <Link to={`/scans/${site.running.scan_id}/live`} className="tag tag--info">
                      en cours
                    </Link>
                  )}
                </td>
                <td>
                  <ScoreValue score={site.latest?.score} />
                </td>
                <td>
                  {site.latest ? (
                    <div className="sev-cell">
                      <span className="strong">{totalFindings(site.latest)}</span>
                      <SeverityBar counts={site.latest.severity_counts} />
                      <span className="muted small">
                        {severityShortText(site.latest.severity_counts)}
                      </span>
                    </div>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td>
                  <Sparkline values={site.scores} label={`Évolution du score de ${site.host}`} />
                </td>
                <td className="muted">{formatRelative(site.lastActivity)}</td>
                <td className="cell-actions">
                  <Link
                    to={`/scans/new?target=${encodeURIComponent(site.target)}`}
                    className="icon-btn"
                    aria-label={`Relancer un scan de ${site.host}`}
                    title="Relancer un scan"
                  >
                    <Icon name="refresh" size={16} strokeWidth={2} />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && <p className="table-empty">Aucun site ne correspond.</p>}
      </div>
      <div className="card__footer">
        <SeverityLegend />
      </div>
    </section>
  );
}

function RecentActivity({ scans }: { scans: ScanResponse[] }) {
  return (
    <section className="card" aria-labelledby="activity-title">
      <div className="card__heading-row">
        <h2 id="activity-title" className="card__title">
          Activité récente
        </h2>
        <Link to="/scans" className="small">
          Tout l’historique
        </Link>
      </div>
      <ul className="list">
        {scans.slice(0, 6).map((scan) => (
          <li key={scan.scan_id} className="list__item">
            <div className="list__main">
              <Link
                to={scan.status === "running" ? `/scans/${scan.scan_id}/live` : `/scans/${scan.scan_id}`}
                className="strong link-plain"
              >
                {hostnameOf(scan.target)}
              </Link>
              <span className="muted small">
                {formatRelative(scan.started_at)} · {plural(scan.modules?.length ?? 0, "module")}
                {scan.status !== "running" && ` · score ${scan.score ?? "—"}`}
              </span>
            </div>
            <StatusPill status={scan.status} partial={isPartial(scan)} />
          </li>
        ))}
      </ul>
    </section>
  );
}

function Recurring({ sites }: { sites: SiteSummary[] }) {
  const recurring = recurringFindings(sites);
  return (
    <section className="card" aria-labelledby="recurring-title">
      <div className="card__heading-row">
        <h2 id="recurring-title" className="card__title">
          Problèmes récurrents
        </h2>
        <span className="muted small">présents sur plusieurs sites</span>
      </div>
      {recurring.length === 0 ? (
        <p className="muted small">Aucun problème commun à plusieurs sites.</p>
      ) : (
        <ul className="list">
          {recurring.map((finding) => (
            <li key={finding.key} className="list__item">
              <SeverityBadge severity={finding.severity} />
              <div className="list__main">
                <span className="strong">{finding.title}</span>
                <span className="muted small mono">{finding.hosts.join(", ")}</span>
              </div>
              <span className="small nowrap">{plural(finding.hosts.length, "site")}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function DashboardPage() {
  useDocumentTitle("Tableau de bord");
  const scans = useResource(api.listScans, [], 10_000);
  const sites = useMemo(() => groupScansBySite(scans.data ?? []), [scans.data]);
  const runningScans = scans.data?.filter((scan) => scan.status === "running") ?? [];
  const running = runningScans[0];

  return (
    <>
      <PageHeader
        title="Tableau de bord"
        subtitle={
          scans.data?.[0]
            ? `${plural(sites.length, "site suivi", "sites suivis")} · dernier scan ${formatRelative(scans.data[0].started_at)}`
            : "Vue d’ensemble des sites que vous testez"
        }
        actions={
          <Link to="/compare" className="btn btn--secondary">
            <Icon name="compare" size={16} />
            Comparer deux scans
          </Link>
        }
      />
      {scans.error && <ErrorNotice error={scans.error} onRetry={scans.reload} />}
      {scans.loading && <Loading />}
      {scans.data && scans.data.length === 0 && (
        <div className="card">
          <EmptyState title="Aucun scan pour l’instant" action={{ to: "/scans/new", label: "Lancer un premier scan" }}>
            Lancez un scan sur un site que vous possédez ou que vous avez le droit de tester. Les
            cibles autorisées se règlent avec ALLOWED_DOMAINS.
          </EmptyState>
        </div>
      )}
      {scans.data && scans.data.length > 0 && (
        <>
          {running && <RunningBanner scan={running} others={runningScans.length - 1} />}
          <Kpis sites={sites} scans={scans.data} />
          <SitesTable sites={sites} />
          <div className="columns">
            <RecentActivity scans={scans.data} />
            <Recurring sites={sites} />
          </div>
        </>
      )}
    </>
  );
}
