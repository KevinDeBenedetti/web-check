import { Link, useSearchParams } from "react-router";
import { api } from "../api/client";
import type { ScanResponse, ScanStatus } from "../api/types";
import { EmptyState, ErrorNotice, Loading } from "../components/Feedback";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { ScoreValue } from "../components/Score";
import { SeverityBar, severityShortText } from "../components/Severity";
import { StatusPill } from "../components/StatusPill";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatDuration, hostnameOf } from "../lib/format";

type Filter = "all" | ScanStatus;

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "Tous" },
  { id: "running", label: "En cours" },
  { id: "success", label: "Terminés" },
  { id: "error", label: "Échecs" },
];

function duration(scan: ScanResponse): string {
  if (!scan.completed_at) return "—";
  return formatDuration(new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime());
}

export function ScansPage() {
  useDocumentTitle("Historique");
  const scans = useResource(api.listScans, [], 10_000);
  const [params, setParams] = useSearchParams();
  const filter = (params.get("status") as Filter | null) ?? "all";
  const query = params.get("q") ?? "";

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value && value !== "all") next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const shown = (scans.data ?? []).filter(
    (scan) =>
      (filter === "all" || scan.status === filter) &&
      scan.target.toLowerCase().includes(query.trim().toLowerCase()),
  );

  return (
    <>
      <PageHeader
        title="Historique"
        subtitle="Les 100 derniers scans, du plus récent au plus ancien."
        actions={
          <Link to="/scans/new" className="btn btn--primary">
            <Icon name="plus" size={16} strokeWidth={2} />
            Nouveau scan
          </Link>
        }
      />
      {scans.error && <ErrorNotice error={scans.error} onRetry={scans.reload} />}
      {scans.loading && <Loading />}
      {scans.data && scans.data.length === 0 && (
        <div className="card">
          <EmptyState title="Aucun scan" action={{ to: "/scans/new", label: "Lancer un scan" }} />
        </div>
      )}
      {scans.data && scans.data.length > 0 && (
        <section className="card card--flush" aria-labelledby="history-title">
          <div className="card__header">
            <h2 id="history-title" className="sr-only">
              Scans
            </h2>
            <div className="chips" role="group" aria-label="Filtrer par statut">
              {FILTERS.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="chip"
                  aria-pressed={filter === item.id}
                  onClick={() => setParam("status", item.id)}
                >
                  {item.label}
                </button>
              ))}
            </div>
            <div className="search">
              <Icon name="search" size={16} />
              <label htmlFor="history-search" className="sr-only">
                Filtrer par cible
              </label>
              <input
                id="history-search"
                type="search"
                className="search__input"
                placeholder="Filtrer par cible…"
                value={query}
                onChange={(event) => setParam("q", event.target.value)}
              />
            </div>
          </div>
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Cible</th>
                  <th scope="col">Statut</th>
                  <th scope="col">Score</th>
                  <th scope="col">Problèmes</th>
                  <th scope="col">Démarré</th>
                  <th scope="col">Durée</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((scan) => (
                  <tr key={scan.scan_id}>
                    <td>
                      <Link
                        to={scan.status === "running" ? `/scans/${scan.scan_id}/live` : `/scans/${scan.scan_id}`}
                        className="mono strong link-plain"
                      >
                        {hostnameOf(scan.target)}
                      </Link>
                      <span className="muted small block mono">{scan.scan_id}</span>
                    </td>
                    <td>
                      <StatusPill
                        status={scan.status}
                        partial={scan.results.some((result) => result.status !== "success")}
                      />
                    </td>
                    <td>
                      <ScoreValue score={scan.status === "running" ? null : scan.score} />
                    </td>
                    <td>
                      <div className="sev-cell">
                        <SeverityBar counts={scan.severity_counts} />
                        <span className="muted small">{severityShortText(scan.severity_counts)}</span>
                      </div>
                    </td>
                    <td className="muted nowrap">{formatDateTime(scan.started_at)}</td>
                    <td className="mono">{duration(scan)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length === 0 && <p className="table-empty">Aucun scan ne correspond.</p>}
          </div>
        </section>
      )}
    </>
  );
}
