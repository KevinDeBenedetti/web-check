import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api } from "../api/client";
import type { AggregatedFinding, ScanResponse } from "../api/types";
import { EmptyState, ErrorNotice, Loading } from "../components/Feedback";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { ScoreValue } from "../components/Score";
import { SeverityBadge } from "../components/Severity";
import { useResource } from "../hooks/useResource";
import { formatDateTime, hostnameOf, plural } from "../lib/format";
import { moduleEngine } from "../lib/labels";

type Kind = "new" | "fixed" | "unchanged";
type Tab = "changes" | Kind | "all";

const KIND_LABELS: Record<Kind, string> = { new: "Nouveau", fixed: "Corrigé", unchanged: "Inchangé" };
const KIND_ICONS = { new: "plus", fixed: "check", unchanged: "minus" } as const;

const TABS: { id: Tab; label: string }[] = [
  { id: "changes", label: "Changements" },
  { id: "new", label: "Nouveaux" },
  { id: "fixed", label: "Corrigés" },
  { id: "all", label: "Tout" },
];

function scanOption(scan: ScanResponse): string {
  return `${formatDateTime(scan.started_at)} · score ${scan.score ?? "—"}`;
}

function Diff({ baseId, headId }: { baseId: string; headId: string }) {
  const comparison = useResource(() => api.compare(baseId, headId), [baseId, headId]);
  const [tab, setTab] = useState<Tab>("changes");

  if (comparison.error) return <ErrorNotice error={comparison.error} onRetry={comparison.reload} />;
  if (!comparison.data) return <Loading label="Comparaison…" />;
  const { base, head, score_delta: delta } = comparison.data;

  const rows: { kind: Kind; finding: AggregatedFinding }[] = [
    ...comparison.data.new.map((finding) => ({ kind: "new" as const, finding })),
    ...comparison.data.fixed.map((finding) => ({ kind: "fixed" as const, finding })),
    ...comparison.data.unchanged.map((finding) => ({ kind: "unchanged" as const, finding })),
  ];
  const count = (kind: Kind) => rows.filter((row) => row.kind === kind).length;
  const tabCount: Record<Tab, number> = {
    changes: count("new") + count("fixed"),
    new: count("new"),
    fixed: count("fixed"),
    unchanged: count("unchanged"),
    all: rows.length,
  };
  const shown = rows.filter(
    (row) => tab === "all" || (tab === "changes" ? row.kind !== "unchanged" : row.kind === tab),
  );

  return (
    <>
      <section className="kpis" aria-label="Évolution">
        <div className="card kpi">
          <span className="kpi__label">Score</span>
          <span className="kpi__value">
            <span className="kpi__from">{base.score}</span>
            <Icon name="arrowRight" size={18} />
            <ScoreValue score={head.score} />
            <span className={delta >= 0 ? "delta delta--up" : "delta delta--down"}>
              {delta >= 0 ? "+" : ""}
              {delta}
            </span>
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi__label">Corrigés</span>
          <span className="kpi__value kpi__value--ok">{count("fixed")}</span>
        </div>
        <div className="card kpi">
          <span className="kpi__label">Nouveaux</span>
          <span className={count("new") ? "kpi__value kpi__value--bad" : "kpi__value"}>{count("new")}</span>
        </div>
        <div className="card kpi">
          <span className="kpi__label">Inchangés</span>
          <span className="kpi__value">{count("unchanged")}</span>
          <span className="kpi__hint">toujours ouverts</span>
        </div>
      </section>

      <section className="card card--flush" aria-labelledby="diff-title">
        <div className="card__header">
          <h2 id="diff-title" className="card__title">
            Différences
          </h2>
          <div className="chips" role="group" aria-label="Afficher">
            {TABS.map((item) => (
              <button
                key={item.id}
                type="button"
                className="chip"
                aria-pressed={tab === item.id}
                onClick={() => setTab(item.id)}
              >
                {item.label} <span className="mono">{tabCount[item.id]}</span>
              </button>
            ))}
          </div>
        </div>
        {shown.length === 0 ? (
          <p className="table-empty">
            {tab === "changes" ? "Aucun changement entre ces deux scans." : "Rien à afficher."}
          </p>
        ) : (
          <ul className="diff-list">
            {shown.map(({ kind, finding }) => (
              <li key={`${kind}-${finding.id}`} className={`diff diff--${kind}`}>
                <span className="diff__kind">
                  <Icon name={KIND_ICONS[kind]} size={16} strokeWidth={2.2} />
                  {KIND_LABELS[kind]}
                </span>
                <SeverityBadge severity={finding.severity} />
                <span className="diff__title">{finding.title}</span>
                <span className="diff__meta mono">
                  {finding.sources.map((source) => moduleEngine(source)).join(", ")}
                </span>
              </li>
            ))}
          </ul>
        )}
        <div className="card__footer row-between small">
          <Link to={`/scans/${base.scan_id}`}>Rapport de référence</Link>
          <Link to={`/scans/${head.scan_id}`}>Rapport comparé</Link>
        </div>
      </section>
    </>
  );
}

export function ComparePage() {
  const scans = useResource(api.listScans, []);
  const [params, setParams] = useSearchParams();

  const finished = useMemo(
    () => (scans.data ?? []).filter((scan) => scan.status !== "running"),
    [scans.data],
  );
  const hosts = useMemo(() => [...new Set(finished.map((scan) => hostnameOf(scan.target)))], [finished]);

  const headParam = finished.find((scan) => scan.scan_id === params.get("head"));
  const host = params.get("site") ?? (headParam ? hostnameOf(headParam.target) : hosts[0]);
  const siteScans = finished.filter((scan) => hostnameOf(scan.target) === host);
  const head = siteScans.find((scan) => scan.scan_id === params.get("head")) ?? siteScans[0];
  const base =
    siteScans.find((scan) => scan.scan_id === params.get("base") && scan.scan_id !== head?.scan_id) ??
    siteScans.find((scan) => head && scan.started_at < head.started_at);

  const update = (next: Record<string, string | undefined>) => {
    const merged = new URLSearchParams(params);
    for (const [key, value] of Object.entries(next)) {
      if (value) merged.set(key, value);
      else merged.delete(key);
    }
    setParams(merged, { replace: true });
  };

  return (
    <>
      <PageHeader
        title="Comparer deux scans"
        subtitle="Ce qui a été corrigé et ce qui est apparu entre deux scans d’un même site."
      />
      {scans.error && <ErrorNotice error={scans.error} onRetry={scans.reload} />}
      {scans.loading && <Loading />}
      {scans.data && hosts.length === 0 && (
        <div className="card">
          <EmptyState title="Aucun scan terminé" action={{ to: "/scans/new", label: "Lancer un scan" }}>
            La comparaison demande au moins deux scans terminés du même site.
          </EmptyState>
        </div>
      )}
      {hosts.length > 0 && (
        <section className="card filters" aria-label="Scans à comparer">
          <div className="field">
            <label htmlFor="cmp-site" className="field__label">
              Site
            </label>
            <select
              id="cmp-site"
              className="input mono"
              value={host}
              onChange={(event) => update({ site: event.target.value, base: undefined, head: undefined })}
            >
              {hosts.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="cmp-base" className="field__label">
              Référence
            </label>
            <select
              id="cmp-base"
              className="input"
              value={base?.scan_id ?? ""}
              onChange={(event) => update({ base: event.target.value })}
              disabled={siteScans.length < 2}
            >
              {!base && <option value="">—</option>}
              {siteScans
                .filter((scan) => scan.scan_id !== head?.scan_id)
                .map((scan) => (
                  <option key={scan.scan_id} value={scan.scan_id}>
                    {scanOption(scan)}
                  </option>
                ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="cmp-head" className="field__label">
              Comparé à
            </label>
            <select
              id="cmp-head"
              className="input"
              value={head?.scan_id ?? ""}
              onChange={(event) => update({ head: event.target.value, base: undefined })}
            >
              {siteScans.map((scan) => (
                <option key={scan.scan_id} value={scan.scan_id}>
                  {scanOption(scan)}
                </option>
              ))}
            </select>
          </div>
          <p className="muted small filters__hint">{plural(siteScans.length, "scan terminé", "scans terminés")}</p>
        </section>
      )}
      {head && base && <Diff baseId={base.scan_id} headId={head.scan_id} />}
      {head && !base && siteScans.length < 2 && (
        <div className="card">
          <EmptyState
            title="Un seul scan pour ce site"
            action={{ to: `/scans/new?target=${encodeURIComponent(head.target)}`, label: "Relancer un scan" }}
          >
            Relancez un scan après vos corrections pour voir ce qui a changé.
          </EmptyState>
        </div>
      )}
    </>
  );
}
