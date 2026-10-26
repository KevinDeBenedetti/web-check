import { type FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { ApiError, api } from "../api/client";
import type { Catalog, ModuleInfo, ScanRequest, ScopeCheckResult } from "../api/types";
import { CodeBlock } from "../components/CopyButton";
import { ErrorNotice, Loading } from "../components/Feedback";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { useResource } from "../hooks/useResource";
import { buildCurlCommand } from "../lib/command";
import { formatDuration, plural } from "../lib/format";
import {
  moduleDescription,
  moduleEngine,
  moduleLabel,
  profileDescription,
  profileLabel,
} from "../lib/labels";

const CUSTOM = "custom";
const DEFAULT_TIMEOUT = 300;

type ScopeState =
  | { kind: "idle" }
  | { kind: "invalid" }
  | { kind: "checking" }
  | { kind: "done"; result: ScopeCheckResult }
  | { kind: "error"; message: string };

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.hostname);
  } catch {
    return false;
  }
}

/** Debounced POST /api/scope/check for the typed target. */
function useScopeCheck(target: string): ScopeState {
  const [state, setState] = useState<ScopeState>({ kind: "idle" });

  useEffect(() => {
    const value = target.trim();
    if (!value) {
      setState({ kind: "idle" });
      return;
    }
    if (!isHttpUrl(value)) {
      setState({ kind: "invalid" });
      return;
    }
    let cancelled = false;
    setState({ kind: "checking" });
    const timer = window.setTimeout(() => {
      api.checkScope(value).then(
        (result) => !cancelled && setState({ kind: "done", result }),
        (error: unknown) =>
          !cancelled &&
          setState({ kind: "error", message: error instanceof Error ? error.message : String(error) }),
      );
    }, 350);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [target]);

  return state;
}

function ScopeMessage({ state }: { state: ScopeState }) {
  switch (state.kind) {
    case "idle":
      return <p className="hint">Saisissez l’URL complète, par exemple https://staging.example.com.</p>;
    case "invalid":
      return <p className="hint hint--bad">L’URL doit commencer par http:// ou https://.</p>;
    case "checking":
      return <p className="hint">Vérification du périmètre…</p>;
    case "error":
      return <p className="hint hint--bad">{state.message}</p>;
    case "done":
      return state.result.allowed ? (
        <p className="hint hint--ok">
          <Icon name="checkCircle" size={16} strokeWidth={2} />
          Dans le périmètre autorisé — règle <span className="mono">{state.result.matched_rule}</span>
        </p>
      ) : (
        <p className="hint hint--bad">
          <Icon name="alert" size={16} strokeWidth={2} />
          <span>
            <span className="mono">{state.result.hostname}</span> est hors périmètre. Ajoutez-le à{" "}
            <span className="mono">ALLOWED_DOMAINS</span> dans <span className="mono">.env</span>{" "}
            puis redémarrez l’API. <Link to="/settings">Voir le périmètre</Link>
          </span>
        </p>
      );
  }
}

interface ModuleGroup {
  title: string;
  modules: ModuleInfo[];
}

function groupModules(modules: ModuleInfo[]): ModuleGroup[] {
  return [
    { title: "Vérifications passives et non destructives", modules: modules.filter((m) => !m.intrusive) },
    { title: "Tests actifs", modules: modules.filter((m) => m.intrusive) },
  ].filter((group) => group.modules.length > 0);
}

function ScanForm({ catalog }: { catalog: Catalog }) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const initialProfile =
    catalog.profiles.find((profile) => profile.id === params.get("profile")) ??
    catalog.profiles.find((profile) => profile.id === catalog.default_profile) ??
    catalog.profiles[0];

  const [target, setTarget] = useState(params.get("target") ?? "");
  const [profileId, setProfileId] = useState(initialProfile?.id ?? CUSTOM);
  const [selected, setSelected] = useState<string[]>(initialProfile?.modules ?? []);
  const [timeoutSeconds, setTimeoutSeconds] = useState(DEFAULT_TIMEOUT);
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<Error>();
  const scope = useScopeCheck(target);

  const groups = useMemo(() => groupModules(catalog.modules), [catalog.modules]);
  const selectedModules = catalog.modules.filter((module) => selected.includes(module.id));
  const intrusiveSelected = selectedModules.filter((module) => module.intrusive);

  const request: ScanRequest =
    profileId === CUSTOM
      ? { target: target.trim(), modules: selectedModules.map((module) => module.id), timeout: timeoutSeconds }
      : { target: target.trim(), profile: profileId, timeout: timeoutSeconds };

  const inScope = scope.kind === "done" && scope.result.allowed;
  const timeoutValid =
    Number.isInteger(timeoutSeconds) && timeoutSeconds >= 30 && timeoutSeconds <= 3600;
  const canSubmit = inScope && selected.length > 0 && timeoutValid && confirmed && !submitting;

  const pickProfile = (id: string) => {
    setProfileId(id);
    const profile = catalog.profiles.find((candidate) => candidate.id === id);
    if (profile) setSelected(profile.modules);
  };

  const toggleModule = (id: string) => {
    setProfileId(CUSTOM);
    setSelected((current) =>
      current.includes(id) ? current.filter((value) => value !== id) : [...current, id],
    );
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setSubmitError(undefined);
    try {
      const scan = await api.startScan(request);
      navigate(`/scans/${scan.scan_id}/live`);
    } catch (error) {
      setSubmitError(error instanceof Error ? error : new ApiError(0, String(error)));
      setSubmitting(false);
    }
  };

  const blockers = [
    !inScope && "une cible dans le périmètre",
    selected.length === 0 && "au moins un module",
    !timeoutValid && "un délai entre 30 et 3600 s",
    !confirmed && "la confirmation d’autorisation",
  ].filter(Boolean);

  return (
    <form className="split" onSubmit={submit} noValidate>
      <div className="split__main stack">
        <section className="card stack" aria-labelledby="target-title">
          <h2 id="target-title" className="card__title">
            1. Cible
          </h2>
          <div className="field">
            <label htmlFor="target" className="field__label">
              URL du site
            </label>
            <input
              id="target"
              type="url"
              className="input mono"
              placeholder="https://staging.example.com"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              autoComplete="url"
              required
              aria-describedby="target-scope"
            />
            <div id="target-scope" aria-live="polite">
              <ScopeMessage state={scope} />
            </div>
          </div>
        </section>

        <section className="card stack" aria-labelledby="profile-title">
          <h2 id="profile-title" className="card__title">
            2. Profil
          </h2>
          <div className="choice-grid" role="radiogroup" aria-labelledby="profile-title">
            {[...catalog.profiles, { id: CUSTOM, name: "Custom", description: "", modules: [] }].map(
              (profile) => {
                const checked = profile.id === profileId;
                const isCustom = profile.id === CUSTOM;
                return (
                  <label key={profile.id} className={checked ? "choice choice--checked" : "choice"}>
                    <span className="choice__head">
                      <input
                        type="radio"
                        name="profile"
                        value={profile.id}
                        checked={checked}
                        onChange={() => pickProfile(profile.id)}
                      />
                      <span className="choice__title">
                        {isCustom ? "Personnalisé" : profileLabel(profile.id, profile.name)}
                      </span>
                    </span>
                    <span className="choice__meta mono">
                      {isCustom ? plural(selected.length, "module") : plural(profile.modules.length, "module")}
                    </span>
                    <span className="choice__text">
                      {isCustom
                        ? "Choisissez les modules un par un ci-dessous."
                        : profileDescription(profile.id, profile.description)}
                    </span>
                  </label>
                );
              },
            )}
          </div>
        </section>

        <section className="card stack" aria-labelledby="modules-title">
          <div className="card__heading-row">
            <h2 id="modules-title" className="card__title">
              3. Ce qui sera testé
            </h2>
            <span className="muted small">
              {selected.length} sur {catalog.modules.length}
            </span>
          </div>
          {groups.map((group) => (
            <fieldset key={group.title} className="fieldset">
              <legend className="eyebrow">{group.title}</legend>
              <div className="choice-grid">
                {group.modules.map((module) => {
                  const checked = selected.includes(module.id);
                  return (
                    <label key={module.id} className={checked ? "choice choice--checked" : "choice"}>
                      <span className="choice__head">
                        <input type="checkbox" checked={checked} onChange={() => toggleModule(module.id)} />
                        <span className="choice__title">{moduleLabel(module.id, module.name)}</span>
                        {module.intrusive && <span className="tag tag--warn">Intrusif</span>}
                      </span>
                      <span className="choice__text">
                        {moduleDescription(module.id, module.description)}
                      </span>
                      <span className="choice__meta mono">
                        {moduleEngine(module.id)} · {module.id}
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>
          ))}
        </section>
      </div>

      <aside className="split__aside stack" aria-label="Résumé et lancement">
        <section className="card stack" aria-labelledby="summary-title">
          <h2 id="summary-title" className="card__title">
            Résumé
          </h2>
          <dl className="summary">
            <dt>Cible</dt>
            <dd className="mono break">{target.trim() || "—"}</dd>
            <dt>Profil</dt>
            <dd>{profileId === CUSTOM ? "Personnalisé" : profileLabel(profileId)}</dd>
            <dt>Modules</dt>
            <dd>
              {selectedModules.length
                ? [...new Set(selectedModules.map((module) => moduleEngine(module.id)))].join(", ")
                : "—"}
            </dd>
            <dt>Durée max.</dt>
            <dd>{selected.length ? formatDuration(selected.length * timeoutSeconds * 1000) : "—"}</dd>
          </dl>
          <div className="field">
            <label htmlFor="timeout" className="field__label">
              Délai max. par module (s)
            </label>
            <input
              id="timeout"
              type="number"
              className="input"
              min={30}
              max={3600}
              step={30}
              value={Number.isNaN(timeoutSeconds) ? "" : timeoutSeconds}
              onChange={(event) => setTimeoutSeconds(event.target.valueAsNumber)}
            />
          </div>
          <div className="field">
            <span className="field__label">Équivalent en ligne de commande</span>
            <CodeBlock
              code={buildCurlCommand(request, window.location.origin)}
              copyLabel="Copier la commande"
              command
            />
          </div>
        </section>

        <section className="card stack" aria-labelledby="consent-title">
          <h2 id="consent-title" className="card__title">
            Autorisation
          </h2>
          <label className="check">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            <span>Ce site m’appartient ou j’ai une autorisation écrite pour le tester.</span>
          </label>
          {intrusiveSelected.length > 0 && (
            <p className="notice notice--warn">
              {intrusiveSelected.map((module) => moduleLabel(module.id)).join(", ")} envoie
              {intrusiveSelected.length > 1 ? "nt" : ""} des requêtes actives qui peuvent créer ou
              modifier des données. Préférez une copie locale ou de pré-production.
            </p>
          )}
          {submitError && <ErrorNotice error={submitError} />}
          <button type="submit" className="btn btn--primary btn--large" disabled={!canSubmit}>
            {submitting ? "Lancement…" : "Lancer le scan"}
          </button>
          {!canSubmit && !submitting && blockers.length > 0 && (
            <p className="hint">Il manque : {blockers.join(", ")}.</p>
          )}
        </section>
      </aside>
    </form>
  );
}

export function NewScanPage() {
  const catalog = useResource(api.catalog, []);
  return (
    <>
      <PageHeader
        title="Nouveau scan"
        subtitle="Choisissez une cible et un profil, puis ajustez les modules."
        back={{ to: "/", label: "Tableau de bord" }}
      />
      {catalog.error && <ErrorNotice error={catalog.error} onRetry={catalog.reload} />}
      {catalog.loading && <Loading />}
      {catalog.data && <ScanForm catalog={catalog.data} />}
    </>
  );
}
