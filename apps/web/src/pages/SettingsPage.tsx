import { type FormEvent, useState } from "react";
import { api, getApiKey, setApiKey } from "../api/client";
import type { ScopeCheckResult, ServiceStatus } from "../api/types";
import { CodeBlock } from "../components/CopyButton";
import { ErrorNotice, Loading } from "../components/Feedback";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { ServicePill } from "../components/StatusPill";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useResource } from "../hooks/useResource";

function startCommand(service: ServiceStatus): string | undefined {
  if (service.id === "api" || service.state === "running") return undefined;
  const profile = service.compose_profile ? `--profile ${service.compose_profile} ` : "";
  return `docker compose ${profile}up -d ${service.id}`;
}

function ScopeTester() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<ScopeCheckResult>();
  const [error, setError] = useState<Error>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!target.trim()) return;
    setError(undefined);
    try {
      setResult(await api.checkScope(target.trim()));
    } catch (reason) {
      setResult(undefined);
      setError(reason instanceof Error ? reason : new Error(String(reason)));
    }
  };

  return (
    <form className="stack-xs" onSubmit={submit}>
      <label htmlFor="scope-test" className="field__label">
        Tester une cible
      </label>
      <div className="row-wrap">
        <input
          id="scope-test"
          type="text"
          className="input mono grow"
          placeholder="https://app.example.com"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
        />
        <button type="submit" className="btn btn--dark">
          Vérifier
        </button>
      </div>
      <div aria-live="polite">
        {error && <p className="hint hint--bad">{error.message}</p>}
        {result &&
          (result.allowed ? (
            <p className="hint hint--ok">
              <Icon name="checkCircle" size={16} strokeWidth={2} />
              <span>
                <span className="mono">{result.hostname}</span> est autorisé par la règle{" "}
                <span className="mono">{result.matched_rule}</span>.
              </span>
            </p>
          ) : (
            <p className="hint hint--bad">
              <Icon name="alert" size={16} strokeWidth={2} />
              <span>
                <span className="mono">{result.hostname ?? result.target}</span> est hors périmètre.
              </span>
            </p>
          ))}
      </div>
    </form>
  );
}

function ApiKeyForm() {
  const [value, setValue] = useState(getApiKey());
  const [saved, setSaved] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setApiKey(value.trim());
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  return (
    <form className="stack-xs" onSubmit={submit}>
      <label htmlFor="api-key" className="field__label">
        Clé API de ce navigateur
      </label>
      <div className="row-wrap">
        <input
          id="api-key"
          type="password"
          className="input mono grow"
          placeholder="Valeur de API_KEY (vide si l’API n’en exige pas)"
          value={value}
          autoComplete="off"
          onChange={(event) => setValue(event.target.value)}
        />
        <button type="submit" className="btn btn--dark">
          {saved ? "Enregistrée" : "Enregistrer"}
        </button>
      </div>
      <p className="hint">
        Envoyée dans l’en-tête <span className="mono">X-API-Key</span> (et en paramètre{" "}
        <span className="mono">api_key</span> pour les exports et le journal en direct). Elle
        reste dans ce navigateur, rien n’est stocké côté API.
      </p>
    </form>
  );
}

export function SettingsPage() {
  useDocumentTitle("Réglages");
  const scope = useResource(api.scope, []);
  const services = useResource(api.services, [], 15_000);
  const health = useResource(api.health, []);
  const exampleRules = scope.data?.rules.length ? scope.data.rules.join(",") : "example.com";

  return (
    <>
      <PageHeader
        title="Réglages"
        subtitle={
          <>
            La configuration vit sur cette machine : <span className="mono">.env</span>,{" "}
            <span className="mono">docker-compose.yml</span> et <span className="mono">data/</span>.
          </>
        }
        actions={
          <a href="/docs" className="btn btn--secondary" target="_blank" rel="noreferrer">
            <Icon name="external" size={16} />
            Documentation de l’API
          </a>
        }
      />

      <div className="columns">
        <section className="card stack" aria-labelledby="scope-title">
          <div className="stack-xs">
            <h2 id="scope-title" className="card__title">
              Périmètre autorisé
            </h2>
            <p className="muted small">
              Seules ces cibles peuvent être scannées. Une règle <span className="mono">example.com</span>{" "}
              couvre aussi ses sous-domaines ; <span className="mono">*.example.com</span> ne couvre que
              les sous-domaines.
            </p>
          </div>
          {scope.error && <ErrorNotice error={scope.error} onRetry={scope.reload} />}
          {scope.loading && <Loading />}
          {scope.data && (
            <ul className="rule-list">
              {scope.data.rules.map((rule) => (
                <li key={rule} className="mono">
                  {rule}
                </li>
              ))}
              {scope.data.rules.length === 0 && <li className="muted">Aucune règle : tout est refusé.</li>}
            </ul>
          )}
          <div className="stack-xs">
            <span className="field__label">Modifier le périmètre</span>
            <p className="muted small">
              Éditez <span className="mono">ALLOWED_DOMAINS</span> dans <span className="mono">.env</span>, puis
              redémarrez l’API.
            </p>
            <CodeBlock
              code={`ALLOWED_DOMAINS="${exampleRules}"\ndocker compose up -d api`}
              copyLabel="Copier"
              command
            />
          </div>
          <ScopeTester />
        </section>

        <section className="card stack" aria-labelledby="api-title">
          <h2 id="api-title" className="card__title">
            API
          </h2>
          <dl className="summary">
            <dt>État</dt>
            <dd>
              {health.data ? (
                <span className="pill pill--ok">en ligne</span>
              ) : health.error ? (
                <span className="pill pill--bad">injoignable</span>
              ) : (
                "…"
              )}
            </dd>
            <dt>Adresse</dt>
            <dd className="mono">{window.location.origin}</dd>
            <dt>Clé API</dt>
            <dd>
              {getApiKey() ? (
                <span className="pill pill--ok">renseignée</span>
              ) : (
                <span className="pill pill--neutral">aucune</span>
              )}
            </dd>
            <dt>Historique</dt>
            <dd className="mono">data/web-check.db</dd>
            <dt>Rapports</dt>
            <dd>
              Exports JSON, Markdown et SARIF depuis chaque rapport, ou{" "}
              <span className="mono">GET /api/scans/&#123;id&#125;/export</span>
            </dd>
          </dl>
          <ApiKeyForm />
        </section>
      </div>

      <section className="card card--flush" aria-labelledby="services-heading">
        <div className="card__header">
          <div className="stack-xs">
            <h2 id="services-heading" className="card__title">
              Moteurs et services Docker
            </h2>
            <p className="muted small">
              L’état est lu via le socket Docker monté dans le conteneur de l’API.
            </p>
          </div>
          <button type="button" className="btn btn--secondary" onClick={services.reload}>
            <Icon name="refresh" size={16} />
            Actualiser
          </button>
        </div>
        {services.error && <ErrorNotice error={services.error} onRetry={services.reload} />}
        {services.loading && <Loading />}
        {services.data && (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Service</th>
                  <th scope="col">Image</th>
                  <th scope="col">État</th>
                  <th scope="col">Pour le démarrer</th>
                </tr>
              </thead>
              <tbody>
                {services.data.map((service) => {
                  const command = startCommand(service);
                  return (
                    <tr key={service.id}>
                      <td>
                        <span className="strong">{service.name}</span>
                        <span className="muted small block">{service.role}</span>
                      </td>
                      <td className="mono small">{service.image ?? service.container ?? "—"}</td>
                      <td>
                        <ServicePill state={service.state} />
                      </td>
                      <td>
                        {command ? (
                          <code className="inline-code">{command}</code>
                        ) : (
                          <span className="muted small">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {services.data?.some((service) => service.state === "unknown") && (
          <p className="card__footer muted small">
            « inconnu » : l’API n’a pas accès à Docker (CLI absente ou socket non monté).
          </p>
        )}
      </section>
    </>
  );
}
