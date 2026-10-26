import type { ScanStatus, ServiceState, Severity } from "../api/types";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};

export const STATUS_LABELS: Record<ScanStatus, string> = {
  running: "En cours",
  success: "Terminé",
  error: "Échec",
  timeout: "Délai dépassé",
};

export const SERVICE_STATE_LABELS: Record<ServiceState, string> = {
  running: "actif",
  stopped: "arrêté",
  missing: "absent",
  unknown: "inconnu",
};

interface ModuleCopy {
  label: string;
  engine: string;
  description: string;
}

// French copy for the module ids of /api/catalog; unknown ids fall back to the API's name.
const MODULE_COPY: Record<string, ModuleCopy> = {
  headers: {
    label: "En-têtes HTTP",
    engine: "web-check",
    description: "HSTS, CSP, X-Frame-Options, CORS, attributs des cookies, bannières serveur",
  },
  dns: {
    label: "DNS et e-mail",
    engine: "web-check",
    description: "Enregistrements DNS, SPF, DMARC, DKIM, transfert de zone",
  },
  testssl: {
    label: "Chiffrement TLS",
    engine: "SSLyze",
    description: "Protocoles, suites de chiffrement, validité du certificat",
  },
  nuclei: {
    label: "Failles connues",
    engine: "Nuclei",
    description: "CVE et mauvaises configurations référencées par des modèles",
  },
  nikto: {
    label: "Configuration serveur",
    engine: "Nikto",
    description: "Fichiers par défaut, logiciels obsolètes, méthodes HTTP risquées",
  },
  zap: {
    label: "Analyse dynamique",
    engine: "OWASP ZAP",
    description: "Exploration du site puis règles d’analyse active de ZAP",
  },
  wapiti: {
    label: "Audit applicatif",
    engine: "Wapiti",
    description: "Audit en boîte noire des formulaires et paramètres",
  },
  sqlmap: {
    label: "Injection SQL",
    engine: "SQLMap",
    description: "Teste les paramètres contre l’injection SQL",
  },
  xsstrike: {
    label: "XSS réfléchi",
    engine: "XSStrike",
    description: "Teste les paramètres contre le XSS réfléchi",
  },
};

// Names stored by scans made before results were keyed by the requested module id.
const MODULE_ALIASES: Record<string, string> = { dns_enum: "dns", sslyze: "testssl" };

/** Module id as requested in the scan, for results stored under an older name. */
export function canonicalModule(moduleId: string): string {
  return MODULE_ALIASES[moduleId] ?? moduleId;
}

function copyFor(moduleId: string): ModuleCopy | undefined {
  return MODULE_COPY[canonicalModule(moduleId)];
}

export function moduleLabel(moduleId: string, fallback?: string): string {
  return copyFor(moduleId)?.label ?? fallback ?? moduleId;
}

export function moduleEngine(moduleId: string): string {
  return copyFor(moduleId)?.engine ?? moduleId;
}

export function moduleDescription(moduleId: string, fallback: string): string {
  return copyFor(moduleId)?.description ?? fallback;
}

const PROFILE_COPY: Record<string, { label: string; description: string }> = {
  quick: { label: "Rapide", description: "Vérifications passives : en-têtes, DNS, TLS." },
  standard: {
    label: "Standard",
    description: "Ajoute les failles connues et la configuration du serveur.",
  },
  full: { label: "Complet", description: "Ajoute l’analyse dynamique d’OWASP ZAP." },
};

export function profileLabel(profileId: string, fallback?: string): string {
  return PROFILE_COPY[profileId]?.label ?? fallback ?? profileId;
}

export function profileDescription(profileId: string, fallback: string): string {
  return PROFILE_COPY[profileId]?.description ?? fallback;
}

export type ScoreBand = "good" | "fair" | "poor";

export function scoreBand(score: number): ScoreBand {
  if (score >= 80) return "good";
  if (score >= 60) return "fair";
  return "poor";
}

export const SCORE_BAND_LABELS: Record<ScoreBand, string> = {
  good: "Bon",
  fair: "À améliorer",
  poor: "Critique",
};
