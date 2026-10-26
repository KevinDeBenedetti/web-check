import type { Severity, SeverityCounts } from "../api/types";
import { SEVERITIES, SEVERITY_LABELS } from "../lib/labels";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev sev--${severity}`}>{SEVERITY_LABELS[severity]}</span>;
}

interface SeverityBarProps {
  counts: Partial<SeverityCounts>;
  /** Hide informational findings, which do not affect the score. */
  withoutInfo?: boolean;
}

export function SeverityBar({ counts, withoutInfo = true }: SeverityBarProps) {
  const shown = SEVERITIES.filter((severity) => !withoutInfo || severity !== "info");
  const total = shown.reduce((sum, severity) => sum + (counts[severity] ?? 0), 0);
  return (
    <div className="sev-bar" aria-hidden="true">
      {total > 0 &&
        shown.map((severity) => (
          <span
            key={severity}
            className={`sev-bar__part sev-fill--${severity}`}
            style={{ flexGrow: counts[severity] ?? 0 }}
          />
        ))}
    </div>
  );
}

export function SeverityLegend() {
  return (
    <ul className="legend">
      {SEVERITIES.filter((severity) => severity !== "info").map((severity) => (
        <li key={severity}>
          <span className={`legend__swatch sev-fill--${severity}`} aria-hidden="true" />
          {SEVERITY_LABELS[severity]}
        </li>
      ))}
    </ul>
  );
}

/** "1 crit. · 3 élev." — the counts that matter most, for compact rows. */
export function severityShortText(counts: Partial<SeverityCounts>): string {
  const parts: string[] = [];
  if (counts.critical) parts.push(`${counts.critical} crit.`);
  if (counts.high) parts.push(`${counts.high} élev.`);
  return parts.join(" · ");
}
