import type { CheckResult, Finding, Severity } from "../api/types";
import { SEVERITIES } from "./labels";

export interface FindingWithSources extends Finding {
  key: string;
  sources: string[];
}

const rank = (severity: Severity) => SEVERITIES.indexOf(severity);

/** Same normalisation as the API (apps/api/services/findings.py). */
export function findingKey(title: string): string {
  return title.replace(/\s+/g, " ").trim().toLowerCase();
}

export function compareSeverity(a: Severity, b: Severity): number {
  return rank(a) - rank(b);
}

/** Merge findings that share a title across modules, highest severity first. */
export function dedupeFindings(results: CheckResult[]): FindingWithSources[] {
  const merged = new Map<string, FindingWithSources>();
  for (const result of results) {
    for (const finding of result.findings) {
      const key = findingKey(finding.title);
      const existing = merged.get(key);
      if (!existing) {
        merged.set(key, { ...finding, key, sources: [result.module] });
        continue;
      }
      if (compareSeverity(finding.severity, existing.severity) < 0) {
        existing.severity = finding.severity;
      }
      if (!existing.sources.includes(result.module)) existing.sources.push(result.module);
    }
  }
  return [...merged.values()].sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.title.localeCompare(b.title, "fr"),
  );
}

export function countBySeverity(findings: { severity: Severity }[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/** Markdown snippet for pasting a finding into a ticket. */
export function findingToMarkdown(
  finding: Pick<
    Finding,
    "severity" | "title" | "description" | "remediation" | "reference" | "cve"
  > & { sources: string[] },
  target: string,
): string {
  const lines = [
    `### [${finding.severity.toUpperCase()}] ${finding.title}`,
    "",
    `- Cible : ${target}`,
    `- Sources : ${finding.sources.join(", ")}`,
  ];
  if (finding.cve) lines.push(`- CVE : ${finding.cve}`);
  lines.push("", finding.description.trim());
  if (finding.remediation) lines.push("", `**Correction :** ${finding.remediation.trim()}`);
  if (finding.reference) lines.push("", `Référence : ${finding.reference}`);
  return `${lines.join("\n")}\n`;
}
