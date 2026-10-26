import type { ScanResponse, Severity } from "../api/types";
import { compareSeverity, dedupeFindings, findingKey } from "./findings";
import { hostnameOf } from "./format";

export interface SiteSummary {
  host: string;
  target: string;
  /** Most recent finished scan, used for the score and findings. */
  latest: ScanResponse | undefined;
  running: ScanResponse | undefined;
  /** Scores of finished scans, oldest first (last 12). */
  scores: number[];
  scanCount: number;
  lastActivity: string;
}

const isFinished = (scan: ScanResponse) => scan.status !== "running";

/** Group scans by host. Scans are expected newest first, as returned by GET /api/scans. */
export function groupScansBySite(scans: ScanResponse[]): SiteSummary[] {
  const byHost = new Map<string, ScanResponse[]>();
  for (const scan of scans) {
    const host = hostnameOf(scan.target);
    byHost.set(host, [...(byHost.get(host) ?? []), scan]);
  }

  return [...byHost.entries()]
    .map(([host, siteScans]) => {
      const finished = siteScans.filter(isFinished);
      const newest = siteScans[0]!;
      return {
        host,
        target: newest.target,
        latest: finished[0],
        running: siteScans.find((scan) => scan.status === "running"),
        scores: finished
          .slice(0, 12)
          .map((scan) => scan.score ?? 0)
          .reverse(),
        scanCount: siteScans.length,
        lastActivity: newest.started_at,
      };
    })
    .sort((a, b) => b.lastActivity.localeCompare(a.lastActivity));
}

export interface RecurringFinding {
  key: string;
  title: string;
  severity: Severity;
  hosts: string[];
}

/** Findings present in the latest finished scan of at least two sites. */
export function recurringFindings(sites: SiteSummary[], limit = 5): RecurringFinding[] {
  const byKey = new Map<string, RecurringFinding>();
  for (const site of sites) {
    if (!site.latest) continue;
    for (const finding of dedupeFindings(site.latest.results)) {
      const key = findingKey(finding.title);
      const entry = byKey.get(key) ?? {
        key,
        title: finding.title,
        severity: finding.severity,
        hosts: [],
      };
      if (compareSeverity(finding.severity, entry.severity) < 0) entry.severity = finding.severity;
      entry.hosts.push(site.host);
      byKey.set(key, entry);
    }
  }
  return [...byKey.values()]
    .filter((entry) => entry.hosts.length >= 2)
    .sort(
      (a, b) =>
        b.hosts.length - a.hosts.length ||
        compareSeverity(a.severity, b.severity) ||
        a.title.localeCompare(b.title, "fr"),
    )
    .slice(0, limit);
}

/** Share of requested modules that already have a result, from 0 to 1. */
export function scanProgress(scan: ScanResponse): number {
  const total = scan.modules?.length ?? 0;
  if (scan.status !== "running") return 1;
  if (total === 0) return 0;
  return Math.min(1, scan.results.length / total);
}
