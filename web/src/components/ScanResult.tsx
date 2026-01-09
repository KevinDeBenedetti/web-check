import { formatDistanceToNow } from "date-fns";
import { fr } from "date-fns/locale";
import type { CheckResult } from "../types/api";
import { SeverityBadge } from "./SeverityBadge";

interface ScanResultProps {
  result: CheckResult;
}

const statusColors = {
  success: "text-green-400",
  error: "text-red-400",
  timeout: "text-yellow-400",
  running: "text-blue-400",
};

export function ScanResult({ result }: ScanResultProps) {
  return (
    <div className="bg-slate-800 rounded-lg shadow-lg p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-700 pb-4">
        <div>
          <h3 className="text-xl font-bold text-white">{result.module}</h3>
          <p className="text-sm text-gray-400">{result.target}</p>
        </div>
        <div className="text-right">
          <span className={`font-semibold ${statusColors[result.status]}`}>
            {result.status.toUpperCase()}
          </span>
          <p className="text-xs text-gray-500">
            {formatDistanceToNow(new Date(result.timestamp), { addSuffix: true, locale: fr })}
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-slate-700 rounded p-3">
          <p className="text-xs text-gray-400">Durée</p>
          <p className="text-lg font-semibold text-white">
            {(result.duration_ms / 1000).toFixed(1)}s
          </p>
        </div>
        <div className="bg-slate-700 rounded p-3">
          <p className="text-xs text-gray-400">Vulnérabilités</p>
          <p className="text-lg font-semibold text-white">{result.findings.length}</p>
        </div>
        <div className="bg-slate-700 rounded p-3">
          <p className="text-xs text-gray-400">Catégorie</p>
          <p className="text-lg font-semibold text-white capitalize">{result.category}</p>
        </div>
      </div>

      {/* Error */}
      {result.error && (
        <div className="bg-red-900/20 border border-red-700 rounded p-3">
          <p className="text-sm text-red-400">{result.error}</p>
        </div>
      )}

      {/* Findings */}
      {result.findings.length > 0 && (
        <div>
          <h4 className="text-lg font-semibold text-white mb-3">Vulnérabilités Détectées</h4>
          <div className="space-y-3">
            {result.findings.map((finding, idx) => (
              <div
                key={idx}
                className="bg-slate-700 rounded-lg p-4 border-l-4"
                style={{
                  borderLeftColor:
                    finding.severity === "critical"
                      ? "#dc2626"
                      : finding.severity === "high"
                        ? "#f97316"
                        : finding.severity === "medium"
                          ? "#eab308"
                          : "#3b82f6",
                }}
              >
                <div className="flex items-start justify-between mb-2">
                  <h5 className="font-semibold text-white">{finding.title}</h5>
                  <SeverityBadge severity={finding.severity}>
                    {finding.severity.toUpperCase()}
                  </SeverityBadge>
                </div>
                <p className="text-sm text-gray-300 mb-2">{finding.description}</p>
                <div className="flex gap-4 text-xs text-gray-400">
                  {finding.cve && <span>CVE: {finding.cve}</span>}
                  {finding.cvss_score !== undefined && (
                    <span>CVSS: {finding.cvss_score.toFixed(1)}</span>
                  )}
                  {finding.reference && (
                    <a
                      href={finding.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary-400 hover:underline"
                    >
                      Référence ↗
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
