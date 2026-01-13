import { formatDistanceToNow } from "date-fns";
import { fr } from "date-fns/locale";
import { ExternalLink } from "lucide-react";
import type { CheckResult } from "../types/api";
import { SeverityBadge } from "./SeverityBadge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface ScanResultProps {
  result: CheckResult;
}

const statusColors = {
  success: "text-green-400",
  error: "text-red-400",
  timeout: "text-yellow-400",
  running: "text-blue-400",
};

const severityBorderColors = {
  critical: "border-l-red-600",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-blue-500",
  info: "border-l-gray-500",
};

export function ScanResult({ result }: ScanResultProps) {
  return (
    <Card className="border-slate-700">
      <CardHeader className="border-b border-slate-700">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{result.module}</CardTitle>
            <CardDescription>{result.target}</CardDescription>
          </div>
          <div className="text-right">
            <Badge variant="secondary" className={cn(statusColors[result.status])}>
              {result.status.toUpperCase()}
            </Badge>
            <p className="text-xs text-muted-foreground mt-1">
              {formatDistanceToNow(new Date(result.timestamp), { addSuffix: true, locale: fr })}
            </p>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-6 space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-slate-700/50 rounded-lg p-3 border border-slate-600">
            <p className="text-xs text-muted-foreground">Durée</p>
            <p className="text-lg font-semibold">{(result.duration_ms / 1000).toFixed(1)}s</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-3 border border-slate-600">
            <p className="text-xs text-muted-foreground">Vulnérabilités</p>
            <p className="text-lg font-semibold">{result.findings.length}</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-3 border border-slate-600">
            <p className="text-xs text-muted-foreground">Catégorie</p>
            <p className="text-lg font-semibold capitalize">{result.category}</p>
          </div>
        </div>

        {/* Error */}
        {result.error && (
          <div className="bg-destructive/20 border border-destructive rounded-lg p-3">
            <p className="text-sm text-destructive">{result.error}</p>
          </div>
        )}

        {/* Findings */}
        {result.findings.length > 0 && (
          <div className="space-y-3">
            <h4 className="text-lg font-semibold">Vulnérabilités Détectées</h4>
            <div className="space-y-3">
              {result.findings.map((finding, idx) => (
                <Card
                  key={idx}
                  className={cn(
                    "bg-slate-700/50 border-l-4",
                    severityBorderColors[finding.severity]
                  )}
                >
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between gap-2">
                      <CardTitle className="text-base">{finding.title}</CardTitle>
                      <SeverityBadge severity={finding.severity}>
                        {finding.severity.toUpperCase()}
                      </SeverityBadge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <CardDescription className="text-sm">{finding.description}</CardDescription>
                    <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                      {finding.cve && (
                        <Badge variant="outline" className="font-mono">
                          {finding.cve}
                        </Badge>
                      )}
                      {finding.cvss_score !== undefined && finding.cvss_score !== null && (
                        <Badge variant="outline">CVSS: {finding.cvss_score.toFixed(1)}</Badge>
                      )}
                      {finding.reference && (
                        <a
                          href={finding.reference}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-primary hover:underline"
                        >
                          Référence
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
