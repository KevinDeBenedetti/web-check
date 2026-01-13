import { BarChart3 } from "lucide-react";
import type { CheckResult } from "../types/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface ScanStatsProps {
  results: CheckResult[];
}

export function ScanStats({ results }: ScanStatsProps) {
  if (results.length === 0) return null;

  const stats = {
    total: results.length,
    success: results.filter((r) => r.status === "success").length,
    error: results.filter((r) => r.status === "error").length,
    timeout: results.filter((r) => r.status === "timeout").length,
    totalFindings: results.reduce((sum, r) => sum + r.findings.length, 0),
    critical: results.reduce(
      (sum, r) => sum + r.findings.filter((f) => f.severity === "critical").length,
      0
    ),
    high: results.reduce(
      (sum, r) => sum + r.findings.filter((f) => f.severity === "high").length,
      0
    ),
    medium: results.reduce(
      (sum, r) => sum + r.findings.filter((f) => f.severity === "medium").length,
      0
    ),
    low: results.reduce((sum, r) => sum + r.findings.filter((f) => f.severity === "low").length, 0),
    totalDuration: results.reduce((sum, r) => sum + r.duration_ms, 0),
  };

  return (
    <Card className="border-slate-700 mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BarChart3 className="w-5 h-5" />
          Scan Statistics
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
            <p className="text-xs text-muted-foreground mb-1">Tools</p>
            <p className="text-2xl font-bold">{stats.total}</p>
            <p className="text-xs text-green-400 mt-1">
              {stats.success} successful
              {stats.error > 0 && `, ${stats.error} errors`}
              {stats.timeout > 0 && `, ${stats.timeout} timeout`}
            </p>
          </div>

          <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
            <p className="text-xs text-muted-foreground mb-1">Vulnerabilities</p>
            <p className="text-2xl font-bold">{stats.totalFindings}</p>
            <p className="text-xs text-muted-foreground mt-1">Total</p>
          </div>

          <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
            <p className="text-xs text-muted-foreground mb-1">Total Duration</p>
            <p className="text-2xl font-bold">{(stats.totalDuration / 1000).toFixed(1)}s</p>
            <p className="text-xs text-muted-foreground mt-1">Cumulative</p>
          </div>

          <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
            <p className="text-xs text-muted-foreground mb-1">Average Duration</p>
            <p className="text-2xl font-bold">
              {(stats.totalDuration / stats.total / 1000).toFixed(1)}s
            </p>
            <p className="text-xs text-muted-foreground mt-1">Per Tool</p>
          </div>
        </div>

        {stats.totalFindings > 0 && (
          <div className="space-y-3">
            <h4 className="text-sm font-semibold">Distribution by Severity</h4>
            <div className="grid grid-cols-4 gap-3">
              <Card className="bg-red-900/20 border-red-700">
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold text-red-400">{stats.critical}</p>
                  <p className="text-xs text-red-300">Critical</p>
                </CardContent>
              </Card>
              <Card className="bg-orange-900/20 border-orange-700">
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold text-orange-400">{stats.high}</p>
                  <p className="text-xs text-orange-300">High</p>
                </CardContent>
              </Card>
              <Card className="bg-yellow-900/20 border-yellow-700">
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold text-yellow-400">{stats.medium}</p>
                  <p className="text-xs text-yellow-300">Medium</p>
                </CardContent>
              </Card>
              <Card className="bg-blue-900/20 border-blue-700">
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold text-blue-400">{stats.low}</p>
                  <p className="text-xs text-blue-300">Low</p>
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
