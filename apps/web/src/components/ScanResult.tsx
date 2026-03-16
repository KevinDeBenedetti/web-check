import { formatDistanceToNow } from "date-fns";
import { enUS } from "date-fns/locale";
import { ExternalLink, AlertCircle, ShieldAlert } from "lucide-react";
import type { CheckResult } from "../types/api";
import { SeverityBadge } from "./SeverityBadge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
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
  const criticalFindings = result.findings.filter((f) => f.severity === "critical");
  const highFindings = result.findings.filter((f) => f.severity === "high");
  const mediumFindings = result.findings.filter((f) => f.severity === "medium");
  const lowFindings = result.findings.filter((f) => f.severity === "low");
  const infoFindings = result.findings.filter((f) => f.severity === "info");

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
              {formatDistanceToNow(new Date(result.timestamp), { addSuffix: true, locale: enUS })}
            </p>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-6 space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-slate-700/50 rounded-lg p-3 border border-slate-600">
            <p className="text-xs text-muted-foreground">Duration</p>
            <p className="text-lg font-semibold">{(result.duration_ms / 1000).toFixed(1)}s</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-3 border border-slate-600">
            <p className="text-xs text-muted-foreground">Vulnerabilities</p>
            <p className="text-lg font-semibold">{result.findings.length}</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-3 border border-slate-600">
            <p className="text-xs text-muted-foreground">Category</p>
            <p className="text-lg font-semibold capitalize">{result.category}</p>
          </div>
        </div>

        {/* Error */}
        {result.error && (
          <div className="bg-destructive/20 border border-destructive rounded-lg p-3 flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
            <p className="text-sm text-destructive">{result.error}</p>
          </div>
        )}

        {/* Findings organized by severity */}
        {result.findings.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-lg font-semibold flex items-center gap-2">
                <ShieldAlert className="w-5 h-5" />
                Detected Vulnerabilities
              </h4>
              <div className="flex gap-2 text-xs">
                {criticalFindings.length > 0 && (
                  <Badge variant="destructive">{criticalFindings.length} Critical</Badge>
                )}
                {highFindings.length > 0 && (
                  <Badge className="bg-orange-500">{highFindings.length} High</Badge>
                )}
                {mediumFindings.length > 0 && (
                  <Badge className="bg-yellow-500">{mediumFindings.length} Medium</Badge>
                )}
                {lowFindings.length > 0 && (
                  <Badge className="bg-blue-500">{lowFindings.length} Low</Badge>
                )}
                {infoFindings.length > 0 && (
                  <Badge variant="secondary">{infoFindings.length} Info</Badge>
                )}
              </div>
            </div>

            <Accordion type="multiple" className="w-full">
              {/* Critical Findings */}
              {criticalFindings.length > 0 && (
                <AccordionItem value="critical" className="border-slate-700">
                  <AccordionTrigger className="hover:no-underline">
                    <div className="flex items-center gap-2 text-left">
                      <SeverityBadge severity="critical">CRITICAL</SeverityBadge>
                      <span className="font-semibold">
                        Critical Issues ({criticalFindings.length})
                      </span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-3 pt-2">
                      {criticalFindings.map((finding, idx) => (
                        <FindingCard key={`critical-${idx}`} finding={finding} />
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              )}

              {/* High Findings */}
              {highFindings.length > 0 && (
                <AccordionItem value="high" className="border-slate-700">
                  <AccordionTrigger className="hover:no-underline">
                    <div className="flex items-center gap-2 text-left">
                      <SeverityBadge severity="high">HIGH</SeverityBadge>
                      <span className="font-semibold">High Issues ({highFindings.length})</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-3 pt-2">
                      {highFindings.map((finding, idx) => (
                        <FindingCard key={`high-${idx}`} finding={finding} />
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              )}

              {/* Medium Findings */}
              {mediumFindings.length > 0 && (
                <AccordionItem value="medium" className="border-slate-700">
                  <AccordionTrigger className="hover:no-underline">
                    <div className="flex items-center gap-2 text-left">
                      <SeverityBadge severity="medium">MEDIUM</SeverityBadge>
                      <span className="font-semibold">Medium Issues ({mediumFindings.length})</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-3 pt-2">
                      {mediumFindings.map((finding, idx) => (
                        <FindingCard key={`medium-${idx}`} finding={finding} />
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              )}

              {/* Low Findings */}
              {lowFindings.length > 0 && (
                <AccordionItem value="low" className="border-slate-700">
                  <AccordionTrigger className="hover:no-underline">
                    <div className="flex items-center gap-2 text-left">
                      <SeverityBadge severity="low">LOW</SeverityBadge>
                      <span className="font-semibold">Low Issues ({lowFindings.length})</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-3 pt-2">
                      {lowFindings.map((finding, idx) => (
                        <FindingCard key={`low-${idx}`} finding={finding} />
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              )}

              {/* Info Findings */}
              {infoFindings.length > 0 && (
                <AccordionItem value="info" className="border-slate-700">
                  <AccordionTrigger className="hover:no-underline">
                    <div className="flex items-center gap-2 text-left">
                      <SeverityBadge severity="info">INFO</SeverityBadge>
                      <span className="font-semibold">Informational ({infoFindings.length})</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-3 pt-2">
                      {infoFindings.map((finding, idx) => (
                        <FindingCard key={`info-${idx}`} finding={finding} />
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              )}
            </Accordion>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Helper component for finding cards
interface FindingCardProps {
  finding: CheckResult["findings"][0];
}

function FindingCard({ finding }: FindingCardProps) {
  return (
    <Card className={cn("bg-slate-700/50 border-l-4", severityBorderColors[finding.severity])}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-base">{finding.title}</CardTitle>
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
              Reference
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
