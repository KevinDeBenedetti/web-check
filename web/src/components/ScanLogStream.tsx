import { useEffect, useState, useRef, useMemo } from "react";
import {
  Plug,
  Info,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Container,
  PartyPopper,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ScanTimeline } from "./ScanTimeline";

interface LogEntry {
  timestamp: string;
  scan_id?: string;
  type: "connected" | "info" | "success" | "warning" | "error" | "docker" | "complete";
  message: string;
  module?: string;
  command?: string;
  findings_count?: number;
  status?: string;
}

interface ScanLogStreamProps {
  scanId: string;
  onComplete?: () => void;
}

const logTypeColors = {
  connected: "text-blue-400",
  info: "text-muted-foreground",
  success: "text-green-400",
  warning: "text-yellow-400",
  error: "text-red-400",
  docker: "text-purple-400",
  complete: "text-green-500",
};

const LogIcon = ({ type }: { type: LogEntry["type"] }) => {
  const iconClass = "w-4 h-4";
  switch (type) {
    case "connected":
      return <Plug className={iconClass} />;
    case "info":
      return <Info className={iconClass} />;
    case "success":
      return <CheckCircle2 className={iconClass} />;
    case "warning":
      return <AlertTriangle className={iconClass} />;
    case "error":
      return <XCircle className={iconClass} />;
    case "docker":
      return <Container className={iconClass} />;
    case "complete":
      return <PartyPopper className={iconClass} />;
  }
};

export function ScanLogStream({ scanId, onComplete }: ScanLogStreamProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const apiUrl = window.location.origin;
    const eventSource = new EventSource(`${apiUrl}/api/scans/${scanId}/logs`);

    eventSource.onopen = () => {
      setIsConnected(true);
      setError(null);
    };

    eventSource.onmessage = (event) => {
      try {
        const data: LogEntry = JSON.parse(event.data);
        setLogs((prev) => [...prev, data]);

        if (data.type === "complete") {
          eventSource.close();
          setIsConnected(false);
          onComplete?.();
        }
      } catch (err) {
        console.error("Failed to parse log entry:", err);
      }
    };

    eventSource.onerror = (err) => {
      console.error("EventSource error:", err);
      setError("Connexion perdue avec le serveur");
      setIsConnected(false);
      eventSource.close();
    };

    return () => {
      eventSource.close();
      setIsConnected(false);
    };
  }, [scanId, onComplete]);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (logsContainerRef.current) {
      logsContainerRef.current.scrollTop = logsContainerRef.current.scrollHeight;
    }
  }, [logs]);

  // Extraire les informations de timeline depuis les logs
  const timelineSteps = useMemo(() => {
    const modulesMap = new Map<string, {
      module: string;
      status: "pending" | "running" | "success" | "error";
      startTime?: string;
      endTime?: string;
      findingsCount?: number;
    }>();

    // Extraire les modules du message initial
    const infoLog = logs.find((l) => l.type === "info" && l.message?.includes("Starting scan with modules"));
    if (infoLog) {
      const match = infoLog.message.match(/modules: (.+)/);
      if (match) {
        const moduleNames = match[1].split(",").map((m) => m.trim());
        moduleNames.forEach((module) => {
          if (!modulesMap.has(module)) {
            modulesMap.set(module, {
              module,
              status: "pending",
            });
          }
        });
      }
    }

    logs.forEach((log) => {
      if (!log.module) return;

      const existing = modulesMap.get(log.module);

      if (log.type === "docker") {
        // Module démarré
        modulesMap.set(log.module, {
          ...existing,
          module: log.module,
          status: "running",
          startTime: log.timestamp,
        });
      } else if (log.type === "success") {
        // Module terminé avec succès
        modulesMap.set(log.module, {
          ...existing,
          module: log.module,
          status: "success",
          endTime: log.timestamp,
          findingsCount: log.findings_count ?? 0,
        });
      } else if (log.type === "error") {
        // Module en erreur
        modulesMap.set(log.module, {
          ...existing,
          module: log.module,
          status: "error",
          endTime: log.timestamp,
        });
      }
    });

    return Array.from(modulesMap.values());
  }, [logs]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Timeline */}
      {timelineSteps.length > 0 && <ScanTimeline steps={timelineSteps} />}

      {/* Logs */}
    <Card className="border-slate-700">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Logs en Temps Réel</CardTitle>
            <CardDescription>Scan ID: {scanId}</CardDescription>
          </div>
          {isConnected ? (
            <Badge variant="secondary" className="text-green-400 gap-2">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
              </span>
              Connecté
            </Badge>
          ) : (
            <Badge variant="outline">Déconnecté</Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Error */}
        {error && (
          <div className="bg-destructive/20 border border-destructive rounded-lg p-3">
            <p className="text-sm text-destructive">{error}</p>
          </div>
        )}

        {/* Logs Container */}
        <div
          ref={logsContainerRef}
          className="bg-slate-900 rounded-lg border border-slate-700 p-4 h-96 overflow-y-auto font-mono text-sm space-y-2"
        >
          {logs.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">En attente des logs...</p>
          ) : (
            logs.map((log, idx) => (
              <div key={idx} className="flex items-start gap-2 group hover:bg-slate-800/50 p-1 rounded">
                <span className="text-muted-foreground text-xs mt-0.5 w-20 flex-shrink-0">
                  {log.timestamp
                    ? new Date(log.timestamp).toLocaleTimeString("fr-FR")
                    : "--:--:--"}
                </span>
                <span className={cn("mt-0.5", logTypeColors[log.type])}>
                  <LogIcon type={log.type} />
                </span>
                <div className="flex-1 min-w-0">
                  <span className={logTypeColors[log.type]}>
                    {log.module && (
                      <Badge variant="outline" className="font-mono text-xs mr-2">
                        {log.module}
                      </Badge>
                    )}
                    {log.message}
                  </span>
                  {log.command && (
                    <div className="text-xs text-muted-foreground mt-1 ml-4 opacity-70">
                      $ {log.command}
                    </div>
                  )}
                  {log.findings_count !== undefined && (
                    <Badge variant="secondary" className="text-xs ml-2">
                      {log.findings_count} vulnérabilités
                    </Badge>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Stats */}
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{logs.length} événements</span>
        </div>
      </CardContent>
    </Card>
    </div>
  );
}
