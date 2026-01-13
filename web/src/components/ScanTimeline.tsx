import { CheckCircle2, Clock, Loader2, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface TimelineStep {
  module: string;
  status: "pending" | "running" | "success" | "error";
  startTime?: string;
  endTime?: string;
  findingsCount?: number;
}

interface ScanTimelineProps {
  steps: TimelineStep[];
}

const statusConfig = {
  pending: {
    icon: Clock,
    color: "text-muted-foreground",
    bgColor: "bg-slate-700",
    label: "En attente",
  },
  running: {
    icon: Loader2,
    color: "text-blue-400",
    bgColor: "bg-blue-500/20",
    label: "En cours",
  },
  success: {
    icon: CheckCircle2,
    color: "text-green-400",
    bgColor: "bg-green-500/20",
    label: "Terminé",
  },
  error: {
    icon: AlertCircle,
    color: "text-red-400",
    bgColor: "bg-red-500/20",
    label: "Erreur",
  },
};

export function ScanTimeline({ steps }: ScanTimelineProps) {
  const completedSteps = steps.filter((s) => s.status === "success").length;
  const totalSteps = steps.length;
  const progressPercentage = totalSteps > 0 ? (completedSteps / totalSteps) * 100 : 0;

  return (
    <Card className="border-slate-700">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Progression du Scan</CardTitle>
          <span className="text-sm text-muted-foreground">
            {completedSteps}/{totalSteps} modules
          </span>
        </div>
        {/* Barre de progression */}
        <div className="mt-4 w-full bg-slate-700 rounded-full h-2 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-blue-500 to-green-500 transition-all duration-500"
            style={{ width: `${progressPercentage}%` }}
          />
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {steps.map((step, idx) => {
          const config = statusConfig[step.status];
          const Icon = config.icon;
          const isLast = idx === steps.length - 1;

          return (
            <div key={`${step.module}-${idx}`} className="relative flex items-start gap-4">
              {/* Ligne verticale */}
              {!isLast && (
                <div
                  className={cn(
                    "absolute left-5 top-10 w-0.5 h-full transition-colors",
                    step.status === "success" ? "bg-green-500/50" : "bg-slate-600"
                  )}
                />
              )}

              {/* Icône */}
              <div
                className={cn(
                  "relative z-10 w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all",
                  config.bgColor,
                  step.status === "success" ? "border-green-500" : "border-slate-600"
                )}
              >
                <Icon
                  className={cn(
                    "w-5 h-5",
                    config.color,
                    step.status === "running" && "animate-spin"
                  )}
                />
              </div>

              {/* Contenu */}
              <div className="flex-1 pb-6">
                <div className="flex items-center justify-between">
                  <h4 className="text-base font-semibold capitalize">{step.module}</h4>
                  <span className={cn("text-xs", config.color)}>{config.label}</span>
                </div>

                {step.startTime && (
                  <p className="text-xs text-muted-foreground mt-1">
                    Démarré à {new Date(step.startTime).toLocaleTimeString("fr-FR")}
                  </p>
                )}

                {step.status === "success" && step.findingsCount !== undefined && (
                  <div className="mt-2 inline-flex items-center gap-2 px-3 py-1 bg-slate-700/50 rounded-full text-xs">
                    <CheckCircle2 className="w-3 h-3 text-green-400" />
                    <span>
                      {step.findingsCount} vulnérabilité{step.findingsCount !== 1 ? "s" : ""}{" "}
                      détectée{step.findingsCount !== 1 ? "s" : ""}
                    </span>
                  </div>
                )}

                {step.status === "error" && (
                  <div className="mt-2 inline-flex items-center gap-2 px-3 py-1 bg-red-500/20 rounded-full text-xs text-red-400">
                    <AlertCircle className="w-3 h-3" />
                    <span>Le scan a échoué</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
