import { Badge } from "@/components/ui/badge";
import type { Severity } from "../types/api";
import { cn } from "@/lib/utils";

interface BadgeProps {
  severity: Severity;
  children: React.ReactNode;
}

const severityVariants: Record<Severity, string> = {
  critical: "bg-red-600 hover:bg-red-700 text-white",
  high: "bg-orange-500 hover:bg-orange-600 text-white",
  medium: "bg-yellow-500 hover:bg-yellow-600 text-black",
  low: "bg-blue-500 hover:bg-blue-600 text-white",
  info: "bg-gray-500 hover:bg-gray-600 text-white",
};

export function SeverityBadge({ severity, children }: BadgeProps) {
  return (
    <Badge variant="default" className={cn(severityVariants[severity])}>
      {children}
    </Badge>
  );
}
