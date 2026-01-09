import type { Severity } from "../types/api";

interface BadgeProps {
  severity: Severity;
  children: React.ReactNode;
}

const severityColors: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  info: "bg-gray-500 text-white",
};

export function SeverityBadge({ severity, children }: BadgeProps) {
  return (
    <span className={`px-2 py-1 text-xs font-semibold rounded ${severityColors[severity]}`}>
      {children}
    </span>
  );
}
