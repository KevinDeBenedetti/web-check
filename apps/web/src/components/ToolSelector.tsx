import type { ScanTool } from "../types/api";
import { AVAILABLE_TOOLS } from "../constants/tools";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface ToolSelectorProps {
  selectedTools: ScanTool[];
  onToggleTool: (toolId: ScanTool) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
}

export function ToolSelector({
  selectedTools,
  onToggleTool,
  onSelectAll,
  onClearAll,
}: ToolSelectorProps) {
  return (
    <TooltipProvider delayDuration={300}>
      <div className="space-y-3">
        {/* Header */}
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-muted-foreground">
            Tools ({selectedTools.length}/{AVAILABLE_TOOLS.length})
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onSelectAll}
              className="text-xs text-primary hover:underline transition-colors"
            >
              All
            </button>
            <span className="text-xs text-muted-foreground">•</span>
            <button
              type="button"
              onClick={onClearAll}
              className="text-xs text-primary hover:underline transition-colors"
            >
              None
            </button>
          </div>
        </div>

        {/* Tool Grid */}
        <div className="grid grid-cols-2 gap-2">
          {AVAILABLE_TOOLS.map((tool) => {
            const isSelected = selectedTools.includes(tool.id);

            return (
              <Tooltip key={tool.id}>
                <TooltipTrigger asChild>
                  <label
                    className={cn(
                      "flex items-center gap-2.5 px-3 py-2.5 rounded-lg cursor-pointer transition-all duration-200",
                      "border-2 hover:shadow-md",
                      isSelected
                        ? "border-primary bg-primary/5 shadow-sm"
                        : "border-slate-700/50 bg-slate-800/30 hover:border-slate-600 hover:bg-slate-800/50"
                    )}
                  >
                    <Checkbox
                      checked={isSelected}
                      onCheckedChange={() => onToggleTool(tool.id)}
                      className={cn(
                        "transition-all",
                        isSelected && "data-[state=checked]:bg-primary"
                      )}
                    />
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      <span className="text-lg leading-none flex-shrink-0">{tool.icon}</span>
                      <span className="font-medium text-sm truncate">{tool.name}</span>
                    </div>
                  </label>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs bg-slate-900 border-slate-700">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-base">{tool.icon}</span>
                      <span className="font-semibold">{tool.name}</span>
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[10px] px-1.5 py-0",
                          tool.category === "quick"
                            ? "border-green-500/50 text-green-400"
                            : tool.category === "deep"
                              ? "border-blue-500/50 text-blue-400"
                              : "border-purple-500/50 text-purple-400"
                        )}
                      >
                        {tool.category}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {tool.description}
                    </p>
                    <div className="text-[10px] text-muted-foreground/70 pt-1 border-t border-slate-700/50">
                      Timeout: {tool.defaultTimeout}s
                    </div>
                  </div>
                </TooltipContent>
              </Tooltip>
            );
          })}
        </div>
      </div>
    </TooltipProvider>
  );
}
