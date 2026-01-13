import { useState } from "react";
import { Rocket } from "lucide-react";
import type { ScanTool } from "../types/api";
import { AVAILABLE_TOOLS, FULL_SCAN_CONFIG } from "../constants/tools";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface ScanFormProps {
  onSubmit: (target: string, tools: ScanTool[], timeout: number) => void;
  isLoading: boolean;
}

export function ScanForm({ onSubmit, isLoading }: ScanFormProps) {
  const [target, setTarget] = useState("");
  const [selectedTools, setSelectedTools] = useState<ScanTool[]>(["nuclei"]);
  const [timeout, setTimeout] = useState(900);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (target && selectedTools.length > 0) {
      onSubmit(target, selectedTools, timeout);
    }
  };

  const handleFullScan = (e: React.MouseEvent) => {
    e.preventDefault();
    if (target) {
      setSelectedTools(FULL_SCAN_CONFIG.tools);
      onSubmit(target, FULL_SCAN_CONFIG.tools, FULL_SCAN_CONFIG.timeout);
    }
  };

  const toggleTool = (toolId: ScanTool) => {
    setSelectedTools((prev) =>
      prev.includes(toolId) ? prev.filter((t) => t !== toolId) : [...prev, toolId]
    );
  };

  const selectAllTools = () => {
    setSelectedTools(AVAILABLE_TOOLS.map((tool) => tool.id));
  };

  const clearAllTools = () => {
    setSelectedTools([]);
  };

  return (
    <Card className="border-slate-700">
      <CardHeader>
        <CardTitle className="text-2xl">Nouveau Scan</CardTitle>
        <CardDescription>Configurez votre scan de sécurité</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target URL */}
          <div className="space-y-2">
            <Label htmlFor="target">URL Cible</Label>
            <Input
              type="url"
              id="target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              required
              className="bg-slate-700 border-slate-600"
            />
          </div>

          {/* Tool Selection */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Outils de Scan ({selectedTools.length} sélectionnés)</Label>
              <div className="flex gap-2 text-sm">
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  onClick={selectAllTools}
                  className="h-auto p-0 text-primary"
                >
                  Tous
                </Button>
                <span className="text-muted-foreground">|</span>
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  onClick={clearAllTools}
                  className="h-auto p-0 text-primary"
                >
                  Aucun
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              {AVAILABLE_TOOLS.map((tool) => (
                <label
                  key={tool.id}
                  className={cn(
                    "flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-colors",
                    "bg-slate-700/50 hover:bg-slate-700 border border-transparent hover:border-slate-600"
                  )}
                >
                  <Checkbox
                    checked={selectedTools.includes(tool.id)}
                    onCheckedChange={() => toggleTool(tool.id)}
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-lg">{tool.icon}</span>
                      <span className="font-medium">{tool.name}</span>
                      <Badge
                        variant="secondary"
                        className={cn(
                          tool.category === "quick"
                            ? "bg-green-900/50 text-green-300 hover:bg-green-900/70"
                            : tool.category === "deep"
                              ? "bg-blue-900/50 text-blue-300 hover:bg-blue-900/70"
                              : "bg-purple-900/50 text-purple-300 hover:bg-purple-900/70"
                        )}
                      >
                        {tool.category}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{tool.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Timeout */}
          <div className="space-y-2">
            <Label htmlFor="timeout">Timeout (secondes)</Label>
            <Input
              type="number"
              id="timeout"
              value={timeout}
              onChange={(e) => setTimeout(Number(e.target.value))}
              min="30"
              max="3600"
              className="bg-slate-700 border-slate-600"
            />
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2">
            <Button
              type="submit"
              disabled={isLoading || selectedTools.length === 0}
              className="flex-1"
            >
              {isLoading ? "Scan en cours..." : "Lancer le Scan"}
            </Button>
            <Button
              type="button"
              onClick={handleFullScan}
              disabled={isLoading || !target}
              variant="secondary"
              className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white"
            >
              <Rocket className="w-4 h-4 mr-2" />
              Full Scan
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
