import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield, Loader2 } from "lucide-react";
import { scans } from "./services/api";
import { ScanForm } from "./components/ScanForm";
import { ScanResult } from "./components/ScanResult";
import { ScanStats } from "./components/ScanStats";
import { ScanLogStream } from "./components/ScanLogStream";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { CheckResult, ScanTool } from "./types/api";

function App() {
  const [results, setResults] = useState<CheckResult[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [isLoadingScan, setIsLoadingScan] = useState(false);
  const queryClient = useQueryClient();

  // Récupérer la liste des scans existants
  const {
    data: savedScans,
    isLoading: isLoadingScans,
    error: scansError,
    isSuccess,
  } = useQuery({
    queryKey: ["scans"],
    queryFn: async () => {
      console.log("Fetching scans...");
      const result = await scans.list();
      console.log("Scans fetched:", result);
      return result;
    },
    refetchInterval: 10000, // Refresh toutes les 10s
  });

  // Debug logs
  console.log("Query state:", {
    data: savedScans,
    isLoading: isLoadingScans,
    error: scansError,
    isSuccess,
    dataLength: savedScans?.length,
  });

  // Mutation pour démarrer un scan complet avec logs streaming
  const startFullScan = useMutation({
    mutationFn: async ({
      target,
      tools,
      timeout,
    }: {
      target: string;
      tools: ScanTool[];
      timeout: number;
    }) => {
      return scans.start({ target, modules: tools, timeout });
    },
    onSuccess: (data) => {
      setActiveScanId(data.scan_id);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const handleScan = (target: string, tools: ScanTool[], timeout: number) => {
    // Réinitialiser l'état lors d'un nouveau scan
    setSelectedScanId(null);
    setResults([]);
    // Utiliser la nouvelle API avec streaming de logs
    startFullScan.mutate({ target, tools, timeout });
  };

  const handleScanComplete = () => {
    // Rafraîchir les scans et récupérer les résultats
    queryClient.invalidateQueries({ queryKey: ["scans"] });
    if (activeScanId) {
      scans.get(activeScanId).then((scan) => {
        setResults(scan.results);
        setSelectedScanId(activeScanId); // Marquer ce scan comme sélectionné
        setActiveScanId(null);
      });
    }
  };

  const handleScanClick = async (scanId: string) => {
    // Si on clique sur le même scan, ne rien faire
    if (selectedScanId === scanId && results.length > 0) {
      return;
    }

    setIsLoadingScan(true);
    setSelectedScanId(scanId);
    setResults([]); // Réinitialiser les résultats avant de charger

    try {
      const scan = await scans.get(scanId);
      setResults(scan.results);
    } catch (error) {
      console.error("Failed to load scan:", error);
      setResults([]);
    } finally {
      setIsLoadingScan(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "success":
        return "text-green-400";
      case "error":
        return "text-red-400";
      default:
        return "text-yellow-400";
    }
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-800/50 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">Vigil</h1>
              <p className="text-sm text-muted-foreground">Security Scanner Dashboard</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Sidebar - Formulaire */}
          <div className="lg:col-span-1 space-y-6">
            <ScanForm onSubmit={handleScan} isLoading={startFullScan.isPending} />

            {/* Scans sauvegardés */}
            {isLoadingScans && (
              <Card className="border-slate-700">
                <CardContent className="pt-6">
                  <p className="text-sm text-muted-foreground">Chargement des scans...</p>
                </CardContent>
              </Card>
            )}

            {scansError && (
              <Card className="border-destructive bg-destructive/10">
                <CardContent className="pt-6">
                  <p className="text-sm text-destructive">
                    Erreur:{" "}
                    {scansError instanceof Error
                      ? scansError.message
                      : "Impossible de charger les scans"}
                  </p>
                </CardContent>
              </Card>
            )}

            {!isLoadingScans && !scansError && savedScans && savedScans.length === 0 && (
              <Card className="border-slate-700">
                <CardContent className="pt-6">
                  <p className="text-sm text-muted-foreground">Aucun scan disponible</p>
                </CardContent>
              </Card>
            )}

            {savedScans && savedScans.length > 0 && (
              <Card className="border-slate-700">
                <CardContent className="pt-6">
                  <h3 className="text-lg font-semibold mb-4">
                    Scans Récents ({savedScans.length})
                  </h3>
                  <div className="space-y-2">
                    {savedScans.slice(0, 5).map((scan) => (
                      <div
                        key={scan.scan_id}
                        onClick={() => handleScanClick(scan.scan_id)}
                        className={cn(
                          "bg-slate-700/50 p-3 rounded-lg hover:bg-slate-700 transition-colors cursor-pointer border",
                          selectedScanId === scan.scan_id
                            ? "border-primary ring-2 ring-primary/50"
                            : "border-slate-600"
                        )}
                      >
                        <p className="text-sm font-medium truncate">{scan.target}</p>
                        <div className="flex items-center justify-between mt-1">
                          <span className="text-xs text-muted-foreground font-mono">
                            {scan.scan_id}
                          </span>
                          <Badge
                            variant="secondary"
                            className={cn("text-xs", getStatusColor(scan.status))}
                          >
                            {scan.status}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Main Content - Résultats */}
          <div className="lg:col-span-2">
            {/* Logs en temps réel */}
            {activeScanId && (
              <div className="mb-6">
                <ScanLogStream scanId={activeScanId} onComplete={handleScanComplete} />
              </div>
            )}

            {/* Statistiques */}
            {results.length > 0 && <ScanStats results={results} />}

            {startFullScan.isPending && !activeScanId && (
              <Card className="border-slate-700">
                <CardContent className="p-8 text-center">
                  <Loader2 className="w-12 h-12 animate-spin mx-auto mb-4 text-primary" />
                  <p className="font-semibold">Démarrage du scan...</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Connexion aux services de scanning
                  </p>
                </CardContent>
              </Card>
            )}

            {isLoadingScan && (
              <Card className="border-slate-700">
                <CardContent className="p-8 text-center">
                  <Loader2 className="w-12 h-12 animate-spin mx-auto mb-4 text-primary" />
                  <p className="font-semibold">Chargement des résultats...</p>
                </CardContent>
              </Card>
            )}

            {startFullScan.isError && (
              <Card className="border-destructive bg-destructive/10">
                <CardContent className="p-6">
                  <h3 className="text-destructive font-semibold mb-2">Erreur lors du scan</h3>
                  <p className="text-sm text-muted-foreground">
                    {startFullScan.error instanceof Error
                      ? startFullScan.error.message
                      : "Une erreur est survenue"}
                  </p>
                </CardContent>
              </Card>
            )}

            {/* Résultats des scans */}
            {results.length > 0 && (
              <div className="space-y-6">
                {/* En-tête des résultats */}
                {selectedScanId && (
                  <div className="flex items-center justify-between mb-2">
                    <h2 className="text-xl font-semibold">Résultats du scan</h2>
                    <Badge variant="outline" className="font-mono">
                      {selectedScanId}
                    </Badge>
                  </div>
                )}
                {results.map((result, idx) => (
                  <ScanResult key={`${selectedScanId || activeScanId}-${idx}`} result={result} />
                ))}
              </div>
            )}

            {/* Message "Aucun résultat" uniquement si vraiment rien n'est en cours */}
            {results.length === 0 &&
              !startFullScan.isPending &&
              !activeScanId &&
              !isLoadingScan &&
              !selectedScanId && (
                <Card className="border-slate-700">
                  <CardContent className="p-12 text-center">
                    <span className="text-6xl mb-4 block">🔍</span>
                    <h3 className="text-xl font-semibold mb-2">Aucun résultat</h3>
                    <p className="text-muted-foreground">
                      Lancez un scan pour commencer à analyser votre cible
                    </p>
                  </CardContent>
                </Card>
              )}

            {/* Message si scan sélectionné mais aucun résultat */}
            {results.length === 0 && selectedScanId && !isLoadingScan && !activeScanId && (
              <Card className="border-slate-700">
                <CardContent className="p-12 text-center">
                  <span className="text-6xl mb-4 block">📭</span>
                  <h3 className="text-xl font-semibold mb-2">Aucun résultat pour ce scan</h3>
                  <p className="text-muted-foreground">
                    Ce scan n'a généré aucun résultat ou est peut-être en cours d'exécution.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
