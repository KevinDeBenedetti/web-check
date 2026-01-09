import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { quickScans, deepScans, securityScans, scans } from "./services/api";
import { ScanForm } from "./components/ScanForm";
import { ScanResult } from "./components/ScanResult";
import type { CheckResult, ScanCategory } from "./types/api";

function App() {
  const [results, setResults] = useState<CheckResult[]>([]);

  // Récupérer la liste des scans existants
  const { data: savedScans } = useQuery({
    queryKey: ["scans"],
    queryFn: scans.list,
    refetchInterval: 10000, // Refresh toutes les 10s
  });

  // Mutation pour lancer un scan
  const mutation = useMutation({
    mutationFn: async ({
      target,
      scanType,
      timeout,
    }: {
      target: string;
      scanType: ScanCategory;
      timeout: number;
    }) => {
      if (scanType === "quick") {
        return quickScans.nuclei(target, timeout);
      } else if (scanType === "deep") {
        return deepScans.fullScan(target, timeout);
      } else {
        return securityScans.zap(target, timeout);
      }
    },
    onSuccess: (data) => {
      setResults((prev) => [data, ...prev]);
    },
  });

  const handleScan = (target: string, scanType: ScanCategory, timeout: number) => {
    mutation.mutate({ target, scanType, timeout });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary-600 rounded-lg flex items-center justify-center">
              <span className="text-2xl">🛡️</span>
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Vigil</h1>
              <p className="text-sm text-gray-400">Security Scanner Dashboard</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Sidebar - Formulaire */}
          <div className="lg:col-span-1">
            <ScanForm onSubmit={handleScan} isLoading={mutation.isPending} />

            {/* Scans sauvegardés */}
            {savedScans && savedScans.length > 0 && (
              <div className="mt-6 bg-slate-800 p-6 rounded-lg shadow-lg">
                <h3 className="text-lg font-semibold text-white mb-4">Scans Récents</h3>
                <div className="space-y-2">
                  {savedScans.slice(0, 5).map((scan) => (
                    <div
                      key={scan.scan_id}
                      className="bg-slate-700 p-3 rounded hover:bg-slate-600 transition-colors cursor-pointer"
                    >
                      <p className="text-sm font-medium text-white truncate">{scan.target}</p>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-xs text-gray-400">{scan.scan_id}</span>
                        <span
                          className={`text-xs font-semibold ${
                            scan.status === "success"
                              ? "text-green-400"
                              : scan.status === "error"
                                ? "text-red-400"
                                : "text-yellow-400"
                          }`}
                        >
                          {scan.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Main Content - Résultats */}
          <div className="lg:col-span-2">
            {mutation.isPending && (
              <div className="bg-slate-800 rounded-lg shadow-lg p-8 text-center">
                <div className="inline-block animate-spin rounded-full h-12 w-12 border-4 border-primary-500 border-t-transparent mb-4"></div>
                <p className="text-white font-semibold">Scan en cours...</p>
                <p className="text-gray-400 text-sm mt-2">
                  Cela peut prendre quelques minutes selon le type de scan
                </p>
              </div>
            )}

            {mutation.isError && (
              <div className="bg-red-900/20 border border-red-700 rounded-lg p-6">
                <h3 className="text-red-400 font-semibold mb-2">Erreur lors du scan</h3>
                <p className="text-gray-300 text-sm">
                  {mutation.error instanceof Error
                    ? mutation.error.message
                    : "Une erreur est survenue"}
                </p>
              </div>
            )}

            {results.length === 0 && !mutation.isPending && (
              <div className="bg-slate-800 rounded-lg shadow-lg p-12 text-center">
                <span className="text-6xl mb-4 block">🔍</span>
                <h3 className="text-xl font-semibold text-white mb-2">Aucun résultat</h3>
                <p className="text-gray-400">
                  Lancez un scan pour commencer à analyser votre cible
                </p>
              </div>
            )}

            <div className="space-y-6">
              {results.map((result, idx) => (
                <ScanResult key={idx} result={result} />
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
