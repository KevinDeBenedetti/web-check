import { useState } from "react";
import type { ScanCategory } from "../types/api";

interface ScanFormProps {
  onSubmit: (target: string, scanType: ScanCategory, timeout: number) => void;
  isLoading: boolean;
}

export function ScanForm({ onSubmit, isLoading }: ScanFormProps) {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState<ScanCategory>("quick");
  const [timeout, setTimeout] = useState(300);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (target) {
      onSubmit(target, scanType, timeout);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-slate-800 p-6 rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold text-white mb-6">Nouveau Scan</h2>

      <div className="space-y-4">
        <div>
          <label htmlFor="target" className="block text-sm font-medium text-gray-300 mb-2">
            URL Cible
          </label>
          <input
            type="url"
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            required
            className="w-full px-4 py-2 bg-slate-700 text-white rounded border border-slate-600 focus:border-primary-500 focus:outline-none"
          />
        </div>

        <div>
          <label htmlFor="scanType" className="block text-sm font-medium text-gray-300 mb-2">
            Type de Scan
          </label>
          <select
            id="scanType"
            value={scanType}
            onChange={(e) => setScanType(e.target.value as ScanCategory)}
            className="w-full px-4 py-2 bg-slate-700 text-white rounded border border-slate-600 focus:border-primary-500 focus:outline-none"
          >
            <option value="quick">Rapide (Nuclei)</option>
            <option value="deep">Approfondi (Nikto)</option>
            <option value="security">Sécurité (ZAP)</option>
          </select>
        </div>

        <div>
          <label htmlFor="timeout" className="block text-sm font-medium text-gray-300 mb-2">
            Timeout (secondes)
          </label>
          <input
            type="number"
            id="timeout"
            value={timeout}
            onChange={(e) => setTimeout(Number(e.target.value))}
            min="30"
            max="1200"
            className="w-full px-4 py-2 bg-slate-700 text-white rounded border border-slate-600 focus:border-primary-500 focus:outline-none"
          />
        </div>

        <button
          type="submit"
          disabled={isLoading}
          className="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-slate-600 text-white font-semibold py-3 px-4 rounded transition-colors"
        >
          {isLoading ? "Scan en cours..." : "Lancer le Scan"}
        </button>
      </div>
    </form>
  );
}
