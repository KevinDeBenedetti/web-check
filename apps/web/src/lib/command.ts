import type { ScanRequest } from "../api/types";

/** curl command that starts the same scan, for scripts or CI. */
export function buildCurlCommand(request: ScanRequest, origin: string): string {
  const body = JSON.stringify(request);
  return [
    `curl -X POST ${origin}/api/scans/start`,
    `  -H 'Content-Type: application/json'`,
    `  -d '${body.replace(/'/g, "'\\''")}'`,
  ].join(" \\\n");
}
