import type { ScanRequest } from "../api/types";

/** curl command that starts the same scan, for scripts or CI. */
export function buildCurlCommand(request: ScanRequest, origin: string, authenticated = false): string {
  const body = JSON.stringify(request);
  return [
    `curl -X POST ${origin}/api/scans/start`,
    `  -H 'Content-Type: application/json'`,
    // The key itself is never written into the command: it is read from the environment.
    ...(authenticated ? [`  -H "X-API-Key: $WEB_CHECK_API_KEY"`] : []),
    `  -d '${body.replace(/'/g, "'\\''")}'`,
  ].join(" \\\n");
}
