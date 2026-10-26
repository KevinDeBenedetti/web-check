import { useCallback, useEffect, useState } from "react";
import { logsUrl } from "../api/client";
import type { LogEntry } from "../api/types";

export type StreamState = "connecting" | "open" | "complete" | "closed";

/**
 * Follow the SSE log stream of a scan. The API replays past entries on connect,
 * so reconnecting starts from a clean list.
 */
export function useScanLogs(scanId: string | undefined, enabled: boolean) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [state, setState] = useState<StreamState>("connecting");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!scanId || !enabled) return;
    setEntries([]);
    setState("connecting");

    const source = new EventSource(logsUrl(scanId));
    source.onopen = () => setState("open");
    source.onmessage = (event: MessageEvent<string>) => {
      let entry: LogEntry;
      try {
        entry = JSON.parse(event.data) as LogEntry;
      } catch {
        return;
      }
      if (entry.type === "connected") return;
      setEntries((previous) => [...previous, entry]);
      if (entry.type === "complete") {
        source.close();
        setState("complete");
      }
    };
    source.onerror = () => {
      // Don't let EventSource reconnect on its own: the replay would duplicate entries.
      source.close();
      setState((previous) => (previous === "complete" ? previous : "closed"));
    };
    return () => source.close();
  }, [scanId, enabled, attempt]);

  const reconnect = useCallback(() => setAttempt((value) => value + 1), []);
  return { entries, state, reconnect };
}
