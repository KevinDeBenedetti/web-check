import { useCallback, useEffect, useState } from "react";
import { authHeaders, logsUrl } from "../api/client";
import type { LogEntry } from "../api/types";
import { createSseParser } from "../lib/sse";

export type StreamState = "connecting" | "open" | "complete" | "closed";

/**
 * Follow the SSE log stream of a scan. The API replays past entries on connect,
 * so reconnecting starts from a clean list. Read with fetch rather than
 * EventSource, which cannot send the API key header.
 */
export function useScanLogs(scanId: string | undefined, enabled: boolean) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [state, setState] = useState<StreamState>("connecting");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!scanId || !enabled) return;
    setEntries([]);
    setState("connecting");

    const controller = new AbortController();
    let complete = false;
    const parser = createSseParser((data) => {
      let entry: LogEntry;
      try {
        entry = JSON.parse(data) as LogEntry;
      } catch {
        return;
      }
      if (entry.type === "connected") return;
      setEntries((previous) => [...previous, entry]);
      if (entry.type === "complete") {
        complete = true;
        setState("complete");
        controller.abort();
      }
    });

    (async () => {
      const response = await fetch(logsUrl(scanId), {
        headers: { Accept: "text/event-stream", ...authHeaders() },
        signal: controller.signal,
      });
      if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);
      setState("open");
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        parser.push(value);
      }
      parser.end();
    })().then(
      () => {
        if (!complete) setState("closed");
      },
      () => {
        // Aborted on completion or unmount; any other failure is a lost connection.
        if (!complete && !controller.signal.aborted) setState("closed");
      },
    );

    return () => controller.abort();
  }, [scanId, enabled, attempt]);

  const reconnect = useCallback(() => setAttempt((value) => value + 1), []);
  return { entries, state, reconnect };
}
