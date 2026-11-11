/**
 * Incremental parser for a `text/event-stream` body read through `fetch`.
 *
 * `EventSource` cannot send the API key header, so the log stream is read with
 * `fetch` instead. Only the `data:` field is used (the API sends one JSON object
 * per event); comment lines such as `: keepalive` are ignored.
 */
export interface SseParser {
  /** Feed a decoded chunk; complete events are delivered to `onData` in order. */
  push(chunk: string): void;
  /** Deliver a trailing event that was not terminated by a blank line. */
  end(): void;
}

export function createSseParser(onData: (data: string) => void): SseParser {
  let buffer = "";

  const dispatch = (raw: string) => {
    const data = raw
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).replace(/^ /, ""))
      .join("\n");
    if (data) onData(data);
  };

  return {
    push(chunk) {
      buffer += chunk.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      let end = buffer.indexOf("\n\n");
      while (end !== -1) {
        dispatch(buffer.slice(0, end));
        buffer = buffer.slice(end + 2);
        end = buffer.indexOf("\n\n");
      }
    },
    end() {
      if (buffer.trim()) dispatch(buffer);
      buffer = "";
    },
  };
}
