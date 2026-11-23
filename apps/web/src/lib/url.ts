/** True for an absolute http(s) URL with a host: the only kind rendered as a link or scanned. */
export function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.hostname);
  } catch {
    return false;
  }
}

/** File name of a `Content-Disposition: attachment; filename="…"` header, or null. */
export function filenameFromDisposition(header: string | null): string | null {
  const match = header?.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
  if (!match?.[1]) return null;
  // The value names a download: keep a plain file name only.
  let decoded = match[1];
  try {
    decoded = decodeURIComponent(decoded);
  } catch {
    // Not percent-encoded after all: keep the raw value.
  }
  const name = decoded.replace(/[/\\]/g, "").trim();
  return name || null;
}
