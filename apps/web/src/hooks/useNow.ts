import { useEffect, useState } from "react";

/** Current time, refreshed every `intervalMs` while `active` is true. */
export function useNow(intervalMs: number, active = true): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNow(new Date()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs, active]);
  return now;
}
