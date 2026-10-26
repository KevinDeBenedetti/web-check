import { type DependencyList, useCallback, useEffect, useRef, useState } from "react";

export interface Resource<T> {
  data: T | undefined;
  error: Error | undefined;
  /** True until the first response (or error) for the current dependencies. */
  loading: boolean;
  reload: () => void;
}

/**
 * Load data and optionally refresh it every `refreshMs` milliseconds.
 * Changing `deps` clears the previous data and loads again.
 */
export function useResource<T>(
  load: () => Promise<T>,
  deps: DependencyList,
  refreshMs?: number,
): Resource<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    setData(undefined);
    setError(undefined);
  }, deps);

  useEffect(() => {
    let cancelled = false;
    loadRef.current().then(
      (value) => {
        if (cancelled) return;
        setData(value);
        setError(undefined);
      },
      (reason: unknown) => {
        if (cancelled) return;
        setError(reason instanceof Error ? reason : new Error(String(reason)));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [...deps, tick]);

  useEffect(() => {
    if (!refreshMs) return;
    const timer = window.setInterval(() => setTick((value) => value + 1), refreshMs);
    return () => window.clearInterval(timer);
  }, [refreshMs]);

  const reload = useCallback(() => setTick((value) => value + 1), []);
  return { data, error, loading: data === undefined && error === undefined, reload };
}
