import { useCallback, useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';

/**
 * Poll an async source. Pauses while the window is hidden, never overlaps requests and
 * keeps the last good value when a refresh fails.
 */
export function usePoll<T>(fetcher: () => Promise<T>, intervalMs: number, enabled = true) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const inFlight = useRef<Promise<T> | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const refresh = useCallback(async () => {
    if (inFlight.current) return inFlight.current;
    const p = (async () => {
      try {
        const next = await fetcherRef.current();
        setData(next);
        setError(null);
        return next;
      } catch (e) {
        setError(e as Error);
        throw e;
      } finally {
        inFlight.current = null;
        setLoading(false);
      }
    })();
    inFlight.current = p;
    return p;
  }, []);

  useEffect(() => {
    if (!enabled) return;
    refresh().catch(() => {});
    const tick = () => {
      if (!document.hidden) refresh().catch(() => {});
    };
    const timer = window.setInterval(tick, intervalMs);
    const onVisible = () => {
      if (!document.hidden) refresh().catch(() => {});
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [enabled, intervalMs, refresh]);

  return { data, error, loading, refresh, setData };
}

export type Route = 'overview' | 'traffic' | 'policy' | 'integrations' | 'vault' | 'rules';
const ROUTES: Route[] = ['overview', 'traffic', 'policy', 'integrations', 'vault', 'rules'];

/** Hash routing: `#/traffic?id=…`. Survives reloads, needs no server routes. */
export function useRoute() {
  const parse = () => {
    const [path, query = ''] = window.location.hash.replace(/^#\/?/, '').split('?');
    const route = (ROUTES.includes(path as Route) ? path : 'overview') as Route;
    return { route, params: new URLSearchParams(query) };
  };
  const [state, setState] = useState(parse);
  const routeRef = useRef(state.route);
  routeRef.current = state.route;

  useEffect(() => {
    const onHash = () => {
      const next = parse();
      const routeChanged = next.route !== routeRef.current;
      const focusHeading = () => document.getElementById('view-title')?.focus({ preventScroll: true });

      if (!routeChanged || typeof document.startViewTransition !== 'function') {
        setState(next);
        if (routeChanged) queueMicrotask(focusHeading);
        return;
      }

      const transition = document.startViewTransition(() => {
        flushSync(() => setState(next));
      });
      transition.finished.finally(focusHeading);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const navigate = useCallback((route: Route, params?: Record<string, string>) => {
    const q = params ? `?${new URLSearchParams(params).toString()}` : '';
    window.location.hash = `/${route}${q}`;
  }, []);
  return { ...state, navigate };
}

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}
