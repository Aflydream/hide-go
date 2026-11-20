import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api, ApiError } from './lib/api';
import { usePoll, useRoute, type Route } from './lib/hooks';
import type { GatewayStatus, HarnessProfile, HideConfig, TrafficSummary, VaultEntry } from './types';
import { useToast } from './components/ui';

interface Store {
  config: HideConfig | null;
  saveConfig: (next: HideConfig, successMessage?: string) => Promise<boolean>;
  saving: boolean;
  status: GatewayStatus | null;
  statusError: Error | null;
  logs: TrafficSummary[];
  logsLoading: boolean;
  refreshLogs: () => Promise<unknown>;
  harnesses: HarnessProfile[];
  refreshHarnesses: () => Promise<unknown>;
  vault: VaultEntry[];
  vaultLoading: boolean;
  refreshVault: () => Promise<unknown>;
  route: Route;
  params: URLSearchParams;
  navigate: (route: Route, params?: Record<string, string>) => void;
  openSimulator: () => void;
  simulatorOpen: boolean;
  closeSimulator: () => void;
}

const StoreContext = createContext<Store | null>(null);

export function useStore(): Store {
  const s = useContext(StoreContext);
  if (!s) throw new Error('StoreProvider missing');
  return s;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const toast = useToast();
  const { route, params, navigate } = useRoute();
  const [config, setConfig] = useState<HideConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const saveSeq = useRef(0);
  const confirmedConfigRef = useRef<HideConfig | null>(null);

  const status = usePoll(api.status, 2500);
  const logs = usePoll(api.logs, 2500);
  const harnesses = usePoll(api.harnesses, 8000);
  const needsVault = route === 'vault' || route === 'traffic';
  const vault = usePoll(api.vault, 5000, needsVault);

  // Config is loaded once and after each save; it is not polled, so edits are never overwritten.
  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api
        .config()
        .then((c) => {
          if (cancelled) return;
          confirmedConfigRef.current = c;
          setConfig(c);
        })
        .catch(() => !cancelled && window.setTimeout(load, 2000));
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const saveConfig = useCallback(
    async (next: HideConfig, successMessage = '设置已保存') => {
      const seq = ++saveSeq.current;
      setConfig(next);
      setSaving(true);
      try {
        const saved = await api.saveConfig(next);
        confirmedConfigRef.current = saved;
        if (seq === saveSeq.current) setConfig(saved);
        toast.push({ tone: 'brand', title: successMessage });
        return true;
      } catch (e) {
        if (seq === saveSeq.current) setConfig(confirmedConfigRef.current);
        toast.push({ tone: 'danger', title: '保存失败，已恢复为生效中的设置', body: (e as Error).message });
        return false;
      } finally {
        if (seq === saveSeq.current) setSaving(false);
      }
    },
    [toast],
  );

  const value = useMemo<Store>(
    () => ({
      config,
      saveConfig,
      saving,
      status: status.data,
      statusError: status.error,
      logs: logs.data ?? [],
      logsLoading: logs.loading,
      refreshLogs: logs.refresh,
      harnesses: harnesses.data ?? [],
      refreshHarnesses: harnesses.refresh,
      vault: vault.data ?? [],
      vaultLoading: vault.loading,
      refreshVault: vault.refresh,
      route,
      params,
      navigate,
      openSimulator: () => setSimulatorOpen(true),
      simulatorOpen,
      closeSimulator: () => setSimulatorOpen(false),
    }),
    [config, saveConfig, saving, status.data, status.error, logs.data, logs.loading, logs.refresh, harnesses.data, harnesses.refresh, vault.data, vault.loading, vault.refresh, route, params, navigate, simulatorOpen],
  );

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}

export function isAuthError(e: Error | null): boolean {
  return e instanceof ApiError && e.status === 401;
}
