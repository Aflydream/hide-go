import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api, ApiError } from './lib/api';
import { usePoll, useRoute, type Route } from './lib/hooks';
import { useI18n } from './lib/i18n';
import type { GatewayStatus, HarnessProfile, HideConfig, TrafficSummary, UpdateCheckResult, VaultEntry } from './types';
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
  updateInfo: UpdateCheckResult | null;
  updateError: string | null;
  checkingUpdates: boolean;
  checkForUpdates: (force?: boolean) => Promise<UpdateCheckResult | null>;
  route: Route;
  params: URLSearchParams;
  navigate: (route: Route, params?: Record<string, string>) => void;
  openSimulator: () => void;
  simulatorOpen: boolean;
  closeSimulator: () => void;
}

const StoreContext = createContext<Store | null>(null);
const EMPTY_LOGS: TrafficSummary[] = [];
const EMPTY_HARNESSES: HarnessProfile[] = [];
const EMPTY_VAULT: VaultEntry[] = [];

export function useStore(): Store {
  const s = useContext(StoreContext);
  if (!s) throw new Error('StoreProvider missing');
  return s;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const toast = useToast();
  const { syncPrefFromConfig, t } = useI18n();
  const { route, params, navigate } = useRoute();
  const [config, setConfig] = useState<HideConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<UpdateCheckResult | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const saveSeq = useRef(0);
  const confirmedConfigRef = useRef<HideConfig | null>(null);
  const syncedLangRef = useRef(false);
  const autoCheckDoneRef = useRef(false);

  const openSimulator = useCallback(() => setSimulatorOpen(true), []);
  const closeSimulator = useCallback(() => setSimulatorOpen(false), []);

  const checkForUpdates = useCallback(
    async (force = false) => {
      setCheckingUpdates(true);
      setUpdateError(null);
      try {
        const res = await api.checkUpdates(force);
        setUpdateInfo(res);
        if (force) {
          toast.push({
            tone: 'brand',
            title: res.updateAvailable
              ? t('settings.updatesToastAvailable', { version: res.latestVersion })
              : t('settings.updatesToastLatest', { version: res.currentVersion }),
          });
        }
        return res;
      } catch (e) {
        const msg = (e as Error).message;
        setUpdateError(msg);
        if (force) {
          toast.push({
            tone: 'danger',
            title: t('settings.updatesToastFailed'),
            body: msg,
          });
        }
        return null;
      } finally {
        setCheckingUpdates(false);
      }
    },
    [toast, t],
  );

  const status = usePoll(api.status, 2500);
  const logs = usePoll(api.logs, 2500);
  const harnesses = usePoll(api.harnesses, 8000);
  const needsVault = route === 'vault' || route === 'traffic';
  const vault = usePoll(api.vault, 5000, needsVault);

  // Config is loaded once and after each save; it is not polled, so edits are never overwritten.
  useEffect(() => {
    let cancelled = false;
    let timerId: number | undefined;
    const load = () =>
      api
        .config()
        .then((c) => {
          if (cancelled) return;
          confirmedConfigRef.current = c;
          if (!syncedLangRef.current) {
            syncedLangRef.current = true;
            syncPrefFromConfig(c.language);
          }
          setConfig(c);
        })
        .catch(() => {
          if (!cancelled) {
            timerId = window.setTimeout(load, 2000);
          }
        });
    load();
    return () => {
      cancelled = true;
      if (timerId !== undefined) window.clearTimeout(timerId);
    };
  }, [syncPrefFromConfig]);

  useEffect(() => {
    if (config && !autoCheckDoneRef.current && config.autoCheckUpdates !== false) {
      autoCheckDoneRef.current = true;
      void checkForUpdates(false);
    }
  }, [config, checkForUpdates]);

  const saveConfig = useCallback(
    async (next: HideConfig, successMessage?: string) => {
      const seq = ++saveSeq.current;
      setConfig(next);
      setSaving(true);
      try {
        const saved = await api.saveConfig(next);
        confirmedConfigRef.current = saved;
        if (seq === saveSeq.current) setConfig(saved);
        toast.push({ tone: 'brand', title: successMessage ?? t('store.saved') });
        return true;
      } catch (e) {
        if (seq === saveSeq.current) setConfig(confirmedConfigRef.current);
        toast.push({
          tone: 'danger',
          title: t('store.saveFailed'),
          body: (e as Error).message,
        });
        return false;
      } finally {
        if (seq === saveSeq.current) setSaving(false);
      }
    },
    [toast, t],
  );

  const value = useMemo<Store>(
    () => ({
      config,
      saveConfig,
      saving,
      status: status.data,
      statusError: status.error,
      logs: logs.data ?? EMPTY_LOGS,
      logsLoading: logs.loading,
      refreshLogs: logs.refresh,
      harnesses: harnesses.data ?? EMPTY_HARNESSES,
      refreshHarnesses: harnesses.refresh,
      vault: vault.data ?? EMPTY_VAULT,
      vaultLoading: vault.loading,
      refreshVault: vault.refresh,
      updateInfo,
      updateError,
      checkingUpdates,
      checkForUpdates,
      route,
      params,
      navigate,
      openSimulator,
      simulatorOpen,
      closeSimulator,
    }),
    [config, saveConfig, saving, status.data, status.error, logs.data, logs.loading, logs.refresh, harnesses.data, harnesses.refresh, vault.data, vault.loading, vault.refresh, updateInfo, updateError, checkingUpdates, checkForUpdates, route, params, navigate, openSimulator, simulatorOpen, closeSimulator],
  );

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}

export function isAuthError(e: Error | null): boolean {
  return e instanceof ApiError && e.status === 401;
}
