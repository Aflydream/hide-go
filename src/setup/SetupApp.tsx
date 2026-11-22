import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import {
  ArrowRight,
  Check,
  CheckCircle,
  FolderOpen,
  LinkSimple,
  Translate,
  Trash,
  WarningCircle,
} from '@phosphor-icons/react';
import { WindowFrame } from '../components/WindowFrame';
import logoMark from '../assets/logo-mark.png';
import { getHarnessLabel } from '../lib/format';
import {
  LOCALE_META,
  SUPPORTED_LOCALES,
  localizeHarnessIntegrationNote,
  localizeSetupStepDetail,
  localizeSetupStepLabel,
  translate,
  useI18n,
  type Locale,
} from '../lib/i18n';
import type { HarnessActionResult, HarnessKind, HarnessProfile, UiLanguage } from '../types';

declare global {
  interface Window {
    __HIDE_GO_SETUP_TOKEN__?: string;
  }
}

interface SetupStepStatus {
  id: string;
  label: string;
  state: 'pending' | 'running' | 'done' | 'error';
  detail?: string | null;
}

interface SetupInfo {
  mode: 'install' | 'uninstall';
  version: string;
  platform: 'windows' | 'macos' | 'linux';
  systemLocale?: string;
  language?: UiLanguage;
  hasInstallPayload: boolean;
  defaultInstallDir: string;
  alreadyInstalled: boolean;
  existingInstallDir: string | null;
  defaultProxyPort: number;
  configPath: string | null;
  harnesses: HarnessProfile[];
}

interface InstallResponse {
  ok: boolean;
  installDir: string;
  desktopBinary: string;
  daemonBinary: string;
  uninstallerBinary: string;
  shortcutsCreated: string[];
  pathUpdated: boolean;
  autostartEnabled: boolean;
  harnesses: HarnessProfile[];
  steps: SetupStepStatus[];
  error?: string | null;
}

interface UninstallResponse {
  ok: boolean;
  removedPaths: string[];
  disconnectedHarnesses: HarnessActionResult[];
  steps: SetupStepStatus[];
  error?: string | null;
}

function takeSetupToken(): string {
  const injected = window.__HIDE_GO_SETUP_TOKEN__ ?? '';
  if (window.__HIDE_GO_SETUP_TOKEN__ !== undefined) {
    delete window.__HIDE_GO_SETUP_TOKEN__;
  }
  return injected;
}

const setupToken = takeSetupToken();

function getInstallDirError(rawDir: string, platform: string | undefined, locale: Locale): string | null {
  const trimmed = rawDir.trim();
  if (!trimmed) return translate(locale, 'setup.dirError.empty');
  const norm = trimmed.replace(/[\\/]+$/, '') || (trimmed.startsWith('/') ? '/' : trimmed);
  const low = (platform === 'windows' || /^[a-zA-Z]:/.test(norm)) ? norm.toLowerCase().replace(/\//g, '\\') : norm;

  if (low === '/' || /^[a-z]:$/i.test(low)) {
    return translate(locale, 'setup.dirError.root');
  }
  if (/^[a-z]:\\windows(\\|$)/i.test(low)) {
    return translate(locale, 'setup.dirError.windowsSys');
  }
  if (
    /^[a-z]:\\(users\\[^\\]+(|\\desktop|\\documents|\\downloads)|program files( \(x86\))?|programdata)$/i.test(low) ||
    /^\/(applications|users|home|tmp|var|etc|usr|usr\/local|bin|sbin|system|library)$/i.test(low) ||
    /^\/(users|home)\/[^/]+(\/(desktop|documents|downloads))?$/i.test(low)
  ) {
    return translate(locale, 'setup.dirError.protected');
  }
  return null;
}

async function setupFetch<T>(url: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (setupToken) headers.set('X-Hide-Go-Setup-Token', setupToken);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const res = await fetch(url, { ...init, headers, credentials: 'omit', cache: 'no-store' });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      msg = body.message ?? body.error ?? msg;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return (await res.json()) as T;
}

function ToggleRow({
  title,
  desc,
  checked,
  onChange,
  disabled,
}: {
  title: string;
  desc: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  const switchId = useId();
  const titleId = useId();
  const descId = useId();
  return (
    <div className="flex items-center justify-between gap-4 py-3.5">
      <label htmlFor={switchId} className="min-w-0 flex-1 cursor-pointer select-none">
        <p id={titleId} className="text-sm font-medium text-fg">
          {title}
        </p>
        <p id={descId} className="mt-0.5 text-xs leading-5 text-fg-muted">
          {desc}
        </p>
      </label>
      <button
        id={switchId}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-labelledby={titleId}
        aria-describedby={descId}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 ${
          checked ? 'border-brand-solid bg-brand-solid' : 'border-line-control bg-surface-3'
        } ${disabled ? 'cursor-not-allowed opacity-50' : ''}`}
      >
        <span
          aria-hidden="true"
          className={`inline-block h-3.5 w-3.5 transform rounded-full shadow-sm transition-transform ${
            checked ? 'translate-x-[17px] bg-brand-on' : 'translate-x-[2px] bg-fg-muted'
          }`}
        />
      </button>
    </div>
  );
}

const STEP_NUMS: Array<{ num: string; key: 'setup.stepRail.1' | 'setup.stepRail.2' | 'setup.stepRail.3' | 'setup.stepRail.4' }> = [
  { num: '01', key: 'setup.stepRail.1' },
  { num: '02', key: 'setup.stepRail.2' },
  { num: '03', key: 'setup.stepRail.3' },
  { num: '04', key: 'setup.stepRail.4' },
];

export function SetupApp() {
  const { pref, locale, systemLocale, setPref, syncPrefFromConfig, t } = useI18n();
  const [info, setInfo] = useState<SetupInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const stepHeadingRef = useRef<HTMLHeadingElement>(null);
  const userChangedLangRef = useRef(false);

  const [installDir, setInstallDir] = useState('');
  const [createDesktopShortcut, setCreateDesktopShortcut] = useState(true);
  const [createStartMenuShortcut, setCreateStartMenuShortcut] = useState(true);
  const [addToPath, setAddToPath] = useState(true);
  const [autostartDaemon, setAutostartDaemon] = useState(false);

  const [busy, setBusy] = useState(false);
  const [pickingDir, setPickingDir] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [installRes, setInstallRes] = useState<InstallResponse | null>(null);
  const [selectedKinds, setSelectedKinds] = useState<HarnessKind[]>([]);
  const [connectResults, setConnectResults] = useState<HarnessActionResult[] | null>(null);
  const [launched, setLaunched] = useState(false);

  const [removeConfig, setRemoveConfig] = useState(false);
  const [uninstallRes, setUninstallRes] = useState<UninstallResponse | null>(null);

  useEffect(() => {
    document.title = t(info?.mode === 'uninstall' ? 'setup.windowTitle.uninstall' : 'setup.windowTitle.install');
  }, [info?.mode, t]);

  const transitionStep = useCallback((next: 1 | 2 | 3 | 4) => {
    const focusHeading = () => stepHeadingRef.current?.focus({ preventScroll: true });
    if (typeof document.startViewTransition !== 'function') {
      setStep(next);
      queueMicrotask(focusHeading);
      return;
    }
    const transition = document.startViewTransition(() => {
      flushSync(() => setStep(next));
    });
    transition.finished.finally(focusHeading);
  }, []);

  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const loadInfo = useCallback(async () => {
    try {
      const data = await setupFetch<SetupInfo>('/api/setup/info');
      if (!mountedRef.current) return;
      if (!userChangedLangRef.current && data.language) {
        syncPrefFromConfig(data.language);
      }
      setInfo(data);
      setInstallDir((prev) => prev || data.existingInstallDir || data.defaultInstallDir);
      const autoSelectable = data.harnesses
        .filter((h) => h.installed && h.autoConnectMode !== 'manual')
        .map((h) => h.kind);
      setSelectedKinds(autoSelectable);
    } catch (e) {
      if (mountedRef.current) setLoadError((e as Error).message);
    }
  }, [syncPrefFromConfig]);

  useEffect(() => {
    loadInfo();
  }, [loadInfo]);

  const activeHarnesses = useMemo(() => installRes?.harnesses ?? info?.harnesses ?? [], [installRes, info]);
  const autoConnectableKinds = useMemo(
    () => activeHarnesses.filter((h) => h.autoConnectMode !== 'manual').map((h) => h.kind),
    [activeHarnesses],
  );
  const selectedSet = useMemo(() => new Set(selectedKinds), [selectedKinds]);
  const allAutoSelected =
    autoConnectableKinds.length > 0 && autoConnectableKinds.every((k) => selectedSet.has(k));

  const pickInstallDir = async () => {
    if (pickingDir || busy) return;
    setPickingDir(true);
    setActionError(null);
    try {
      const res = await setupFetch<{ path: string | null }>('/api/setup/pick-dir', {
        method: 'POST',
        body: JSON.stringify({ initialDir: installDir || null, locale }),
      });
      if (res.path) setInstallDir(res.path);
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setPickingDir(false);
    }
  };

  const installDirError = installDir.trim() ? getInstallDirError(installDir, info?.platform, locale) : null;

  const startInstall = async () => {
    const dirErr = getInstallDirError(installDir, info?.platform, locale);
    if (dirErr) {
      setActionError(dirErr);
      return;
    }
    setBusy(true);
    setActionError(null);
    setInstallRes(null);
    transitionStep(2);
    try {
      const res = await setupFetch<InstallResponse>('/api/setup/install', {
        method: 'POST',
        body: JSON.stringify({
          installDir,
          createShortcuts: createDesktopShortcut || createStartMenuShortcut,
          createDesktopShortcut: info?.platform !== 'macos' && createDesktopShortcut,
          createStartMenuShortcut,
          addToPath: info?.platform !== 'windows' && addToPath,
          autostartDaemon,
          language: pref,
        }),
      });
      setInstallRes(res);
      if (!res.ok) {
        setActionError(res.error ?? t('setup.installFailed'));
      } else {
        const autoSelectable = res.harnesses
          .filter((h) => h.installed && h.autoConnectMode !== 'manual')
          .map((h) => h.kind);
        setSelectedKinds(autoSelectable);
        transitionStep(3);
      }
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const applyHarnesses = async (skip = false) => {
    setBusy(true);
    setActionError(null);
    try {
      if (!skip && selectedKinds.length > 0) {
        const res = await setupFetch<HarnessActionResult[]>('/api/setup/connect-harnesses', {
          method: 'POST',
          body: JSON.stringify({ kinds: selectedKinds }),
        });
        setConnectResults(res);
      } else {
        setConnectResults([]);
      }
      transitionStep(4);
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const closeSetup = async () => {
    await setupFetch('/api/setup/quit', { method: 'POST', body: '{}' }).catch(() => null);
    window.__hideGoWin?.close();
    window.close();
  };

  const launchDesktop = async () => {
    setBusy(true);
    setActionError(null);
    try {
      await setupFetch('/api/setup/launch', {
        method: 'POST',
        body: JSON.stringify({ installDir: installRes?.installDir ?? installDir }),
      });
      setLaunched(true);
      window.setTimeout(() => {
        window.__hideGoWin?.close();
      }, 450);
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const runUninstall = async () => {
    setBusy(true);
    setActionError(null);
    try {
      const res = await setupFetch<UninstallResponse>('/api/setup/uninstall', {
        method: 'POST',
        body: JSON.stringify({
          installDir: info?.existingInstallDir ?? null,
          removeConfig,
        }),
      });
      setUninstallRes(res);
      if (!res.ok) setActionError(res.error ?? t('setup.uninstallFailed'));
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const frameTitle = t(info?.mode === 'uninstall' ? 'setup.frameTitle.uninstall' : 'setup.frameTitle.install');
  const frameBadge = info ? `v${info.version}` : undefined;

  const headerSlot = (
    <div className="inline-flex h-7 items-center gap-1 rounded px-1.5 text-2xs text-fg-muted transition-colors hover:bg-surface-3 hover:text-fg">
      <Translate aria-hidden="true" size={13} className="shrink-0" />
      <select
        aria-label={t('setup.langAria')}
        value={pref}
        onChange={(e) => {
          userChangedLangRef.current = true;
          setPref(e.target.value as UiLanguage);
        }}
        className="cursor-pointer bg-transparent text-2xs font-medium text-fg focus:outline-none"
      >
        <option value="system" className="bg-surface text-fg">
          {t('setup.langAuto', { lang: LOCALE_META[systemLocale].nativeName })}
        </option>
        {SUPPORTED_LOCALES.map((loc) => (
          <option key={loc.code} value={loc.code} className="bg-surface text-fg">
            {loc.nativeName}
          </option>
        ))}
      </select>
    </div>
  );

  if (loadError) {
    return (
      <WindowFrame title={frameTitle} headerSlot={headerSlot} resizable={false} minWidthClass="min-w-[760px]">
        <div className="flex flex-1 items-center justify-center p-8">
          <div role="alert" className="w-full max-w-md rounded-md border border-danger/40 bg-surface p-6">
            <p className="text-sm font-semibold text-danger">{t('setup.cannotConnectTitle')}</p>
            <p className="mt-2 text-xs text-fg-muted">{loadError}</p>
          </div>
        </div>
      </WindowFrame>
    );
  }

  if (!info) {
    return (
      <WindowFrame title={frameTitle} headerSlot={headerSlot} resizable={false} minWidthClass="min-w-[760px]">
        <div className="flex flex-1 items-center justify-center text-sm text-fg-muted">{t('common.initializing')}</div>
      </WindowFrame>
    );
  }

  if (info.mode === 'uninstall') {
    return (
      <WindowFrame title={frameTitle} badge={frameBadge} headerSlot={headerSlot} resizable={false} minWidthClass="min-w-[760px]">
        <main className="mx-auto flex min-h-0 w-full max-w-2xl flex-1 flex-col justify-between bg-surface p-8">
          <div className="min-h-0 flex-1 space-y-5 overflow-y-auto pr-1">
            <header className="flex items-center justify-between border-b border-line pb-5">
              <div className="flex items-center gap-3">
                <img src={logoMark} alt="" className="h-8 w-8 shrink-0" />
                <div>
                  <div className="flex items-baseline gap-2">
                    <h1 className="text-lg font-semibold text-fg">{t('setup.uninstallHeading')}</h1>
                    <span className="font-mono text-xs text-fg-subtle">v{info.version}</span>
                  </div>
                  <p className="mt-0.5 text-xs text-fg-muted">{t('setup.uninstallSubtitle')}</p>
                </div>
              </div>
              <Trash aria-hidden="true" size={20} className="text-danger" />
            </header>

            {!uninstallRes ? (
              <div className="divide-y divide-line border-b border-line">
                {info.existingInstallDir && (
                  <div className="flex items-center justify-between gap-4 py-3 text-xs">
                    <span className="text-fg-subtle">{t('setup.installDirLabel')}</span>
                    <code className="truncate font-mono text-fg" title={info.existingInstallDir}>
                      {info.existingInstallDir}
                    </code>
                  </div>
                )}
                <ToggleRow
                  title={t('setup.removeConfigTitle')}
                  desc={
                    info.configPath
                      ? t('setup.removeConfigDescWithPath', { path: info.configPath })
                      : t('setup.removeConfigDescGeneric')
                  }
                  checked={removeConfig}
                  onChange={setRemoveConfig}
                />
              </div>
            ) : (
              <div className="divide-y divide-line border-y border-line">
                {uninstallRes.steps.map((s) => (
                  <div key={s.id} className="flex items-center justify-between gap-4 py-3 text-xs">
                    <span className="inline-flex items-center gap-2 font-medium text-fg">
                      {s.state === 'done' ? (
                        <CheckCircle aria-hidden="true" size={15} weight="fill" className="shrink-0 text-brand" />
                      ) : (
                        <WarningCircle aria-hidden="true" size={15} weight="fill" className="shrink-0 text-danger" />
                      )}
                      {localizeSetupStepLabel(s.id, s.label, locale)}
                    </span>
                    <span className={`font-mono ${s.state === 'done' ? 'text-fg-muted' : 'text-danger'}`}>
                      {localizeSetupStepDetail(s.detail, locale) ?? s.state}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {actionError && (
              <p role="alert" className="text-xs text-danger">
                {actionError}
              </p>
            )}
          </div>

          <footer className="mt-5 flex shrink-0 justify-end gap-2 border-t border-line pt-4">
            {!uninstallRes ? (
              <>
                <button
                  type="button"
                  onClick={closeSetup}
                  className="cursor-pointer rounded border border-line-strong bg-surface px-4 py-2 text-xs font-medium text-fg transition-colors hover:bg-surface-2"
                >
                  {t('common.cancel')}
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={runUninstall}
                  className="cursor-pointer rounded bg-danger-solid px-4 py-2 text-xs font-medium text-white transition-opacity hover:opacity-95 disabled:opacity-50"
                >
                  {t(busy ? 'setup.uninstalling' : 'setup.confirmUninstall')}
                </button>
              </>
            ) : (
              <button
                type="button"
                onClick={closeSetup}
                className="cursor-pointer rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95"
              >
                {t('common.done')}
              </button>
            )}
          </footer>
        </main>
      </WindowFrame>
    );
  }

  return (
    <WindowFrame title={frameTitle} badge={frameBadge} headerSlot={headerSlot} resizable={false} minWidthClass="min-w-[760px]">
      <div className="grid min-h-0 flex-1 grid-cols-[212px_minmax(0,1fr)]">
        {/* Left architectural step rail */}
        <aside className="flex flex-col justify-between border-r border-line bg-surface-2/70 p-6">
          <div>
            <div className="flex items-center gap-2.5">
              <img src={logoMark} alt="" className="h-6 w-6 shrink-0" />
              <div className="flex items-baseline gap-1.5">
                <span className="text-sm font-semibold tracking-tight text-fg">{t('shell.appName')}</span>
                <span className="font-mono text-2xs text-fg-subtle">v{info.version}</span>
              </div>
            </div>
            <p className="mt-1.5 text-xs text-fg-subtle">{t('setup.brandTagline')}</p>

            <ol className="mt-8 space-y-5" aria-label={t('setup.stepsNavAria')}>
              {STEP_NUMS.map((s, idx) => {
                const n = (idx + 1) as 1 | 2 | 3 | 4;
                const done = step > n;
                const current = step === n;
                const hasNext = idx < STEP_NUMS.length - 1;
                return (
                  <li key={s.num} aria-current={current ? 'step' : undefined} className="relative flex items-center gap-3">
                    {hasNext && (
                      <span
                        aria-hidden="true"
                        className={`absolute left-[11px] top-6 h-5 w-px ${done ? 'bg-brand-solid' : 'bg-line'}`}
                      />
                    )}
                    <span
                      className={`relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border font-mono text-2xs font-semibold transition-colors ${
                        done
                          ? 'border-brand-solid bg-brand-solid text-brand-on'
                          : current
                            ? 'border-brand-solid bg-brand/15 text-brand'
                            : 'border-line-strong bg-surface text-fg-subtle'
                      }`}
                    >
                      {done ? <Check aria-hidden="true" size={12} weight="bold" /> : s.num}
                    </span>
                    <span className={`text-xs font-medium ${current ? 'text-fg' : done ? 'text-fg-muted' : 'text-fg-subtle'}`}>
                      {t(s.key)}
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>

          {info.alreadyInstalled && (
            <div className="border-t border-line pt-4 text-2xs leading-5 text-brand">
              {t('setup.alreadyInstalledNotice')}
            </div>
          )}
        </aside>

        {/* Main setup panel */}
        <main className="flex min-h-0 flex-1 flex-col justify-between bg-surface px-8 py-7">
          <div className="min-h-0 flex-1 overflow-y-auto pr-1">
            {step === 1 && (
              <div className="space-y-5">
                <div>
                  <h1 ref={stepHeadingRef} tabIndex={-1} className="w-fit text-lg font-semibold text-fg focus:outline-none">
                    {t(info.alreadyInstalled ? 'setup.updateHeading' : 'setup.installHeading')}
                  </h1>
                  <p className="mt-1 text-xs leading-5 text-fg-muted">
                    {t(info.alreadyInstalled ? 'setup.updateSubtitle' : 'setup.installSubtitle')}
                  </p>
                </div>

                {!info.hasInstallPayload && (
                  <div role="alert" className="flex items-start gap-2 rounded-md border border-danger/40 bg-danger/10 px-3.5 py-2.5 text-xs text-danger">
                    <WarningCircle aria-hidden="true" size={16} className="mt-0.5 shrink-0" />
                    <span>{t('setup.missingPayloadNotice')}</span>
                  </div>
                )}

                <div>
                  <label htmlFor="install-dir-input" className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-fg">
                    <FolderOpen aria-hidden="true" size={14} className="text-fg-subtle" />
                    {t('setup.installDirLabel')}
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id="install-dir-input"
                      type="text"
                      value={installDir}
                      onChange={(e) => {
                        setInstallDir(e.target.value);
                        setActionError(null);
                      }}
                      title={installDir}
                      aria-invalid={!!installDirError}
                      aria-describedby={installDirError ? 'install-dir-error' : undefined}
                      className="h-9 min-w-0 flex-1 rounded border border-line-control bg-surface px-3 font-mono text-xs text-fg focus:border-brand-solid focus:outline-none focus:ring-2 focus:ring-brand/20"
                    />
                    <button
                      type="button"
                      disabled={pickingDir || busy}
                      onClick={pickInstallDir}
                      className="inline-flex h-9 shrink-0 cursor-pointer items-center gap-1.5 rounded border border-line-strong bg-surface px-3.5 text-xs font-medium text-fg transition-colors hover:border-line-control hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {t(pickingDir ? 'setup.pickingDir' : 'setup.changeDir')}
                    </button>
                  </div>
                  {installDirError && (
                    <p id="install-dir-error" role="alert" className="mt-1.5 text-2xs text-danger">
                      {installDirError}
                    </p>
                  )}
                </div>

                <div className="divide-y divide-line border-y border-line">
                  {info.platform !== 'macos' && (
                    <ToggleRow
                      title={t('setup.optDesktopShortcutTitle')}
                      desc={t('setup.optDesktopShortcutDesc')}
                      checked={createDesktopShortcut}
                      onChange={setCreateDesktopShortcut}
                    />
                  )}
                  <ToggleRow
                    title={t(info.platform === 'windows' ? 'setup.optStartMenuTitle' : 'setup.optAppMenuTitle')}
                    desc={t(
                      info.platform === 'windows'
                        ? 'setup.optStartMenuDesc'
                        : info.platform === 'macos'
                          ? 'setup.optAppMenuDescMac'
                          : 'setup.optAppMenuDescLinux',
                    )}
                    checked={createStartMenuShortcut}
                    onChange={setCreateStartMenuShortcut}
                  />
                  {info.platform !== 'windows' && (
                    <ToggleRow
                      title={t('setup.optPathTitle')}
                      desc={t('setup.optPathDesc')}
                      checked={addToPath}
                      onChange={setAddToPath}
                    />
                  )}
                  <ToggleRow
                    title={t('setup.optAutostartTitle')}
                    desc={t('setup.optAutostartDesc')}
                    checked={autostartDaemon}
                    onChange={setAutostartDaemon}
                  />
                </div>
                {actionError && (
                  <p role="alert" className="text-xs text-danger">
                    {actionError}
                  </p>
                )}
              </div>
            )}

            {step === 2 && (
              <div className="space-y-5">
                <div>
                  <h1 ref={stepHeadingRef} tabIndex={-1} className="w-fit text-lg font-semibold text-fg focus:outline-none">
                    {t('setup.installingHeading')}
                  </h1>
                  <p className="mt-1 truncate font-mono text-xs text-fg-muted" title={installDir}>
                    {installDir}
                  </p>
                </div>
                <div
                  role="progressbar"
                  aria-label={t('setup.progressAria')}
                  aria-valuetext={busy ? t('setup.progressWorking') : installRes?.ok ? t('setup.progressDone') : t('setup.progressAborted')}
                  className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3"
                >
                  {busy ? (
                    <div className="hg-progress-indeterminate h-full rounded-full bg-brand-solid" />
                  ) : (
                    <div className={`h-full w-full transition-colors ${installRes?.ok ? 'bg-brand-solid' : 'bg-danger-solid'}`} />
                  )}
                </div>
                <div className="divide-y divide-line border-y border-line">
                  {(
                    installRes?.steps ?? [
                      {
                        id: 'dir',
                        label: t('setup.stepDefaultDir'),
                        state: busy ? ('running' as const) : ('error' as const),
                        detail: busy ? undefined : t('setup.stepDetailFailed'),
                      },
                      { id: 'bin', label: t('setup.stepDefaultBin'), state: 'pending' as const },
                      { id: 'sys', label: t('setup.stepDefaultSys'), state: 'pending' as const },
                      { id: 'scan', label: t('setup.stepDefaultScan'), state: 'pending' as const },
                    ]
                  ).map((s) => (
                    <div key={s.id} className="flex items-center justify-between gap-4 py-3 text-xs">
                      <span className="inline-flex items-center gap-2.5 font-medium text-fg">
                        {s.state === 'done' ? (
                          <CheckCircle aria-hidden="true" size={15} weight="fill" className="shrink-0 text-brand" />
                        ) : s.state === 'error' ? (
                          <WarningCircle aria-hidden="true" size={15} weight="fill" className="shrink-0 text-danger" />
                        ) : s.state === 'running' ? (
                          <span aria-hidden="true" className="h-2 w-2 shrink-0 rounded-full bg-brand motion-safe:animate-pulse" />
                        ) : (
                          <span aria-hidden="true" className="h-1.5 w-1.5 shrink-0 rounded-full bg-line-strong" />
                        )}
                        {localizeSetupStepLabel(s.id, s.label, locale)}
                      </span>
                      <span className={`font-mono ${s.state === 'error' ? 'text-danger' : 'text-fg-subtle'}`}>
                        {localizeSetupStepDetail(s.detail, locale) ??
                          (s.state === 'running'
                            ? t('setup.stepDetailWorking')
                            : busy
                              ? t('setup.stepDetailPending')
                              : t('setup.stepDetailAborted'))}
                      </span>
                    </div>
                  ))}
                </div>
                {actionError && (
                  <div role="alert" className="rounded-md border border-danger/30 bg-danger/10 p-3.5 text-xs text-danger">
                    {actionError}
                  </div>
                )}
              </div>
            )}

            {step === 3 && (
              <div className="space-y-4">
                <div className="flex items-end justify-between gap-4">
                  <div>
                    <h1 ref={stepHeadingRef} tabIndex={-1} className="w-fit text-lg font-semibold text-fg focus:outline-none">
                      {t('setup.step3Heading')}
                    </h1>
                    <p className="mt-1 text-xs leading-5 text-fg-muted">
                      {t('setup.step3Desc', { addr: `127.0.0.1:${info.defaultProxyPort}` })}
                    </p>
                  </div>
                  {autoConnectableKinds.length >= 2 && (
                    <button
                      type="button"
                      onClick={() => setSelectedKinds(allAutoSelected ? [] : autoConnectableKinds)}
                      className="shrink-0 cursor-pointer text-xs font-medium text-brand hover:underline"
                    >
                      {t(allAutoSelected ? 'setup.deselectAll' : 'setup.selectAll')}
                    </button>
                  )}
                </div>

                <div className="divide-y divide-line border-y border-line">
                  {activeHarnesses.map((h) => {
                    const canAuto = h.autoConnectMode !== 'manual';
                    const checked = selectedSet.has(h.kind);
                    const statusLabel = !canAuto
                      ? t('setup.statusManual')
                      : h.configured
                        ? t('setup.statusConfigured')
                        : h.installed
                          ? t('setup.statusInstalled')
                          : t('setup.statusNotDetected');
                    const statusTone = !canAuto
                      ? 'text-warn font-medium'
                      : h.configured || h.installed
                        ? 'text-brand font-medium'
                        : 'text-fg-subtle';
                    const localizedNote = localizeHarnessIntegrationNote(h.kind, h.integrationNote, locale);
                    return (
                      <label
                        key={h.kind}
                        className={`flex items-center justify-between gap-4 py-2.5 text-xs transition-colors ${
                          canAuto ? 'cursor-pointer hover:bg-surface-2/50' : 'opacity-70'
                        }`}
                      >
                        <div className="flex min-w-0 items-center gap-3">
                          <input
                            type="checkbox"
                            className="h-4 w-4 shrink-0 rounded border-line-control"
                            disabled={!canAuto}
                            checked={canAuto && checked}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedKinds((prev) => (prev.includes(h.kind) ? prev : [...prev, h.kind]));
                              } else {
                                setSelectedKinds((prev) => prev.filter((k) => k !== h.kind));
                              }
                            }}
                          />
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-fg">{h.name}</div>
                            {h.installPaths.length > 0 && (
                              <div className="mt-0.5 truncate font-mono text-2xs text-fg-subtle" title={h.installPaths.join(', ')}>
                                {h.installPaths[0]}
                              </div>
                            )}
                            {!canAuto && localizedNote && (
                              <div className="mt-0.5 text-2xs leading-4 text-fg-muted">{localizedNote}</div>
                            )}
                          </div>
                        </div>
                        <span className={`shrink-0 text-2xs ${statusTone}`}>{statusLabel}</span>
                      </label>
                    );
                  })}
                </div>
                {actionError && (
                  <p role="alert" className="text-xs text-danger">
                    {actionError}
                  </p>
                )}
              </div>
            )}

            {step === 4 && (
              <div className="space-y-5">
                <div className="flex items-center gap-3">
                  <CheckCircle aria-hidden="true" size={26} weight="fill" className="shrink-0 text-brand" />
                  <div>
                    <h1 ref={stepHeadingRef} tabIndex={-1} className="w-fit text-lg font-semibold text-fg focus:outline-none">
                      {t(info.alreadyInstalled ? 'setup.step4UpdateTitle' : 'setup.step4InstallTitle')}
                    </h1>
                    <p className="mt-0.5 text-xs text-fg-muted">{t('setup.step4ReadySubtitle')}</p>
                  </div>
                </div>

                <dl className="divide-y divide-line border-y border-line text-xs">
                  <div className="flex items-center justify-between gap-4 py-2.5">
                    <dt className="shrink-0 text-fg-subtle">{t('setup.installDirLabel')}</dt>
                    <dd className="min-w-0">
                      <code className="block truncate font-mono text-fg" title={installRes?.installDir ?? installDir}>
                        {installRes?.installDir ?? installDir}
                      </code>
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-4 py-2.5">
                    <dt className="shrink-0 text-fg-subtle">{t('setup.step4ShortcutsLabel')}</dt>
                    <dd className="text-fg">
                      {t((installRes?.shortcutsCreated.length ?? 0) > 0 ? 'setup.step4ShortcutsCreated' : 'setup.step4ShortcutsSkipped')}
                    </dd>
                  </div>
                  {info.platform !== 'windows' && (
                    <div className="flex items-center justify-between gap-4 py-2.5">
                      <dt className="shrink-0 text-fg-subtle">{t('setup.step4PathLabel')}</dt>
                      <dd className="text-fg">
                        {t(installRes?.pathUpdated ? 'setup.step4PathUpdated' : 'setup.step4PathUnchanged')}
                      </dd>
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-4 py-2.5">
                    <dt className="shrink-0 text-fg-subtle">{t('setup.step4AutostartLabel')}</dt>
                    <dd className="text-fg">
                      {t(installRes?.autostartEnabled ? 'setup.step4AutostartOn' : 'setup.step4AutostartOff')}
                    </dd>
                  </div>
                </dl>

                {connectResults && connectResults.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="label-caps">
                      {t('setup.step4ConnectedSummary', { count: connectResults.filter((r) => r.ok).length })}
                    </p>
                    <div className="divide-y divide-line border-y border-line">
                      {connectResults.map((r) => (
                        <div key={r.kind} className="flex items-center justify-between gap-3 py-2 text-xs">
                          <span className="inline-flex shrink-0 items-center gap-1.5 font-medium text-fg">
                            <LinkSimple aria-hidden="true" size={13} className={r.ok ? 'text-brand' : 'text-warn'} />
                            {getHarnessLabel(r.kind, locale)}
                          </span>
                          <span className={`truncate ${r.ok ? 'text-brand' : 'text-warn'}`} title={r.message}>
                            {r.message}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {launched && (
                  <div role="status" className="flex items-center gap-2 rounded-md border border-brand/30 bg-brand/10 px-3.5 py-2.5 text-xs text-brand">
                    <CheckCircle aria-hidden="true" size={16} weight="fill" />
                    <span>{t('setup.step4LaunchedBanner')}</span>
                  </div>
                )}
                {actionError && (
                  <p role="alert" className="text-xs text-danger">
                    {actionError}
                  </p>
                )}
              </div>
            )}
          </div>

          <footer className="mt-5 flex shrink-0 items-center justify-between border-t border-line pt-4">
            {step === 1 && (
              <>
                <button type="button" onClick={closeSetup} className="cursor-pointer text-xs text-fg-subtle transition-colors hover:text-fg">
                  {t('common.cancel')}
                </button>
                <button
                  type="button"
                  disabled={busy || !info.hasInstallPayload || !installDir.trim() || !!installDirError}
                  onClick={startInstall}
                  className="inline-flex cursor-pointer items-center gap-2 rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {t(info.alreadyInstalled ? 'setup.startUpdate' : 'setup.startInstall')}
                  <ArrowRight aria-hidden="true" size={14} />
                </button>
              </>
            )}

            {step === 2 && (
              <>
                <span className="text-xs text-fg-subtle">{t(busy ? 'setup.pleaseWait' : 'setup.installAborted')}</span>
                {actionError && (
                  <button
                    type="button"
                    onClick={() => transitionStep(1)}
                    className="cursor-pointer rounded border border-line-strong bg-surface px-4 py-2 text-xs font-medium text-fg transition-colors hover:bg-surface-2"
                  >
                    {t('setup.backToOptions')}
                  </button>
                )}
              </>
            )}

            {step === 3 && (
              <>
                <button type="button" disabled={busy} onClick={() => applyHarnesses(true)} className="cursor-pointer text-xs text-fg-subtle transition-colors hover:text-fg">
                  {t('setup.skip')}
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => applyHarnesses(false)}
                  className="inline-flex cursor-pointer items-center gap-2 rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95 disabled:opacity-50"
                >
                  {selectedKinds.length > 0 ? t('setup.connectAndContinue', { count: selectedKinds.length }) : t('setup.nextStep')}
                  <ArrowRight aria-hidden="true" size={14} />
                </button>
              </>
            )}

            {step === 4 && (
              <>
                <button
                  type="button"
                  onClick={closeSetup}
                  className="cursor-pointer rounded border border-line-strong bg-surface px-4 py-2 text-xs font-medium text-fg transition-colors hover:bg-surface-2"
                >
                  {t('common.done')}
                </button>
                {!launched && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={launchDesktop}
                    className="inline-flex cursor-pointer items-center gap-2 rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95 disabled:opacity-50"
                  >
                    {t('setup.launchDesktop')}
                  </button>
                )}
              </>
            )}
          </footer>
        </main>
      </div>
    </WindowFrame>
  );
}
