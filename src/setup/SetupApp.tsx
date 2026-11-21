import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import {
  ArrowRight,
  Check,
  CheckCircle,
  FolderOpen,
  LinkSimple,
  Trash,
  WarningCircle,
} from '@phosphor-icons/react';
import { WindowFrame } from '../components/WindowFrame';
import logoMark from '../assets/logo-mark.png';
import { HARNESS_LABEL } from '../lib/format';
import type { HarnessActionResult, HarnessKind, HarnessProfile } from '../types';

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
  hasEmbeddedBinaries: boolean;
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

function getInstallDirError(rawDir: string, platform?: string): string | null {
  const trimmed = rawDir.trim();
  if (!trimmed) return '请选择安装位置';
  const norm = trimmed.replace(/[\\/]+$/, '') || (trimmed.startsWith('/') ? '/' : trimmed);
  const low = (platform === 'windows' || /^[a-zA-Z]:/.test(norm)) ? norm.toLowerCase().replace(/\//g, '\\') : norm;

  if (low === '/' || /^[a-z]:$/i.test(low)) {
    return '不能直接安装到磁盘根目录，请选择专用子目录（例如 …\\Hide-Go）';
  }
  if (/^[a-z]:\\windows(\\|$)/i.test(low)) {
    return '不能安装到 Windows 系统目录下，请选择用户目录中的子目录';
  }
  if (
    /^[a-z]:\\(users\\[^\\]+(|\\desktop|\\documents|\\downloads)|program files( \(x86\))?|programdata)$/i.test(low) ||
    /^\/(applications|users|home|tmp|var|etc|usr|usr\/local|bin|sbin|system|library)$/i.test(low) ||
    /^\/(users|home)\/[^/]+(\/(desktop|documents|downloads))?$/i.test(low)
  ) {
    return '不能直接安装到系统目录或桌面/文档根文件夹，请选择专用的 Hide-Go 子目录';
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

const STEPS = [
  { num: '01', title: '安装位置' },
  { num: '02', title: '安装程序' },
  { num: '03', title: '连接工具' },
  { num: '04', title: '完成' },
];

export function SetupApp() {
  const [info, setInfo] = useState<SetupInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const stepHeadingRef = useRef<HTMLHeadingElement>(null);

  const [installDir, setInstallDir] = useState('');
  const [createShortcuts, setCreateShortcuts] = useState(true);
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
      setInfo(data);
      setInstallDir((prev) => prev || data.existingInstallDir || data.defaultInstallDir);
      const autoSelectable = data.harnesses
        .filter((h) => h.installed && h.autoConnectMode !== 'manual')
        .map((h) => h.kind);
      setSelectedKinds(autoSelectable);
    } catch (e) {
      if (mountedRef.current) setLoadError((e as Error).message);
    }
  }, []);

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
        body: JSON.stringify({ initialDir: installDir || null }),
      });
      if (res.path) setInstallDir(res.path);
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setPickingDir(false);
    }
  };

  const installDirError = installDir.trim() ? getInstallDirError(installDir, info?.platform) : null;

  const startInstall = async () => {
    const dirErr = getInstallDirError(installDir, info?.platform);
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
          createShortcuts,
          addToPath: info?.platform !== 'windows' && addToPath,
          autostartDaemon,
        }),
      });
      setInstallRes(res);
      if (!res.ok) {
        setActionError(res.error ?? '安装过程发生错误');
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
      if (!res.ok) setActionError(res.error ?? '卸载未能全部完成');
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const frameTitle = info?.mode === 'uninstall' ? 'Hide-Go 卸载' : 'Hide-Go 安装';
  const frameBadge = info ? `v${info.version}` : undefined;

  if (loadError) {
    return (
      <WindowFrame title={frameTitle} resizable={false} minWidthClass="min-w-[760px]">
        <div className="flex flex-1 items-center justify-center p-8">
          <div role="alert" className="w-full max-w-md rounded-md border border-danger/40 bg-surface p-6">
            <p className="text-sm font-semibold text-danger">无法连接安装服务</p>
            <p className="mt-2 text-xs text-fg-muted">{loadError}</p>
          </div>
        </div>
      </WindowFrame>
    );
  }

  if (!info) {
    return (
      <WindowFrame title={frameTitle} resizable={false} minWidthClass="min-w-[760px]">
        <div className="flex flex-1 items-center justify-center text-sm text-fg-muted">正在初始化…</div>
      </WindowFrame>
    );
  }

  if (info.mode === 'uninstall') {
    return (
      <WindowFrame title={frameTitle} badge={frameBadge} resizable={false} minWidthClass="min-w-[760px]">
        <main className="mx-auto flex min-h-0 w-full max-w-2xl flex-1 flex-col justify-between bg-surface p-8">
          <div className="min-h-0 flex-1 space-y-5 overflow-y-auto pr-1">
            <header className="flex items-center justify-between border-b border-line pb-5">
              <div className="flex items-center gap-3">
                <img src={logoMark} alt="" className="h-8 w-8 shrink-0" />
                <div>
                  <div className="flex items-baseline gap-2">
                    <h1 className="text-lg font-semibold text-fg">卸载 Hide-Go</h1>
                    <span className="font-mono text-xs text-fg-subtle">v{info.version}</span>
                  </div>
                  <p className="mt-0.5 text-xs text-fg-muted">停止后台服务、还原工具配置并清理程序文件。</p>
                </div>
              </div>
              <Trash aria-hidden="true" size={20} className="text-danger" />
            </header>

            {!uninstallRes ? (
              <div className="divide-y divide-line border-b border-line">
                {info.existingInstallDir && (
                  <div className="flex items-center justify-between gap-4 py-3 text-xs">
                    <span className="text-fg-subtle">安装位置</span>
                    <code className="truncate font-mono text-fg" title={info.existingInstallDir}>
                      {info.existingInstallDir}
                    </code>
                  </div>
                )}
                <ToggleRow
                  title="同时删除个人配置与规则"
                  desc={info.configPath ? `删除 ${info.configPath} 及备份文件` : '删除个人配置目录'}
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
                      {s.label}
                    </span>
                    <span className={`font-mono ${s.state === 'done' ? 'text-fg-muted' : 'text-danger'}`}>
                      {s.detail ?? s.state}
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
                  取消
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={runUninstall}
                  className="cursor-pointer rounded bg-danger-solid px-4 py-2 text-xs font-medium text-white transition-opacity hover:opacity-95 disabled:opacity-50"
                >
                  {busy ? '正在卸载…' : '确认卸载'}
                </button>
              </>
            ) : (
              <button
                type="button"
                onClick={closeSetup}
                className="cursor-pointer rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95"
              >
                完成
              </button>
            )}
          </footer>
        </main>
      </WindowFrame>
    );
  }

  return (
    <WindowFrame title={frameTitle} badge={frameBadge} resizable={false} minWidthClass="min-w-[760px]">
      <div className="grid min-h-0 flex-1 grid-cols-[212px_minmax(0,1fr)]">
        {/* Left architectural step rail */}
        <aside className="flex flex-col justify-between border-r border-line bg-surface-2/70 p-6">
          <div>
            <div className="flex items-center gap-2.5">
              <img src={logoMark} alt="" className="h-6 w-6 shrink-0" />
              <div className="flex items-baseline gap-1.5">
                <span className="text-sm font-semibold tracking-tight text-fg">Hide-Go</span>
                <span className="font-mono text-2xs text-fg-subtle">v{info.version}</span>
              </div>
            </div>
            <p className="mt-1.5 text-xs text-fg-subtle">本地 AI 隐私代理</p>

            <ol className="mt-8 space-y-5" aria-label="安装步骤">
              {STEPS.map((s, idx) => {
                const n = (idx + 1) as 1 | 2 | 3 | 4;
                const done = step > n;
                const current = step === n;
                const hasNext = idx < STEPS.length - 1;
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
                      {s.title}
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>

          {info.alreadyInstalled && (
            <div className="border-t border-line pt-4 text-2xs leading-5 text-brand">
              已检测到旧版本，安装时将直接更新并保留配置
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
                    {info.alreadyInstalled ? '更新 Hide-Go' : '安装 Hide-Go'}
                  </h1>
                  <p className="mt-1 text-xs leading-5 text-fg-muted">
                    {info.alreadyInstalled ? '将覆盖更新现有程序，配置文件不受影响。' : '选择安装位置与启动选项。'}
                  </p>
                </div>

                {!info.hasEmbeddedBinaries && (
                  <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn/10 px-3.5 py-2.5 text-xs text-warn">
                    <WarningCircle aria-hidden="true" size={16} className="mt-0.5 shrink-0" />
                    <span>开发构建模式：将从相邻构建目录定位程序文件。</span>
                  </div>
                )}

                <div>
                  <label htmlFor="install-dir-input" className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-fg">
                    <FolderOpen aria-hidden="true" size={14} className="text-fg-subtle" />
                    安装位置
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id="install-dir-input"
                      type="text"
                      readOnly
                      value={installDir}
                      title={installDir}
                      aria-invalid={!!installDirError}
                      aria-describedby={installDirError ? 'install-dir-error' : undefined}
                      className="h-9 min-w-0 flex-1 rounded border border-line-control bg-surface-2/60 px-3 font-mono text-xs text-fg focus:border-brand-solid focus:outline-none focus:ring-2 focus:ring-brand/20"
                    />
                    <button
                      type="button"
                      disabled={pickingDir || busy}
                      onClick={pickInstallDir}
                      className="inline-flex h-9 shrink-0 cursor-pointer items-center gap-1.5 rounded border border-line-strong bg-surface px-3.5 text-xs font-medium text-fg transition-colors hover:border-line-control hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {pickingDir ? '选择中…' : '更改…'}
                    </button>
                  </div>
                  {installDirError && (
                    <p id="install-dir-error" role="alert" className="mt-1.5 text-2xs text-danger">
                      {installDirError}
                    </p>
                  )}
                </div>

                <div className="divide-y divide-line border-y border-line">
                  <ToggleRow
                    title="创建快捷方式"
                    desc={info.platform === 'windows' ? '在桌面和开始菜单创建入口' : '在桌面和应用列表创建入口'}
                    checked={createShortcuts}
                    onChange={setCreateShortcuts}
                  />
                  {info.platform !== 'windows' && (
                    <ToggleRow
                      title="添加到 PATH"
                      desc="支持在终端直接启动"
                      checked={addToPath}
                      onChange={setAddToPath}
                    />
                  )}
                  <ToggleRow
                    title="开机自动启动"
                    desc="登录系统后在后台运行代理服务"
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
                    正在安装
                  </h1>
                  <p className="mt-1 truncate font-mono text-xs text-fg-muted" title={installDir}>
                    {installDir}
                  </p>
                </div>
                <div
                  role="progressbar"
                  aria-label="安装进度"
                  aria-valuetext={busy ? '正在写入程序文件' : installRes?.ok ? '安装完成' : '安装中止'}
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
                        label: '准备安装目录',
                        state: busy ? ('running' as const) : ('error' as const),
                        detail: busy ? undefined : '失败',
                      },
                      { id: 'bin', label: '写入程序文件', state: 'pending' as const },
                      { id: 'sys', label: '配置快捷方式与系统入口', state: 'pending' as const },
                      { id: 'scan', label: '检测本机 AI 工具', state: 'pending' as const },
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
                        {s.label}
                      </span>
                      <span className={`font-mono ${s.state === 'error' ? 'text-danger' : 'text-fg-subtle'}`}>
                        {s.detail ?? (s.state === 'running' ? '处理中…' : busy ? '等待中' : '已中止')}
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
                      连接本机 AI 工具
                    </h1>
                    <p className="mt-1 text-xs leading-5 text-fg-muted">
                      将已选工具的请求转发至本地代理 <code className="font-mono text-fg">127.0.0.1:{info.defaultProxyPort}</code>，修改前自动备份原配置。
                    </p>
                  </div>
                  {autoConnectableKinds.length >= 2 && (
                    <button
                      type="button"
                      onClick={() => setSelectedKinds(allAutoSelected ? [] : autoConnectableKinds)}
                      className="shrink-0 cursor-pointer text-xs font-medium text-brand hover:underline"
                    >
                      {allAutoSelected ? '取消全选' : '全选'}
                    </button>
                  )}
                </div>

                <div className="divide-y divide-line border-y border-line">
                  {activeHarnesses.map((h) => {
                    const canAuto = h.autoConnectMode !== 'manual';
                    const checked = selectedSet.has(h.kind);
                    const statusLabel = !canAuto
                      ? '需手动配置'
                      : h.configured
                        ? '已接入'
                        : h.installed
                          ? '已安装'
                          : '未检测到';
                    const statusTone = !canAuto
                      ? 'text-warn font-medium'
                      : h.configured || h.installed
                        ? 'text-brand font-medium'
                        : 'text-fg-subtle';
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
                            {!canAuto && h.integrationNote && (
                              <div className="mt-0.5 text-2xs leading-4 text-fg-muted">{h.integrationNote}</div>
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
                      安装完成
                    </h1>
                    <p className="mt-0.5 text-xs text-fg-muted">Hide-Go 已准备就绪。</p>
                  </div>
                </div>

                <dl className="divide-y divide-line border-y border-line text-xs">
                  <div className="flex items-center justify-between gap-4 py-2.5">
                    <dt className="shrink-0 text-fg-subtle">安装位置</dt>
                    <dd className="min-w-0">
                      <code className="block truncate font-mono text-fg" title={installRes?.installDir ?? installDir}>
                        {installRes?.installDir ?? installDir}
                      </code>
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-4 py-2.5">
                    <dt className="shrink-0 text-fg-subtle">快捷方式</dt>
                    <dd className="text-fg">{(installRes?.shortcutsCreated.length ?? 0) > 0 ? '已创建' : '未创建'}</dd>
                  </div>
                  {info.platform !== 'windows' && (
                    <div className="flex items-center justify-between gap-4 py-2.5">
                      <dt className="shrink-0 text-fg-subtle">环境变量 PATH</dt>
                      <dd className="text-fg">{installRes?.pathUpdated ? '已添加到用户 PATH（新终端生效）' : '未修改'}</dd>
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-4 py-2.5">
                    <dt className="shrink-0 text-fg-subtle">开机自启</dt>
                    <dd className="text-fg">{installRes?.autostartEnabled ? '已开启' : '未开启'}</dd>
                  </div>
                </dl>

                {connectResults && connectResults.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="label-caps">已接入工具（{connectResults.filter((r) => r.ok).length} 项）</p>
                    <div className="divide-y divide-line border-y border-line">
                      {connectResults.map((r) => (
                        <div key={r.kind} className="flex items-center justify-between gap-3 py-2 text-xs">
                          <span className="inline-flex shrink-0 items-center gap-1.5 font-medium text-fg">
                            <LinkSimple aria-hidden="true" size={13} className={r.ok ? 'text-brand' : 'text-warn'} />
                            {HARNESS_LABEL[r.kind] ?? r.kind}
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
                    <span>Hide-Go 已启动，窗口即将关闭。</span>
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
                  取消
                </button>
                <button
                  type="button"
                  disabled={busy || !installDir.trim() || !!installDirError}
                  onClick={startInstall}
                  className="inline-flex cursor-pointer items-center gap-2 rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {info.alreadyInstalled ? '开始更新' : '开始安装'}
                  <ArrowRight aria-hidden="true" size={14} />
                </button>
              </>
            )}

            {step === 2 && (
              <>
                <span className="text-xs text-fg-subtle">{busy ? '请稍候…' : '安装已中止'}</span>
                {actionError && (
                  <button
                    type="button"
                    onClick={() => transitionStep(1)}
                    className="cursor-pointer rounded border border-line-strong bg-surface px-4 py-2 text-xs font-medium text-fg transition-colors hover:bg-surface-2"
                  >
                    返回修改选项
                  </button>
                )}
              </>
            )}

            {step === 3 && (
              <>
                <button type="button" disabled={busy} onClick={() => applyHarnesses(true)} className="cursor-pointer text-xs text-fg-subtle transition-colors hover:text-fg">
                  跳过
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => applyHarnesses(false)}
                  className="inline-flex cursor-pointer items-center gap-2 rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95 disabled:opacity-50"
                >
                  {selectedKinds.length > 0 ? `接入 (${selectedKinds.length}) 并继续` : '下一步'}
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
                  完成
                </button>
                {!launched && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={launchDesktop}
                    className="inline-flex cursor-pointer items-center gap-2 rounded bg-brand-solid px-5 py-2 text-xs font-medium text-brand-on transition-opacity hover:opacity-95 disabled:opacity-50"
                  >
                    启动 Hide-Go
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
