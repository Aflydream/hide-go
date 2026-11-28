import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  ChartLineUp,
  ArrowsClockwise,
  ArrowsLeftRight,
  ShieldCheck,
  Plugs,
  Vault as VaultIcon,
  BracketsAngle,
  Gear,
  Eye,
  EyeSlash,
  Lightning,
  PaperPlaneTilt,
  WarningCircle,
  WifiSlash,
} from '@phosphor-icons/react';
import { StoreProvider, isAuthError, useStore } from './store';
import { api } from './lib/api';
import { Badge, Button, Dialog, Segmented, ToastProvider, cx, useToast, type SegmentTone } from './components/ui';
import { ColorSchemeProvider, WindowFrame } from './components/WindowFrame';
import type { Route } from './lib/hooks';
import { formatCount, formatDuration, getHarnessLabel, getModeLabel } from './lib/format';
import { I18nProvider, translate, useI18n, type Locale } from './lib/i18n';
import type { PrivacyMode } from './types';
import { Overview } from './views/Overview';
import { Traffic } from './views/Traffic';
import { Policy } from './views/Policy';
import { Integrations } from './views/Integrations';
import { VaultView } from './views/Vault';
import { Rules } from './views/Rules';
import { Settings } from './views/Settings';
import { SimulateDialog } from './views/SimulateDialog';

interface NavItem {
  route: Route;
  label: string;
  icon: ReactNode;
  title: string;
  description: string;
}

function getNavItems(locale: Locale): NavItem[] {
  return [
    {
      route: 'overview',
      label: translate(locale, 'nav.overview'),
      icon: <ChartLineUp size={18} />,
      title: translate(locale, 'nav.overviewTitle'),
      description: translate(locale, 'nav.overviewDesc'),
    },
    {
      route: 'traffic',
      label: translate(locale, 'nav.traffic'),
      icon: <ArrowsLeftRight size={18} />,
      title: translate(locale, 'nav.trafficTitle'),
      description: translate(locale, 'nav.trafficDesc'),
    },
    {
      route: 'policy',
      label: translate(locale, 'nav.policy'),
      icon: <ShieldCheck size={18} />,
      title: translate(locale, 'nav.policyTitle'),
      description: translate(locale, 'nav.policyDesc'),
    },
    {
      route: 'rules',
      label: translate(locale, 'nav.rules'),
      icon: <BracketsAngle size={18} />,
      title: translate(locale, 'nav.rulesTitle'),
      description: translate(locale, 'nav.rulesDesc'),
    },
    {
      route: 'vault',
      label: translate(locale, 'nav.vault'),
      icon: <VaultIcon size={18} />,
      title: translate(locale, 'nav.vaultTitle'),
      description: translate(locale, 'nav.vaultDesc'),
    },
    {
      route: 'integrations',
      label: translate(locale, 'nav.integrations'),
      icon: <Plugs size={18} />,
      title: translate(locale, 'nav.integrationsTitle'),
      description: translate(locale, 'nav.integrationsDesc'),
    },
    {
      route: 'settings',
      label: translate(locale, 'nav.settings'),
      icon: <Gear size={18} />,
      title: translate(locale, 'nav.settingsTitle'),
      description: translate(locale, 'nav.settingsDesc'),
    },
  ];
}

function getModeOptions(locale: Locale): Array<{ value: PrivacyMode; label: string; icon: ReactNode; title: string; tone: SegmentTone }> {
  return [
    {
      value: 'audit-only',
      label: getModeLabel('audit-only', locale),
      icon: <Eye size={14} />,
      title: translate(locale, 'mode.auditOnlyDesc'),
      tone: 'warn',
    },
    {
      value: 'auto-desensitize',
      label: getModeLabel('auto-desensitize', locale),
      icon: <ShieldCheck size={14} />,
      title: translate(locale, 'mode.autoDesensitizeDesc'),
      tone: 'brand',
    },
    {
      value: 'all-hide',
      label: getModeLabel('all-hide', locale),
      icon: <EyeSlash size={14} />,
      title: translate(locale, 'mode.allHideDesc'),
      tone: 'ink',
    },
  ];
}

function Sidebar({ navItems }: { navItems: NavItem[] }) {
  const { route, navigate, logs, vault, status, config, statusError, updateInfo } = useStore();
  const { locale, t } = useI18n();
  const liveCount = useMemo(() => logs.reduce((n, l) => n + (l.simulated ? 0 : 1), 0), [logs]);
  const online = !!status && !statusError;
  const counts: Partial<Record<Route, number>> = {
    traffic: liveCount,
    vault: status?.activeVaultTokens ?? vault.length,
    rules: config?.customRules.length,
  };
  return (
    <aside className="flex w-[212px] shrink-0 flex-col bg-bg px-2.5 pb-2.5 pt-1 max-[1180px]:w-14 max-[1180px]:px-1.5" aria-label={t('shell.navAria')}>
      <nav className="flex-1 space-y-0.5" aria-label={t('shell.viewsAria')}>
        {navItems.map((item) => {
          const active = item.route === route;
          const count = counts[item.route];
          const hasUpdateDot = item.route === 'settings' && !!updateInfo?.updateAvailable;
          return (
            <button
              key={item.route}
              type="button"
              onClick={() => navigate(item.route)}
              aria-current={active ? 'page' : undefined}
              title={item.label}
              className={cx(
                'relative flex h-9 w-full cursor-pointer items-center gap-2.5 rounded-lg px-2.5 text-[13px] transition-all max-[1180px]:justify-center max-[1180px]:px-0',
                active
                  ? 'hg-nav-active bg-surface font-medium text-fg shadow-control'
                  : 'text-fg-muted hover:bg-surface-3/70 hover:text-fg',
              )}
            >
              <span aria-hidden="true" className={cx('flex shrink-0', active ? 'text-fg' : 'text-fg-subtle')}>
                {item.icon}
              </span>
              <span className="flex-1 truncate text-left max-[1180px]:sr-only">{item.label}</span>
              {hasUpdateDot && (
                <span
                  aria-hidden="true"
                  className="h-1.5 w-1.5 shrink-0 rounded-full bg-info max-[1180px]:absolute max-[1180px]:right-2 max-[1180px]:top-2"
                />
              )}
              {count !== undefined && count > 0 && (
                <span className="tabular rounded-full bg-surface-3 px-1.5 py-px font-mono text-2xs text-fg-subtle max-[1180px]:hidden">
                  {formatCount(count, locale)}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="mt-2 rounded-xl border border-line/80 bg-surface/90 px-3 py-2.5 shadow-control max-[1180px]:hidden">
        <div role="status" aria-live="polite">
          <div className="flex items-center gap-2 text-xs">
            <span aria-hidden="true" className={cx('h-2 w-2 rounded-full', online ? 'bg-ok' : 'bg-danger')} />
            <span className="font-medium text-fg">{online ? t('shell.online') : t('shell.offline')}</span>
            {config && <span className="tabular ml-auto font-mono text-2xs text-fg-subtle">:{config.proxyPort}</span>}
          </div>
          {status && (
            <p className="tabular mt-1 pl-4 text-2xs text-fg-subtle">
              {t('shell.uptime', { duration: formatDuration(status.uptimeSecs, locale) })}
            </p>
          )}
        </div>
      </div>
    </aside>
  );
}

function TopBar({ navItems }: { navItems: NavItem[] }) {
  const { route, config, saveConfig, openSimulator } = useStore();
  const { locale, t } = useI18n();
  const item = navItems.find((n) => n.route === route) ?? navItems[0];
  const modeOptions = useMemo(() => getModeOptions(locale), [locale]);
  return (
    <header className="flex h-[54px] shrink-0 items-center justify-between gap-4 border-b border-line/75 bg-surface px-6">
      <div className="flex min-w-0 items-baseline gap-2.5">
        <h1 id="view-title" tabIndex={-1} className="w-fit shrink-0 text-[15px] font-semibold tracking-tight text-fg focus:outline-none">
          {item.title}
        </h1>
        <p className="truncate text-xs text-fg-subtle max-[1120px]:hidden">{item.description}</p>
      </div>
      <div role="toolbar" aria-label={t('shell.quickControlsAria')} className="flex shrink-0 items-center gap-2.5">
        <div role="group" aria-label={t('shell.requestTestAria')}>
          <Button size="sm" variant="secondary" icon={<PaperPlaneTilt size={13} />} onClick={openSimulator}>
            {t('shell.simulate')}
          </Button>
        </div>
        {config ? (
          <Segmented
            label={t('shell.globalModeAria')}
            value={config.mode}
            onChange={(mode) =>
              mode !== config.mode &&
              saveConfig({ ...config, mode }, t('shell.modeSwitched', { mode: getModeLabel(mode, locale) }))
            }
            options={modeOptions}
          />
        ) : (
          <span className="h-8 w-[260px] animate-pulse rounded-lg bg-surface-3" aria-hidden="true" />
        )}
      </div>
    </header>
  );
}

function ConnectionBanner() {
  const { statusError } = useStore();
  const { t } = useI18n();
  if (!statusError) return null;
  const auth = isAuthError(statusError);
  return (
    <div role="alert" className="mx-5 mt-3 flex items-center gap-2.5 rounded-xl border border-danger/25 bg-danger/10 px-4 py-2.5 text-xs text-danger">
      <WifiSlash aria-hidden="true" size={15} weight="bold" className="shrink-0" />
      <span className="font-semibold">{t(auth ? 'shell.invalidTokenTitle' : 'shell.unreachableTitle')}</span>
      <span className="text-fg-muted">{t(auth ? 'shell.invalidTokenBody' : 'shell.unreachableBody')}</span>
    </div>
  );
}

function AuditWarning() {
  const { config, route, navigate } = useStore();
  const { t } = useI18n();
  if (!config || config.mode !== 'audit-only' || route === 'policy') return null;
  return (
    <div className="mx-5 mt-3 flex items-center gap-2.5 rounded-xl border border-warn/25 bg-warn/10 px-4 py-2 text-xs">
      <Lightning aria-hidden="true" size={14} weight="fill" className="shrink-0 text-warn" />
      <span className="font-semibold text-warn">{t('shell.auditBannerTitle')}</span>
      <span className="truncate text-fg-muted">{t('shell.auditBannerBody')}</span>
      <button type="button" onClick={() => navigate('policy')} className="ml-auto shrink-0 cursor-pointer font-medium text-fg underline-offset-2 hover:underline">
        {t('shell.auditBannerAction')}
      </button>
    </div>
  );
}

function RestartReminderBanner() {
  const { runtimeHealth, navigate } = useStore();
  const { locale, t } = useI18n();
  const pending = runtimeHealth?.runningHarnesses.filter((h) => h.needsRestart) ?? [];
  if (pending.length === 0) return null;
  const sep = locale === 'zh-CN' ? '、' : ', ';
  const names = pending.map((h) => getHarnessLabel(h.kind, locale)).join(sep);
  return (
    <div role="status" className="mx-5 mt-3 flex items-center gap-2.5 rounded-xl border border-warn/25 bg-warn/10 px-4 py-2 text-xs">
      <ArrowsClockwise aria-hidden="true" size={14} weight="bold" className="shrink-0 text-warn" />
      <span className="font-semibold text-warn">{t('shell.restartBannerTitle', { tools: names })}</span>
      <span className="truncate text-fg-muted">{t('shell.restartBannerBody')}</span>
      <button
        type="button"
        onClick={() => navigate('integrations', { tool: pending[0]!.kind })}
        className="ml-auto shrink-0 cursor-pointer font-medium text-fg underline-offset-2 hover:underline"
      >
        {t('shell.restartBannerAction')}
      </button>
    </div>
  );
}

function ConflictResolutionModal() {
  const { config, runtimeHealth, resolveConflict } = useStore();
  const { t } = useI18n();
  const toast = useToast();
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const conflict = config?.mode !== 'audit-only' ? (runtimeHealth?.conflicts[0] ?? null) : null;

  const handleAction = async (action: 'stop-peer' | 'switch-hidego-audit' | 'dismiss') => {
    if (!conflict) return;
    setBusyAction(action);
    try {
      await resolveConflict(conflict.id, action);
    } finally {
      setBusyAction(null);
    }
  };

  const handleQuitHideGo = async () => {
    setBusyAction('quit-hidego');
    try {
      await api.quitDesktop();
    } catch {
      toast.push({
        tone: 'warn',
        title: t('conflict.quitUnsupportedTitle'),
        body: t('conflict.quitUnsupportedBody'),
      });
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <Dialog
      open={Boolean(conflict)}
      onClose={() => void handleAction('dismiss')}
      title={t('conflict.title')}
      description={t('conflict.description')}
      width="max-w-lg"
      footer={
        conflict ? (
          <div className="flex w-full flex-wrap items-center justify-end gap-2">
            <Button size="sm" variant="ghost" disabled={busyAction !== null} onClick={() => void handleAction('dismiss')}>
              {t('conflict.actionIgnore')}
            </Button>
            <Button size="sm" variant="secondary" disabled={busyAction !== null} onClick={() => void handleAction('switch-hidego-audit')}>
              {t('conflict.actionSwitchAudit')}
            </Button>
            <Button size="sm" variant="secondary" disabled={busyAction !== null} onClick={() => void handleQuitHideGo()}>
              {t('conflict.actionQuitHideGo')}
            </Button>
            {conflict.canStopPeer && (
              <Button size="sm" variant="danger" disabled={busyAction !== null} onClick={() => void handleAction('stop-peer')}>
                {t('conflict.actionStopPeer', { peer: conflict.peerName })}
              </Button>
            )}
          </div>
        ) : null
      }
    >
      {conflict && (
        <div className="space-y-3 text-xs">
          <div className="flex items-start gap-2.5 rounded-md border border-warn/40 bg-warn/10 p-3">
            <WarningCircle aria-hidden="true" size={16} weight="bold" className="mt-0.5 shrink-0 text-warn" />
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-semibold text-fg">{conflict.peerName}</span>
                {conflict.port ? <Badge tone="warn">127.0.0.1:{conflict.port}</Badge> : null}
                {conflict.pid ? <Badge tone="neutral">PID {conflict.pid}</Badge> : null}
              </div>
              <p className="break-all leading-5 text-fg-muted">{conflict.detail}</p>
            </div>
          </div>
          <p className="leading-5 text-fg-muted">{t('conflict.guidance')}</p>
        </div>
      )}
    </Dialog>
  );
}

function Main() {
  const { route } = useStore();
  const mainRef = useRef<HTMLElement>(null);
  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [route]);
  return (
    <main ref={mainRef} id="main" tabIndex={-1} className="min-h-0 flex-1 overflow-y-auto focus:outline-none">
      {route === 'overview' && <Overview />}
      {route === 'traffic' && <Traffic />}
      {route === 'policy' && <Policy />}
      {route === 'rules' && <Rules />}
      {route === 'vault' && <VaultView />}
      {route === 'integrations' && <Integrations />}
      {route === 'settings' && <Settings />}
    </main>
  );
}

function Shell() {
  const { simulatorOpen, closeSimulator, status, statusError, config } = useStore();
  const { locale, t } = useI18n();
  const navItems = useMemo(() => getNavItems(locale), [locale]);

  useEffect(() => {
    document.title = status
      ? t('shell.requestsTitle', { count: formatCount(status.totalRequests, locale) })
      : t('shell.consoleTitle');
  }, [status, locale, t]);

  const online = !!status && !statusError;
  const statusChip = (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 rounded-full border px-2 py-px font-mono text-2xs max-[1000px]:hidden',
        online ? 'border-line bg-surface text-fg-muted shadow-control' : 'border-line bg-surface-2 text-fg-subtle',
      )}
    >
      <span aria-hidden="true" className={cx('h-1.5 w-1.5 rounded-full', online ? 'bg-ok' : 'bg-danger')} />
      127.0.0.1:{config?.proxyPort ?? 18787}
    </span>
  );

  return (
    <WindowFrame title={t('shell.appName')} badge={status ? `v${status.version}` : undefined} statusSlot={statusChip} minWidthClass="min-w-[960px]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-12 focus:z-[70] focus:rounded-lg focus:border focus:border-line-strong focus:bg-surface focus:px-3 focus:py-2 focus:text-sm"
      >
        {t('shell.skipToContent')}
      </a>
      <div className="flex min-h-0 flex-1 bg-bg">
        <Sidebar navItems={navItems} />
        <div className="flex min-w-0 flex-1 flex-col pb-2.5 pr-2.5">
          <div className="hg-sheet flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-line/85 bg-surface shadow-sheet">
            <TopBar navItems={navItems} />
            <ConnectionBanner />
            <AuditWarning />
            <RestartReminderBanner />
            <Main />
          </div>
        </div>
      </div>
      <SimulateDialog open={simulatorOpen} onClose={closeSimulator} />
      <ConflictResolutionModal />
    </WindowFrame>
  );
}

export default function App() {
  return (
    <I18nProvider>
      <ColorSchemeProvider>
        <ToastProvider>
          <StoreProvider>
            <Shell />
          </StoreProvider>
        </ToastProvider>
      </ColorSchemeProvider>
    </I18nProvider>
  );
}
