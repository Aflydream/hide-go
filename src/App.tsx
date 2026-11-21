import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import {
  ChartLineUp,
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
  WifiSlash,
} from '@phosphor-icons/react';
import { StoreProvider, isAuthError, useStore } from './store';
import { Button, Segmented, ToastProvider, cx, type SegmentTone } from './components/ui';
import { ColorSchemeProvider, WindowFrame } from './components/WindowFrame';
import type { Route } from './lib/hooks';
import { formatCount, formatDuration, getModeLabel } from './lib/format';
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
  const { route, navigate, logs, vault, status, config, statusError } = useStore();
  const { locale, t } = useI18n();
  const liveCount = useMemo(() => logs.reduce((n, l) => n + (l.simulated ? 0 : 1), 0), [logs]);
  const online = !!status && !statusError;
  const counts: Partial<Record<Route, number>> = {
    traffic: liveCount,
    vault: status?.activeVaultTokens ?? vault.length,
    rules: config?.customRules.length,
  };
  return (
    <aside className="flex w-52 shrink-0 flex-col border-r border-line bg-surface-2/60 max-[1180px]:w-14" aria-label={t('shell.navAria')}>
      <nav className="flex-1 space-y-0.5 px-2 pt-3" aria-label={t('shell.viewsAria')}>
        {navItems.map((item) => {
          const active = item.route === route;
          const count = counts[item.route];
          return (
            <button
              key={item.route}
              type="button"
              onClick={() => navigate(item.route)}
              aria-current={active ? 'page' : undefined}
              title={item.label}
              className={cx(
                'relative flex h-9 w-full cursor-pointer items-center gap-3 rounded px-2.5 text-sm transition-colors max-[1180px]:justify-center max-[1180px]:px-0',
                active ? 'bg-surface font-medium text-fg shadow-[0_0_0_1px_rgb(var(--line-strong))]' : 'text-fg-muted hover:bg-surface-3/70 hover:text-fg',
              )}
            >
              {active && <span aria-hidden="true" className="hg-active-bar absolute inset-y-2 left-0 w-0.5 rounded-full bg-brand" />}
              <span aria-hidden="true" className={cx('flex', active && 'text-brand')}>
                {item.icon}
              </span>
              <span className="flex-1 truncate text-left max-[1180px]:sr-only">{item.label}</span>
              {count !== undefined && count > 0 && (
                <span className="tabular rounded-sm bg-surface-3 px-1.5 py-px font-mono text-2xs text-fg-subtle max-[1180px]:hidden">
                  {formatCount(count, locale)}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="border-t border-line p-3 max-[1180px]:hidden">
        <div role="status" aria-live="polite">
          <div className="flex items-center gap-2 text-xs">
            <span aria-hidden="true" className={cx('h-2 w-2 rounded-full', online ? 'bg-brand' : 'bg-danger')} />
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
    <header className="flex h-12 shrink-0 items-center justify-between gap-4 border-b border-line bg-surface px-6">
      <div className="flex min-w-0 items-baseline gap-2.5">
        <h1 id="view-title" tabIndex={-1} className="w-fit shrink-0 text-base font-semibold text-fg focus:outline-none">
          {item.title}
        </h1>
        <p className="truncate text-xs text-fg-subtle max-[1100px]:hidden">{item.description}</p>
      </div>
      <div role="toolbar" aria-label={t('shell.quickControlsAria')} className="flex shrink-0 items-center gap-3">
        <div role="group" aria-label={t('shell.requestTestAria')}>
          <Button size="sm" variant="ghost" icon={<PaperPlaneTilt size={14} />} onClick={openSimulator}>
            {t('shell.simulate')}
          </Button>
        </div>
        <span role="separator" aria-orientation="vertical" className="h-5 w-px bg-line" />
        <span className="label-caps max-[1280px]:hidden" id="mode-label">
          {t('shell.modeLabel')}
        </span>
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
          <span className="h-8 w-[260px] animate-pulse rounded bg-surface-3" aria-hidden="true" />
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
    <div role="alert" className="flex items-center gap-3 border-b border-danger/40 bg-danger/10 px-6 py-2 text-sm text-danger">
      <WifiSlash aria-hidden="true" size={16} weight="bold" />
      <span className="font-medium">{t(auth ? 'shell.invalidTokenTitle' : 'shell.unreachableTitle')}</span>
      <span className="text-xs text-fg-muted">{t(auth ? 'shell.invalidTokenBody' : 'shell.unreachableBody')}</span>
    </div>
  );
}

function AuditWarning() {
  const { config, route, navigate } = useStore();
  const { t } = useI18n();
  if (!config || config.mode !== 'audit-only' || route === 'policy') return null;
  return (
    <div className="flex items-center gap-3 border-b border-warn/40 bg-warn/10 px-6 py-2 text-xs">
      <Lightning aria-hidden="true" size={14} weight="fill" className="text-warn" />
      <span className="font-medium text-warn">{t('shell.auditBannerTitle')}</span>
      <span className="text-fg-muted">{t('shell.auditBannerBody')}</span>
      <button type="button" onClick={() => navigate('policy')} className="ml-auto cursor-pointer font-medium text-fg underline-offset-2 hover:underline">
        {t('shell.auditBannerAction')}
      </button>
    </div>
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
        'inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-px font-mono text-2xs max-[1000px]:hidden',
        online ? 'border-brand/30 bg-brand/10 text-brand' : 'border-line bg-surface-2 text-fg-subtle',
      )}
    >
      <span aria-hidden="true" className={cx('h-1.5 w-1.5 rounded-full', online ? 'bg-brand' : 'bg-danger')} />
      127.0.0.1:{config?.proxyPort ?? 18787}
    </span>
  );

  return (
    <WindowFrame title={t('shell.appName')} badge={status ? `v${status.version}` : undefined} statusSlot={statusChip} minWidthClass="min-w-[960px]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-12 focus:z-[70] focus:rounded focus:border focus:border-line-strong focus:bg-surface focus:px-3 focus:py-2 focus:text-sm"
      >
        {t('shell.skipToContent')}
      </a>
      <div className="flex min-h-0 flex-1">
        <Sidebar navItems={navItems} />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar navItems={navItems} />
          <ConnectionBanner />
          <AuditWarning />
          <Main />
        </div>
      </div>
      <SimulateDialog open={simulatorOpen} onClose={closeSimulator} />
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
