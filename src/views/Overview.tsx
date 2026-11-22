import { useMemo, type ReactNode } from 'react';
import { ArrowRight, Check, Minus, ArrowsLeftRight, Plugs } from '@phosphor-icons/react';
import { useStore } from '../store';
import { Badge, Button, CopyButton, EmptyState, Panel, Skeleton, cx } from '../components/ui';
import {
  HARNESS_ORDER,
  describeAction,
  formatCount,
  formatLatency,
  getCategoryLabel,
  getCoverThemeLabel,
  getHarnessLabel,
  getModeLabel,
  getPolicyLabel,
  proxyBase,
} from '../lib/format';
import { useI18n } from '../lib/i18n';
import type { HarnessKind, HarnessProfile, TrafficSummary } from '../types';
import { SeverityBadge } from './Traffic';

function Metric({ label, value, hint, tone }: { label: string; value: number | undefined; hint: string; tone?: 'brand' | 'warn' }) {
  const { locale } = useI18n();
  return (
    <div className="min-w-0 bg-surface px-5 py-4">
      <p className="label-caps">{label}</p>
      {value === undefined ? (
        <Skeleton className="mt-2 h-7 w-16" />
      ) : (
        <p className={cx('tabular mt-1 font-mono text-2xl font-semibold', tone === 'brand' ? 'text-brand' : tone === 'warn' ? 'text-warn' : 'text-fg')}>
          {formatCount(value, locale)}
        </p>
      )}
      <p className="mt-0.5 truncate text-xs text-fg-subtle">{hint}</p>
    </div>
  );
}

function ProtectionRow({ on, label, detail }: { on: boolean; label: string; detail: ReactNode }) {
  const { t } = useI18n();
  return (
    <li className="flex items-start gap-3 px-4 py-2.5">
      <span
        aria-hidden="true"
        className={cx('mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm', on ? 'bg-brand/15 text-brand' : 'bg-surface-3 text-fg-subtle')}
      >
        {on ? <Check size={11} weight="bold" /> : <Minus size={11} weight="bold" />}
      </span>
      <div className="min-w-0">
        <p className="text-sm text-fg">
          {label}
          <span className="sr-only">{t(on ? 'overview.enabledSr' : 'overview.disabledSr')}</span>
        </p>
        <p className="text-xs text-fg-subtle">{detail}</p>
      </div>
    </li>
  );
}

export function Overview() {
  const { status, config, logs, harnesses, navigate, openSimulator } = useStore();
  const { locale, t } = useI18n();
  const { liveCount, recent, liveByHarness, profileByKind } = useMemo(() => {
    const byHarness = new Map<HarnessKind, { count: number; latest?: TrafficSummary }>();
    let count = 0;
    for (const l of logs) {
      if (l.simulated) continue;
      count += 1;
      const entry = byHarness.get(l.harness);
      if (entry) {
        entry.count += 1;
      } else {
        byHarness.set(l.harness, { count: 1, latest: l });
      }
    }
    const profiles = new Map<HarnessKind, HarnessProfile>();
    for (const h of harnesses) {
      profiles.set(h.kind, h);
    }
    return {
      liveCount: count,
      recent: logs.slice(0, 8),
      liveByHarness: byHarness,
      profileByKind: profiles,
    };
  }, [logs, harnesses]);
  const base = config ? proxyBase(config.proxyPort) : null;
  const protecting = Boolean(config && config.mode !== 'audit-only');
  const telemetryBlocked =
    Boolean(protecting && config && (config.blockSilentTelemetry || (config.mode === 'all-hide' && config.allHide.enableTelemetryChaff)));
  const simCount = logs.length - liveCount;

  return (
    <div className="mx-auto max-w-[1360px] space-y-5 p-6">
      <section aria-label={t('overview.metricsAria')} className="grid grid-cols-3 gap-px overflow-hidden rounded-md border border-line bg-line xl:grid-cols-6">
        <Metric label={t('overview.metricRequests')} value={status?.totalRequests} hint={t('overview.metricRequestsHint')} />
        <Metric
          label={t('overview.metricFindings')}
          value={status?.totalFindings}
          hint={t(protecting ? 'overview.metricFindingsMaskedHint' : 'overview.metricFindingsAuditHint')}
          tone={protecting ? 'brand' : 'warn'}
        />
        <Metric label={t('overview.metricRestored')} value={status?.totalRestored} hint={t('overview.metricRestoredHint')} tone="brand" />
        <Metric label={t('overview.metricWithheld')} value={status?.totalWithheld} hint={t('overview.metricWithheldHint')} />
        <Metric
          label={t('overview.metricBlocked')}
          value={status?.totalBlocked}
          hint={t('overview.metricBlockedHint')}
          tone={status?.totalBlocked ? 'warn' : undefined}
        />
        <Metric label={t('overview.metricVault')} value={status?.activeVaultTokens} hint={t('overview.metricVaultHint')} />
      </section>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel
          title={t('overview.recentTitle')}
          description={t('overview.recentDesc', { live: liveCount, sim: simCount })}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate('traffic')}>
              {t('overview.viewAllTraffic')} <ArrowRight aria-hidden="true" size={13} />
            </Button>
          }
        >
          {recent.length === 0 ? (
            <EmptyState
              icon={<ArrowsLeftRight size={20} />}
              title={t('overview.noTrafficTitle')}
              action={
                <div className="flex gap-2">
                  <Button size="sm" variant="primary" onClick={() => navigate('integrations')}>
                    {t('overview.connectTools')}
                  </Button>
                  <Button size="sm" onClick={openSimulator}>
                    {t('overview.simulateRequest')}
                  </Button>
                </div>
              }
            >
              {t('overview.noTrafficBody')}
            </EmptyState>
          ) : (
            <table className="w-full table-fixed text-left text-xs">
              <thead>
                <tr className="border-b border-line text-2xs text-fg-subtle">
                  <th scope="col" className="w-24 px-4 py-2 font-medium">{t('overview.colTime')}</th>
                  <th scope="col" className="w-28 px-2 py-2 font-medium">{t('overview.colTool')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('overview.colEndpoint')}</th>
                  <th scope="col" className="w-24 px-2 py-2 font-medium">{t('overview.colAction')}</th>
                  <th scope="col" className="w-20 px-2 py-2 text-right font-medium">{t('overview.colFindings')}</th>
                  <th scope="col" className="w-20 px-4 py-2 text-right font-medium">{t('overview.colLatency')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {recent.map((r) => {
                  const action = describeAction(r.actionTaken, locale);
                  return (
                    <tr key={r.id} className="cursor-pointer transition-colors hover:bg-surface-2" onClick={() => navigate('traffic', { id: r.id })}>
                      <td className="tabular px-4 py-2 font-mono text-fg-muted">{r.timestamp.slice(0, 8)}</td>
                      <td className="truncate px-2 py-2 text-fg">
                        {getHarnessLabel(r.harness, locale)}
                        {r.simulated && <span className="ml-1.5 text-2xs text-info">{t('overview.simulatedTag')}</span>}
                      </td>
                      <td className="truncate px-2 py-2 font-mono text-fg-muted">
                        <button
                          type="button"
                          className="max-w-full truncate text-left hover:text-fg"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate('traffic', { id: r.id });
                          }}
                        >
                          {r.endpoint}
                        </button>
                      </td>
                      <td className="px-2 py-2">
                        <Badge tone={action.tone}>{action.label}</Badge>
                      </td>
                      <td className="px-2 py-2 text-right">
                        {r.findingCount > 0 ? <SeverityBadge severity={r.topSeverity} count={r.findingCount} /> : <span className="text-fg-subtle">{t('common.none')}</span>}
                      </td>
                      <td className="tabular px-4 py-2 text-right font-mono text-fg-muted">{formatLatency(r.latencyMs)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel
          title={t('overview.scopeTitle')}
          description={config ? t('overview.scopeCurrentMode', { mode: getModeLabel(config.mode, locale) }) : t('common.loading')}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate('policy')}>
              {t('overview.scopeConfigure')}
            </Button>
          }
        >
          {config ? (
            <ul className="divide-y divide-line">
              <ProtectionRow
                on={protecting && config.protectSecretsAndKeys}
                label={t('overview.scopeSecrets')}
                detail={t('overview.scopeSecretsDetail')}
              />
              <ProtectionRow
                on={protecting && config.protectProjectPaths}
                label={t('overview.scopePaths')}
                detail={t('overview.scopePathsDetail')}
              />
              <ProtectionRow
                on={protecting && config.protectInternalNetwork}
                label={t('overview.scopeNetwork')}
                detail={t('overview.scopeNetworkDetail')}
              />
              <ProtectionRow
                on={telemetryBlocked}
                label={t('overview.scopeTelemetry')}
                detail={t('overview.scopeTelemetryDetail')}
              />
              <ProtectionRow
                on={protecting}
                label={t('overview.scopeToolSecrets')}
                detail={getPolicyLabel(config.toolCallSecretPolicy, locale)}
              />
              <ProtectionRow
                on={config.mode === 'all-hide'}
                label={t('overview.scopeAllHide')}
                detail={
                  config.mode === 'all-hide'
                    ? t('overview.scopeAllHideDetail', { theme: getCoverThemeLabel(config.allHide.coverTheme, locale) })
                    : t('overview.scopeDisabled')
                }
              />
            </ul>
          ) : (
            <div className="space-y-3 p-4">
              {Array.from({ length: 5 }, (_, i) => (
                <Skeleton key={i} className="h-8" />
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel title={t('overview.activityTitle')} description={t('overview.activityDesc')}>
          <ul className="grid grid-cols-2 gap-px bg-line lg:grid-cols-4">
            {HARNESS_ORDER.map((kind) => {
              const summary = liveByHarness.get(kind);
              const count = summary?.count ?? 0;
              const latest = summary?.latest;
              const profile = profileByKind.get(kind);
              const auditInfo = status?.harnessAudit?.find((h) => h.harness === kind);
              const hasRisk = Boolean(
                auditInfo && (auditInfo.telemetryEvents > 0 || auditInfo.bulkUploadEvents > 0 || auditInfo.sensitiveExfilEvents > 0),
              );
              return (
                <li key={kind} className="bg-surface">
                  <button
                    type="button"
                    onClick={() => navigate('integrations', { tool: kind })}
                    className="block w-full cursor-pointer px-4 py-3 text-left transition-colors hover:bg-surface-2"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        aria-hidden="true"
                        className={cx('h-1.5 w-1.5 rounded-full', hasRisk ? 'bg-warn' : count ? 'bg-brand' : 'bg-line-strong')}
                      />
                      <span className="truncate text-sm text-fg">{getHarnessLabel(kind, locale)}</span>
                    </div>
                    <p className="tabular mt-1 font-mono text-lg font-semibold text-fg">{count}</p>
                    <p className="truncate text-2xs text-fg-subtle">
                      {latest
                        ? `${latest.timestamp.slice(0, 8)} · ${getCategoryLabel(latest.category, locale)}`
                        : profile
                          ? t('overview.activityNoTraffic')
                          : t('common.none')}
                    </p>
                  </button>
                </li>
              );
            })}
            <li className="flex items-center bg-surface px-4 py-3">
              <Button size="sm" variant="ghost" icon={<Plugs size={14} />} onClick={() => navigate('integrations')}>
                {t('overview.integrationGuide')}
              </Button>
            </li>
          </ul>
        </Panel>

        <Panel title={t('overview.endpointsTitle')} description={t('overview.endpointsDesc')}>
          <div className="space-y-2 p-4">
            {base
              ? [
                  { slug: 'claude-code', path: '/claude-code' },
                  { slug: 'codex', path: '/codex/v1' },
                  { slug: 'grok-build', path: '/grok-build/v1' },
                ].map(({ slug, path }) => (
                  <div key={slug} className="flex items-center gap-2 rounded border border-line bg-surface-2 py-1 pl-3 pr-1">
                    <code className="min-w-0 flex-1 truncate font-mono text-xs text-fg">{`${base}${path}`}</code>
                    <CopyButton compact text={`${base}${path}`} label={t('overview.copyEndpoint', { slug })} />
                  </div>
                ))
              : Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-8" />)}
            <p className="pt-1 text-xs text-fg-subtle">{t('overview.loopbackOnly')}</p>
          </div>
        </Panel>
      </div>
    </div>
  );
}
