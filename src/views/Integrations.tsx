import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { ArrowsClockwise, ArrowRight, CheckCircle, DownloadSimple, LinkBreak, LinkSimple, Play, Plus, ShieldCheck, Terminal, X } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { Badge, Button, Callout, CopyButton, Segmented, Skeleton, Switch, cx, inputClass, useToast } from '../components/ui';
import { formatCount, getPurposeLabel, getPurposeTone, proxyBase } from '../lib/format';
import { localizeHarnessIntegrationNote, localizeHarnessTargets, translate, useI18n, type Locale } from '../lib/i18n';
import type { CaStatus, HarnessKind, HarnessProfile, MitmHostsResponse } from '../types';
import { useSimulate } from './SimulateDialog';

type Shell = 'bash' | 'powershell';

const FALLBACK_TARGETS: Partial<Record<HarnessProfile['kind'], string[]>> = {
  'claude-code': ['~/.claude/settings.json'],
  codex: ['~/.codex/config.toml ([model_providers.*].base_url)', '环境变量 OPENAI_BASE_URL'],
  antigravity: ['系统代理链（运行期接管，退出自动还原）', 'Antigravity User/settings.json', '环境变量 HTTPS_PROXY / NODE_EXTRA_CA_CERTS'],
  zcode: ['环境变量 ZCODE_HTTP_PROXY / ZCODE_AGENT_CA_CERT / HTTPS_PROXY / NODE_EXTRA_CA_CERTS'],
  qoder: ['Qoder/User/settings.json', 'QoderCN/User/settings.json', '环境变量 NODE_EXTRA_CA_CERTS'],
  cursor: ['Cursor/User/settings.json', '环境变量 NODE_EXTRA_CA_CERTS'],
  'grok-build': ['环境变量 GROK_XAI_API_BASE_URL / HTTPS_PROXY / NODE_EXTRA_CA_CERTS'],
};

function describeAutoConnectMode(profile: HarnessProfile, locale: Locale): string {
  const rawTargets =
    profile.autoConnectTargets && profile.autoConnectTargets.length > 0
      ? profile.autoConnectTargets
      : (FALLBACK_TARGETS[profile.kind] ?? []);
  const targets = localizeHarnessTargets(rawTargets, locale);
  const sep = locale === 'zh-CN' ? '、' : ', ';
  const targetText = targets.join(sep);

  if (profile.autoConnectMode === 'configFile') {
    return targetText
      ? translate(locale, 'integrations.modeConfig', { targets: targetText })
      : translate(locale, 'integrations.modeConfigGeneric');
  }
  if (profile.autoConnectMode === 'envVar') {
    return targetText
      ? translate(locale, 'integrations.modeEnv', { targets: targetText })
      : translate(locale, 'integrations.modeEnvGeneric');
  }
  return translate(locale, 'integrations.modeManual');
}

function CaTrustCard({
  caStatus,
  caError,
  mitmHosts,
  savingConfig,
  busy,
  exporting,
  onTrust,
  onUntrust,
  onExport,
  onRetry,
  onToggleSystemProxy,
  onAddMitmHost,
  onRemoveMitmHost,
}: {
  caStatus: CaStatus | null;
  caError: string | null;
  mitmHosts: MitmHostsResponse | null;
  savingConfig: boolean;
  busy: boolean;
  exporting: boolean;
  onTrust: () => void;
  onUntrust: () => void;
  onExport: () => void;
  onRetry: () => void;
  onToggleSystemProxy: (enabled: boolean) => void;
  onAddMitmHost: (host: string) => void;
  onRemoveMitmHost: (host: string) => void;
}) {
  const { locale, t } = useI18n();
  const [hostInput, setHostInput] = useState('');
  const extraHosts = mitmHosts?.mitmExtraHosts ?? [];
  const observedHosts = mitmHosts?.observedHosts ?? [];

  const submitHost = () => {
    const clean = hostInput.trim().toLowerCase();
    if (!clean) return;
    onAddMitmHost(clean);
    setHostInput('');
  };
  return (
    <section aria-label={t('integrations.caSectionAria')} className="mx-auto max-w-3xl px-8 pt-6">
      <div className="rounded-md border border-line bg-surface-2 px-4 py-3.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <ShieldCheck
              aria-hidden="true"
              size={18}
              weight={caStatus?.installedInOsStore ? 'fill' : 'regular'}
              className={caStatus?.installedInOsStore ? 'shrink-0 text-brand' : 'shrink-0 text-warn'}
            />
            <h2 className="truncate text-sm font-semibold text-fg">{t('integrations.caTitle')}</h2>
            {!caStatus ? (
              caError ? (
                <Badge tone="danger" dot>
                  {t('integrations.caFetchFailed')}
                </Badge>
              ) : (
                <Skeleton className="h-5 w-24" />
              )
            ) : !caStatus.ready ? (
              <Badge tone="danger" dot>
                {t('integrations.caNotReady')}
              </Badge>
            ) : caStatus.installedInOsStore ? (
              <Badge tone="brand" dot>
                {t('integrations.caTrusted')}
              </Badge>
            ) : (
              <Badge tone="warn" dot>
                {t('integrations.caNeedsTrust')}
              </Badge>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {caError && (
              <Button size="sm" variant="ghost" onClick={onRetry}>
                {t('common.retry')}
              </Button>
            )}
            {caStatus && !caStatus.installedInOsStore && (
              <Button
                size="sm"
                variant="primary"
                icon={<ShieldCheck size={14} />}
                disabled={busy || !caStatus.ready || !caStatus.osTrustSupported}
                onClick={onTrust}
              >
                {t('integrations.caTrustBtn')}
              </Button>
            )}
            {caStatus && caStatus.installedInOsStore && (
              <Button size="sm" variant="secondary" icon={<LinkBreak size={14} />} disabled={busy} onClick={onUntrust}>
                {t('integrations.caUntrustBtn')}
              </Button>
            )}
            <Button
              size="sm"
              variant="secondary"
              icon={<DownloadSimple size={14} />}
              disabled={exporting || !caStatus?.ready}
              onClick={onExport}
            >
              {t('integrations.caExportBtn')}
            </Button>
          </div>
        </div>

        {caError ? (
          <p role="alert" className="mt-2.5 text-xs text-danger">
            {caError}
          </p>
        ) : caStatus && (!caStatus.installedInOsStore || !caStatus.osTrustSupported) ? (
          <div className="mt-3 space-y-1.5 border-t border-line pt-2.5 text-xs">
            <div className="flex items-center justify-between gap-3">
              <span className="shrink-0 text-fg-subtle">{t('integrations.caPathLabel')}</span>
              <div className="flex min-w-0 items-center gap-1">
                <code className="truncate font-mono text-fg-muted" title={caStatus.caCertPath}>
                  {caStatus.caCertPath}
                </code>
                <CopyButton compact text={caStatus.caCertPath} label={t('integrations.caCopyPath')} />
              </div>
            </div>
            {!caStatus.osTrustSupported && (
              <p className="text-warn">{caStatus.osTrustDetail || t('integrations.caManualFallback')}</p>
            )}
          </div>
        ) : null}

        <details className="mt-2.5 border-t border-line pt-2 text-2xs text-fg-subtle">
          <summary className="cursor-pointer select-none hover:text-fg-muted">
            {t('integrations.caSummary')}
          </summary>
          <div className="mt-2 space-y-1.5">
            <p className="leading-5">
              {t('integrations.caHostsBefore')}
              <code className="font-mono text-fg-muted">api.openai.com</code>
              {', '}
              <code className="font-mono text-fg-muted">api.anthropic.com</code>
              {', '}
              <code className="font-mono text-fg-muted">generativelanguage.googleapis.com</code>
              {', '}
              <code className="font-mono text-fg-muted">cloudcode-pa.googleapis.com</code>
              {', '}
              <code className="font-mono text-fg-muted">api2.cursor.sh</code>
              {', '}
              <code className="font-mono text-fg-muted">*.qoder.*</code>
              {', '}
              <code className="font-mono text-fg-muted">api.x.ai</code>
              {t('integrations.caHostsAfter')}
            </p>
            {mitmHosts?.systemProxySupported && (
              <div className="flex items-center justify-between gap-3 border-t border-line pt-2 text-xs">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="truncate text-fg-muted">{t('integrations.sysProxyLabel')}</span>
                  <Badge tone={mitmHosts.systemProxyActive ? 'brand' : 'neutral'} dot>
                    {t(mitmHosts.systemProxyActive ? 'integrations.sysProxyActive' : 'integrations.sysProxyInactive')}
                  </Badge>
                </div>
                <Switch
                  checked={mitmHosts.systemProxyChain}
                  disabled={savingConfig}
                  label={t('integrations.sysProxyLabel')}
                  onChange={onToggleSystemProxy}
                />
              </div>
            )}
            <div className="space-y-2 border-t border-line pt-2 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-fg-subtle">{t('integrations.customMitmHostsLabel')}</span>
                <div className="flex items-center gap-1.5">
                  <input
                    type="text"
                    value={hostInput}
                    onChange={(e) => setHostInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        submitHost();
                      }
                    }}
                    placeholder={t('integrations.customMitmHostPlaceholder')}
                    className={cx(inputClass, 'h-7 w-56 font-mono text-xs')}
                  />
                  <Button size="sm" variant="secondary" icon={<Plus size={12} />} disabled={savingConfig || !hostInput.trim()} onClick={submitHost}>
                    {t('integrations.addHostBtn')}
                  </Button>
                </div>
              </div>
              {extraHosts.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {extraHosts.map((h) => (
                    <span
                      key={h}
                      className="inline-flex items-center gap-1 rounded border border-line bg-surface px-2 py-0.5 font-mono text-2xs text-fg"
                    >
                      {h}
                      <button
                        type="button"
                        aria-label={t('integrations.removeHostAria', { host: h })}
                        onClick={() => onRemoveMitmHost(h)}
                        disabled={savingConfig}
                        className="cursor-pointer text-fg-subtle hover:text-danger disabled:opacity-50"
                      >
                        <X size={11} />
                      </button>
                    </span>
                  ))}
                </div>
              )}
              <div className="space-y-1.5 border-t border-line pt-2">
                <span className="text-fg-subtle">{t('integrations.observedHostsLabel')}</span>
                {observedHosts.length === 0 ? (
                  <p className="text-2xs text-fg-subtle">{t('integrations.observedEmpty')}</p>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {observedHosts.slice(0, 12).map((item) => {
                      const alreadyExtra = extraHosts.some((e) => e.toLowerCase() === item.host.toLowerCase());
                      return (
                        <span
                          key={`${item.host}:${item.port}`}
                          className="inline-flex items-center gap-1.5 rounded border border-line bg-surface px-2 py-0.5 text-2xs"
                        >
                          <code className="font-mono text-fg-muted">{item.host}</code>
                          {item.purpose && item.purpose !== 'other-api' && item.purpose !== 'chat-inference' && (
                            <Badge tone={getPurposeTone(item.purpose)}>
                              {getPurposeLabel(item.purpose, locale)}
                            </Badge>
                          )}
                          {item.riskKind === 'telemetry' && !item.purpose && (
                            <Badge tone="warn">{t('integrations.observedTelemetryBadge')}</Badge>
                          )}
                          {item.riskKind === 'upload-storage' && !item.purpose && (
                            <Badge tone="warn">{t('integrations.observedUploadBadge')}</Badge>
                          )}
                          {item.tlsFailed ? (
                            <Badge tone="danger">{t('integrations.observedTlsFailed')}</Badge>
                          ) : item.mitm ? (
                            <Badge tone="brand">{t('integrations.observedMitmBadge')}</Badge>
                          ) : !alreadyExtra ? (
                            <button
                              type="button"
                              disabled={savingConfig}
                              onClick={() => onAddMitmHost(item.host)}
                              className="inline-flex cursor-pointer items-center gap-0.5 font-medium text-brand hover:underline disabled:opacity-50"
                            >
                              <Plus size={10} />
                              {t('integrations.observedAddMitm')}
                            </button>
                          ) : null}
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
            {caStatus && (
              <div className="space-y-1 border-t border-line pt-2 text-xs">
                <div className="flex items-center justify-between gap-3">
                  <span className="shrink-0 text-fg-subtle">{t('integrations.caFingerprintLabel')}</span>
                  <div className="flex min-w-0 items-center gap-1">
                    <code className="truncate font-mono text-fg-muted" title={caStatus.fingerprintSha256}>
                      {caStatus.fingerprintSha256}
                    </code>
                    <CopyButton compact text={caStatus.fingerprintSha256} label={t('integrations.caCopyFingerprint')} />
                  </div>
                </div>
                {caStatus.installedInOsStore && caStatus.osTrustSupported && (
                  <div className="flex items-center justify-between gap-3">
                    <span className="shrink-0 text-fg-subtle">{t('integrations.caPathLabel')}</span>
                    <div className="flex min-w-0 items-center gap-1">
                      <code className="truncate font-mono text-fg-muted" title={caStatus.caCertPath}>
                        {caStatus.caCertPath}
                      </code>
                      <CopyButton compact text={caStatus.caCertPath} label={t('integrations.caCopyPath')} />
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </details>
      </div>
    </section>
  );
}

function Block({ index, title, aside, children }: { index: string; title: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="border-t border-line py-6">
      <div className="mb-3 flex min-h-7 items-center gap-3">
        <span className="tabular font-mono text-2xs text-fg-subtle">{index}</span>
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        {aside && <div className="ml-auto">{aside}</div>}
      </div>
      {children}
    </section>
  );
}

function ToolDetail({
  profile,
  port,
  liveCount,
  shell,
  caStatus,
  caBusy,
  onTrustCa,
  onShell,
  onRefresh,
}: {
  profile: HarnessProfile;
  port: number;
  liveCount: number;
  shell: Shell;
  caStatus: CaStatus | null;
  caBusy: boolean;
  onTrustCa: () => void;
  onShell: (s: Shell) => void;
  onRefresh: () => Promise<unknown>;
}) {
  const { navigate } = useStore();
  const { locale, t } = useI18n();
  const toast = useToast();
  const { run, busy: simBusy } = useSimulate();
  const [connecting, setConnecting] = useState(false);

  const entry = `${proxyBase(port)}${profile.localProxyRoute}`;
  const snippet = shell === 'bash' ? profile.envSetupBash : profile.envSetupPowershell;
  const effectiveTraffic = Math.max(liveCount, profile.trafficCount);
  const integrationNote = localizeHarnessIntegrationNote(profile.kind, profile.integrationNote, locale);

  const handleConnect = async () => {
    setConnecting(true);
    try {
      const res = await api.connectHarness(profile.kind);
      toast.push({
        tone: res.ok ? 'brand' : 'warn',
        title: res.ok ? t('integrations.connectedToast', { name: profile.name }) : t('integrations.cannotAutoToast'),
        body: res.message,
      });
      await onRefresh();
    } catch (e) {
      toast.push({ tone: 'danger', title: t('integrations.connectFailedToast'), body: (e as Error).message });
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    setConnecting(true);
    try {
      const res = await api.disconnectHarness(profile.kind);
      toast.push({
        tone: res.ok ? 'brand' : 'danger',
        title: res.ok ? t('integrations.disconnectedToast', { name: profile.name }) : t('integrations.disconnectFailedToast'),
        body: res.message,
      });
      await onRefresh();
    } catch (e) {
      toast.push({ tone: 'danger', title: t('integrations.disconnectFailedToast'), body: (e as Error).message });
    } finally {
      setConnecting(false);
    }
  };

  const timeSuffix = profile.lastSeenAt
    ? locale === 'zh-CN'
      ? `（${profile.lastSeenAt}）`
      : ` (${profile.lastSeenAt})`
    : '';

  return (
    <article className="mx-auto max-w-3xl px-8 pb-10 pt-5">
      <header className="pb-5">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold text-fg">{profile.name}</h2>
          {profile.autoConnectMode === 'manual' ? (
            <Badge tone="neutral">{t('integrations.transportLimited')}</Badge>
          ) : profile.requiresCaTrust ? (
            <Badge tone={caStatus?.installedInOsStore ? 'brand' : 'warn'}>
              {t(caStatus?.installedInOsStore ? 'integrations.transportMitmTrusted' : 'integrations.transportMitmUntrusted')}
            </Badge>
          ) : (
            <Badge tone="brand">{t('integrations.transportBaseUrl')}</Badge>
          )}
          {profile.installed ? (
            <Badge tone="brand">{t('integrations.badgeInstalled')}</Badge>
          ) : (
            <Badge>{t('integrations.badgeNotInstalled')}</Badge>
          )}
          {profile.configured ? (
            <Badge tone="brand" dot>
              {t('integrations.badgeConfigured')}
            </Badge>
          ) : (
            <Badge dot>{t('integrations.badgeNotConfigured')}</Badge>
          )}
          {profile.detectedActive && (
            <Badge tone="info" dot>
              {t('integrations.badgeLiveTraffic', { count: formatCount(effectiveTraffic, locale) })}
            </Badge>
          )}
        </div>
        <p className="mt-1 text-xs text-fg-subtle">{profile.protocolFamily}</p>
        {integrationNote && (
          <div className="mt-4">
            <Callout
              tone={profile.autoConnectMode === 'manual' ? 'warn' : 'info'}
              title={t(profile.autoConnectMode === 'manual' ? 'integrations.calloutManual' : 'integrations.calloutAuto')}
            >
              {integrationNote}
            </Callout>
          </div>
        )}
        {profile.configured && profile.requiresCaTrust && caStatus && !caStatus.installedInOsStore && (
          <div className="mt-4">
            <Callout
              tone="warn"
              title={t('integrations.caWarnTitle')}
              action={
                <Button
                  size="sm"
                  variant="primary"
                  icon={<ShieldCheck size={14} />}
                  disabled={caBusy || !caStatus.ready || !caStatus.osTrustSupported}
                  onClick={onTrustCa}
                >
                  {t('integrations.caWarnInstallBtn')}
                </Button>
              }
            >
              {caStatus.osTrustSupported
                ? t('integrations.caWarnBodySupported', { name: profile.name })
                : t('integrations.caWarnBodyUnsupported')}
            </Callout>
          </div>
        )}
      </header>

      <Block
        index="01"
        title={t('integrations.blockConnectTitle')}
        aside={
          (profile.autoConnectMode !== 'manual' || profile.configured) && (
            <div className="flex items-center gap-2">
              {profile.autoConnectMode !== 'manual' && (
                <Button
                  size="sm"
                  variant={profile.configured ? 'secondary' : 'primary'}
                  icon={<LinkSimple size={14} />}
                  disabled={connecting}
                  onClick={handleConnect}
                >
                  {t(profile.configured ? 'integrations.reapplyConfig' : 'integrations.autoConnect')}
                </Button>
              )}
              {profile.configured && (
                <Button size="sm" icon={<LinkBreak size={14} />} disabled={connecting} onClick={handleDisconnect}>
                  {t('integrations.disconnect')}
                </Button>
              )}
            </div>
          )
        }
      >
        <div className="space-y-3 rounded-md border border-line bg-surface-2 px-4 py-3 text-xs">
          <div className="flex items-start justify-between gap-4">
            <span className="shrink-0 text-fg-subtle">{t('integrations.connectMethod')}</span>
            <span className="text-right text-fg">{describeAutoConnectMode(profile, locale)}</span>
          </div>
          {profile.requiresCaTrust && (
            <div className="flex items-start justify-between gap-4 border-t border-line pt-2.5">
              <span className="shrink-0 text-fg-subtle">{t('integrations.tlsCertLabel')}</span>
              <span className={cx('text-right font-mono', caStatus?.installedInOsStore ? 'text-brand' : 'text-warn')}>
                {caStatus?.installedInOsStore
                  ? t('integrations.caTrusted')
                  : caStatus && !caStatus.osTrustSupported
                    ? t('integrations.tlsCertManual')
                    : t('integrations.tlsCertUntrusted')}
              </span>
            </div>
          )}
          <div className="flex items-start justify-between gap-4 border-t border-line pt-2.5">
            <span className="shrink-0 text-fg-subtle">{t('integrations.currentStateLabel')}</span>
            <span className={cx('text-right font-mono', profile.configured ? 'text-brand' : 'text-fg-muted')}>
              {profile.configured
                ? t('integrations.stateActiveVia', { via: profile.configuredVia ?? entry })
                : t('integrations.stateNotRouted')}
            </span>
          </div>
          <div className="flex items-start justify-between gap-4 border-t border-line pt-2.5">
            <span className="shrink-0 text-fg-subtle">{t('integrations.detectedPathsLabel')}</span>
            <div className="min-w-0 text-right font-mono text-fg-muted">
              {profile.installPaths.length > 0 ? (
                profile.installPaths.map((p) => (
                  <div key={p} className="truncate" title={p}>
                    {p}
                  </div>
                ))
              ) : (
                <span>{t('integrations.noDetectedPaths')}</span>
              )}
            </div>
          </div>
        </div>
      </Block>

      <Block index="02" title={t('integrations.blockRouteTitle')}>
        <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-stretch rounded-md border border-line">
          <div className="min-w-0 py-3 pl-4 pr-2">
            <p className="label-caps">{t('integrations.localEntryLabel')}</p>
            <div className="mt-1 flex items-center gap-1">
              <code className="min-w-0 truncate font-mono text-sm text-brand" title={entry}>
                {entry}
              </code>
              <CopyButton compact text={entry} label={t('integrations.copyEntry')} />
            </div>
          </div>
          <span aria-hidden="true" className="flex items-center px-2 text-fg-subtle">
            <ArrowRight size={16} />
          </span>
          <div className="min-w-0 border-l border-line px-4 py-3">
            <p className="label-caps">{t('integrations.forwardToLabel')}</p>
            <code className="mt-1 block truncate py-1 font-mono text-sm text-fg-muted" title={profile.defaultUpstream}>
              {profile.defaultUpstream}
            </code>
          </div>
        </div>
        <p className="mt-2 text-xs leading-5 text-fg-subtle">
          {t('integrations.customUpstreamHintBefore')}
          <code className="font-mono text-fg-muted">HIDE_GO_UPSTREAM_URL</code>
          {t('integrations.customUpstreamHintMid')}
          <code className="font-mono text-fg-muted">X-Hide-Go-Upstream</code>
        </p>
      </Block>

      <Block
        index="03"
        title={t('integrations.blockEnvTitle')}
        aside={
          <Segmented
            size="sm"
            label={t('integrations.shellTypeAria')}
            value={shell}
            onChange={onShell}
            options={[
              { value: 'bash', label: 'Bash / Zsh' },
              { value: 'powershell', label: 'PowerShell' },
            ]}
          />
        }
      >
        <div className="overflow-hidden rounded-md border border-line">
          <div className="flex h-9 items-center gap-2 border-b border-line bg-surface-2 pl-3 pr-1">
            <Terminal aria-hidden="true" size={14} className="shrink-0 text-fg-subtle" />
            <span className="truncate text-xs text-fg-subtle">{t('integrations.currentShellOnly')}</span>
            <span className="ml-auto">
              <CopyButton compact text={snippet} label={t('integrations.copySnippet')} />
            </span>
          </div>
          <pre tabIndex={0} className="overflow-x-auto px-4 py-3 font-mono text-xs leading-6 text-fg">
            {snippet}
          </pre>
        </div>
      </Block>

      <Block index="04" title={t('integrations.blockVerifyTitle')}>
        {effectiveTraffic > 0 ? (
          <Callout
            tone="brand"
            title={t('integrations.capturedTrafficTitle', {
              count: formatCount(effectiveTraffic, locale),
              time: timeSuffix,
            })}
            action={
              <Button size="sm" onClick={() => navigate('traffic')}>
                {t('integrations.viewTraffic')}
              </Button>
            }
          >
            {t('integrations.capturedTrafficBody')}
          </Callout>
        ) : (
          <p className="text-sm leading-6 text-fg-muted">
            {t('integrations.verifyHint', { name: profile.name })}
          </p>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button size="sm" icon={<Play size={13} weight="fill" />} disabled={simBusy} onClick={() => run(profile.kind, 'interactive-prompt')}>
            {t('integrations.simChat')}
          </Button>
          <Button size="sm" icon={<Play size={13} weight="fill" />} disabled={simBusy} onClick={() => run(profile.kind, 'codebase-indexing')}>
            {t('integrations.simIndex')}
          </Button>
          <span className="text-xs text-fg-subtle">{t('integrations.simOfflineNote')}</span>
        </div>
      </Block>
    </article>
  );
}

export function Integrations() {
  const { harnesses, refreshHarnesses, config, saveConfig, saving, logs, params, navigate } = useStore();
  const { t } = useI18n();
  const toast = useToast();
  const [shell, setShell] = useState<Shell>(() => (/win/i.test(navigator.platform) ? 'powershell' : 'bash'));
  const [scanning, setScanning] = useState(false);
  const [connectingAll, setConnectingAll] = useState(false);
  const [caStatus, setCaStatus] = useState<CaStatus | null>(null);
  const [caError, setCaError] = useState<string | null>(null);
  const [mitmHosts, setMitmHosts] = useState<MitmHostsResponse | null>(null);
  const [caBusy, setCaBusy] = useState(false);
  const [exportingCert, setExportingCert] = useState(false);
  const selected = harnesses.find((h) => h.kind === params.get('tool')) ?? harnesses[0] ?? null;

  const refreshCaStatus = useCallback(async () => {
    try {
      const [nextCa, nextHosts] = await Promise.all([api.getCaStatus(), api.getMitmHosts().catch(() => null)]);
      setCaStatus(nextCa);
      if (nextHosts) setMitmHosts(nextHosts);
      setCaError(null);
    } catch (e) {
      setCaError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    void refreshCaStatus();
  }, [refreshCaStatus]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshHarnesses(), refreshCaStatus()]);
  }, [refreshHarnesses, refreshCaStatus]);

  const liveCounts = useMemo(() => {
    const counts = new Map<HarnessKind, number>();
    for (const l of logs) {
      if (!l.simulated) counts.set(l.harness, (counts.get(l.harness) ?? 0) + 1);
    }
    return counts;
  }, [logs]);

  const { installedCount, configuredCount } = useMemo(() => {
    let installed = 0;
    let configured = 0;
    for (const h of harnesses) {
      if (h.installed) installed += 1;
      if (h.configured) configured += 1;
    }
    return { installedCount: installed, configuredCount: configured };
  }, [harnesses]);

  if (!selected || !config) {
    return (
      <div className="grid h-full min-h-0 grid-cols-[280px_minmax(0,1fr)]" aria-busy="true">
        <div className="space-y-2 border-r border-line bg-surface p-4">
          {Array.from({ length: 7 }, (_, i) => (
            <Skeleton key={i} className="h-11" />
          ))}
        </div>
        <div className="space-y-4 bg-surface p-8">
          <Skeleton className="h-7 w-1/3" />
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-40" />
        </div>
      </div>
    );
  }

  const handleScan = async () => {
    setScanning(true);
    try {
      await refreshAll();
      toast.push({ tone: 'brand', title: t('integrations.scanDone') });
    } catch (e) {
      toast.push({ tone: 'danger', title: t('integrations.scanFailed'), body: (e as Error).message });
    } finally {
      setScanning(false);
    }
  };

  const handleConnectAll = async () => {
    setConnectingAll(true);
    try {
      const results = await api.connectAllHarnesses();
      await refreshAll();
      const succeeded = results.filter((r) => r.ok).length;
      toast.push({
        tone: succeeded > 0 ? 'brand' : 'warn',
        title: succeeded > 0 ? t('integrations.connectAllOkTitle', { count: succeeded }) : t('integrations.connectAllNoneTitle'),
        body: t(succeeded > 0 ? 'integrations.connectAllOkBody' : 'integrations.connectAllNoneBody'),
      });
    } catch (e) {
      toast.push({ tone: 'danger', title: t('integrations.connectAllFailed'), body: (e as Error).message });
    } finally {
      setConnectingAll(false);
    }
  };

  const handleTrustCa = async () => {
    setCaBusy(true);
    try {
      const next = await api.trustCa();
      setCaStatus(next);
      setCaError(null);
      toast.push({
        tone: next.installedInOsStore ? 'brand' : 'warn',
        title: t(next.installedInOsStore ? 'integrations.caTrustedToast' : 'integrations.caNotEffectiveToast'),
        body: next.osTrustDetail,
      });
    } catch (e) {
      toast.push({ tone: 'danger', title: t('integrations.caTrustFailed'), body: (e as Error).message });
    } finally {
      setCaBusy(false);
    }
  };

  const handleUntrustCa = async () => {
    setCaBusy(true);
    try {
      const next = await api.untrustCa();
      setCaStatus(next);
      setCaError(null);
      toast.push({
        tone: !next.installedInOsStore ? 'brand' : 'warn',
        title: t(!next.installedInOsStore ? 'integrations.caUntrustedToast' : 'integrations.caStillPresentToast'),
        body: next.osTrustDetail,
      });
    } catch (e) {
      toast.push({ tone: 'danger', title: t('integrations.caUntrustFailed'), body: (e as Error).message });
    } finally {
      setCaBusy(false);
    }
  };

  const handleExportCert = async () => {
    setExportingCert(true);
    try {
      const blob = await api.downloadCaCert();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'hide-go-ca.crt';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast.push({
        tone: 'brand',
        title: t('integrations.caExportedTitle'),
        body: t('integrations.caExportedBody'),
      });
    } catch (e) {
      toast.push({ tone: 'danger', title: t('integrations.caExportFailed'), body: (e as Error).message });
    } finally {
      setExportingCert(false);
    }
  };

  const handleToggleSystemProxy = async (enabled: boolean) => {
    const ok = await saveConfig({ ...config, systemProxyChain: enabled });
    if (ok) {
      await refreshCaStatus();
    }
  };

  const handleAddMitmHost = async (rawHost: string) => {
    const clean = rawHost.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]?.split(':')[0] ?? '';
    if (!clean) return;
    const prev = config.mitmExtraHosts ?? [];
    if (prev.some((h) => h.toLowerCase() === clean)) return;
    const ok = await saveConfig(
      { ...config, mitmExtraHosts: [...prev, clean] },
      t('integrations.mitmHostAdded', { host: clean }),
    );
    if (ok) {
      await refreshCaStatus();
    }
  };

  const handleRemoveMitmHost = async (host: string) => {
    const prev = config.mitmExtraHosts ?? [];
    const ok = await saveConfig(
      { ...config, mitmExtraHosts: prev.filter((h) => h.toLowerCase() !== host.toLowerCase()) },
      t('integrations.mitmHostRemoved', { host }),
    );
    if (ok) {
      await refreshCaStatus();
    }
  };

  return (
    <div className="grid h-full min-h-0 grid-cols-[280px_minmax(0,1fr)]">
      <nav aria-label={t('integrations.navAria')} className="flex min-h-0 flex-col border-r border-line bg-surface">
        <div className="border-b border-line p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="label-caps">
              {t('integrations.summaryCount', {
                installed: installedCount,
                total: harnesses.length,
                configured: configuredCount,
              })}
            </span>
            <button
              type="button"
              onClick={handleScan}
              disabled={scanning}
              title={t('integrations.scanBtnTitle')}
              className="inline-flex cursor-pointer items-center gap-1 rounded px-1.5 py-1 text-2xs text-fg-muted hover:bg-surface-2 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus/40 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <ArrowsClockwise size={13} className={scanning ? 'animate-spin' : undefined} />
              {t('integrations.scanBtn')}
            </button>
          </div>
          <Button
            size="sm"
            variant="primary"
            className="mt-2.5 w-full justify-center"
            icon={<CheckCircle size={14} />}
            disabled={connectingAll || installedCount === 0}
            onClick={handleConnectAll}
          >
            {t('integrations.connectAllBtn')}
          </Button>
        </div>
        <ul className="min-h-0 flex-1 divide-y divide-line overflow-y-auto">
          {harnesses.map((h) => {
            const active = h.kind === selected.kind;
            const statusText = h.detectedActive
              ? t('integrations.statusActive')
              : h.configured
                ? t('integrations.statusConfigured')
                : h.installed
                  ? t('integrations.statusInstalled')
                  : t('integrations.statusMissing');
            const dotTone = h.detectedActive
              ? 'bg-brand'
              : h.configured
                ? 'bg-brand-solid'
                : h.installed
                  ? 'bg-warn'
                  : 'bg-line-strong';
            return (
              <li key={h.kind}>
                <button
                  type="button"
                  onClick={() => navigate('integrations', { tool: h.kind })}
                  aria-current={active ? 'true' : undefined}
                  className={cx(
                    'relative flex w-full cursor-pointer items-center gap-3 px-4 py-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus/40',
                    active ? 'bg-brand/[0.07]' : 'hover:bg-surface-2',
                  )}
                >
                  {active && <span aria-hidden="true" className="hg-active-bar absolute inset-y-0 left-0 w-0.5 bg-brand" />}
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg">{h.name}</span>
                  <span className="inline-flex shrink-0 items-center gap-1.5 text-2xs text-fg-subtle">
                    <span aria-hidden="true" className={cx('h-1.5 w-1.5 rounded-full', dotTone)} />
                    {statusText}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="min-h-0 overflow-y-auto bg-surface">
        <CaTrustCard
          caStatus={caStatus}
          caError={caError}
          mitmHosts={mitmHosts}
          savingConfig={saving}
          busy={caBusy}
          exporting={exportingCert}
          onTrust={handleTrustCa}
          onUntrust={handleUntrustCa}
          onExport={handleExportCert}
          onRetry={refreshCaStatus}
          onToggleSystemProxy={handleToggleSystemProxy}
          onAddMitmHost={handleAddMitmHost}
          onRemoveMitmHost={handleRemoveMitmHost}
        />
        <section aria-label={t('integrations.compatTitle')} className="mx-auto max-w-3xl px-8 pt-3">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line bg-surface-2 px-4 py-2.5 text-xs">
            <span className="font-medium text-fg">{t('integrations.compatTitle')}</span>
            <div className="flex flex-wrap items-center gap-3">
              <span className="inline-flex items-center gap-1.5">
                <span className="text-fg-subtle">{t('integrations.compatOpenAi')}</span>
                <code className="font-mono text-brand">{`${proxyBase(config.proxyPort)}/codex/v1`}</code>
                <CopyButton compact text={`${proxyBase(config.proxyPort)}/codex/v1`} label={t('integrations.copyEntry')} />
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="text-fg-subtle">{t('integrations.compatAnthropic')}</span>
                <code className="font-mono text-brand">{`${proxyBase(config.proxyPort)}/claude-code`}</code>
                <CopyButton compact text={`${proxyBase(config.proxyPort)}/claude-code`} label={t('integrations.copyEntry')} />
              </span>
            </div>
          </div>
        </section>
        <ToolDetail
          key={selected.kind}
          profile={selected}
          port={config.proxyPort}
          liveCount={liveCounts.get(selected.kind) ?? 0}
          shell={shell}
          caStatus={caStatus}
          caBusy={caBusy}
          onTrustCa={handleTrustCa}
          onShell={setShell}
          onRefresh={refreshAll}
        />
      </div>
    </div>
  );
}
