import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { ArrowsClockwise, ArrowRight, CheckCircle, DownloadSimple, LinkBreak, LinkSimple, Play, ShieldCheck, Terminal } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { Badge, Button, Callout, CopyButton, Segmented, Skeleton, cx, useToast } from '../components/ui';
import { formatCount, proxyBase } from '../lib/format';
import type { CaStatus, HarnessKind, HarnessProfile } from '../types';
import { useSimulate } from './SimulateDialog';

type Shell = 'bash' | 'powershell';

const FALLBACK_TARGETS: Partial<Record<HarnessProfile['kind'], string[]>> = {
  'claude-code': ['~/.claude/settings.json'],
  codex: ['~/.codex/config.toml', '环境变量 HTTPS_PROXY / NODE_EXTRA_CA_CERTS'],
  antigravity: ['Antigravity IDE/User/settings.json', '环境变量 HTTPS_PROXY / NODE_EXTRA_CA_CERTS'],
  zcode: ['环境变量 ZCODE_HTTP_PROXY / ZCODE_AGENT_CA_CERT / HTTPS_PROXY / NODE_EXTRA_CA_CERTS'],
  qoder: ['Qoder/User/settings.json', 'QoderCN/User/settings.json', '环境变量 NODE_EXTRA_CA_CERTS'],
  cursor: ['Cursor/User/settings.json', '环境变量 NODE_EXTRA_CA_CERTS'],
  'grok-build': ['环境变量 GROK_XAI_API_BASE_URL / HTTPS_PROXY / NODE_EXTRA_CA_CERTS'],
};

function describeAutoConnectMode(profile: HarnessProfile): string {
  const targets =
    profile.autoConnectTargets && profile.autoConnectTargets.length > 0
      ? profile.autoConnectTargets
      : (FALLBACK_TARGETS[profile.kind] ?? []);
  const targetText = targets.join('、');

  if (profile.autoConnectMode === 'configFile') {
    return targetText
      ? `写入配置文件（${targetText}），修改前保留原设置备份`
      : '写入配置文件与共享环境变量，修改前保留原设置备份';
  }
  if (profile.autoConnectMode === 'envVar') {
    return targetText
      ? `写入当前用户的持久化环境变量（${targetText}），支持一键回滚`
      : '写入当前用户的持久化环境变量，支持一键回滚';
  }
  return '仅支持手动配置（请参考下方网关路由与临时环境变量说明）';
}

function CaTrustCard({
  caStatus,
  caError,
  busy,
  exporting,
  onTrust,
  onUntrust,
  onExport,
  onRetry,
}: {
  caStatus: CaStatus | null;
  caError: string | null;
  busy: boolean;
  exporting: boolean;
  onTrust: () => void;
  onUntrust: () => void;
  onExport: () => void;
  onRetry: () => void;
}) {
  return (
    <section aria-label="本地根证书与 TLS 信任" className="mx-auto max-w-3xl px-8 pt-6">
      <div className="rounded-md border border-line bg-surface-2 px-4 py-3.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <ShieldCheck
              aria-hidden="true"
              size={18}
              weight={caStatus?.installedInOsStore ? 'fill' : 'regular'}
              className={caStatus?.installedInOsStore ? 'shrink-0 text-brand' : 'shrink-0 text-warn'}
            />
            <h2 className="truncate text-sm font-semibold text-fg">本地根证书（HTTP CONNECT 选择性脱敏）</h2>
            {!caStatus ? (
              caError ? (
                <Badge tone="danger" dot>
                  状态获取失败
                </Badge>
              ) : (
                <Skeleton className="h-5 w-24" />
              )
            ) : !caStatus.ready ? (
              <Badge tone="danger" dot>
                证书未就绪
              </Badge>
            ) : caStatus.installedInOsStore ? (
              <Badge tone="brand" dot>
                已信任
              </Badge>
            ) : (
              <Badge tone="warn" dot>
                需安装本地根证书
              </Badge>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {caError && (
              <Button size="sm" variant="ghost" onClick={onRetry}>
                重试
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
                安装并信任根证书
              </Button>
            )}
            {caStatus && caStatus.installedInOsStore && (
              <Button size="sm" variant="secondary" icon={<LinkBreak size={14} />} disabled={busy} onClick={onUntrust}>
                卸载证书信任
              </Button>
            )}
            <Button
              size="sm"
              variant="secondary"
              icon={<DownloadSimple size={14} />}
              disabled={exporting || !caStatus?.ready}
              onClick={onExport}
            >
              导出证书
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
              <span className="shrink-0 text-fg-subtle">证书路径</span>
              <div className="flex min-w-0 items-center gap-1">
                <code className="truncate font-mono text-fg-muted" title={caStatus.caCertPath}>
                  {caStatus.caCertPath}
                </code>
                <CopyButton compact text={caStatus.caCertPath} label="复制证书路径" />
              </div>
            </div>
            {!caStatus.osTrustSupported && (
              <p className="text-warn">{caStatus.osTrustDetail || '当前系统不支持一键安装信任，请点击「导出证书」后手动导入系统受信任根证书。'}</p>
            )}
          </div>
        ) : null}

        <details className="mt-2.5 border-t border-line pt-2 text-2xs text-fg-subtle">
          <summary className="cursor-pointer select-none hover:text-fg-muted">
            HTTPS 仅脱敏 AI API 主机，普通站点直连透传
          </summary>
          <div className="mt-2 space-y-1.5">
            <p className="leading-5">
              拦截主机：<code className="font-mono text-fg-muted">api.openai.com</code>、
              <code className="font-mono text-fg-muted">api.anthropic.com</code>、
              <code className="font-mono text-fg-muted">generativelanguage.googleapis.com</code>、
              <code className="font-mono text-fg-muted">api2.cursor.sh</code>、
              <code className="font-mono text-fg-muted">*.qoder.*</code>、
              <code className="font-mono text-fg-muted">api.x.ai</code>；GitHub、npm、OAuth 登录、网银等均直接透传，不解密。
            </p>
            {caStatus && (
              <div className="space-y-1 border-t border-line pt-2 text-xs">
                <div className="flex items-center justify-between gap-3">
                  <span className="shrink-0 text-fg-subtle">SHA-256 指纹</span>
                  <div className="flex min-w-0 items-center gap-1">
                    <code className="truncate font-mono text-fg-muted" title={caStatus.fingerprintSha256}>
                      {caStatus.fingerprintSha256}
                    </code>
                    <CopyButton compact text={caStatus.fingerprintSha256} label="复制 SHA-256 指纹" />
                  </div>
                </div>
                {caStatus.installedInOsStore && caStatus.osTrustSupported && (
                  <div className="flex items-center justify-between gap-3">
                    <span className="shrink-0 text-fg-subtle">证书路径</span>
                    <div className="flex min-w-0 items-center gap-1">
                      <code className="truncate font-mono text-fg-muted" title={caStatus.caCertPath}>
                        {caStatus.caCertPath}
                      </code>
                      <CopyButton compact text={caStatus.caCertPath} label="复制证书路径" />
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
  const toast = useToast();
  const { run, busy: simBusy } = useSimulate();
  const [connecting, setConnecting] = useState(false);

  const entry = `${proxyBase(port)}${profile.localProxyRoute}`;
  const snippet = shell === 'bash' ? profile.envSetupBash : profile.envSetupPowershell;
  const effectiveTraffic = Math.max(liveCount, profile.trafficCount);

  const handleConnect = async () => {
    setConnecting(true);
    try {
      const res = await api.connectHarness(profile.kind);
      toast.push({
        tone: res.ok ? 'brand' : 'warn',
        title: res.ok ? `${profile.name} 已接入网关` : '无法自动接入',
        body: res.message,
      });
      await onRefresh();
    } catch (e) {
      toast.push({ tone: 'danger', title: '接入失败', body: (e as Error).message });
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
        title: res.ok ? `${profile.name} 已恢复原配置` : '断开失败',
        body: res.message,
      });
      await onRefresh();
    } catch (e) {
      toast.push({ tone: 'danger', title: '断开失败', body: (e as Error).message });
    } finally {
      setConnecting(false);
    }
  };

  return (
    <article className="mx-auto max-w-3xl px-8 pb-10 pt-5">
      <header className="pb-5">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold text-fg">{profile.name}</h2>
          {profile.installed ? (
            <Badge tone="brand">已检测到本机安装</Badge>
          ) : (
            <Badge>未检测到安装</Badge>
          )}
          {profile.configured ? (
            <Badge tone="brand" dot>
              已接入网关
            </Badge>
          ) : (
            <Badge dot>未配置接入</Badge>
          )}
          {profile.detectedActive && (
            <Badge tone="info" dot>
              实时流量 · {formatCount(effectiveTraffic)}
            </Badge>
          )}
        </div>
        <p className="mt-1 text-xs text-fg-subtle">{profile.protocolFamily}</p>
        {profile.integrationNote && (
          <div className="mt-4">
            <Callout
              tone={profile.autoConnectMode === 'manual' ? 'warn' : 'info'}
              title={profile.autoConnectMode === 'manual' ? '手动接入说明' : '接入说明'}
            >
              {profile.integrationNote}
            </Callout>
          </div>
        )}
        {profile.configured && profile.requiresCaTrust && caStatus && !caStatus.installedInOsStore && (
          <div className="mt-4">
            <Callout
              tone="warn"
              title="未信任本地根证书"
              action={
                <Button
                  size="sm"
                  variant="primary"
                  icon={<ShieldCheck size={14} />}
                  disabled={caBusy || !caStatus.ready || !caStatus.osTrustSupported}
                  onClick={onTrustCa}
                >
                  安装并信任
                </Button>
              }
            >
              {caStatus.osTrustSupported
                ? `已接入 ${profile.name}，IDE 的代理对话与搜索需先安装并信任本地根证书。`
                : `当前系统不支持自动写入信任，请点击上方「导出证书」手动导入系统根证书存储。`}
            </Callout>
          </div>
        )}
      </header>

      <Block
        index="01"
        title="本机检测与一键接入"
        aside={
          profile.autoConnectMode !== 'manual' && (
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant={profile.configured ? 'secondary' : 'primary'}
                icon={<LinkSimple size={14} />}
                disabled={connecting}
                onClick={handleConnect}
              >
                {profile.configured ? '重新写入配置' : '自动接入网关'}
              </Button>
              {profile.configured && (
                <Button size="sm" icon={<LinkBreak size={14} />} disabled={connecting} onClick={handleDisconnect}>
                  断开并恢复
                </Button>
              )}
            </div>
          )
        }
      >
        <div className="space-y-3 rounded-md border border-line bg-surface-2 px-4 py-3 text-xs">
          <div className="flex items-start justify-between gap-4">
            <span className="shrink-0 text-fg-subtle">接入方式</span>
            <span className="text-right text-fg">{describeAutoConnectMode(profile)}</span>
          </div>
          {profile.requiresCaTrust && (
            <div className="flex items-start justify-between gap-4 border-t border-line pt-2.5">
              <span className="shrink-0 text-fg-subtle">TLS 根证书</span>
              <span className={cx('text-right font-mono', caStatus?.installedInOsStore ? 'text-brand' : 'text-warn')}>
                {caStatus?.installedInOsStore
                  ? '已信任'
                  : caStatus && !caStatus.osTrustSupported
                    ? '需手动导入系统根证书'
                    : '未信任（点击上方安装）'}
              </span>
            </div>
          )}
          <div className="flex items-start justify-between gap-4 border-t border-line pt-2.5">
            <span className="shrink-0 text-fg-subtle">当前接入状态</span>
            <span className={cx('text-right font-mono', profile.configured ? 'text-brand' : 'text-fg-muted')}>
              {profile.configured ? `已生效 · ${profile.configuredVia ?? entry}` : '尚未指向 Hide-Go'}
            </span>
          </div>
          <div className="flex items-start justify-between gap-4 border-t border-line pt-2.5">
            <span className="shrink-0 text-fg-subtle">发现的本机路径</span>
            <div className="min-w-0 text-right font-mono text-fg-muted">
              {profile.installPaths.length > 0 ? (
                profile.installPaths.map((p) => (
                  <div key={p} className="truncate" title={p}>
                    {p}
                  </div>
                ))
              ) : (
                <span>未在 PATH 或默认目录发现</span>
              )}
            </div>
          </div>
        </div>
      </Block>

      <Block index="02" title="网关路由">
        <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-stretch rounded-md border border-line">
          <div className="min-w-0 py-3 pl-4 pr-2">
            <p className="label-caps">本地入口</p>
            <div className="mt-1 flex items-center gap-1">
              <code className="min-w-0 truncate font-mono text-sm text-brand" title={entry}>
                {entry}
              </code>
              <CopyButton compact text={entry} label="复制本地入口地址" />
            </div>
          </div>
          <span aria-hidden="true" className="flex items-center px-2 text-fg-subtle">
            <ArrowRight size={16} />
          </span>
          <div className="min-w-0 border-l border-line px-4 py-3">
            <p className="label-caps">转发到</p>
            <code className="mt-1 block truncate py-1 font-mono text-sm text-fg-muted" title={profile.defaultUpstream}>
              {profile.defaultUpstream}
            </code>
          </div>
        </div>
        <p className="mt-2 text-xs leading-5 text-fg-subtle">
          自定义上游：<code className="font-mono text-fg-muted">HIDE_GO_UPSTREAM_URL</code> 或请求头 <code className="font-mono text-fg-muted">X-Hide-Go-Upstream</code>
        </p>
      </Block>

      <Block
        index="03"
        title="临时环境变量（单终端）"
        aside={
          <Segmented
            size="sm"
            label="终端类型"
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
            <span className="truncate text-xs text-fg-subtle">仅对当前终端会话生效</span>
            <span className="ml-auto">
              <CopyButton compact text={snippet} label="复制命令" />
            </span>
          </div>
          <pre tabIndex={0} className="overflow-x-auto px-4 py-3 font-mono text-xs leading-6 text-fg">
            {snippet}
          </pre>
        </div>
      </Block>

      <Block index="04" title="验证接入">
        {effectiveTraffic > 0 ? (
          <Callout
            tone="brand"
            title={`本会话已捕获 ${formatCount(effectiveTraffic)} 条真实请求${profile.lastSeenAt ? `（${profile.lastSeenAt}）` : ''}`}
            action={
              <Button size="sm" onClick={() => navigate('traffic')}>
                查看流量
              </Button>
            }
          >
            请求已经过本地网关。
          </Callout>
        ) : (
          <p className="text-sm leading-6 text-fg-muted">
            接入后在 {profile.name} 中发送一次对话，「流量」页出现记录即生效。
          </p>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button size="sm" icon={<Play size={13} weight="fill" />} disabled={simBusy} onClick={() => run(profile.kind, 'interactive-prompt')}>
            模拟对话请求
          </Button>
          <Button size="sm" icon={<Play size={13} weight="fill" />} disabled={simBusy} onClick={() => run(profile.kind, 'codebase-indexing')}>
            模拟代码索引
          </Button>
          <span className="text-xs text-fg-subtle">离线演练，不联网</span>
        </div>
      </Block>
    </article>
  );
}

export function Integrations() {
  const { harnesses, refreshHarnesses, config, logs, params, navigate } = useStore();
  const toast = useToast();
  const [shell, setShell] = useState<Shell>(() => (/win/i.test(navigator.platform) ? 'powershell' : 'bash'));
  const [scanning, setScanning] = useState(false);
  const [connectingAll, setConnectingAll] = useState(false);
  const [caStatus, setCaStatus] = useState<CaStatus | null>(null);
  const [caError, setCaError] = useState<string | null>(null);
  const [caBusy, setCaBusy] = useState(false);
  const [exportingCert, setExportingCert] = useState(false);
  const selected = harnesses.find((h) => h.kind === params.get('tool')) ?? harnesses[0] ?? null;

  const refreshCaStatus = useCallback(async () => {
    try {
      const next = await api.getCaStatus();
      setCaStatus(next);
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
      toast.push({ tone: 'brand', title: '本机扫描已刷新' });
    } catch (e) {
      toast.push({ tone: 'danger', title: '扫描失败', body: (e as Error).message });
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
        title: succeeded > 0 ? `已接入 ${succeeded} 个工具` : '无可自动接入的工具',
        body: succeeded > 0 ? '新会话将自动走 Hide-Go 网关' : '请先安装工具或使用右侧终端命令',
      });
    } catch (e) {
      toast.push({ tone: 'danger', title: '批量接入失败', body: (e as Error).message });
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
        title: next.installedInOsStore ? '本地根证书已安装并受信任' : '证书信任尚未生效',
        body: next.osTrustDetail,
      });
    } catch (e) {
      toast.push({ tone: 'danger', title: '安装根证书失败', body: (e as Error).message });
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
        title: !next.installedInOsStore ? '已移除本地根证书信任' : '证书信任仍然存在',
        body: next.osTrustDetail,
      });
    } catch (e) {
      toast.push({ tone: 'danger', title: '卸载证书信任失败', body: (e as Error).message });
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
      toast.push({ tone: 'brand', title: '已导出本地根证书', body: '文件名：hide-go-ca.crt（仅含公钥）' });
    } catch (e) {
      toast.push({ tone: 'danger', title: '导出证书失败', body: (e as Error).message });
    } finally {
      setExportingCert(false);
    }
  };

  return (
    <div className="grid h-full min-h-0 grid-cols-[280px_minmax(0,1fr)]">
      <nav aria-label="支持的工具" className="flex min-h-0 flex-col border-r border-line bg-surface">
        <div className="border-b border-line p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="label-caps">
              本机已安装 {installedCount}/{harnesses.length} · 已接入 {configuredCount}
            </span>
            <button
              type="button"
              onClick={handleScan}
              disabled={scanning}
              title="重新扫描本机工具"
              className="inline-flex cursor-pointer items-center gap-1 rounded px-1.5 py-1 text-2xs text-fg-muted hover:bg-surface-2 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus/40 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <ArrowsClockwise size={13} className={scanning ? 'animate-spin' : undefined} />
              扫描
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
            一键接入已检测工具
          </Button>
        </div>
        <ul className="min-h-0 flex-1 divide-y divide-line overflow-y-auto">
          {harnesses.map((h) => {
            const active = h.kind === selected.kind;
            const statusText = h.detectedActive ? '有流量' : h.configured ? '已接入' : h.installed ? '已安装' : '未安装';
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
          busy={caBusy}
          exporting={exportingCert}
          onTrust={handleTrustCa}
          onUntrust={handleUntrustCa}
          onExport={handleExportCert}
          onRetry={refreshCaStatus}
        />
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
