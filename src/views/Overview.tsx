import type { ReactNode } from 'react';
import { ArrowRight, Check, Minus, ArrowsLeftRight, Plugs } from '@phosphor-icons/react';
import { useStore } from '../store';
import { Badge, Button, CopyButton, EmptyState, Panel, Skeleton, cx } from '../components/ui';
import {
  CATEGORY_LABEL,
  COVER_THEME_LABEL,
  HARNESS_LABEL,
  HARNESS_ORDER,
  MODE_LABEL,
  POLICY_LABEL,
  describeAction,
  formatCount,
  formatLatency,
  proxyBase,
} from '../lib/format';
import { SeverityBadge } from './Traffic';

function Metric({ label, value, hint, tone }: { label: string; value: number | undefined; hint: string; tone?: 'brand' | 'warn' }) {
  return (
    <div className="min-w-0 bg-surface px-5 py-4">
      <p className="label-caps">{label}</p>
      {value === undefined ? (
        <Skeleton className="mt-2 h-7 w-16" />
      ) : (
        <p className={cx('tabular mt-1 font-mono text-2xl font-semibold', tone === 'brand' ? 'text-brand' : tone === 'warn' ? 'text-warn' : 'text-fg')}>
          {formatCount(value)}
        </p>
      )}
      <p className="mt-0.5 truncate text-xs text-fg-subtle">{hint}</p>
    </div>
  );
}

function ProtectionRow({ on, label, detail }: { on: boolean; label: string; detail: ReactNode }) {
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
          <span className="sr-only">{on ? '：已开启' : '：未开启'}</span>
        </p>
        <p className="text-xs text-fg-subtle">{detail}</p>
      </div>
    </li>
  );
}

export function Overview() {
  const { status, config, logs, harnesses, navigate, openSimulator } = useStore();
  const live = logs.filter((l) => !l.simulated);
  const recent = logs.slice(0, 8);
  const base = config ? proxyBase(config.proxyPort) : null;
  const protecting = config && config.mode !== 'audit-only';
  const telemetryBlocked =
    !!protecting && (config.blockSilentTelemetry || (config.mode === 'all-hide' && config.allHide.enableTelemetryChaff));

  return (
    <div className="mx-auto max-w-[1360px] space-y-5 p-6">
      <section aria-label="运行指标" className="grid grid-cols-3 gap-px overflow-hidden rounded-md border border-line bg-line xl:grid-cols-6">
        <Metric label="已代理请求" value={status?.totalRequests} hint="自本次启动以来" />
        <Metric label="敏感项" value={status?.totalFindings} hint={protecting ? '已在出境前替换' : '仅审计，未替换'} tone={protecting ? 'brand' : 'warn'} />
        <Metric label="已还原" value={status?.totalRestored} hint="返回时换回真实值" tone="brand" />
        <Metric label="凭据保留" value={status?.totalWithheld} hint="未写回工具调用参数" />
        <Metric label="遥测拦截" value={status?.totalBlocked} hint="在本地直接应答" tone={status?.totalBlocked ? 'warn' : undefined} />
        <Metric label="映射表条目" value={status?.activeVaultTokens} hint="仅驻留内存" />
      </section>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel
          title="最近流量"
          description={`窗口内 ${live.length} 条真实请求，${logs.length - live.length} 条模拟`}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate('traffic')}>
              全部流量 <ArrowRight aria-hidden="true" size={13} />
            </Button>
          }
        >
          {recent.length === 0 ? (
            <EmptyState
              icon={<ArrowsLeftRight size={20} />}
              title="还没有流量"
              action={
                <div className="flex gap-2">
                  <Button size="sm" variant="primary" onClick={() => navigate('integrations')}>
                    接入 AI 工具
                  </Button>
                  <Button size="sm" onClick={openSimulator}>
                    发送模拟请求
                  </Button>
                </div>
              }
            >
              把 AI 编程工具的 API 地址指向本地网关后，每个请求都会出现在这里。
            </EmptyState>
          ) : (
            <table className="w-full table-fixed text-left text-xs">
              <thead>
                <tr className="border-b border-line text-2xs text-fg-subtle">
                  <th scope="col" className="w-24 px-4 py-2 font-medium">时间</th>
                  <th scope="col" className="w-28 px-2 py-2 font-medium">工具</th>
                  <th scope="col" className="px-2 py-2 font-medium">端点</th>
                  <th scope="col" className="w-24 px-2 py-2 font-medium">处理</th>
                  <th scope="col" className="w-20 px-2 py-2 text-right font-medium">敏感项</th>
                  <th scope="col" className="w-20 px-4 py-2 text-right font-medium">耗时</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {recent.map((r) => {
                  const action = describeAction(r.actionTaken);
                  return (
                    <tr key={r.id} className="cursor-pointer transition-colors hover:bg-surface-2" onClick={() => navigate('traffic', { id: r.id })}>
                      <td className="tabular px-4 py-2 font-mono text-fg-muted">{r.timestamp.slice(0, 8)}</td>
                      <td className="truncate px-2 py-2 text-fg">
                        {HARNESS_LABEL[r.harness]}
                        {r.simulated && <span className="ml-1.5 text-2xs text-info">模拟</span>}
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
                        {r.findingCount > 0 ? <SeverityBadge severity={r.topSeverity} count={r.findingCount} /> : <span className="text-fg-subtle">—</span>}
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
          title="保护范围"
          description={config ? `当前模式：${MODE_LABEL[config.mode]}` : '加载中'}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate('policy')}>
              调整
            </Button>
          }
        >
          {config ? (
            <ul className="divide-y divide-line">
              <ProtectionRow on={protecting && config.protectSecretsAndKeys ? true : false} label="凭据与密钥" detail="API Key、私钥、数据库连接串、配置文件中的密码" />
              <ProtectionRow on={protecting && config.protectProjectPaths ? true : false} label="本机路径与身份" detail="用户目录、邮箱；目录结构保持不变" />
              <ProtectionRow on={protecting && config.protectInternalNetwork ? true : false} label="内网地址与域名" detail="RFC 1918 地址、.internal / .corp 等域名" />
              <ProtectionRow on={telemetryBlocked} label="静默遥测" detail="遥测端点在本地应答，推理请求永不拦截" />
              <ProtectionRow on={!!protecting} label="工具调用中的凭据" detail={POLICY_LABEL[config.toolCallSecretPolicy]} />
              <ProtectionRow
                on={config.mode === 'all-hide'}
                label="All-Hide 代码伪装"
                detail={config.mode === 'all-hide' ? `词库：${COVER_THEME_LABEL[config.allHide.coverTheme]}` : '未启用'}
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
        <Panel title="工具活跃度" description="最近 200 条">
          <ul className="grid grid-cols-2 gap-px bg-line lg:grid-cols-4">
            {HARNESS_ORDER.map((kind) => {
              const rows = live.filter((l) => l.harness === kind);
              const profile = harnesses.find((h) => h.kind === kind);
              return (
                <li key={kind} className="bg-surface">
                  <button
                    type="button"
                    onClick={() => navigate('integrations', { tool: kind })}
                    className="block w-full cursor-pointer px-4 py-3 text-left transition-colors hover:bg-surface-2"
                  >
                    <div className="flex items-center gap-2">
                      <span aria-hidden="true" className={cx('h-1.5 w-1.5 rounded-full', rows.length ? 'bg-brand' : 'bg-line-strong')} />
                      <span className="truncate text-sm text-fg">{HARNESS_LABEL[kind]}</span>
                    </div>
                    <p className="tabular mt-1 font-mono text-lg font-semibold text-fg">{rows.length}</p>
                    <p className="truncate text-2xs text-fg-subtle">
                      {rows[0] ? `${rows[0].timestamp.slice(0, 8)} · ${CATEGORY_LABEL[rows[0].category]}` : profile ? '暂无流量' : '—'}
                    </p>
                  </button>
                </li>
              );
            })}
            <li className="flex items-center bg-surface px-4 py-3">
              <Button size="sm" variant="ghost" icon={<Plugs size={14} />} onClick={() => navigate('integrations')}>
                查看接入方式
              </Button>
            </li>
          </ul>
        </Panel>

        <Panel title="网关入口" description="Tool Base URL">
          <div className="space-y-2 p-4">
            {base
              ? ['claude-code', 'codex', 'grok-build'].map((slug) => (
                  <div key={slug} className="flex items-center gap-2 rounded border border-line bg-surface-2 py-1 pl-3 pr-1">
                    <code className="min-w-0 flex-1 truncate font-mono text-xs text-fg">{`${base}/${slug}`}</code>
                    <CopyButton compact text={`${base}/${slug}`} label={`复制 ${slug} 地址`} />
                  </div>
                ))
              : Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-8" />)}
            <p className="pt-1 text-xs text-fg-subtle">仅监听 127.0.0.1</p>
          </div>
        </Panel>
      </div>
    </div>
  );
}
