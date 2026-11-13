import { useState, type ReactNode } from 'react';
import { ArrowRight, Play, Terminal } from '@phosphor-icons/react';
import { useStore } from '../store';
import { Badge, Button, Callout, CopyButton, Segmented, Skeleton, cx } from '../components/ui';
import { formatCount, proxyBase } from '../lib/format';
import type { HarnessProfile } from '../types';
import { useSimulate } from './SimulateDialog';

type Shell = 'bash' | 'powershell';

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
  onShell,
}: {
  profile: HarnessProfile;
  port: number;
  liveCount: number;
  shell: Shell;
  onShell: (s: Shell) => void;
}) {
  const { navigate } = useStore();
  const { run, busy } = useSimulate();
  const entry = `${proxyBase(port)}${profile.localProxyRoute}`;
  const snippet = shell === 'bash' ? profile.envSetupBash : profile.envSetupPowershell;

  return (
    <article className="mx-auto max-w-3xl px-8 pb-10 pt-7">
      <header className="pb-6">
        <div className="flex items-center gap-2.5">
          <h2 className="text-lg font-semibold text-fg">{profile.name}</h2>
          {profile.detectedActive ? (
            <Badge tone="brand" dot>
              已检测到流量
            </Badge>
          ) : (
            <Badge dot>未检测到流量</Badge>
          )}
        </div>
        <p className="mt-0.5 text-xs text-fg-subtle">
          {profile.vendorName} · {profile.protocolFamily}
        </p>
        <p className="mt-3 text-sm leading-6 text-fg-muted">{profile.description}</p>
        {profile.integrationNote && (
          <div className="mt-4">
            <Callout tone="warn" title="接入限制">
              {profile.integrationNote}
            </Callout>
          </div>
        )}
      </header>

      <Block index="01" title="网关路由">
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
          使用自建或第三方兼容端点时，启动网关前设置 <code className="font-mono text-fg-muted">HIDE_GO_UPSTREAM_URL</code>，或在请求中附带{' '}
          <code className="font-mono text-fg-muted">X-Hide-Go-Upstream</code> 头覆盖上游地址。
        </p>
      </Block>

      <Block
        index="02"
        title="设置环境变量"
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
            <span className="truncate text-xs text-fg-subtle">在启动 {profile.name} 的同一个终端里执行</span>
            <span className="ml-auto">
              <CopyButton compact text={snippet} label="复制命令" />
            </span>
          </div>
          <pre tabIndex={0} className="overflow-x-auto px-4 py-3 font-mono text-xs leading-6 text-fg">
            {snippet}
          </pre>
        </div>
      </Block>

      <Block index="03" title="验证接入">
        {liveCount > 0 ? (
          <Callout
            tone="brand"
            title={`窗口内已收到 ${formatCount(liveCount)} 条真实请求`}
            action={
              <Button size="sm" onClick={() => navigate('traffic')}>
                查看流量
              </Button>
            }
          >
            该工具的请求正在经过网关。
          </Callout>
        ) : (
          <p className="text-sm leading-6 text-fg-muted">
            通过 {profile.name} 发起一次对话，请求出现在「流量」页即表示接入成功。
          </p>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button size="sm" icon={<Play size={13} weight="fill" />} disabled={busy} onClick={() => run(profile.kind, 'interactive-prompt')}>
            模拟对话请求
          </Button>
          <Button size="sm" icon={<Play size={13} weight="fill" />} disabled={busy} onClick={() => run(profile.kind, 'codebase-indexing')}>
            模拟代码索引
          </Button>
          <span className="text-xs text-fg-subtle">模拟请求不联网，用于预览该工具的处理效果。</span>
        </div>
      </Block>

      <Block index="04" title="该工具默认上传的数据">
        <ul className="divide-y divide-line rounded-md border border-line">
          {profile.riskSummary.map((risk) => (
            <li key={risk} className="flex items-start gap-3 px-4 py-2.5 text-sm leading-5 text-fg-muted">
              <span aria-hidden="true" className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-sm bg-warn" />
              {risk}
            </li>
          ))}
        </ul>
      </Block>
    </article>
  );
}

export function Integrations() {
  const { harnesses, config, logs, params, navigate } = useStore();
  const [shell, setShell] = useState<Shell>(() => (/win/i.test(navigator.platform) ? 'powershell' : 'bash'));
  const selected = harnesses.find((h) => h.kind === params.get('tool')) ?? harnesses[0] ?? null;

  if (!selected || !config) {
    return (
      <div className="grid h-full min-h-0 grid-cols-[260px_minmax(0,1fr)]" aria-busy="true">
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

  const liveCount = (kind: HarnessProfile['kind']) => logs.filter((l) => l.harness === kind && !l.simulated).length;

  return (
    <div className="grid h-full min-h-0 grid-cols-[260px_minmax(0,1fr)]">
      <nav aria-label="支持的工具" className="min-h-0 overflow-y-auto border-r border-line bg-surface">
        <p className="label-caps border-b border-line px-4 py-2.5">支持的工具 · {harnesses.length}</p>
        <ul className="divide-y divide-line">
          {harnesses.map((h) => {
            const active = h.kind === selected.kind;
            return (
              <li key={h.kind}>
                <button
                  type="button"
                  onClick={() => navigate('integrations', { tool: h.kind })}
                  aria-current={active ? 'true' : undefined}
                  className={cx(
                    'relative flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors',
                    active ? 'bg-brand/[0.07]' : 'hover:bg-surface-2',
                  )}
                >
                  {active && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-0.5 bg-brand" />}
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-fg">{h.name}</span>
                    <span className="block truncate text-2xs text-fg-subtle">{h.vendorName}</span>
                  </span>
                  <span
                    aria-hidden="true"
                    className={cx('h-1.5 w-1.5 shrink-0 rounded-full', h.detectedActive ? 'bg-brand' : 'bg-line-strong')}
                  />
                  <span className="sr-only">{h.detectedActive ? '已检测到流量' : '未检测到流量'}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="min-h-0 overflow-y-auto bg-surface">
        <ToolDetail key={selected.kind} profile={selected} port={config.proxyPort} liveCount={liveCount(selected.kind)} shell={shell} onShell={setShell} />
      </div>
    </div>
  );
}
