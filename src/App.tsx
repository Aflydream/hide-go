import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import {
  ChartLineUp,
  ArrowsLeftRight,
  ShieldCheck,
  Plugs,
  Vault as VaultIcon,
  BracketsAngle,
  Eye,
  EyeSlash,
  Lightning,
  PaperPlaneTilt,
  WifiSlash,
} from '@phosphor-icons/react';
import { StoreProvider, isAuthError, useStore } from './store';
import { Button, Segmented, ToastProvider, cx, type SegmentTone } from './components/ui';
import { WindowFrame } from './components/WindowFrame';
import type { Route } from './lib/hooks';
import { MODE_LABEL, formatCount, formatDuration } from './lib/format';
import type { PrivacyMode } from './types';
import { Overview } from './views/Overview';
import { Traffic } from './views/Traffic';
import { Policy } from './views/Policy';
import { Integrations } from './views/Integrations';
import { VaultView } from './views/Vault';
import { Rules } from './views/Rules';
import { SimulateDialog } from './views/SimulateDialog';

const NAV: Array<{ route: Route; label: string; icon: ReactNode; title: string; description: string }> = [
  { route: 'overview', label: '概览', icon: <ChartLineUp size={18} />, title: '概览', description: '运行状态与最近流量' },
  { route: 'traffic', label: '流量', icon: <ArrowsLeftRight size={18} />, title: '流量检视', description: '请求 / 响应对照与敏感项' },
  { route: 'policy', label: '保护策略', icon: <ShieldCheck size={18} />, title: '保护策略', description: '脱敏范围与工具参数策略' },
  { route: 'rules', label: '自定义规则', icon: <BracketsAngle size={18} />, title: '自定义规则', description: '项目专有正则规则' },
  { route: 'vault', label: '映射表', icon: <VaultIcon size={18} />, title: '映射表', description: '内存中的占位符对照表' },
  { route: 'integrations', label: '工具接入', icon: <Plugs size={18} />, title: '工具接入', description: '检测并接入本机 AI 工具' },
];

const MODE_OPTIONS: Array<{ value: PrivacyMode; label: string; icon: ReactNode; title: string; tone: SegmentTone }> = [
  { value: 'audit-only', label: MODE_LABEL['audit-only'], icon: <Eye size={14} />, title: '只记录，不修改请求', tone: 'warn' },
  { value: 'auto-desensitize', label: MODE_LABEL['auto-desensitize'], icon: <ShieldCheck size={14} />, title: '替换密钥、路径与内网信息，返回时还原', tone: 'brand' },
  { value: 'all-hide', label: MODE_LABEL['all-hide'], icon: <EyeSlash size={14} />, title: '在脱敏基础上伪装代码标识符与字面量', tone: 'ink' },
];

function Sidebar() {
  const { route, navigate, logs, vault, status, config, statusError } = useStore();
  const liveCount = useMemo(() => logs.reduce((n, l) => n + (l.simulated ? 0 : 1), 0), [logs]);
  const online = !!status && !statusError;
  const counts: Partial<Record<Route, number>> = {
    traffic: liveCount,
    vault: status?.activeVaultTokens ?? vault.length,
    rules: config?.customRules.length,
  };
  return (
    <aside className="flex w-52 shrink-0 flex-col border-r border-line bg-surface-2/60 max-[1180px]:w-14" aria-label="主导航">
      <nav className="flex-1 space-y-0.5 px-2 pt-3" aria-label="控制台视图">
        {NAV.map((item) => {
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
                  {formatCount(count)}
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
            <span className="font-medium text-fg">{online ? '网关运行中' : '网关未连接'}</span>
            {config && <span className="tabular ml-auto font-mono text-2xs text-fg-subtle">:{config.proxyPort}</span>}
          </div>
          {status && <p className="tabular mt-1 pl-4 text-2xs text-fg-subtle">已运行 {formatDuration(status.uptimeSecs)}</p>}
        </div>
      </div>
    </aside>
  );
}

function TopBar() {
  const { route, config, saveConfig, openSimulator } = useStore();
  const item = NAV.find((n) => n.route === route) ?? NAV[0];
  return (
    <header className="flex h-12 shrink-0 items-center justify-between gap-4 border-b border-line bg-surface px-6">
      <div className="flex min-w-0 items-baseline gap-2.5">
        <h1 id="view-title" tabIndex={-1} className="w-fit shrink-0 text-base font-semibold text-fg focus:outline-none">
          {item.title}
        </h1>
        <p className="truncate text-xs text-fg-subtle max-[1100px]:hidden">{item.description}</p>
      </div>
      <div role="toolbar" aria-label="网关快捷控制" className="flex shrink-0 items-center gap-3">
        <div role="group" aria-label="请求测试">
          <Button size="sm" variant="ghost" icon={<PaperPlaneTilt size={14} />} onClick={openSimulator}>
            模拟请求
          </Button>
        </div>
        <span role="separator" aria-orientation="vertical" className="h-5 w-px bg-line" />
        <span className="label-caps max-[1280px]:hidden" id="mode-label">
          处理模式
        </span>
        {config ? (
          <Segmented
            label="全局处理模式"
            value={config.mode}
            onChange={(mode) => mode !== config.mode && saveConfig({ ...config, mode }, `已切换为「${MODE_LABEL[mode]}」`)}
            options={MODE_OPTIONS}
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
  if (!statusError) return null;
  const auth = isAuthError(statusError);
  return (
    <div role="alert" className="flex items-center gap-3 border-b border-danger/40 bg-danger/10 px-6 py-2 text-sm text-danger">
      <WifiSlash aria-hidden="true" size={16} weight="bold" />
      <span className="font-medium">{auth ? '管理令牌无效' : '无法连接本地网关'}</span>
      <span className="text-xs text-fg-muted">
        {auth ? '请关闭窗口并从 Hide-Go 桌面程序重新启动。' : '界面数据可能已过期，正在自动重试…'}
      </span>
    </div>
  );
}

function AuditWarning() {
  const { config, route, navigate } = useStore();
  if (!config || config.mode !== 'audit-only' || route === 'policy') return null;
  return (
    <div className="flex items-center gap-3 border-b border-warn/40 bg-warn/10 px-6 py-2 text-xs">
      <Lightning aria-hidden="true" size={14} weight="fill" className="text-warn" />
      <span className="font-medium text-warn">仅审计模式</span>
      <span className="text-fg-muted">密钥、路径和内网地址会原样发送给模型厂商。</span>
      <button type="button" onClick={() => navigate('policy')} className="ml-auto cursor-pointer font-medium text-fg underline-offset-2 hover:underline">
        查看保护策略
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
    </main>
  );
}

function Shell() {
  const { simulatorOpen, closeSimulator, status, statusError, config } = useStore();
  useEffect(() => {
    document.title = status ? `Hide-Go · ${formatCount(status.totalRequests)} 请求` : 'Hide-Go 控制台';
  }, [status]);

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
    <WindowFrame title="Hide-Go" badge={status ? `v${status.version}` : undefined} statusSlot={statusChip} minWidthClass="min-w-[960px]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-12 focus:z-[70] focus:rounded focus:border focus:border-line-strong focus:bg-surface focus:px-3 focus:py-2 focus:text-sm"
      >
        跳到主要内容
      </a>
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
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
    <ToastProvider>
      <StoreProvider>
        <Shell />
      </StoreProvider>
    </ToastProvider>
  );
}
