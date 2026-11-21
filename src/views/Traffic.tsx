import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowsLeftRight, MagnifyingGlass, Trash, PaperPlaneTilt, WarningCircle, Funnel } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import {
  CATEGORY_LABEL,
  FINDING_LABEL,
  HARNESS_LABEL,
  HARNESS_ORDER,
  MODE_LABEL,
  SEVERITY_LABEL,
  SEVERITY_RANK,
  describeAction,
  formatBytes,
  formatLatency,
} from '../lib/format';
import type { HarnessKind, Severity, TrafficAuditRecord, TrafficCategory } from '../types';
import { Badge, Button, Callout, ConfirmDialog, EmptyState, Skeleton, Switch, Tabs, cx, inputClass, useToast } from '../components/ui';
import { CodeView, buildMatcher } from '../components/CodeView';

export function SeverityBadge({ severity, count }: { severity: Severity | null; count: number }) {
  const tone = severity === 'critical' || severity === 'high' ? 'danger' : severity === 'medium' ? 'warn' : 'neutral';
  return (
    <Badge tone={tone} className="tabular">
      {count}
      <span className="sr-only">项，最高{severity ? SEVERITY_LABEL[severity] : ''}</span>
    </Badge>
  );
}

type DetailTab = 'request' | 'response' | 'findings' | 'meta';
type ActionFilter = 'all' | 'masked' | 'blocked' | 'passed' | 'error';

function matchesAction(action: string, filter: ActionFilter) {
  const tone = describeAction(action);
  switch (filter) {
    case 'all':
      return true;
    case 'masked':
      return tone.tone === 'brand';
    case 'blocked':
      return tone.tone === 'warn';
    case 'passed':
      return action === 'passed';
    case 'error':
      return tone.tone === 'danger';
  }
}

const selectClass = cx(inputClass, 'h-8 cursor-pointer pr-7');

export function Traffic() {
  const { logs, logsLoading, params, navigate, refreshLogs, openSimulator, vault } = useStore();
  const toast = useToast();
  const [query, setQuery] = useState('');
  const [harness, setHarness] = useState<HarnessKind | 'all'>('all');
  const [category, setCategory] = useState<TrafficCategory | 'all'>('all');
  const [action, setAction] = useState<ActionFilter>('all');
  const [hideSimulated, setHideSimulated] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [tab, setTab] = useState<DetailTab>('request');
  const selectedId = params.get('id');

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return logs.filter(
      (r) =>
        (harness === 'all' || r.harness === harness) &&
        (category === 'all' || r.category === category) &&
        (!hideSimulated || !r.simulated) &&
        matchesAction(r.actionTaken, action) &&
        (!q || r.endpoint.toLowerCase().includes(q) || HARNESS_LABEL[r.harness].toLowerCase().includes(q) || r.id.startsWith(q)),
    );
  }, [logs, query, harness, category, action, hideSimulated]);

  const select = useCallback((id: string) => navigate('traffic', { id }), [navigate]);
  const effectiveId = selectedId ?? rows[0]?.id ?? null;
  const hasSelectedRow = effectiveId !== null && rows.some((r) => r.id === effectiveId);

  const listRef = useRef<HTMLTableSectionElement>(null);
  const onListKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const i = rows.findIndex((r) => r.id === effectiveId);
    const next = rows[Math.min(rows.length - 1, Math.max(0, i + (e.key === 'ArrowDown' ? 1 : -1)))];
    if (next) {
      select(next.id);
      listRef.current?.querySelector<HTMLElement>(`[data-id="${next.id}"]`)?.focus();
    }
  };

  const clear = async () => {
    try {
      await api.clearLogs();
      await refreshLogs();
      navigate('traffic');
      toast.push({ tone: 'brand', title: '流量记录已清空' });
    } catch (e) {
      toast.push({ tone: 'danger', title: '清空失败', body: (e as Error).message });
    }
    setConfirmClear(false);
  };

  const filtersActive = query || harness !== 'all' || category !== 'all' || action !== 'all' || hideSimulated;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface px-6 py-2.5">
        <div className="relative">
          <MagnifyingGlass aria-hidden="true" size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-subtle" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索端点或工具"
            aria-label="搜索流量"
            className={cx(inputClass, 'h-8 w-56 pl-8')}
          />
        </div>
        <select aria-label="按工具筛选" value={harness} onChange={(e) => setHarness(e.target.value as HarnessKind | 'all')} className={selectClass}>
          <option value="all">全部工具</option>
          {HARNESS_ORDER.map((h) => (
            <option key={h} value={h}>
              {HARNESS_LABEL[h]}
            </option>
          ))}
        </select>
        <select aria-label="按类别筛选" value={category} onChange={(e) => setCategory(e.target.value as TrafficCategory | 'all')} className={selectClass}>
          <option value="all">全部类别</option>
          {(Object.keys(CATEGORY_LABEL) as TrafficCategory[]).map((c) => (
            <option key={c} value={c}>
              {CATEGORY_LABEL[c]}
            </option>
          ))}
        </select>
        <select aria-label="按处理结果筛选" value={action} onChange={(e) => setAction(e.target.value as ActionFilter)} className={selectClass}>
          <option value="all">全部结果</option>
          <option value="masked">已脱敏 / 伪装</option>
          <option value="blocked">已拦截</option>
          <option value="passed">原样透传</option>
          <option value="error">转发失败</option>
        </select>
        <label className="ml-1 flex cursor-pointer items-center gap-2 text-xs text-fg-muted">
          <Switch checked={hideSimulated} onChange={setHideSimulated} label="隐藏模拟记录" />
          隐藏模拟记录
        </label>
        {filtersActive && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setQuery('');
              setHarness('all');
              setCategory('all');
              setAction('all');
              setHideSimulated(false);
            }}
          >
            重置筛选
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <span className="tabular text-xs text-fg-subtle" role="status">
            {rows.length} / {logs.length} 条
          </span>
          <Button size="sm" icon={<PaperPlaneTilt size={14} />} onClick={openSimulator}>
            模拟请求
          </Button>
          <Button size="sm" variant="ghost" icon={<Trash size={14} />} disabled={!logs.length} onClick={() => setConfirmClear(true)}>
            清空
          </Button>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-[minmax(420px,5fr)_minmax(0,7fr)]">
        <div className="min-h-0 overflow-y-auto border-r border-line bg-surface">
          {logsLoading && !logs.length ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 8 }, (_, i) => (
                <Skeleton key={i} className="h-9" />
              ))}
            </div>
          ) : rows.length === 0 ? (
            filtersActive ? (
              <EmptyState icon={<Funnel size={20} />} title="无匹配记录">
                尝试调整筛选或搜索词
              </EmptyState>
            ) : (
              <EmptyState
                icon={<ArrowsLeftRight size={20} />}
                title="暂无流量"
                action={
                  <Button size="sm" variant="primary" onClick={() => navigate('integrations')}>
                    查看接入方式
                  </Button>
                }
              >
                接入工具或运行模拟请求后，记录将显示在此
              </EmptyState>
            )
          ) : (
            <table className="w-full table-fixed text-left text-xs">
              <caption className="sr-only">流量记录，使用上下方向键切换</caption>
              <thead className="sticky top-0 z-10 bg-surface-2">
                <tr className="border-b border-line text-2xs text-fg-subtle">
                  <th scope="col" className="w-[76px] py-2 pl-4 font-medium">时间</th>
                  <th scope="col" className="py-2 pl-2 font-medium">工具 / 端点</th>
                  <th scope="col" className="w-[92px] py-2 pl-2 font-medium">处理</th>
                  <th scope="col" className="w-12 py-2 pl-2 text-right font-medium">状态</th>
                  <th scope="col" className="w-14 py-2 pl-2 pr-4 text-right font-medium">敏感项</th>
                </tr>
              </thead>
              <tbody ref={listRef} onKeyDown={onListKey} className="divide-y divide-line">
                {rows.map((r, idx) => {
                  const active = r.id === effectiveId;
                  const act = describeAction(r.actionTaken);
                  const rowTabIndex = active || (!hasSelectedRow && idx === 0) ? 0 : -1;
                  return (
                    <tr
                      key={r.id}
                      data-id={r.id}
                      tabIndex={rowTabIndex}
                      aria-selected={active}
                      onClick={() => select(r.id)}
                      onKeyDown={(e) => e.key === 'Enter' && select(r.id)}
                      className={cx(
                        'relative cursor-pointer transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus',
                        active ? 'bg-brand/[0.07]' : 'hover:bg-surface-2',
                      )}
                    >
                      <td className="tabular relative py-2 pl-4 align-top font-mono text-fg-muted">
                        {active && <span aria-hidden="true" className="hg-active-bar absolute inset-y-0 left-0 w-0.5 bg-brand" />}
                        {r.timestamp.slice(0, 8)}
                      </td>
                      <td className="min-w-0 py-2 pl-2">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate font-medium text-fg">{HARNESS_LABEL[r.harness]}</span>
                          <span className="shrink-0 text-2xs text-fg-subtle">{CATEGORY_LABEL[r.category]}</span>
                          {r.simulated && <span className="shrink-0 text-2xs text-info">模拟</span>}
                        </div>
                        <p className="truncate font-mono text-2xs text-fg-subtle" title={r.endpoint}>
                          {r.method} {r.endpoint}
                        </p>
                      </td>
                      <td className="py-2 pl-2 align-top">
                        <Badge tone={act.tone}>{act.label}</Badge>
                      </td>
                      <td className={cx('tabular py-2 pl-2 text-right align-top font-mono', r.status >= 400 || r.status === 0 ? 'text-danger' : 'text-fg-muted')}>
                        {r.status || '—'}
                      </td>
                      <td className="py-2 pl-2 pr-4 text-right align-top">
                        {r.findingCount > 0 ? <SeverityBadge severity={r.topSeverity} count={r.findingCount} /> : <span className="text-fg-subtle">—</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        <div className="min-h-0 min-w-0 bg-surface">
          {effectiveId ? (
            <RecordDetail key={effectiveId} id={effectiveId} vaultTokens={vault} tab={tab} onTabChange={setTab} />
          ) : (
            <EmptyState icon={<ArrowsLeftRight size={20} />} title="选择一条记录">
              对比本地原文、厂商视角与还原结果
            </EmptyState>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={clear}
        title="清空流量记录？"
        description="仅清除列表显示，统计计数与映射表保留。"
        confirmLabel="清空记录"
      />
    </div>
  );
}

function RecordDetail({
  id,
  vaultTokens,
  tab,
  onTabChange,
}: {
  id: string;
  vaultTokens: { token: string; originalRaw: string; secret: boolean }[];
  tab: DetailTab;
  onTabChange: (tab: DetailTab) => void;
}) {
  const [record, setRecord] = useState<TrafficAuditRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .log(id)
      .then((r) => !cancelled && setRecord(r))
      .catch((e) => !cancelled && setError((e as Error).message));
    return () => {
      cancelled = true;
    };
  }, [id]);

  const matchers = useMemo(() => {
    if (!record) return null;
    const jsonEscaped = (s: string) => JSON.stringify(s).slice(1, -1);
    const vendorText = record.vendorVisiblePayload + record.vendorRawResponse;
    const presentTokens: string[] = [];
    const presentOriginals: string[] = [];
    for (const v of vaultTokens) {
      const escapedToken = jsonEscaped(v.token);
      if (vendorText.includes(v.token) || vendorText.includes(escapedToken)) {
        presentTokens.push(v.token, escapedToken);
        presentOriginals.push(v.originalRaw, jsonEscaped(v.originalRaw));
      }
    }
    const findingTokens = record.findings
      .map((f) => f.replacementToken)
      .filter((t) => !t.startsWith('<<CHAFF') && !/[一-鿿]/.test(t));
    return {
      vendor: buildMatcher([...findingTokens, ...presentTokens], true),
      local: buildMatcher(presentOriginals, false),
    };
  }, [record, vaultTokens]);

  if (error) {
    return (
      <div className="p-6">
        <Callout tone="warn" title="记录已不可用">
          {error === 'record has expired from the audit window' ? '该记录已滚出最近 200 条的保留窗口。' : error}
        </Callout>
      </div>
    );
  }
  if (!record || !matchers) {
    return (
      <div className="space-y-3 p-6" aria-busy="true">
        <Skeleton className="h-6 w-1/2" />
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  const act = describeAction(record.actionTaken);
  const findingsTotal = record.findings.reduce((n, f) => n + f.count, 0);
  const blockedLocally = record.actionTaken === 'telemetry-blocked';

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="border-b border-line px-5 py-3">
        <div className="flex items-center gap-2">
          <Badge tone={act.tone}>{act.label}</Badge>
          <Badge>{MODE_LABEL[record.appliedMode]}</Badge>
          {record.simulated && <Badge tone="info">模拟</Badge>}
          <span className="tabular ml-auto font-mono text-2xs text-fg-subtle">{record.timestamp}</span>
        </div>
        <p className="mt-2 truncate font-mono text-sm text-fg" title={record.endpoint}>
          <span className="text-fg-subtle">{record.method}</span> {record.endpoint}
        </p>
        <dl className="mt-1.5 flex flex-wrap gap-x-5 gap-y-1 text-xs text-fg-subtle">
          <div className="flex gap-1.5">
            <dt>工具</dt>
            <dd className="text-fg-muted">{HARNESS_LABEL[record.harness]}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt>上游</dt>
            <dd className="text-fg-muted">{blockedLocally ? '未发出（本地应答）' : record.upstreamVendor}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt>状态</dt>
            <dd className={cx('tabular font-mono', record.status >= 400 || record.status === 0 ? 'text-danger' : 'text-fg-muted')}>{record.status || '—'}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt>耗时</dt>
            <dd className="tabular font-mono text-fg-muted">{formatLatency(record.latencyMs)}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt>还原</dt>
            <dd className="tabular font-mono text-fg-muted">{record.restoredCount}</dd>
          </div>
        </dl>
      </header>

      <Tabs
        idPrefix="detail"
        label="记录详情"
        value={tab}
        onChange={onTabChange}
        tabs={[
          { value: 'request', label: '请求对照' },
          { value: 'response', label: '响应对照' },
          { value: 'findings', label: '敏感项', count: findingsTotal },
          { value: 'meta', label: '元数据' },
        ]}
      />

      <div id="detail-panel" role="tabpanel" aria-labelledby={`detail-tab-${tab}`} className="flex min-h-0 flex-1 flex-col">
        {(record.truncated || record.withheldCount > 0) && (tab === 'request' || tab === 'response') && (
          <div className="space-y-2 border-b border-line px-4 py-2.5">
            {record.truncated && <p className="text-xs text-fg-subtle">正文已截断（超过 64 KB）</p>}
            {record.withheldCount > 0 && tab === 'response' && (
              <p className="flex items-center gap-1.5 text-xs text-warn">
                <WarningCircle aria-hidden="true" size={13} weight="bold" />
                已保留 {record.withheldCount} 个工具参数凭据占位符
              </p>
            )}
          </div>
        )}
        {tab === 'request' && (
          <div className="grid min-h-0 flex-1 grid-rows-2 divide-y divide-line 2xl:grid-cols-2 2xl:grid-rows-1 2xl:divide-x 2xl:divide-y-0">
            <CodeView title="本地发出" caption="本地原文" text={record.localRequestPayload} bytes={record.requestBytes} matcher={matchers.local} mark="secret" />
            <CodeView
              title="厂商收到"
              caption={blockedLocally ? '未发出' : '已改写'}
              text={record.vendorVisiblePayload}
              matcher={matchers.vendor}
              emptyText="已在本地拦截"
            />
          </div>
        )}
        {tab === 'response' && (
          <div className="grid min-h-0 flex-1 grid-rows-2 divide-y divide-line 2xl:grid-cols-2 2xl:grid-rows-1 2xl:divide-x 2xl:divide-y-0">
            <CodeView title="厂商返回" caption="含占位符" text={record.vendorRawResponse} matcher={matchers.vendor} emptyText="无上游响应" />
            <CodeView title="交给工具" caption="已还原" text={record.localRestoredResponse} bytes={record.responseBytes} matcher={matchers.local} mark="secret" />
          </div>
        )}
        {tab === 'findings' && <FindingsTable record={record} />}
        {tab === 'meta' && <MetaList record={record} />}
      </div>
    </div>
  );
}

function FindingsTable({ record }: { record: TrafficAuditRecord }) {
  const sorted = useMemo(
    () => [...record.findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]),
    [record.findings],
  );
  if (!sorted.length) {
    return (
      <EmptyState icon={<MagnifyingGlass size={20} />} title="未检出敏感数据">
        未命中内置规则或自定义规则
      </EmptyState>
    );
  }
  return (
    <div className="min-h-0 overflow-auto">
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-surface-2">
          <tr className="border-b border-line text-2xs text-fg-subtle">
            <th scope="col" className="px-4 py-2 font-medium">级别</th>
            <th scope="col" className="px-2 py-2 font-medium">类型</th>
            <th scope="col" className="px-2 py-2 font-medium">原值（遮罩）</th>
            <th scope="col" className="px-2 py-2 font-medium">替换为</th>
            <th scope="col" className="px-4 py-2 text-right font-medium">次数</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {sorted.map((f, i) => (
            <tr key={i}>
              <td className="px-4 py-2">
                <Badge tone={f.severity === 'critical' || f.severity === 'high' ? 'danger' : f.severity === 'medium' ? 'warn' : 'neutral'}>{SEVERITY_LABEL[f.severity]}</Badge>
              </td>
              <td className="px-2 py-2">
                <p className="text-fg">{FINDING_LABEL[f.kind]}</p>
                <p className="text-2xs text-fg-subtle">{f.label}</p>
              </td>
              <td className="px-2 py-2 font-mono text-danger">{f.originalPreview}</td>
              <td className="max-w-[260px] truncate px-2 py-2 font-mono text-brand" title={f.replacementToken}>
                {f.replacementToken}
              </td>
              <td className="tabular px-4 py-2 text-right font-mono text-fg-muted">{f.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MetaList({ record }: { record: TrafficAuditRecord }) {
  const rows: Array<[string, React.ReactNode]> = [
    ['记录 ID', <code className="font-mono">{record.id}</code>],
    ['时间', record.timestamp],
    ['工具', HARNESS_LABEL[record.harness]],
    ['类别', CATEGORY_LABEL[record.category]],
    ['模式', MODE_LABEL[record.appliedMode]],
    ['处理动作', <code className="font-mono">{record.actionTaken}</code>],
    ['上游', record.upstreamVendor],
    ['HTTP 状态', record.status || '未发出'],
    ['请求大小', formatBytes(record.requestBytes)],
    ['响应大小', formatBytes(record.responseBytes)],
    ['还原的占位符', record.restoredCount],
    ['保留的凭据占位符', record.withheldCount],
    ['正文截断', record.truncated ? '是（超过 64 KB）' : '否'],
    ['来源', record.simulated ? '内置模拟器（未联网）' : '真实流量'],
  ];
  return (
    <dl className="min-h-0 divide-y divide-line overflow-auto text-xs">
      {rows.map(([k, v]) => (
        <div key={k} className="grid grid-cols-[160px_1fr] gap-4 px-5 py-2.5">
          <dt className="text-fg-subtle">{k}</dt>
          <dd className="tabular break-all text-fg">{v}</dd>
        </div>
      ))}
    </dl>
  );
}
