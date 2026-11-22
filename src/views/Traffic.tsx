import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowsLeftRight, MagnifyingGlass, Trash, PaperPlaneTilt, WarningCircle, Funnel } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import {
  HARNESS_ORDER,
  SEVERITY_RANK,
  describeAction,
  formatBytes,
  formatLatency,
  getCategoryLabel,
  getFindingLabel,
  getHarnessLabel,
  getModeLabel,
  getSeverityLabel,
} from '../lib/format';
import { useI18n } from '../lib/i18n';
import type { HarnessKind, Severity, TrafficAuditRecord, TrafficCategory } from '../types';
import { Badge, Button, Callout, ConfirmDialog, EmptyState, Skeleton, Switch, Tabs, cx, inputClass, useToast } from '../components/ui';
import { CodeView, buildMatcher } from '../components/CodeView';

export function SeverityBadge({ severity, count }: { severity: Severity | null; count: number }) {
  const { locale, t } = useI18n();
  const tone = severity === 'critical' || severity === 'high' ? 'danger' : severity === 'medium' ? 'warn' : 'neutral';
  const maxSeverity = severity ? getSeverityLabel(severity, locale) : '';
  return (
    <Badge tone={tone} className="tabular">
      {count}
      <span className="sr-only">{t('traffic.severitySr', { severity: maxSeverity })}</span>
    </Badge>
  );
}

type DetailTab = 'request' | 'response' | 'findings' | 'meta';
type ActionFilter = 'all' | 'masked' | 'blocked' | 'passed' | 'error';

function matchesAction(action: string, filter: ActionFilter) {
  const tone = describeAction(action, 'en');
  switch (filter) {
    case 'all':
      return true;
    case 'masked':
      return tone.tone === 'brand';
    case 'blocked':
      return tone.tone === 'warn';
    case 'passed':
      return action === 'passed' || action === 'protobuf-passed' || action === 'protobuf-audited';
    case 'error':
      return tone.tone === 'danger';
  }
}

const selectClass = cx(inputClass, 'h-8 cursor-pointer pr-7');

export function Traffic() {
  const { logs, logsLoading, params, navigate, refreshLogs, openSimulator, vault } = useStore();
  const { locale, t } = useI18n();
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
        (!q ||
          r.endpoint.toLowerCase().includes(q) ||
          getHarnessLabel(r.harness, locale).toLowerCase().includes(q) ||
          r.id.startsWith(q)),
    );
  }, [logs, query, harness, category, action, hideSimulated, locale]);

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
      toast.push({ tone: 'brand', title: t('traffic.clearSuccess') });
    } catch (e) {
      toast.push({ tone: 'danger', title: t('traffic.clearFailed'), body: (e as Error).message });
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
            placeholder={t('traffic.searchPlaceholder')}
            aria-label={t('traffic.searchAria')}
            className={cx(inputClass, 'h-8 w-56 pl-8')}
          />
        </div>
        <select aria-label={t('traffic.filterToolAria')} value={harness} onChange={(e) => setHarness(e.target.value as HarnessKind | 'all')} className={selectClass}>
          <option value="all">{t('traffic.allTools')}</option>
          {HARNESS_ORDER.map((h) => (
            <option key={h} value={h}>
              {getHarnessLabel(h, locale)}
            </option>
          ))}
        </select>
        <select aria-label={t('traffic.filterCategoryAria')} value={category} onChange={(e) => setCategory(e.target.value as TrafficCategory | 'all')} className={selectClass}>
          <option value="all">{t('traffic.allCategories')}</option>
          {(['interactive-prompt', 'tool-execution-sync', 'codebase-indexing', 'telemetry'] as TrafficCategory[]).map((c) => (
            <option key={c} value={c}>
              {getCategoryLabel(c, locale)}
            </option>
          ))}
        </select>
        <select aria-label={t('traffic.filterActionAria')} value={action} onChange={(e) => setAction(e.target.value as ActionFilter)} className={selectClass}>
          <option value="all">{t('traffic.allActions')}</option>
          <option value="masked">{t('traffic.actionMasked')}</option>
          <option value="blocked">{t('traffic.actionBlocked')}</option>
          <option value="passed">{t('traffic.actionPassed')}</option>
          <option value="error">{t('traffic.actionError')}</option>
        </select>
        <label className="ml-1 flex cursor-pointer items-center gap-2 text-xs text-fg-muted">
          <Switch checked={hideSimulated} onChange={setHideSimulated} label={t('traffic.hideSimulated')} />
          {t('traffic.hideSimulated')}
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
            {t('common.resetFilters')}
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <span className="tabular text-xs text-fg-subtle" role="status">
            {t('traffic.countSummary', { rows: rows.length, total: logs.length })}
          </span>
          <Button size="sm" icon={<PaperPlaneTilt size={14} />} onClick={openSimulator}>
            {t('shell.simulate')}
          </Button>
          <Button size="sm" variant="ghost" icon={<Trash size={14} />} disabled={!logs.length} onClick={() => setConfirmClear(true)}>
            {t('common.clear')}
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
              <EmptyState icon={<Funnel size={20} />} title={t('traffic.noMatchesTitle')}>
                {t('traffic.noMatchesBody')}
              </EmptyState>
            ) : (
              <EmptyState
                icon={<ArrowsLeftRight size={20} />}
                title={t('traffic.emptyTitle')}
                action={
                  <Button size="sm" variant="primary" onClick={() => navigate('integrations')}>
                    {t('overview.integrationGuide')}
                  </Button>
                }
              >
                {t('traffic.emptyBody')}
              </EmptyState>
            )
          ) : (
            <table className="w-full table-fixed text-left text-xs">
              <caption className="sr-only">{t('traffic.tableCaption')}</caption>
              <thead className="sticky top-0 z-10 bg-surface-2">
                <tr className="border-b border-line text-2xs text-fg-subtle">
                  <th scope="col" className="w-[76px] py-2 pl-4 font-medium">{t('traffic.colTime')}</th>
                  <th scope="col" className="py-2 pl-2 font-medium">{t('traffic.colToolEndpoint')}</th>
                  <th scope="col" className="w-[104px] py-2 pl-2 font-medium">{t('traffic.colAction')}</th>
                  <th scope="col" className="w-12 py-2 pl-2 text-right font-medium">{t('traffic.colStatus')}</th>
                  <th scope="col" className="w-14 py-2 pl-2 pr-4 text-right font-medium">{t('traffic.colFindings')}</th>
                </tr>
              </thead>
              <tbody ref={listRef} onKeyDown={onListKey} className="divide-y divide-line">
                {rows.map((r, idx) => {
                  const active = r.id === effectiveId;
                  const act = describeAction(r.actionTaken, locale);
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
                          <span className="truncate font-medium text-fg">{getHarnessLabel(r.harness, locale)}</span>
                          <span className="shrink-0 text-2xs text-fg-subtle">{getCategoryLabel(r.category, locale)}</span>
                          {r.simulated && <span className="shrink-0 text-2xs text-info">{t('overview.simulatedTag')}</span>}
                        </div>
                        <p className="truncate font-mono text-2xs text-fg-subtle" title={r.endpoint}>
                          {r.method} {r.endpoint}
                        </p>
                      </td>
                      <td className="py-2 pl-2 align-top">
                        <Badge tone={act.tone}>{act.label}</Badge>
                      </td>
                      <td className={cx('tabular py-2 pl-2 text-right align-top font-mono', r.status >= 400 || r.status === 0 ? 'text-danger' : 'text-fg-muted')}>
                        {r.status || t('common.none')}
                      </td>
                      <td className="py-2 pl-2 pr-4 text-right align-top">
                        {r.findingCount > 0 ? <SeverityBadge severity={r.topSeverity} count={r.findingCount} /> : <span className="text-fg-subtle">{t('common.none')}</span>}
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
            <EmptyState icon={<ArrowsLeftRight size={20} />} title={t('traffic.selectPromptTitle')}>
              {t('traffic.selectPromptBody')}
            </EmptyState>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={clear}
        title={t('traffic.confirmClearTitle')}
        description={t('traffic.confirmClearDesc')}
        confirmLabel={t('traffic.confirmClearBtn')}
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
  const { locale, t } = useI18n();
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
      .filter((tok) => !tok.startsWith('<<CHAFF') && !/[一-鿿]/.test(tok));
    return {
      vendor: buildMatcher([...findingTokens, ...presentTokens], true),
      local: buildMatcher(presentOriginals, false),
    };
  }, [record, vaultTokens]);

  if (error) {
    return (
      <div className="p-6">
        <Callout tone="warn" title={t('traffic.recordUnavailable')}>
          {error === 'record has expired from the audit window' ? t('traffic.recordExpired') : error}
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

  const act = describeAction(record.actionTaken, locale);
  const findingsTotal = record.findings.reduce((n, f) => n + f.count, 0);
  const blockedLocally = record.actionTaken === 'telemetry-blocked';

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="border-b border-line px-5 py-3">
        <div className="flex items-center gap-2">
          <Badge tone={act.tone}>{act.label}</Badge>
          <Badge>{getModeLabel(record.appliedMode, locale)}</Badge>
          {record.simulated && <Badge tone="info">{t('overview.simulatedTag')}</Badge>}
          <span className="tabular ml-auto font-mono text-2xs text-fg-subtle">{record.timestamp}</span>
        </div>
        <p className="mt-2 truncate font-mono text-sm text-fg" title={record.endpoint}>
          <span className="text-fg-subtle">{record.method}</span> {record.endpoint}
        </p>
        <dl className="mt-1.5 flex flex-wrap gap-x-5 gap-y-1 text-xs text-fg-subtle">
          <div className="flex gap-1.5">
            <dt>{t('traffic.labelTool')}</dt>
            <dd className="text-fg-muted">{getHarnessLabel(record.harness, locale)}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt>{t('traffic.labelUpstream')}</dt>
            <dd className="text-fg-muted">{blockedLocally ? t('traffic.blockedLocally') : record.upstreamVendor}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt>{t('traffic.labelStatus')}</dt>
            <dd className={cx('tabular font-mono', record.status >= 400 || record.status === 0 ? 'text-danger' : 'text-fg-muted')}>
              {record.status || t('common.none')}
            </dd>
          </div>
          <div className="flex gap-1.5">
            <dt>{t('traffic.labelLatency')}</dt>
            <dd className="tabular font-mono text-fg-muted">{formatLatency(record.latencyMs)}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt>{t('traffic.labelRestored')}</dt>
            <dd className="tabular font-mono text-fg-muted">{record.restoredCount}</dd>
          </div>
        </dl>
      </header>

      <Tabs
        idPrefix="detail"
        label={t('traffic.detailTabsAria')}
        value={tab}
        onChange={onTabChange}
        tabs={[
          { value: 'request', label: t('traffic.tabRequest') },
          { value: 'response', label: t('traffic.tabResponse') },
          { value: 'findings', label: t('traffic.tabFindings'), count: findingsTotal },
          { value: 'meta', label: t('traffic.tabMeta') },
        ]}
      />

      <div id="detail-panel" role="tabpanel" aria-labelledby={`detail-tab-${tab}`} className="flex min-h-0 flex-1 flex-col">
        {(record.truncated || record.withheldCount > 0) && (tab === 'request' || tab === 'response') && (
          <div className="space-y-2 border-b border-line px-4 py-2.5">
            {record.truncated && <p className="text-xs text-fg-subtle">{t('traffic.truncatedNotice')}</p>}
            {record.withheldCount > 0 && tab === 'response' && (
              <p className="flex items-center gap-1.5 text-xs text-warn">
                <WarningCircle aria-hidden="true" size={13} weight="bold" />
                {t('traffic.withheldNotice', { count: record.withheldCount })}
              </p>
            )}
          </div>
        )}
        {tab === 'request' && (
          <div className="grid min-h-0 flex-1 grid-rows-2 divide-y divide-line 2xl:grid-cols-2 2xl:grid-rows-1 2xl:divide-x 2xl:divide-y-0">
            <CodeView
              title={t('traffic.codeLocalOut')}
              caption={t('traffic.codeLocalOutCaption')}
              text={record.localRequestPayload}
              bytes={record.requestBytes}
              matcher={matchers.local}
              mark="secret"
            />
            <CodeView
              title={t('traffic.codeVendorIn')}
              caption={blockedLocally ? t('traffic.codeVendorBlockedCaption') : t('traffic.codeVendorSanitizedCaption')}
              text={record.vendorVisiblePayload}
              matcher={matchers.vendor}
              emptyText={t('traffic.codeVendorBlockedEmpty')}
            />
          </div>
        )}
        {tab === 'response' && (
          <div className="grid min-h-0 flex-1 grid-rows-2 divide-y divide-line 2xl:grid-cols-2 2xl:grid-rows-1 2xl:divide-x 2xl:divide-y-0">
            <CodeView
              title={t('traffic.codeVendorRaw')}
              caption={t('traffic.codeVendorRawCaption')}
              text={record.vendorRawResponse}
              matcher={matchers.vendor}
              emptyText={t('traffic.codeVendorRawEmpty')}
            />
            <CodeView
              title={t('traffic.codeLocalRestored')}
              caption={t('traffic.codeLocalRestoredCaption')}
              text={record.localRestoredResponse}
              bytes={record.responseBytes}
              matcher={matchers.local}
              mark="secret"
            />
          </div>
        )}
        {tab === 'findings' && <FindingsTable record={record} />}
        {tab === 'meta' && <MetaList record={record} />}
      </div>
    </div>
  );
}

function FindingsTable({ record }: { record: TrafficAuditRecord }) {
  const { locale, t } = useI18n();
  const sorted = useMemo(
    () => [...record.findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]),
    [record.findings],
  );
  if (!sorted.length) {
    return (
      <EmptyState icon={<MagnifyingGlass size={20} />} title={t('traffic.findingsEmptyTitle')}>
        {t('traffic.findingsEmptyBody')}
      </EmptyState>
    );
  }
  return (
    <div className="min-h-0 overflow-auto">
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-surface-2">
          <tr className="border-b border-line text-2xs text-fg-subtle">
            <th scope="col" className="px-4 py-2 font-medium">{t('traffic.findingsColSeverity')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('traffic.findingsColType')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('traffic.findingsColOriginal')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('traffic.findingsColReplacement')}</th>
            <th scope="col" className="px-4 py-2 text-right font-medium">{t('traffic.findingsColCount')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {sorted.map((f, i) => (
            <tr key={i}>
              <td className="px-4 py-2">
                <Badge tone={f.severity === 'critical' || f.severity === 'high' ? 'danger' : f.severity === 'medium' ? 'warn' : 'neutral'}>
                  {getSeverityLabel(f.severity, locale)}
                </Badge>
              </td>
              <td className="px-2 py-2">
                <p className="text-fg">{getFindingLabel(f.kind, locale)}</p>
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
  const { locale, t } = useI18n();
  const rows: Array<[string, React.ReactNode]> = [
    [t('traffic.metaId'), <code className="font-mono">{record.id}</code>],
    [t('traffic.metaTime'), record.timestamp],
    [t('traffic.metaTool'), getHarnessLabel(record.harness, locale)],
    [t('traffic.metaCategory'), getCategoryLabel(record.category, locale)],
    [t('traffic.metaMode'), getModeLabel(record.appliedMode, locale)],
    [t('traffic.metaAction'), <code className="font-mono">{record.actionTaken}</code>],
    [t('traffic.metaUpstream'), record.upstreamVendor],
    [t('traffic.metaStatus'), record.status || t('common.notSent')],
    [t('traffic.metaReqSize'), formatBytes(record.requestBytes)],
    [t('traffic.metaRespSize'), formatBytes(record.responseBytes)],
    [t('traffic.metaRestored'), record.restoredCount],
    [t('traffic.metaWithheld'), record.withheldCount],
    [t('traffic.metaTruncated'), t(record.truncated ? 'traffic.metaTruncatedYes' : 'traffic.metaTruncatedNo')],
    [t('traffic.metaSource'), t(record.simulated ? 'traffic.metaSourceSim' : 'traffic.metaSourceLive')],
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
