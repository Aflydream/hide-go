import { useCallback, useMemo, useState } from 'react';
import { Eye, EyeSlash, Funnel, MagnifyingGlass, Trash, Vault as VaultIcon } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { useDebounced } from '../lib/hooks';
import { formatCount, getVaultCategoryLabel } from '../lib/format';
import { useI18n } from '../lib/i18n';
import { Badge, Button, ConfirmDialog, CopyButton, EmptyState, IconButton, Skeleton, Switch, cx, inputClass, useToast } from '../components/ui';

/** Rows rendered at once; the table is not virtualised and the vault can hold 50,000 entries. */
const ROW_LIMIT = 500;

export function VaultView() {
  const { vault, vaultLoading, refreshVault, openSimulator } = useStore();
  const { locale, t } = useI18n();
  const toast = useToast();
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebounced(query, 120);
  const [category, setCategory] = useState('all');
  const [secretsOnly, setSecretsOnly] = useState(false);
  const [revealAll, setRevealAll] = useState(false);
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(() => new Set());
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  const categories = useMemo(() => Array.from(new Set(vault.map((v) => v.category))).sort(), [vault]);
  const rows = useMemo(() => {
    const q = debouncedQuery.trim().toLowerCase();
    return vault.filter(
      (v) =>
        (category === 'all' || v.category === category) &&
        (!secretsOnly || v.secret) &&
        (!q || v.token.toLowerCase().includes(q) || v.originalRaw.toLowerCase().includes(q)),
    );
  }, [vault, debouncedQuery, category, secretsOnly]);
  const visible = useMemo(() => rows.slice(0, ROW_LIMIT), [rows]);
  const filtersActive = query || category !== 'all' || secretsOnly;

  const toggle = useCallback(
    (token: string) =>
      setRevealed((prev) => {
        const next = new Set(prev);
        if (!next.delete(token)) next.add(token);
        return next;
      }),
    [],
  );

  const clear = async () => {
    setClearing(true);
    try {
      await api.clearVault();
      await refreshVault();
      setRevealed(new Set());
      setRevealAll(false);
      toast.push({ tone: 'brand', title: t('vault.clearedToast') });
    } catch (e) {
      toast.push({ tone: 'danger', title: t('vault.clearFailed'), body: (e as Error).message });
    }
    setClearing(false);
    setConfirmClear(false);
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface px-6 py-2.5">
        <div className="relative">
          <MagnifyingGlass aria-hidden="true" size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-subtle" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('vault.searchPlaceholder')}
            aria-label={t('vault.searchAria')}
            className={cx(inputClass, 'h-8 w-56 pl-8')}
          />
        </div>
        <select aria-label={t('vault.filterCategoryAria')} value={category} onChange={(e) => setCategory(e.target.value)} className={cx(inputClass, 'h-8 cursor-pointer pr-7')}>
          <option value="all">{t('vault.allCategories')}</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {getVaultCategoryLabel(c, locale)}
            </option>
          ))}
        </select>
        <label className="ml-1 flex cursor-pointer items-center gap-2 text-xs text-fg-muted">
          <Switch checked={secretsOnly} onChange={setSecretsOnly} label={t('vault.secretsOnly')} />
          {t('vault.secretsOnly')}
        </label>
        {filtersActive && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setQuery('');
              setCategory('all');
              setSecretsOnly(false);
            }}
          >
            {t('common.resetFilters')}
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <span className="tabular text-xs text-fg-subtle" role="status">
            {t('vault.countSummary', {
              rows: formatCount(rows.length, locale),
              total: formatCount(vault.length, locale),
            })}
          </span>
          <Button
            size="sm"
            aria-pressed={revealAll}
            icon={revealAll ? <EyeSlash size={14} /> : <Eye size={14} />}
            disabled={!vault.length}
            onClick={() => setRevealAll((v) => !v)}
          >
            {t(revealAll ? 'vault.hideAll' : 'vault.revealAll')}
          </Button>
          <Button size="sm" variant="ghost" icon={<Trash size={14} />} disabled={!vault.length} onClick={() => setConfirmClear(true)}>
            {t('common.clear')}
          </Button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto bg-surface">
        {vaultLoading && !vault.length ? (
          <div className="space-y-2 p-4" aria-busy="true">
            {Array.from({ length: 10 }, (_, i) => (
              <Skeleton key={i} className="h-8" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          filtersActive ? (
            <EmptyState icon={<Funnel size={20} />} title={t('vault.noMatchesTitle')}>
              {t('vault.noMatchesBody')}
            </EmptyState>
          ) : (
            <EmptyState
              icon={<VaultIcon size={20} />}
              title={t('vault.emptyTitle')}
              action={
                <Button size="sm" onClick={openSimulator}>
                  {t('overview.simulateRequest')}
                </Button>
              }
            >
              {t('vault.emptyBody')}
            </EmptyState>
          )
        ) : (
          <table className="w-full table-fixed text-left text-xs">
            <caption className="sr-only">{t('vault.tableCaption')}</caption>
            <thead className="sticky top-0 z-10 bg-surface-2">
              <tr className="border-b border-line text-2xs text-fg-subtle">
                <th scope="col" className="w-[34%] py-2 pl-6 font-medium">{t('vault.colToken')}</th>
                <th scope="col" className="py-2 pl-3 font-medium">{t('vault.colOriginal')}</th>
                <th scope="col" className="w-40 py-2 pl-3 font-medium">{t('vault.colCategory')}</th>
                <th scope="col" className="w-16 py-2 pl-3 text-right font-medium">{t('vault.colHits')}</th>
                <th scope="col" className="w-14 py-2 pl-2 pr-5">
                  <span className="sr-only">{t('vault.colActions')}</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {visible.map((v) => {
                const shown = revealAll || revealed.has(v.token);
                return (
                  <tr key={v.token} className="group transition-colors hover:bg-surface-2">
                    <td className="py-1.5 pl-6 align-top">
                      <div className="flex items-start gap-1">
                        <code className="min-w-0 break-all py-1 font-mono text-info">{v.token}</code>
                        <span className="opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100">
                          <CopyButton compact text={v.token} label={t('vault.copyToken')} />
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 pl-3 align-top font-mono">
                      {shown ? <span className="mark-secret break-all px-1 py-0.5">{v.originalRaw}</span> : <span className="break-all text-fg-muted">{v.originalMasked}</span>}
                    </td>
                    <td className="py-2 pl-3 align-top">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="py-0.5 text-fg">{getVaultCategoryLabel(v.category, locale)}</span>
                        {v.secret && <Badge tone="danger">{t('vault.secretBadge')}</Badge>}
                      </div>
                    </td>
                    <td className="tabular py-2.5 pl-3 text-right align-top font-mono text-fg-muted">{formatCount(v.hitCount, locale)}</td>
                    <td className="py-1.5 pl-2 pr-5 text-right align-top">
                      <IconButton
                        label={t(shown ? 'vault.hideRow' : 'vault.revealRow')}
                        pressed={revealed.has(v.token)}
                        disabled={revealAll}
                        icon={shown ? <EyeSlash size={14} /> : <Eye size={14} />}
                        onClick={() => toggle(v.token)}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {rows.length > ROW_LIMIT && (
          <p className="border-t border-line px-6 py-3 text-xs text-fg-subtle">
            {t('vault.rowLimitNotice', { limit: ROW_LIMIT, total: formatCount(rows.length, locale) })}
          </p>
        )}
      </div>

      <p className="shrink-0 border-t border-line bg-surface px-6 py-2 text-xs text-fg-subtle">{t('vault.footerNote')}</p>

      <ConfirmDialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={clear}
        busy={clearing}
        title={t('vault.confirmClearTitle')}
        description={t('vault.confirmClearDesc')}
        confirmLabel={t('vault.confirmClearBtn')}
      />
    </div>
  );
}
