import { useMemo, useState } from 'react';
import { Eye, EyeSlash, Funnel, MagnifyingGlass, Trash, Vault as VaultIcon } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { VAULT_CATEGORY_LABEL, formatCount } from '../lib/format';
import { Badge, Button, ConfirmDialog, CopyButton, EmptyState, IconButton, Skeleton, Switch, cx, inputClass, useToast } from '../components/ui';

/** Rows rendered at once; the table is not virtualised and the vault can hold 50,000 entries. */
const ROW_LIMIT = 500;

export function VaultView() {
  const { vault, vaultLoading, refreshVault, openSimulator } = useStore();
  const toast = useToast();
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [secretsOnly, setSecretsOnly] = useState(false);
  const [revealAll, setRevealAll] = useState(false);
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(new Set());
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  const categories = useMemo(() => Array.from(new Set(vault.map((v) => v.category))).sort(), [vault]);
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return vault.filter(
      (v) =>
        (category === 'all' || v.category === category) &&
        (!secretsOnly || v.secret) &&
        (!q || v.token.toLowerCase().includes(q) || v.originalRaw.toLowerCase().includes(q)),
    );
  }, [vault, query, category, secretsOnly]);
  const visible = rows.slice(0, ROW_LIMIT);
  const filtersActive = query || category !== 'all' || secretsOnly;

  const toggle = (token: string) =>
    setRevealed((prev) => {
      const next = new Set(prev);
      if (!next.delete(token)) next.add(token);
      return next;
    });

  const clear = async () => {
    setClearing(true);
    try {
      await api.clearVault();
      await refreshVault();
      setRevealed(new Set());
      setRevealAll(false);
      toast.push({ tone: 'brand', title: '映射表已清空' });
    } catch (e) {
      toast.push({ tone: 'danger', title: '清空失败', body: (e as Error).message });
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
            placeholder="搜索占位符或真实值"
            aria-label="搜索映射表"
            className={cx(inputClass, 'h-8 w-56 pl-8')}
          />
        </div>
        <select aria-label="按类型筛选" value={category} onChange={(e) => setCategory(e.target.value)} className={cx(inputClass, 'h-8 cursor-pointer pr-7')}>
          <option value="all">全部类型</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {VAULT_CATEGORY_LABEL[c] ?? c}
            </option>
          ))}
        </select>
        <label className="ml-1 flex cursor-pointer items-center gap-2 text-xs text-fg-muted">
          <Switch checked={secretsOnly} onChange={setSecretsOnly} label="只看凭据" />
          只看凭据
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
            重置筛选
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <span className="tabular text-xs text-fg-subtle" role="status">
            {formatCount(rows.length)} / {formatCount(vault.length)} 条
          </span>
          <Button
            size="sm"
            aria-pressed={revealAll}
            icon={revealAll ? <EyeSlash size={14} /> : <Eye size={14} />}
            disabled={!vault.length}
            onClick={() => setRevealAll((v) => !v)}
          >
            {revealAll ? '隐藏真实值' : '显示真实值'}
          </Button>
          <Button size="sm" variant="ghost" icon={<Trash size={14} />} disabled={!vault.length} onClick={() => setConfirmClear(true)}>
            清空
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
            <EmptyState icon={<Funnel size={20} />} title="无匹配条目">
              调整筛选或搜索条件
            </EmptyState>
          ) : (
            <EmptyState
              icon={<VaultIcon size={20} />}
              title="映射表为空"
              action={
                <Button size="sm" onClick={openSimulator}>
                  发送模拟请求
                </Button>
              }
            >
              脱敏或 All-Hide 命中后显示映射关系
            </EmptyState>
          )
        ) : (
          <table className="w-full table-fixed text-left text-xs">
            <caption className="sr-only">占位符与真实值映射表</caption>
            <thead className="sticky top-0 z-10 bg-surface-2">
              <tr className="border-b border-line text-2xs text-fg-subtle">
                <th scope="col" className="w-[34%] py-2 pl-6 font-medium">占位符（厂商可见）</th>
                <th scope="col" className="py-2 pl-3 font-medium">真实值（仅本机）</th>
                <th scope="col" className="w-40 py-2 pl-3 font-medium">类型</th>
                <th scope="col" className="w-16 py-2 pl-3 text-right font-medium">命中</th>
                <th scope="col" className="w-14 py-2 pl-2 pr-5">
                  <span className="sr-only">操作</span>
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
                        <code className="min-w-0 break-all py-1 font-mono text-brand">{v.token}</code>
                        <span className="opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100">
                          <CopyButton compact text={v.token} label="复制占位符" />
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 pl-3 align-top font-mono">
                      {shown ? <span className="mark-secret break-all px-1 py-0.5">{v.originalRaw}</span> : <span className="break-all text-fg-muted">{v.originalMasked}</span>}
                    </td>
                    <td className="py-2 pl-3 align-top">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="py-0.5 text-fg">{VAULT_CATEGORY_LABEL[v.category] ?? v.category}</span>
                        {v.secret && <Badge tone="danger">凭据</Badge>}
                      </div>
                    </td>
                    <td className="tabular py-2.5 pl-3 text-right align-top font-mono text-fg-muted">{formatCount(v.hitCount)}</td>
                    <td className="py-1.5 pl-2 pr-5 text-right align-top">
                      <IconButton
                        label={shown ? '隐藏真实值' : '显示真实值'}
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
            仅显示前 {ROW_LIMIT} 条，共 {formatCount(rows.length)} 条符合条件。请用搜索或筛选缩小范围。
          </p>
        )}
      </div>

      <p className="shrink-0 border-t border-line bg-surface px-6 py-2 text-xs text-fg-subtle">
        仅驻留内存，退出清空 · 上限 50,000 条（LRU 淘汰）
      </p>

      <ConfirmDialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={clear}
        busy={clearing}
        title="清空映射表？"
        description="进行中对话引用的旧占位符将无法继续还原，新请求重新分配。"
        confirmLabel="清空映射表"
      />
    </div>
  );
}
