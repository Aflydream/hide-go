import { memo, useMemo, useState } from 'react';
import { BracketsCurly } from '@phosphor-icons/react';
import { CopyButton, IconButton, cx } from './ui';
import { formatBytes, prettyJson } from '../lib/format';

/** Shapes produced by the gateway, highlighted even when the vault was cleared since. */
const PLACEHOLDER_PATTERNS = [
  String.raw`sk-sem-placeholder-key-\d+`,
  String.raw`<<[A-Z_]+?_\d{3}(?:_\d+)?>>`,
  String.raw`\b198\.1[89]\.\d{1,3}\.\d{1,3}\b`,
  String.raw`/workspace/user_\d+`,
  String.raw`[A-Za-z]:(?:\\\\|\\)workspace(?:\\\\|\\)user_\d+`,
  String.raw`[a-z0-9-]+\.example\.internal`,
  String.raw`dev_member_\d+@sandbox\.example\.org`,
  String.raw`⟦HIDE-CIPHER::[^⟧]*⟧`,
  String.raw`// \[(?:BotanicalSensor|CatalogIndex|OvenController)-\d+\][^\n"]*`,
];

function escapeRegExp(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function buildMatcher(terms: string[], withPlaceholders: boolean): RegExp | null {
  const unique = Array.from(new Set(terms.filter((t) => t.length >= 3)))
    .sort((a, b) => b.length - a.length)
    .slice(0, 1500)
    .map(escapeRegExp);
  const all = [...unique, ...(withPlaceholders ? PLACEHOLDER_PATTERNS : [])];
  if (!all.length) return null;
  try {
    return new RegExp(all.join('|'), 'g');
  } catch {
    return null;
  }
}

function highlight(text: string, matcher: RegExp | null, markClass: string) {
  if (!matcher || !text) return { nodes: [text] as React.ReactNode[], hits: 0 };
  const nodes: React.ReactNode[] = [];
  let last = 0;
  let hits = 0;
  matcher.lastIndex = 0;
  for (let m = matcher.exec(text); m; m = matcher.exec(text)) {
    if (m[0].length === 0) {
      matcher.lastIndex++;
      continue;
    }
    if (m.index > last) nodes.push(text.slice(last, m.index));
    nodes.push(
      <mark key={m.index} className={markClass}>
        {m[0]}
      </mark>,
    );
    hits++;
    last = m.index + m[0].length;
    if (hits > 4000) break;
  }
  nodes.push(text.slice(last));
  return { nodes, hits };
}

export type MarkKind = 'token' | 'secret';

export const CodeView = memo(function CodeView({
  title,
  caption,
  text,
  bytes,
  matcher,
  mark = 'token',
  emptyText = '无内容',
  className,
}: {
  title: string;
  caption?: string;
  text: string;
  bytes?: number;
  matcher: RegExp | null;
  mark?: MarkKind;
  emptyText?: string;
  className?: string;
}) {
  const [pretty, setPretty] = useState(true);
  const display = useMemo(() => (pretty ? prettyJson(text) : text), [pretty, text]);
  const { nodes, hits } = useMemo(() => highlight(display, matcher, mark === 'token' ? 'mark-token' : 'mark-secret'), [display, matcher, mark]);
  const isJson = display !== text || /^\s*[[{]/.test(text);
  return (
    <section aria-label={title} className={cx('flex min-h-0 min-w-0 flex-col', className)}>
      <header className={cx('flex h-9 shrink-0 items-center gap-2 border-b border-l-2 border-b-line bg-surface-2 px-3', mark === 'secret' ? 'border-l-danger' : 'border-l-brand')}>
        <h3 className="truncate text-xs font-semibold text-fg">{title}</h3>
        <span className={cx('shrink-0 rounded-sm px-1 text-2xs font-medium', mark === 'secret' ? 'bg-danger/10 text-danger' : 'bg-brand/10 text-brand')}>
          {mark === 'secret' ? '仅本机' : '厂商可见'}
        </span>
        {caption && <span className="truncate text-2xs text-fg-subtle">{caption}</span>}
        <span className="ml-auto flex items-center gap-1">
          {hits > 0 && (
            <span className={cx('tabular mr-1 text-2xs', mark === 'secret' ? 'text-danger' : 'text-brand')}>
              {hits} 处{mark === 'secret' ? '敏感' : '替换'}
            </span>
          )}
          {bytes !== undefined && <span className="tabular mr-1 text-2xs text-fg-subtle">{formatBytes(bytes)}</span>}
          {isJson && <IconButton label={pretty ? '显示原始格式' : '格式化 JSON'} pressed={pretty} icon={<BracketsCurly size={14} />} onClick={() => setPretty((p) => !p)} />}
          <CopyButton text={display} compact label={`复制${title}`} />
        </span>
      </header>
      {text ? (
        <pre tabIndex={0} className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all bg-surface px-3 py-2.5 font-mono text-xs leading-5 text-fg">
          {nodes}
        </pre>
      ) : (
        <p className="flex flex-1 items-center justify-center bg-surface p-6 text-xs text-fg-subtle">{emptyText}</p>
      )}
    </section>
  );
});
