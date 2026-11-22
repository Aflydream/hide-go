import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDown, BracketsCurly, ChatText, TextAlignLeft } from '@phosphor-icons/react';
import { CopyButton, IconButton, cx } from './ui';
import { extractRequestReadableText, extractSseReadableText, formatBytes, formatCount, prettyJson } from '../lib/format';
import { useI18n } from '../lib/i18n';

/** Shapes produced by the gateway, highlighted even when the vault was cleared since. */
const PLACEHOLDER_PATTERNS = [
  String.raw`sk-sem-placeholder-key-\d+`,
  String.raw`<<[A-Z_]+?_\d{3}(?:_\d+)?>>`,
  String.raw`\b198\.1[89]\.\d{1,3}\.\d{1,3}\b`,
  String.raw`/workspace/user_\d+`,
  String.raw`[A-Za-z]:(?:\\\\|\\|/)workspace(?:\\\\|\\|/)user_\d+`,
  String.raw`/opt/work/[a-z0-9]{8}\b`,
  String.raw`[A-Za-z]:(?:\\\\|\\|/)work(?:\\\\|\\|/)[a-z0-9]{8}\b`,
  String.raw`\b(?:key_ref_[A-Za-z0-9]{20}|sec_[A-Za-z0-9]{18}|tok_[A-Za-z0-9]{24}|ref_[a-z0-9]{10})\b`,
  String.raw`[a-z0-9-]+\.db\.example:\d+`,
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
  emptyText,
  focusTerm,
  className,
}: {
  title: string;
  caption?: string;
  text: string;
  bytes?: number;
  matcher: RegExp | null;
  mark?: MarkKind;
  emptyText?: string;
  focusTerm?: { term: string; seq: number } | null;
  className?: string;
}) {
  const { locale, t } = useI18n();
  const [pretty, setPretty] = useState(true);
  const [sseReadable, setSseReadable] = useState(true);
  const [dialogueView, setDialogueView] = useState(false);
  const [matchCursor, setMatchCursor] = useState(-1);
  const preRef = useRef<HTMLPreElement>(null);

  const sseText = useMemo(() => extractSseReadableText(text), [text]);
  const requestText = useMemo(() => (sseText === null ? extractRequestReadableText(text) : null), [sseText, text]);
  const display = useMemo(() => {
    if (sseText !== null && sseReadable) return sseText;
    if (requestText !== null && dialogueView) return requestText;
    return pretty ? prettyJson(text) : text;
  }, [sseText, sseReadable, requestText, dialogueView, pretty, text]);
  const { nodes, hits } = useMemo(() => highlight(display, matcher, mark === 'token' ? 'mark-token' : 'mark-secret'), [display, matcher, mark]);
  const isJson = sseText === null && (display !== text || /^\s*[[{]/.test(text));
  const resolvedEmpty = emptyText ?? t('common.noContent');

  useEffect(() => {
    setMatchCursor(-1);
  }, [display]);

  useEffect(() => {
    if (!focusTerm?.term) return;
    const pre = preRef.current;
    if (!pre) return;
    const marks = Array.from(pre.querySelectorAll<HTMLElement>('mark'));
    if (!marks.length) return;
    for (const m of marks) {
      m.classList.remove('ring-2', 'ring-focus');
    }
    const needle = focusTerm.term;
    const idx = marks.findIndex((m) => m.textContent === needle || m.textContent?.includes(needle));
    if (idx >= 0) {
      const target = marks[idx]!;
      target.classList.add('ring-2', 'ring-focus');
      target.scrollIntoView({ block: 'center', behavior: 'smooth' });
      setMatchCursor(idx);
    }
  }, [focusTerm, display]);

  const jumpNextMatch = useCallback(() => {
    const pre = preRef.current;
    if (!pre || hits === 0) return;
    const marks = pre.querySelectorAll<HTMLElement>('mark');
    if (!marks.length) return;
    if (matchCursor >= 0 && marks[matchCursor]) {
      marks[matchCursor]!.classList.remove('ring-2', 'ring-focus');
    }
    const next = (matchCursor + 1) % marks.length;
    const target = marks[next];
    if (target) {
      target.classList.add('ring-2', 'ring-focus');
      target.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
    setMatchCursor(next);
  }, [hits, matchCursor]);

  return (
    <section aria-label={title} className={cx('flex min-h-0 min-w-0 flex-col', className)}>
      <header className={cx('flex h-9 shrink-0 items-center gap-2 border-b border-l-2 border-b-line bg-surface-2 px-3', mark === 'secret' ? 'border-l-danger' : 'border-l-brand')}>
        <h3 className="truncate text-xs font-semibold text-fg">{title}</h3>
        <span className={cx('shrink-0 rounded-sm px-1 text-2xs font-medium', mark === 'secret' ? 'bg-danger/10 text-danger' : 'bg-brand/10 text-brand')}>
          {mark === 'secret' ? t('codeView.localOnly') : t('codeView.vendorSees')}
        </span>
        {caption && <span className="truncate text-2xs text-fg-subtle">{caption}</span>}
        <span className="ml-auto flex items-center gap-1">
          {hits > 0 && (
            <>
              <span className={cx('tabular mr-0.5 text-2xs', mark === 'secret' ? 'text-danger' : 'text-brand')}>
                {t(mark === 'secret' ? 'codeView.hitsSensitive' : 'codeView.hitsReplaced', {
                  count: formatCount(hits, locale),
                })}
              </span>
              <IconButton
                label={t('codeView.nextMatch', { index: matchCursor >= 0 ? matchCursor + 1 : 1, total: hits })}
                icon={<ArrowDown size={13} />}
                onClick={jumpNextMatch}
              />
            </>
          )}
          {bytes !== undefined && <span className="tabular mr-1 text-2xs text-fg-subtle">{formatBytes(bytes)}</span>}
          {sseText !== null && (
            <IconButton
              label={sseReadable ? t('codeView.sseRaw') : t('codeView.sseReadable')}
              pressed={sseReadable}
              icon={<TextAlignLeft size={14} />}
              onClick={() => setSseReadable((v) => !v)}
            />
          )}
          {requestText !== null && (
            <IconButton
              label={dialogueView ? t('codeView.jsonView') : t('codeView.dialogueView')}
              pressed={dialogueView}
              icon={<ChatText size={14} />}
              onClick={() => setDialogueView((v) => !v)}
            />
          )}
          {isJson && !dialogueView && (
            <IconButton
              label={pretty ? t('codeView.showRaw') : t('codeView.prettyJson')}
              pressed={pretty}
              icon={<BracketsCurly size={14} />}
              onClick={() => setPretty((p) => !p)}
            />
          )}
          <CopyButton text={display} compact label={t('codeView.copyPanel', { title })} />
        </span>
      </header>
      {text ? (
        <pre ref={preRef} tabIndex={0} className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all bg-surface px-3 py-2.5 font-mono text-xs leading-5 text-fg">
          {nodes}
        </pre>
      ) : (
        <p className="flex flex-1 items-center justify-center bg-surface p-6 text-xs text-fg-subtle">{resolvedEmpty}</p>
      )}
    </section>
  );
});
