import { useEffect, useRef, useState, type FormEvent } from 'react';
import { BracketsAngle, CheckCircle, PencilSimple, Plus, Trash } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { useDebounced } from '../lib/hooks';
import { translate, useI18n, type Locale } from '../lib/i18n';
import type { CustomRule, RuleValidation } from '../types';
import { Button, ConfirmDialog, EmptyState, Field, IconButton, Panel, Skeleton, Switch, cx, inputClass } from '../components/ui';

interface Draft {
  id: string | null;
  name: string;
  pattern: string;
  replacementHint: string;
  sample: string;
}

const EMPTY: Draft = { id: null, name: '', pattern: '', replacementHint: '', sample: '' };

function newRuleId() {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return `rule-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/** The gateway reports the regex engine's own message; map common ones to locale keys. */
function explainRegexError(message: string, locale: Locale): string {
  if (/look-around|look-ahead|look-behind/i.test(message)) return translate(locale, 'rules.errLookaround');
  if (/backreference/i.test(message)) return translate(locale, 'rules.errBackref');
  if (/empty string/i.test(message)) return translate(locale, 'rules.errEmpty');
  if (/size limit|too big/i.test(message)) return translate(locale, 'rules.errTooBig');
  return translate(locale, 'rules.errCompile', { message });
}

/** What the vendor sees in place of a match, mirroring the gateway's keyed naming. */
function replacementPreview(hint: string) {
  const trimmed = hint.trim();
  if (!trimmed) return 'ref_a1b2c3d4e5';
  const dot = trimmed.indexOf('.');
  if (dot > 0 && dot < trimmed.length - 1) {
    return `${trimmed.slice(0, dot)}-a1b2c3d4.${trimmed.slice(dot + 1)}`;
  }
  return `${trimmed}_a1b2c3d4`;
}

function RuleEditor({ draft, onChange, onDone }: { draft: Draft; onChange: (d: Draft) => void; onDone: () => void }) {
  const { config, saveConfig, saving } = useStore();
  const { locale, t } = useI18n();
  const configRef = useRef(config);
  configRef.current = config;
  const [check, setCheck] = useState<{ pattern: string; sample: string; result: RuleValidation } | null>(null);
  const [checkError, setCheckError] = useState<{ pattern: string; message: string } | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const pattern = draft.pattern.trim();
  const debouncedPattern = useDebounced(pattern, 300);
  const debouncedSample = useDebounced(draft.sample, 300);

  // Validate with the gateway itself: it compiles rules with a different engine than the browser's.
  useEffect(() => {
    if (!debouncedPattern) {
      setCheck(null);
      setCheckError(null);
      return;
    }
    let cancelled = false;
    api
      .validateRule(debouncedPattern, debouncedSample || undefined)
      .then((result) => {
        if (cancelled) return;
        setCheck({ pattern: debouncedPattern, sample: debouncedSample, result });
        setCheckError(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setCheck(null);
        setCheckError({ pattern: debouncedPattern, message: (e as Error).message });
      });
    return () => {
      cancelled = true;
    };
  }, [debouncedPattern, debouncedSample]);

  useEffect(() => setSubmitted(false), [draft.id]);

  if (!config) return null;
  const result = pattern && check?.pattern === pattern ? check.result : null;
  const sampleMatched = result && check?.sample === draft.sample;
  const validationErr = checkError?.pattern === pattern ? t('rules.errValidate', { message: checkError.message }) : null;
  const nameError = submitted && !draft.name.trim() ? t('rules.errNameRequired') : null;
  const trimmedHint = draft.replacementHint.trim();
  const hintError =
    trimmedHint &&
    (!/^[A-Za-z0-9_-](?:[A-Za-z0-9._-]{0,46}[A-Za-z0-9_-])?$/.test(trimmedHint) || trimmedHint.includes('..'))
      ? t('rules.errHintInvalid')
      : null;
  const patternError =
    result && !result.valid
      ? explainRegexError(result.message ?? '', locale)
      : validationErr ?? (submitted && !pattern ? t('rules.errPatternRequired') : null);
  const matches = result?.valid && sampleMatched ? (result.matches ?? []) : [];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    if (!draft.name.trim() || !pattern || hintError) return;
    // Re-check on submit so a pattern typed faster than the debounce cannot slip through.
    let verdict: RuleValidation;
    try {
      verdict = await api.validateRule(pattern, draft.sample || undefined);
      setCheck({ pattern, sample: draft.sample, result: verdict });
      setCheckError(null);
    } catch (err) {
      setCheck(null);
      setCheckError({ pattern, message: (err as Error).message });
      return;
    }
    if (!verdict.valid) {
      return;
    }
    const latestConfig = configRef.current;
    if (!latestConfig) return;
    const existing = latestConfig.customRules.find((r) => r.id === draft.id);
    const rule: CustomRule = {
      id: existing?.id ?? newRuleId(),
      name: draft.name.trim(),
      pattern,
      replacementHint: draft.replacementHint.trim(),
      enabled: existing?.enabled ?? true,
    };
    const customRules = existing ? latestConfig.customRules.map((r) => (r.id === rule.id ? rule : r)) : [...latestConfig.customRules, rule];
    if (await saveConfig({ ...latestConfig, customRules }, t(existing ? 'rules.updatedToast' : 'rules.addedToast'))) onDone();
  };

  return (
    <Panel title={t(draft.id ? 'rules.editorEditTitle' : 'rules.editorNewTitle')} description={t('rules.editorDesc')}>
      <form onSubmit={submit} noValidate className="space-y-4 p-4">
        <Field label={t('rules.fieldName')} htmlFor="rule-name" error={nameError}>
          <input
            id="rule-name"
            type="text"
            value={draft.name}
            onChange={(e) => onChange({ ...draft, name: e.target.value })}
            placeholder={t('rules.placeholderName')}
            aria-invalid={!!nameError}
            aria-describedby={nameError ? 'rule-name-error' : undefined}
            className={cx(inputClass, 'h-8 w-full')}
          />
        </Field>
        <Field
          label={t('rules.fieldPattern')}
          htmlFor="rule-pattern"
          error={patternError}
          hint={
            result?.valid ? (
              <span className="flex items-center gap-1 text-brand">
                <CheckCircle aria-hidden="true" size={13} weight="bold" />
                {t('rules.patternValid')}
              </span>
            ) : (
              t('rules.patternHint')
            )
          }
        >
          <input
            id="rule-pattern"
            type="text"
            spellCheck={false}
            autoComplete="off"
            value={draft.pattern}
            onChange={(e) => onChange({ ...draft, pattern: e.target.value })}
            placeholder="ProjectTitan|titan_[a-z0-9_]+"
            aria-invalid={!!patternError}
            aria-describedby={patternError ? 'rule-pattern-error' : 'rule-pattern-hint'}
            className={cx(inputClass, 'h-8 w-full font-mono text-xs')}
          />
        </Field>
        <Field
          label={t('rules.fieldHint')}
          htmlFor="rule-hint"
          error={hintError}
          hint={
            <>
              {t('rules.hintExamplePrefix')}
              <code className="font-mono text-brand">{replacementPreview(draft.replacementHint)}</code>
            </>
          }
        >
          <input
            id="rule-hint"
            type="text"
            spellCheck={false}
            autoComplete="off"
            value={draft.replacementHint}
            onChange={(e) => onChange({ ...draft, replacementHint: e.target.value })}
            placeholder="GreenhouseApp"
            aria-invalid={!!hintError}
            aria-describedby={hintError ? 'rule-hint-error' : 'rule-hint-hint'}
            className={cx(inputClass, 'h-8 w-full font-mono text-xs')}
          />
        </Field>
        <Field label={t('rules.fieldSample')} htmlFor="rule-sample" hint={t('rules.sampleHint')}>
          <textarea
            id="rule-sample"
            rows={3}
            spellCheck={false}
            value={draft.sample}
            onChange={(e) => onChange({ ...draft, sample: e.target.value })}
            placeholder={t('rules.samplePlaceholder')}
            aria-describedby="rule-sample-hint"
            className={cx(inputClass, 'w-full resize-y py-2 font-mono text-xs leading-5')}
          />
        </Field>
        {result?.valid && sampleMatched && draft.sample.trim() && (
          <div role="status" className="rounded border border-line bg-surface-2 px-3 py-2.5">
            <p className="label-caps">
              {matches.length
                ? t('rules.sampleHits', { count: matches.length, plus: matches.length === 20 ? '+' : '' })
                : t('rules.sampleNoHits')}
            </p>
            {matches.length > 0 && (
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {matches.map((m, i) => (
                  <li key={i} className="mark-token break-all px-1 py-0.5 font-mono text-xs">
                    {m}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        <div className="flex justify-end gap-2 border-t border-line pt-4">
          {draft.id && <Button onClick={onDone}>{t('common.cancel')}</Button>}
          <Button type="submit" variant="primary" icon={draft.id ? undefined : <Plus size={14} weight="bold" />} disabled={saving}>
            {t(draft.id ? 'rules.saveChanges' : 'rules.addRule')}
          </Button>
        </div>
      </form>
    </Panel>
  );
}

export function Rules() {
  const { config, saveConfig } = useStore();
  const { t } = useI18n();
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [deleting, setDeleting] = useState<CustomRule | null>(null);

  if (!config) {
    return (
      <div className="mx-auto max-w-[1360px] space-y-3 p-6" aria-busy="true">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-14" />
        ))}
      </div>
    );
  }

  const rules = config.customRules;
  const enabledCount = rules.filter((r) => r.enabled).length;
  const edit = (rule: CustomRule) => {
    setDraft({ id: rule.id, name: rule.name, pattern: rule.pattern, replacementHint: rule.replacementHint, sample: '' });
    document.getElementById('rule-name')?.focus();
  };

  return (
    <div className="mx-auto grid max-w-[1360px] grid-cols-1 items-start gap-5 p-6 xl:grid-cols-[minmax(0,1fr)_400px]">
      <Panel
        title={t('rules.listTitle')}
        description={rules.length ? t('rules.listDesc', { total: rules.length, enabled: enabledCount }) : t('rules.listEmptyDesc')}
      >
        {rules.length === 0 ? (
          <EmptyState icon={<BracketsAngle size={20} />} title={t('rules.emptyTitle')}>
            {t('rules.emptyBody')}
          </EmptyState>
        ) : (
          <table className="w-full table-fixed text-left text-xs">
            <thead>
              <tr className="border-b border-line text-2xs text-fg-subtle">
                <th scope="col" className="w-16 py-2 pl-4 font-medium">{t('rules.colEnabled')}</th>
                <th scope="col" className="py-2 pl-2 font-medium">{t('rules.colNamePattern')}</th>
                <th scope="col" className="w-[30%] py-2 pl-3 font-medium">{t('rules.colReplacement')}</th>
                <th scope="col" className="w-20 py-2 pl-2 pr-3">
                  <span className="sr-only">{t('rules.colActions')}</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rules.map((rule) => (
                <tr key={rule.id} className={cx('transition-colors', rule.id === draft.id ? 'bg-brand/[0.07]' : 'hover:bg-surface-2')}>
                  <td className="py-3 pl-4 align-top">
                    <Switch
                      checked={rule.enabled}
                      label={t('rules.toggleAria', { name: rule.name })}
                      onChange={(enabled) =>
                        saveConfig(
                          { ...config, customRules: rules.map((r) => (r.id === rule.id ? { ...r, enabled } : r)) },
                          t(enabled ? 'rules.enabledToast' : 'rules.disabledToast'),
                        )
                      }
                    />
                  </td>
                  <td className={cx('min-w-0 py-2.5 pl-2 align-top', !rule.enabled && 'opacity-60')}>
                    <p className="truncate text-sm font-medium text-fg">{rule.name}</p>
                    <code className="mt-0.5 block truncate font-mono text-fg-muted" title={rule.pattern}>
                      {rule.pattern}
                    </code>
                  </td>
                  <td className={cx('py-3 pl-3 align-top', !rule.enabled && 'opacity-60')}>
                    <code className={cx('block truncate font-mono', rule.replacementHint ? 'text-brand' : 'text-fg-subtle')} title={replacementPreview(rule.replacementHint)}>
                      {replacementPreview(rule.replacementHint)}
                    </code>
                  </td>
                  <td className="py-2 pl-2 pr-3 text-right align-top">
                    <IconButton label={t('rules.editAria', { name: rule.name })} icon={<PencilSimple size={14} />} onClick={() => edit(rule)} />
                    <IconButton label={t('rules.deleteAria', { name: rule.name })} icon={<Trash size={14} />} onClick={() => setDeleting(rule)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <div className="xl:sticky xl:top-6">
        <RuleEditor draft={draft} onChange={setDraft} onDone={() => setDraft(EMPTY)} />
      </div>

      <ConfirmDialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          const target = deleting;
          setDeleting(null);
          if (!target) return;
          if (target.id === draft.id) setDraft(EMPTY);
          await saveConfig({ ...config, customRules: rules.filter((r) => r.id !== target.id) }, t('rules.deletedToast'));
        }}
        title={t('rules.confirmDeleteTitle', { name: deleting?.name ?? '' })}
        description={t('rules.confirmDeleteDesc')}
        confirmLabel={t('rules.confirmDeleteBtn')}
      />
    </div>
  );
}
