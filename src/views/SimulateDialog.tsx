import { useCallback, useEffect, useState } from 'react';
import { PaperPlaneTilt } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { HARNESS_ORDER, getCategoryLabel, getHarnessLabel, getModeLabel } from '../lib/format';
import { useI18n, type MessageKey } from '../lib/i18n';
import type { HarnessKind, TrafficCategory } from '../types';
import { Button, Callout, Dialog, Field, Kbd, cx, inputClass, useToast } from '../components/ui';

const CATEGORY_LIST: TrafficCategory[] = ['interactive-prompt', 'tool-execution-sync', 'codebase-indexing', 'telemetry'];

const CATEGORY_HINT_KEYS: Record<TrafficCategory, MessageKey> = {
  'interactive-prompt': 'simulate.hintInteractive',
  'tool-execution-sync': 'simulate.hintTool',
  'codebase-indexing': 'simulate.hintIndex',
  telemetry: 'simulate.hintTelemetry',
};

/** Run the offline simulator and jump to the record it produced. */
export function useSimulate() {
  const { navigate, refreshLogs } = useStore();
  const { t } = useI18n();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const clearError = useCallback(() => setError(null), []);
  const run = useCallback(
    async (harness: HarnessKind, category: TrafficCategory, payload?: string) => {
      setBusy(true);
      setError(null);
      try {
        const record = await api.simulate(harness, category, payload);
        await refreshLogs();
        navigate('traffic', { id: record.id });
        return true;
      } catch (e) {
        const message = (e as Error).message;
        setError(message);
        toast.push({ tone: 'danger', title: t('simulate.failedTitle'), body: message });
        return false;
      } finally {
        setBusy(false);
      }
    },
    [navigate, refreshLogs, toast, t],
  );
  return { run, busy, error, clearError };
}

function isBrokenJson(text: string): boolean {
  if (!text.startsWith('{') && !text.startsWith('[')) return false;
  try {
    JSON.parse(text);
    return false;
  } catch {
    return true;
  }
}

export function SimulateDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { config } = useStore();
  const { locale, t } = useI18n();
  const { run, busy, error, clearError } = useSimulate();
  const [harness, setHarness] = useState<HarnessKind>('claude-code');
  const [category, setCategory] = useState<TrafficCategory>('interactive-prompt');
  const [payload, setPayload] = useState('');
  const trimmed = payload.trim();
  const brokenJson = isBrokenJson(trimmed);

  useEffect(() => {
    if (open) clearError();
  }, [open, clearError]);

  const submit = async () => {
    if (busy) return;
    if (await run(harness, category, trimmed || undefined)) onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t('simulate.title')}
      description={t('simulate.description')}
      width="max-w-xl"
      footer={
        <>
          {config && (
            <span className="mr-auto self-center text-xs text-fg-subtle">
              {t('simulate.modeNote', { mode: getModeLabel(config.mode, locale) })}
            </span>
          )}
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" icon={<PaperPlaneTilt size={14} />} onClick={submit} disabled={busy}>
            {t(busy ? 'simulate.sending' : 'simulate.send')}
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="grid grid-cols-2 gap-4">
          <Field label={t('simulate.fieldTool')} htmlFor="sim-harness">
            <select
              id="sim-harness"
              data-autofocus
              value={harness}
              onChange={(e) => setHarness(e.target.value as HarnessKind)}
              className={cx(inputClass, 'h-8 w-full cursor-pointer')}
            >
              {HARNESS_ORDER.map((h) => (
                <option key={h} value={h}>
                  {getHarnessLabel(h, locale)}
                </option>
              ))}
            </select>
          </Field>
          <Field label={t('simulate.fieldCategory')} htmlFor="sim-category" hint={t(CATEGORY_HINT_KEYS[category])}>
            <select
              id="sim-category"
              aria-describedby="sim-category-hint"
              value={category}
              onChange={(e) => setCategory(e.target.value as TrafficCategory)}
              className={cx(inputClass, 'h-8 w-full cursor-pointer')}
            >
              {CATEGORY_LIST.map((c) => (
                <option key={c} value={c}>
                  {getCategoryLabel(c, locale)}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <Field
          label={t('simulate.fieldPayload')}
          htmlFor="sim-payload"
          hint={
            brokenJson ? (
              <span className="text-warn">{t('simulate.brokenJson')}</span>
            ) : (
              <>
                {t('simulate.hintBeforeKbd')}
                <Kbd>Ctrl</Kbd> + <Kbd>Enter</Kbd>
                {t('simulate.hintAfterKbd')}
              </>
            )
          }
        >
          <textarea
            id="sim-payload"
            aria-describedby="sim-payload-hint"
            rows={9}
            spellCheck={false}
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                submit();
              }
            }}
            placeholder={'{\n  "model": "…",\n  "messages": [{ "role": "user", "content": "…" }]\n}'}
            className={cx(inputClass, 'w-full resize-y py-2 font-mono text-xs leading-5')}
          />
        </Field>
        {error && (
          <Callout tone="danger" title={t('simulate.failedTitle')}>
            {error}
          </Callout>
        )}
      </form>
    </Dialog>
  );
}
