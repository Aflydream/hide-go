import { useCallback, useState } from 'react';
import { PaperPlaneTilt } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { CATEGORY_LABEL, HARNESS_LABEL, HARNESS_ORDER, MODE_LABEL } from '../lib/format';
import type { HarnessKind, TrafficCategory } from '../types';
import { Button, Dialog, Field, Kbd, cx, inputClass, useToast } from '../components/ui';

const CATEGORY_HINT: Record<TrafficCategory, string> = {
  'interactive-prompt': '用户提问及其上下文，最常见的推理请求。',
  'tool-execution-sync': '工具执行结果回传给模型。',
  'codebase-indexing': '后台上传代码片段用于建立索引。',
  telemetry: '工具静默上报的使用数据。',
};

/** Run the offline simulator and jump to the record it produced. */
export function useSimulate() {
  const { navigate, refreshLogs } = useStore();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async (harness: HarnessKind, category: TrafficCategory, payload?: string) => {
      setBusy(true);
      try {
        const record = await api.simulate(harness, category, payload);
        await refreshLogs();
        navigate('traffic', { id: record.id });
        return true;
      } catch (e) {
        toast.push({ tone: 'danger', title: '模拟请求失败', body: (e as Error).message });
        return false;
      } finally {
        setBusy(false);
      }
    },
    [navigate, refreshLogs, toast],
  );
  return { run, busy };
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
  const { run, busy } = useSimulate();
  const [harness, setHarness] = useState<HarnessKind>('claude-code');
  const [category, setCategory] = useState<TrafficCategory>('interactive-prompt');
  const [payload, setPayload] = useState('');
  const trimmed = payload.trim();
  const brokenJson = isBrokenJson(trimmed);

  const submit = async () => {
    if (busy) return;
    if (await run(harness, category, trimmed || undefined)) onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="模拟请求"
      description="在本机走一遍完整的改写与还原流程，不连接任何厂商。结果会作为「模拟」记录出现在流量列表中。"
      width="max-w-xl"
      footer={
        <>
          {config && <span className="mr-auto self-center text-xs text-fg-subtle">按当前模式「{MODE_LABEL[config.mode]}」处理</span>}
          <Button onClick={onClose}>取消</Button>
          <Button variant="primary" icon={<PaperPlaneTilt size={14} />} onClick={submit} disabled={busy}>
            {busy ? '处理中…' : '发送'}
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
          <Field label="工具" htmlFor="sim-harness">
            <select
              id="sim-harness"
              data-autofocus
              value={harness}
              onChange={(e) => setHarness(e.target.value as HarnessKind)}
              className={cx(inputClass, 'h-8 w-full cursor-pointer')}
            >
              {HARNESS_ORDER.map((h) => (
                <option key={h} value={h}>
                  {HARNESS_LABEL[h]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="流量类别" htmlFor="sim-category" hint={CATEGORY_HINT[category]}>
            <select
              id="sim-category"
              aria-describedby="sim-category-hint"
              value={category}
              onChange={(e) => setCategory(e.target.value as TrafficCategory)}
              className={cx(inputClass, 'h-8 w-full cursor-pointer')}
            >
              {(Object.keys(CATEGORY_LABEL) as TrafficCategory[]).map((c) => (
                <option key={c} value={c}>
                  {CATEGORY_LABEL[c]}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <Field
          label="请求正文（可选）"
          htmlFor="sim-payload"
          hint={
            brokenJson ? (
              <span className="text-warn">内容以 JSON 开头但无法解析，请检查括号与引号。</span>
            ) : (
              <>
                留空则使用该工具的内置示例。粘贴真实请求体可以检验规则是否命中。<Kbd>Ctrl</Kbd> + <Kbd>Enter</Kbd> 发送。
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
      </form>
    </Dialog>
  );
}
