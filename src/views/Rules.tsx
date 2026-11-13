import { useEffect, useRef, useState, type FormEvent } from 'react';
import { BracketsAngle, CheckCircle, PencilSimple, Plus, Trash } from '@phosphor-icons/react';
import { useStore } from '../store';
import { api } from '../lib/api';
import { useDebounced } from '../lib/hooks';
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

/** The gateway reports the regex engine's own (English) message; translate the common ones. */
function explainRegexError(message: string): string {
  if (/look-around|look-ahead|look-behind/i.test(message)) return '网关的正则引擎不支持环视断言 (?=…) (?!…) (?<=…)，请改用普通分组或字符类。';
  if (/backreference/i.test(message)) return '网关的正则引擎不支持反向引用（\\1 等）。';
  if (/empty string/i.test(message)) return '该表达式能匹配空字符串，会在每个位置命中；请至少要求一个字符。';
  if (/size limit|too big/i.test(message)) return '表达式过于复杂，超出编译大小上限。';
  return `无法编译：${message}`;
}

/** What the vendor sees in place of a match, mirroring the gateway's naming. */
function replacementPreview(hint: string) {
  return `${hint.trim() || 'CustomConcept'}_01`;
}

function RuleEditor({ draft, onChange, onDone }: { draft: Draft; onChange: (d: Draft) => void; onDone: () => void }) {
  const { config, saveConfig, saving } = useStore();
  const configRef = useRef(config);
  configRef.current = config;
  const [check, setCheck] = useState<RuleValidation | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const pattern = draft.pattern.trim();
  const debouncedPattern = useDebounced(pattern, 300);
  const debouncedSample = useDebounced(draft.sample, 300);
  const settled = pattern === debouncedPattern && draft.sample === debouncedSample;

  // Validate with the gateway itself: it compiles rules with a different engine than the browser's.
  useEffect(() => {
    if (!debouncedPattern) {
      setCheck(null);
      return;
    }
    let cancelled = false;
    api
      .validateRule(debouncedPattern, debouncedSample || undefined)
      .then((r) => !cancelled && setCheck(r))
      .catch(() => !cancelled && setCheck(null));
    return () => {
      cancelled = true;
    };
  }, [debouncedPattern, debouncedSample]);

  useEffect(() => setSubmitted(false), [draft.id]);

  if (!config) return null;
  const result = pattern && settled ? check : null;
  const nameError = submitted && !draft.name.trim() ? '请填写规则名称' : null;
  const patternError = result && !result.valid ? explainRegexError(result.message ?? '') : submitted && !pattern ? '请填写正则表达式' : null;
  const matches = result?.valid ? (result.matches ?? []) : [];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    if (!draft.name.trim() || !pattern) return;
    // Re-check on submit so a pattern typed faster than the debounce cannot slip through.
    const verdict = await api.validateRule(pattern).catch(() => null);
    if (verdict && !verdict.valid) {
      setCheck(verdict);
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
    if (await saveConfig({ ...latestConfig, customRules }, existing ? '规则已更新' : '规则已添加')) onDone();
  };

  return (
    <Panel title={draft.id ? '编辑规则' : '新建规则'} description="命中的内容在出站前替换，响应返回时还原">
      <form onSubmit={submit} noValidate className="space-y-4 p-4">
        <Field label="名称" htmlFor="rule-name" error={nameError}>
          <input
            id="rule-name"
            type="text"
            value={draft.name}
            onChange={(e) => onChange({ ...draft, name: e.target.value })}
            placeholder="内部项目代号"
            aria-invalid={!!nameError}
            aria-describedby={nameError ? 'rule-name-error' : undefined}
            className={cx(inputClass, 'h-8 w-full')}
          />
        </Field>
        <Field
          label="正则表达式"
          htmlFor="rule-pattern"
          error={patternError}
          hint={
            result?.valid ? (
              <span className="flex items-center gap-1 text-brand">
                <CheckCircle aria-hidden="true" size={13} weight="bold" />
                网关可以编译该表达式
              </span>
            ) : (
              '使用 Rust regex 语法，由网关编译校验；不支持环视与反向引用。'
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
          label="替换前缀（可选）"
          htmlFor="rule-hint"
          hint={
            <>
              厂商看到的是 <code className="font-mono text-brand">{replacementPreview(draft.replacementHint)}</code>，序号按出现顺序递增。
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
            aria-describedby="rule-hint-hint"
            className={cx(inputClass, 'h-8 w-full font-mono text-xs')}
          />
        </Field>
        <Field label="测试文本（可选）" htmlFor="rule-sample" hint="仅用于预览命中结果，不会保存。">
          <textarea
            id="rule-sample"
            rows={3}
            spellCheck={false}
            value={draft.sample}
            onChange={(e) => onChange({ ...draft, sample: e.target.value })}
            placeholder="粘贴一段包含目标内容的文本"
            aria-describedby="rule-sample-hint"
            className={cx(inputClass, 'w-full resize-y py-2 font-mono text-xs leading-5')}
          />
        </Field>
        {result?.valid && draft.sample.trim() && (
          <div role="status" className="rounded border border-line bg-surface-2 px-3 py-2.5">
            <p className="label-caps">{matches.length ? `命中 ${matches.length}${matches.length === 20 ? '+' : ''} 处` : '测试文本中没有命中'}</p>
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
          {draft.id && <Button onClick={onDone}>取消</Button>}
          <Button type="submit" variant="primary" icon={draft.id ? undefined : <Plus size={14} weight="bold" />} disabled={saving}>
            {draft.id ? '保存修改' : '添加规则'}
          </Button>
        </div>
      </form>
    </Panel>
  );
}

export function Rules() {
  const { config, saveConfig } = useStore();
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
      <Panel title="规则列表" description={rules.length ? `${rules.length} 条规则，${enabledCount} 条生效中` : '尚未添加规则'}>
        {rules.length === 0 ? (
          <EmptyState icon={<BracketsAngle size={20} />} title="还没有自定义规则">
            内置检测器已覆盖常见密钥、连接串、内网地址与本机路径。项目代号、内部域名等只有你知道的内容，在这里补充。
          </EmptyState>
        ) : (
          <table className="w-full table-fixed text-left text-xs">
            <thead>
              <tr className="border-b border-line text-2xs text-fg-subtle">
                <th scope="col" className="w-16 py-2 pl-4 font-medium">启用</th>
                <th scope="col" className="py-2 pl-2 font-medium">名称 / 表达式</th>
                <th scope="col" className="w-[30%] py-2 pl-3 font-medium">替换为</th>
                <th scope="col" className="w-20 py-2 pl-2 pr-3">
                  <span className="sr-only">操作</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rules.map((rule) => (
                <tr key={rule.id} className={cx('transition-colors', rule.id === draft.id ? 'bg-brand/[0.07]' : 'hover:bg-surface-2')}>
                  <td className="py-3 pl-4 align-top">
                    <Switch
                      checked={rule.enabled}
                      label={`启用规则「${rule.name}」`}
                      onChange={(enabled) =>
                        saveConfig({ ...config, customRules: rules.map((r) => (r.id === rule.id ? { ...r, enabled } : r)) }, enabled ? '规则已启用' : '规则已停用')
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
                    <IconButton label={`编辑规则「${rule.name}」`} icon={<PencilSimple size={14} />} onClick={() => edit(rule)} />
                    <IconButton label={`删除规则「${rule.name}」`} icon={<Trash size={14} />} onClick={() => setDeleting(rule)} />
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
          await saveConfig({ ...config, customRules: rules.filter((r) => r.id !== target.id) }, '规则已删除');
        }}
        title={`删除规则「${deleting?.name ?? ''}」？`}
        description="此后该规则命中的内容将不再被替换。映射表中已有的对应条目不受影响，仍可还原。"
        confirmLabel="删除规则"
      />
    </div>
  );
}
