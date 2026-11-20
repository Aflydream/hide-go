import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { ArrowsClockwise, Eye, EyeSlash, ShieldCheck, WarningCircle } from '@phosphor-icons/react';
import { useStore } from '../store';
import { Badge, Button, Callout, ConfirmDialog, IconButton, Skeleton, Switch, cx } from '../components/ui';
import { COVER_THEME_LABEL, MODE_LABEL } from '../lib/format';
import type { CoverTheme, HideConfig, PrivacyMode, ToolCallSecretPolicy } from '../types';

function Section({ index, title, description, children }: { index: string; title: string; description: ReactNode; children: ReactNode }) {
  return (
    <section className="grid grid-cols-1 gap-x-10 gap-y-4 border-b border-line py-7 last:border-b-0 lg:grid-cols-[260px_minmax(0,1fr)]">
      <div>
        <p className="tabular font-mono text-2xs text-fg-subtle">{index}</p>
        <h2 className="mt-1 text-sm font-semibold text-fg">{title}</h2>
        <div className="mt-1.5 text-xs leading-5 text-fg-subtle">{description}</div>
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}

function ToggleRow({
  title,
  description,
  checked,
  onChange,
  disabled,
  badge,
}: {
  title: string;
  description: ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  badge?: ReactNode;
}) {
  const descId = useId();
  return (
    <div className={cx('flex items-start justify-between gap-6 px-4 py-3.5 transition-colors hover:bg-surface-2/50', disabled && 'opacity-60')}>
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium text-fg">{title}</p>
          {badge}
        </div>
        <p id={descId} className="mt-0.5 text-xs leading-5 text-fg-subtle">
          {description}
        </p>
      </div>
      <Switch checked={checked} onChange={onChange} label={title} disabled={disabled} describedBy={descId} />
    </div>
  );
}

function RadioCard<T extends string>({
  name,
  value,
  current,
  onSelect,
  title,
  description,
  children,
  badge,
}: {
  name: string;
  value: T;
  current: T;
  onSelect: (v: T) => void;
  title: string;
  description: ReactNode;
  children?: ReactNode;
  badge?: ReactNode;
}) {
  const selected = value === current;
  const id = useId();
  return (
    <label
      htmlFor={id}
      className={cx(
        'block cursor-pointer rounded-md border px-4 py-3.5 transition-colors',
        selected ? 'border-brand bg-brand/[0.06]' : 'border-line bg-surface hover:border-line-strong',
      )}
    >
      <div className="flex items-start gap-3">
        <input id={id} type="radio" name={name} value={value} checked={selected} onChange={() => onSelect(value)} className="peer sr-only" />
        <span
          aria-hidden="true"
          className={cx(
            'mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-focus',
            selected ? 'border-brand' : 'border-line-control',
          )}
        >
          {selected && <span className="h-2 w-2 rounded-full bg-brand" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-fg">{title}</span>
            {badge}
          </div>
          <div className="mt-0.5 text-xs leading-5 text-fg-muted">{description}</div>
          {children}
        </div>
      </div>
    </label>
  );
}

function Example({ local, vendor }: { local: string; vendor: string }) {
  return (
    <dl className="mt-3 overflow-hidden rounded border border-line font-mono text-2xs leading-5">
      <div className="flex gap-3 bg-surface-2 px-3 py-1.5">
        <dt className="w-10 shrink-0 text-fg-subtle">本地</dt>
        <dd className="min-w-0 break-all text-fg">{local}</dd>
      </div>
      <div className="flex gap-3 border-t border-line px-3 py-1.5">
        <dt className="w-10 shrink-0 text-fg-subtle">厂商</dt>
        <dd className="min-w-0 break-all text-brand">{vendor}</dd>
      </div>
    </dl>
  );
}

function randomSalt() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `hg-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export function Policy() {
  const { config, saveConfig } = useStore();
  const [revealSalt, setRevealSalt] = useState(false);
  const [confirmSalt, setConfirmSalt] = useState(false);
  const themeRefs = useRef<Array<HTMLButtonElement | null>>([]);
  if (!config) {
    return (
      <div className="mx-auto max-w-5xl space-y-4 p-6" aria-busy="true">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-32" />
        ))}
      </div>
    );
  }
  const set = (patch: Partial<HideConfig>, msg?: string) => saveConfig({ ...config, ...patch }, msg);
  const setAllHide = (patch: Partial<HideConfig['allHide']>) => saveConfig({ ...config, allHide: { ...config.allHide, ...patch } });
  const allHideActive = config.mode === 'all-hide';
  const protecting = config.mode !== 'audit-only';

  return (
    <div className="mx-auto max-w-5xl px-6 pb-10">
      <Section
        index="01"
        title="处理模式"
        description="决定网关如何改写发往模型厂商的请求。切换立即对所有已接入的工具生效，无需重启。"
      >
        <div className="space-y-2.5">
          <RadioCard<PrivacyMode>
            name="mode"
            value="audit-only"
            current={config.mode}
            onSelect={(mode) => set({ mode }, `已切换为「${MODE_LABEL[mode]}」`)}
            title="仅审计"
            description="原样转发，只在本地记录检测到的敏感数据。适合先摸清工具到底上传了什么。"
            badge={<Badge tone="warn">不提供保护</Badge>}
          >
            <Example local={'db = "postgres://admin:Sec99@10.16.8.9/vault"'} vendor={'db = "postgres://admin:Sec99@10.16.8.9/vault"'} />
          </RadioCard>
          <RadioCard<PrivacyMode>
            name="mode"
            value="auto-desensitize"
            current={config.mode}
            onSelect={(mode) => set({ mode }, `已切换为「${MODE_LABEL[mode]}」`)}
            title="自动脱敏"
            description="把密钥、连接串、内网地址、用户目录替换为同格式占位符；代码与提示词保持可读，响应返回时自动还原。"
            badge={<Badge tone="brand">推荐</Badge>}
          >
            <Example
              local={'db = "postgres://admin:Sec99@10.16.8.9/vault"  # /home/alice/titan'}
              vendor={'db = "postgres://db_user_01:db_pass_placeholder_01@db-01.example.internal:5432/app_schema_01"  # /workspace/user_01/titan'}
            />
          </RadioCard>
          <RadioCard<PrivacyMode>
            name="mode"
            value="all-hide"
            current={config.mode}
            onSelect={(mode) => set({ mode }, `已切换为「${MODE_LABEL[mode]}」`)}
            title="All-Hide"
            description="在自动脱敏的基础上，把复合代码标识符、// 注释与字符串字面量映射到无关领域。工具定义、调用 ID 与签名块保持原样，请求始终是合法的 API 调用。"
          >
            <Example local={'fn verify_margin(wallet_secret: &str) // 清算阈值校验'} vendor={'fn orchid_lotus_207(fern_moss_481: &str) // [BotanicalSensor-01] Calibrate greenhouse soil humidity and mist interval'} />
          </RadioCard>
        </div>
      </Section>

      <Section
        index="02"
        title="检测范围"
        description={
          <>
            在「自动脱敏」与「All-Hide」下替换这些数据；「仅审计」下只记录。
            {!protecting && <span className="mt-2 block text-warn">当前为仅审计模式，以下设置只影响检测报告。</span>}
          </>
        }
      >
        <div className="divide-y divide-line rounded-md border border-line bg-surface">
          <ToggleRow
            title="凭据与密钥"
            description="API 密钥、PEM 私钥、数据库连接串及 token/password 字段"
            checked={config.protectSecretsAndKeys}
            onChange={(v) => set({ protectSecretsAndKeys: v })}
          />
          <ToggleRow
            title="本机路径与身份"
            description="用户目录前缀与邮箱地址（保留相对目录结构）"
            checked={config.protectProjectPaths}
            onChange={(v) => set({ protectProjectPaths: v })}
          />
          <ToggleRow
            title="内网地址与域名"
            description="RFC 1918 私网 IP（→ 198.18.0.0/15）及 .internal/.local 等内网域名"
            checked={config.protectInternalNetwork}
            onChange={(v) => set({ protectInternalNetwork: v })}
          />
        </div>
      </Section>

      <Section
        index="03"
        title="静默遥测"
        description="按路径匹配遥测端点（不影响对话与推理）"
      >
        <div className="divide-y divide-line rounded-md border border-line bg-surface">
          <ToggleRow
            title="在本地应答遥测请求"
            description="直接返回成功响应，不外发（仅审计模式除外）"
            checked={config.blockSilentTelemetry}
            onChange={(v) => set({ blockSilentTelemetry: v })}
            disabled={!protecting}
          />
        </div>
      </Section>

      <Section
        index="04"
        title="工具调用中的凭据"
        description="防止提示注入诱导本机执行带真实密钥的工具参数"
      >
        <div className="space-y-2.5">
          {(
            [
              ['never', '始终保留占位符', 'Shell / URL / 文件参数均不还原凭据', undefined],
              ['file-edits-only', '仅文件写入时还原', '仅写入或编辑文件的内容字段还原；命令与 URL 保留占位符', <Badge tone="brand">推荐</Badge>],
              ['always', '全部还原', '所有工具调用参数均还原真实凭据', <Badge tone="warn">风险较高</Badge>],
            ] as Array<[ToolCallSecretPolicy, string, string, ReactNode]>
          ).map(([value, title, description, badge]) => (
            <RadioCard<ToolCallSecretPolicy>
              key={value}
              name="secret-policy"
              value={value}
              current={config.toolCallSecretPolicy}
              onSelect={(toolCallSecretPolicy) => set({ toolCallSecretPolicy })}
              title={title}
              description={description}
              badge={badge}
            />
          ))}
          <details className="text-xs text-fg-subtle">
            <summary className="cursor-pointer select-none hover:text-fg-muted">还原范围说明</summary>
            <p className="mt-1.5 leading-5">
              普通文本回复始终还原；本机路径与内网地址不受此项限制。例如启用「仅文件写入时还原」后，
              <code className="mx-1 font-mono">curl …?k=占位符</code> 会保持占位符而不外泄真实密钥。
            </p>
          </details>
        </div>
      </Section>

      <Section
        index="05"
        title="All-Hide 伪装层"
        description={
          <>
            仅在 All-Hide 模式下生效
            {!allHideActive && (
              <Button size="sm" variant="secondary" className="mt-3" icon={<ShieldCheck size={14} />} onClick={() => set({ mode: 'all-hide' }, '已切换为「All-Hide」')}>
                切换到 All-Hide
              </Button>
            )}
          </>
        }
      >
        <div className={cx('divide-y divide-line rounded-md border border-line bg-surface', !allHideActive && 'opacity-80')}>
          <ToggleRow
            title="字符串字面量掩码"
            description="代码引号字面量替换为 <<HIDE_STR_…>>"
            checked={config.allHide.strictLiteralMasking}
            onChange={(v) => setAllHide({ strictLiteralMasking: v })}
          />
          <div className="px-4 py-3.5">
            <div className="flex items-start justify-between gap-6">
              <div>
                <p className="text-sm font-medium text-fg">同构领域伪装</p>
                <p className="mt-0.5 text-xs leading-5 text-fg-subtle">按命名风格映射标识符与 // 注释</p>
              </div>
              <Switch checked={config.allHide.enableIsomorphicCamouflage} onChange={(v) => setAllHide({ enableIsomorphicCamouflage: v })} label="同构领域伪装" />
            </div>
            <div role="radiogroup" aria-label="伪装词库" className="mt-3 grid grid-cols-3 gap-2">
              {(Object.keys(COVER_THEME_LABEL) as CoverTheme[]).map((theme, idx, themes) => {
                const active = config.allHide.coverTheme === theme;
                const onThemeKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
                  const dir =
                    e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
                  if (!dir) return;
                  e.preventDefault();
                  const nextIdx = (idx + dir + themes.length) % themes.length;
                  themeRefs.current[nextIdx]?.focus();
                  setAllHide({ coverTheme: themes[nextIdx] });
                };
                return (
                  <button
                    key={theme}
                    ref={(el) => (themeRefs.current[idx] = el)}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    tabIndex={!config.allHide.enableIsomorphicCamouflage ? undefined : active ? 0 : -1}
                    disabled={!config.allHide.enableIsomorphicCamouflage}
                    onClick={() => setAllHide({ coverTheme: theme })}
                    onKeyDown={onThemeKeyDown}
                    className={cx(
                      'cursor-pointer rounded border px-3 py-2 text-left text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus/40 disabled:cursor-not-allowed disabled:opacity-45',
                      active ? 'border-brand bg-brand/[0.06] text-fg' : 'border-line text-fg-muted hover:border-line-strong',
                    )}
                  >
                    <span className="block font-medium">{COVER_THEME_LABEL[theme]}</span>
                    <span className="mt-0.5 block font-mono text-2xs text-fg-subtle">
                      {theme === 'botanical-garden' ? 'fern_orchid_204' : theme === 'library-catalog' ? 'folio_atlas_318' : 'brioche_glaze_562'}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
          <ToggleRow
            title="密钥流加密"
            description="加密为 ⟦HIDE-CIPHER::…⟧（模型不可读，仅用于原样回传）"
            checked={config.allHide.enableCipherGarble}
            onChange={(v) => setAllHide({ enableCipherGarble: v })}
            badge={config.allHide.enableCipherGarble ? <Badge tone="warn">模型不可读</Badge> : undefined}
          />
          <ToggleRow
            title="索引上传诱饵"
            description="保留 JSON 结构与长度，代码内容替换为诱饵"
            checked={config.allHide.enableTelemetryChaff}
            onChange={(v) => setAllHide({ enableTelemetryChaff: v })}
          />
        </div>
        {allHideActive && config.allHide.enableCipherGarble && (
          <div className="mt-3">
            <Callout tone="warn" title="密钥流加密已开启">
              模型无法读取密文内容；常规编码建议关闭此层。
            </Callout>
          </div>
        )}
      </Section>

      <Section
        index="06"
        title="项目 Salt"
        description="同构伪装映射种子（存本机配置）"
      >
        <div className="flex items-center gap-2 rounded-md border border-line bg-surface px-4 py-3">
          <code className="min-w-0 flex-1 truncate font-mono text-sm text-fg">{revealSalt ? config.projectSalt : `${config.projectSalt.slice(0, 5)}${'•'.repeat(18)}`}</code>
          <IconButton
            label={revealSalt ? '隐藏 Salt' : '显示 Salt'}
            pressed={revealSalt}
            icon={revealSalt ? <EyeSlash size={15} /> : <Eye size={15} />}
            onClick={() => setRevealSalt((v) => !v)}
          />
          <Button size="sm" icon={<ArrowsClockwise size={14} />} onClick={() => setConfirmSalt(true)}>
            重新生成
          </Button>
        </div>
        {config.projectSalt.startsWith('hide-go-quantum-salt') && (
          <p className="mt-2 flex items-center gap-1.5 text-xs text-warn">
            <WarningCircle aria-hidden="true" size={13} weight="bold" />
            当前为旧版默认 Salt，建议重新生成。
          </p>
        )}
      </Section>

      <ConfirmDialog
        open={confirmSalt}
        onClose={() => setConfirmSalt(false)}
        onConfirm={async () => {
          setConfirmSalt(false);
          await saveConfig({ ...config, projectSalt: randomSalt() }, '已生成新的项目 Salt');
        }}
        title="重新生成项目 Salt？"
        description="新出现的标识符将使用新映射；已有映射保持不变，彻底重置请清空映射表。"
        confirmLabel="重新生成"
      />
    </div>
  );
}
