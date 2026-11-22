import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { ArrowsClockwise, Eye, EyeSlash, ShieldCheck, WarningCircle } from '@phosphor-icons/react';
import { useStore } from '../store';
import { Badge, Button, Callout, ConfirmDialog, IconButton, RadioCard, Section, Skeleton, Switch, cx } from '../components/ui';
import { COVER_THEMES, getCoverThemeLabel, getModeLabel, getPolicyLabel } from '../lib/format';
import { useI18n } from '../lib/i18n';
import type { CoverTheme, HideConfig, PrivacyMode, ToolCallSecretPolicy } from '../types';

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

function Example({ local, vendor }: { local: string; vendor: string }) {
  const { t } = useI18n();
  return (
    <dl className="mt-3 overflow-hidden rounded border border-line font-mono text-2xs leading-5">
      <div className="flex gap-3 bg-surface-2 px-3 py-1.5">
        <dt className="w-10 shrink-0 text-fg-subtle">{t('policy.exampleLocal')}</dt>
        <dd className="min-w-0 break-all text-fg">{local}</dd>
      </div>
      <div className="flex gap-3 border-t border-line px-3 py-1.5">
        <dt className="w-10 shrink-0 text-fg-subtle">{t('policy.exampleVendor')}</dt>
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
  const { locale, t } = useI18n();
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
      <Section index="01" title={t('policy.secModeTitle')} description={t('policy.secModeDesc')}>
        <div className="space-y-2.5">
          <RadioCard<PrivacyMode>
            name="mode"
            value="audit-only"
            current={config.mode}
            onSelect={(mode) => set({ mode }, t('shell.modeSwitched', { mode: getModeLabel(mode, locale) }))}
            title={getModeLabel('audit-only', locale)}
            description={t('policy.auditDesc')}
            badge={<Badge tone="warn">{t('policy.auditBadge')}</Badge>}
          >
            <Example local={'db = "postgres://admin:Sec99@10.16.8.9/vault"'} vendor={'db = "postgres://admin:Sec99@10.16.8.9/vault"'} />
          </RadioCard>
          <RadioCard<PrivacyMode>
            name="mode"
            value="auto-desensitize"
            current={config.mode}
            onSelect={(mode) => set({ mode }, t('shell.modeSwitched', { mode: getModeLabel(mode, locale) }))}
            title={getModeLabel('auto-desensitize', locale)}
            description={t('policy.autoDesc')}
            badge={<Badge tone="brand">{t('policy.autoBadge')}</Badge>}
          >
            <Example
              local={'db = "postgres://admin:Sec99@10.16.8.9/vault"  # /home/alice/titan'}
              vendor={'db = "postgres://svc_7k2m9p:q4v8Lx2nR9wB3z@core-4a9c12.db.example:5432/app_8f3e1"  # /opt/work/a7c9e2b1/titan'}
            />
          </RadioCard>
          <RadioCard<PrivacyMode>
            name="mode"
            value="all-hide"
            current={config.mode}
            onSelect={(mode) => set({ mode }, t('shell.modeSwitched', { mode: getModeLabel(mode, locale) }))}
            title={getModeLabel('all-hide', locale)}
            description={t('policy.allHideDesc')}
          >
            <Example
              local={'fn verify_margin(wallet_secret: &str) // liquidation threshold check'}
              vendor={'fn orchid_petal_grove(fern_moss_stem: &str) // Check greenhouse soil moisture before misting cycle (#a7b3)'}
            />
          </RadioCard>
        </div>
      </Section>

      <Section
        index="02"
        title={t('policy.secScopeTitle')}
        description={
          <>
            {t('policy.secScopeDesc')}
            {!protecting && <span className="mt-2 block text-warn">{t('policy.secScopeAuditNote')}</span>}
          </>
        }
      >
        <div className="divide-y divide-line rounded-md border border-line bg-surface">
          <ToggleRow
            title={t('policy.scopeSecretsTitle')}
            description={t('policy.scopeSecretsDesc')}
            checked={config.protectSecretsAndKeys}
            onChange={(v) => set({ protectSecretsAndKeys: v })}
          />
          <ToggleRow
            title={t('policy.scopePathsTitle')}
            description={t('policy.scopePathsDesc')}
            checked={config.protectProjectPaths}
            onChange={(v) => set({ protectProjectPaths: v })}
          />
          <ToggleRow
            title={t('policy.scopeNetworkTitle')}
            description={t('policy.scopeNetworkDesc')}
            checked={config.protectInternalNetwork}
            onChange={(v) => set({ protectInternalNetwork: v })}
          />
        </div>
      </Section>

      <Section index="03" title={t('policy.secTelemetryTitle')} description={t('policy.secTelemetryDesc')}>
        <div className="divide-y divide-line rounded-md border border-line bg-surface">
          <ToggleRow
            title={t('policy.telemetryRowTitle')}
            description={t('policy.telemetryRowDesc')}
            checked={config.blockSilentTelemetry}
            onChange={(v) => set({ blockSilentTelemetry: v })}
            disabled={!protecting}
          />
        </div>
      </Section>

      <Section index="04" title={t('policy.secToolSecretsTitle')} description={t('policy.secToolSecretsDesc')}>
        <div className="space-y-2.5">
          {(
            [
              ['never', getPolicyLabel('never', locale), t('policy.toolNeverDesc'), undefined],
              ['file-edits-only', getPolicyLabel('file-edits-only', locale), t('policy.toolEditsDesc'), <Badge tone="brand">{t('policy.autoBadge')}</Badge>],
              ['always', getPolicyLabel('always', locale), t('policy.toolAlwaysDesc'), <Badge tone="warn">{t('policy.toolAlwaysBadge')}</Badge>],
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
            <summary className="cursor-pointer select-none hover:text-fg-muted">{t('policy.toolScopeSummary')}</summary>
            <p className="mt-1.5 leading-5">
              {t('policy.toolScopeDetailBefore')}
              <code className="mx-1 font-mono">{t('policy.toolScopeDetailCode')}</code>
              {t('policy.toolScopeDetailAfter')}
            </p>
          </details>
        </div>
      </Section>

      <Section
        index="05"
        title={t('policy.secAllHideTitle')}
        description={
          <>
            {t('policy.secAllHideDesc')}
            {!allHideActive && (
              <Button
                size="sm"
                variant="secondary"
                className="mt-3"
                icon={<ShieldCheck size={14} />}
                onClick={() => set({ mode: 'all-hide' }, t('shell.modeSwitched', { mode: getModeLabel('all-hide', locale) }))}
              >
                {t('policy.switchToAllHide')}
              </Button>
            )}
          </>
        }
      >
        <div className={cx('divide-y divide-line rounded-md border border-line bg-surface', !allHideActive && 'opacity-80')}>
          <ToggleRow
            title={t('policy.literalTitle')}
            description={t('policy.literalDesc')}
            checked={config.allHide.strictLiteralMasking}
            onChange={(v) => setAllHide({ strictLiteralMasking: v })}
          />
          <div className="px-4 py-3.5">
            <div className="flex items-start justify-between gap-6">
              <div>
                <p className="text-sm font-medium text-fg">{t('policy.camouflageTitle')}</p>
                <p className="mt-0.5 text-xs leading-5 text-fg-subtle">{t('policy.camouflageDesc')}</p>
              </div>
              <Switch
                checked={config.allHide.enableIsomorphicCamouflage}
                onChange={(v) => setAllHide({ enableIsomorphicCamouflage: v })}
                label={t('policy.camouflageTitle')}
              />
            </div>
            <div role="radiogroup" aria-label={t('policy.coverThemesAria')} className="mt-3 grid grid-cols-3 gap-2">
              {COVER_THEMES.map((theme: CoverTheme, idx, themes) => {
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
                    <span className="block font-medium">{getCoverThemeLabel(theme, locale)}</span>
                    <span className="mt-0.5 block font-mono text-2xs text-fg-subtle">
                      {theme === 'botanical-garden' ? 'fern_orchid_204' : theme === 'library-catalog' ? 'folio_atlas_318' : 'brioche_glaze_562'}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
          <ToggleRow
            title={t('policy.cipherTitle')}
            description={t('policy.cipherDesc')}
            checked={config.allHide.enableCipherGarble}
            onChange={(v) => setAllHide({ enableCipherGarble: v })}
            badge={config.allHide.enableCipherGarble ? <Badge tone="warn">{t('policy.cipherBadge')}</Badge> : undefined}
          />
          <ToggleRow
            title={t('policy.chaffTitle')}
            description={t('policy.chaffDesc')}
            checked={config.allHide.enableTelemetryChaff}
            onChange={(v) => setAllHide({ enableTelemetryChaff: v })}
          />
        </div>
        {allHideActive && config.allHide.enableCipherGarble && (
          <div className="mt-3">
            <Callout tone="warn" title={t('policy.cipherWarnTitle')}>
              {t('policy.cipherWarnBody')}
            </Callout>
          </div>
        )}
      </Section>

      <Section index="06" title={t('policy.secSaltTitle')} description={t('policy.secSaltDesc')}>
        <div className="flex items-center gap-2 rounded-md border border-line bg-surface px-4 py-3">
          <code className="min-w-0 flex-1 truncate font-mono text-sm text-fg">
            {revealSalt ? config.projectSalt : `${config.projectSalt.slice(0, 5)}${'•'.repeat(18)}`}
          </code>
          <IconButton
            label={t(revealSalt ? 'policy.hideSalt' : 'policy.showSalt')}
            pressed={revealSalt}
            icon={revealSalt ? <EyeSlash size={15} /> : <Eye size={15} />}
            onClick={() => setRevealSalt((v) => !v)}
          />
          <Button size="sm" icon={<ArrowsClockwise size={14} />} onClick={() => setConfirmSalt(true)}>
            {t('policy.regenerateSalt')}
          </Button>
        </div>
        {config.projectSalt.startsWith('hide-go-quantum-salt') && (
          <p className="mt-2 flex items-center gap-1.5 text-xs text-warn">
            <WarningCircle aria-hidden="true" size={13} weight="bold" />
            {t('policy.legacySaltWarn')}
          </p>
        )}
      </Section>

      <ConfirmDialog
        open={confirmSalt}
        onClose={() => setConfirmSalt(false)}
        onConfirm={async () => {
          setConfirmSalt(false);
          await saveConfig({ ...config, projectSalt: randomSalt() }, t('policy.saltRegenerated'));
        }}
        title={t('policy.confirmSaltTitle')}
        description={t('policy.confirmSaltDesc')}
        confirmLabel={t('policy.regenerateSalt')}
      />
    </div>
  );
}
