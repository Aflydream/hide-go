import { Fragment, useEffect, useState, type ReactNode } from 'react';
import { ArrowsClockwise, CaretDown, CaretRight, CheckCircle, DownloadSimple } from '@phosphor-icons/react';
import { useStore } from '../store';
import { Badge, Button, CopyButton, Section, Segmented, Skeleton, Switch, cx } from '../components/ui';
import { useColorScheme, type ColorSchemePref } from '../components/WindowFrame';
import { formatBytes, formatDuration } from '../lib/format';
import { SUPPORTED_LOCALES, translate, useI18n } from '../lib/i18n';
import type { UiLanguage } from '../types';

function renderInlineMarkdown(text: string): ReactNode[] {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code key={idx} className="rounded bg-surface-3/80 px-1 py-0.5 font-mono text-[11px] text-fg">
          {part.slice(1, -1)}
        </code>
      );
    }
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong key={idx} className="font-medium text-fg">
          {part.slice(2, -2)}
        </strong>
      );
    }
    return <Fragment key={idx}>{part}</Fragment>;
  });
}

function ReleaseNotesView({ markdown }: { markdown: string }) {
  const lines = markdown.split(/\r?\n/);
  const blocks: ReactNode[] = [];
  let bullets: string[] = [];

  const flushBullets = (keyPrefix: string) => {
    if (bullets.length === 0) return;
    const items = bullets;
    bullets = [];
    blocks.push(
      <ul key={`${keyPrefix}-ul`} className="list-disc space-y-1 pl-4 text-xs leading-relaxed text-fg-muted">
        {items.map((item, i) => (
          <li key={i}>{renderInlineMarkdown(item)}</li>
        ))}
      </ul>,
    );
  };

  lines.forEach((raw, idx) => {
    const line = raw.trim();
    if (!line || line === '---' || line === '***') {
      flushBullets(`b-${idx}`);
      return;
    }
    if (line.startsWith('- ') || line.startsWith('* ')) {
      bullets.push(line.slice(2).trim());
      return;
    }
    flushBullets(`h-${idx}`);
    if (line.startsWith('### ')) {
      blocks.push(
        <h4 key={idx} className="pt-1.5 text-[11px] font-semibold uppercase tracking-wide text-fg first:pt-0">
          {line.slice(4).trim()}
        </h4>,
      );
    } else if (line.startsWith('## ')) {
      blocks.push(
        <h3 key={idx} className="font-mono text-xs font-semibold text-fg">
          {line.slice(3).trim()}
        </h3>,
      );
    } else {
      blocks.push(
        <p key={idx} className="text-xs leading-relaxed text-fg-muted">
          {renderInlineMarkdown(line)}
        </p>,
      );
    }
  });
  flushBullets('end');

  return <div className="space-y-1.5">{blocks}</div>;
}

export function Settings() {
  const {
    config,
    status,
    statusError,
    saveConfig,
    updateInfo,
    updateError,
    checkingUpdates,
    checkForUpdates,
    downloadingUpdate,
    downloadedUpdate,
    downloadUpdateError,
    downloadUpdate,
  } = useStore();
  const { pref, setPref, systemLocale, locale, t } = useI18n();
  const { pref: themePref, setPref: setThemePref } = useColorScheme();
  const [changelogOpen, setChangelogOpen] = useState(false);

  const online = !!status && !statusError;
  const autoCheckEnabled = config ? config.autoCheckUpdates !== false : true;
  const localizedChangelog = updateInfo?.updateAvailable
    ? locale === 'zh-CN'
      ? updateInfo.releaseNotesZh || updateInfo.releaseNotesEn || null
      : updateInfo.releaseNotesEn || updateInfo.releaseNotesZh || null
    : null;

  useEffect(() => {
    setChangelogOpen(false);
  }, [updateInfo?.latestVersion]);

  const formattedCheckedAt = updateInfo?.checkedAt
    ? new Date(updateInfo.checkedAt).toLocaleTimeString(locale === 'zh-CN' ? 'zh-CN' : 'en-US', {
        hour: '2-digit',
        minute: '2-digit',
      })
    : null;

  const handleLanguageSelect = (next: UiLanguage) => {
    setPref(next);
    if (config && config.language !== next) {
      const nextLocale = next === 'system' ? systemLocale : next;
      void saveConfig({ ...config, language: next }, translate(nextLocale, 'settings.langSaved'));
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-6 pb-10">
      <Section index="01" title={t('settings.generalTitle')}>
        <div className="divide-y divide-line rounded-md border border-line bg-surface">
          <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-3">
            <span className="text-sm font-medium text-fg">{t('settings.langTitle')}</span>
            <Segmented<UiLanguage>
              size="sm"
              label={t('settings.langTitle')}
              value={pref}
              onChange={handleLanguageSelect}
              options={[
                { value: 'system', label: t('settings.optionAuto') },
                ...SUPPORTED_LOCALES.map((loc) => ({ value: loc.code, label: loc.nativeName })),
              ]}
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-3">
            <span className="text-sm font-medium text-fg">{t('settings.themeTitle')}</span>
            <Segmented<ColorSchemePref>
              size="sm"
              label={t('settings.themeTitle')}
              value={themePref}
              onChange={setThemePref}
              options={[
                { value: 'system', label: t('settings.optionAuto') },
                { value: 'light', label: t('settings.themeLightTitle') },
                { value: 'dark', label: t('settings.themeDarkTitle') },
              ]}
            />
          </div>
        </div>
      </Section>

      <Section index="02" title={t('settings.updatesTitle')}>
        {!config ? (
          <div className="space-y-2.5" aria-busy="true">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : (
          <div className="divide-y divide-line rounded-md border border-line bg-surface">
            <div className="flex items-center justify-between gap-6 px-4 py-3">
              <span className="text-sm font-medium text-fg">{t('settings.updatesAutoTitle')}</span>
              <Switch
                checked={autoCheckEnabled}
                onChange={(next) =>
                  void saveConfig({ ...config, autoCheckUpdates: next }, t('settings.updatesAutoSaved'))
                }
                label={t('settings.updatesAutoTitle')}
              />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-fg">
                    {t('settings.updatesCurrentLabel', {
                      version: updateInfo?.currentVersion ?? status?.version ?? '—',
                    })}
                  </span>
                  {updateInfo?.updateAvailable ? (
                    <Badge tone="brand" dot>
                      {t('settings.updatesAvailable', { version: updateInfo.latestVersion })}
                    </Badge>
                  ) : updateInfo ? (
                    <Badge tone="neutral">
                      <CheckCircle size={12} weight="fill" className="text-brand" />
                      {t('settings.updatesUpToDate')}
                    </Badge>
                  ) : updateError ? (
                    <Badge tone="warn">{t('settings.updatesFailed')}</Badge>
                  ) : null}
                </div>
                {formattedCheckedAt ? (
                  <p className="mt-0.5 text-xs text-fg-subtle">
                    {t('settings.updatesLastChecked', { time: formattedCheckedAt })}
                  </p>
                ) : updateError ? (
                  <p className="mt-0.5 truncate text-xs text-fg-subtle" title={updateError}>
                    {updateError}
                  </p>
                ) : null}
              </div>

              <div className="flex shrink-0 items-center gap-2">
                {updateInfo?.updateAvailable && (
                  <Button
                    size="sm"
                    variant="primary"
                    disabled={downloadingUpdate}
                    icon={
                      downloadingUpdate ? (
                        <ArrowsClockwise size={14} className="animate-spin" />
                      ) : (
                        <DownloadSimple size={14} />
                      )
                    }
                    onClick={() => void downloadUpdate()}
                  >
                    {downloadingUpdate
                      ? t('settings.updatesDownloading')
                      : updateInfo.assetSize
                        ? `${t('settings.updatesDownloadBtn')} (${formatBytes(updateInfo.assetSize)})`
                        : t('settings.updatesDownloadBtn')}
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={checkingUpdates || downloadingUpdate}
                  icon={<ArrowsClockwise size={14} className={checkingUpdates ? 'animate-spin' : undefined} />}
                  onClick={() => void checkForUpdates(true)}
                >
                  {checkingUpdates ? t('settings.updatesChecking') : t('settings.updatesCheckBtn')}
                </Button>
              </div>
            </div>

            {(downloadedUpdate || downloadUpdateError) && (
              <div className="flex flex-wrap items-center justify-between gap-3 bg-surface-2/40 px-4 py-2.5 text-xs">
                {downloadedUpdate ? (
                  <>
                    <div className="min-w-0">
                      <span className="font-medium text-fg">
                        {downloadedUpdate.launched
                          ? t('settings.updatesDownloadLaunchedNote', { file: downloadedUpdate.fileName })
                          : t('settings.updatesDownloadSavedNote', { file: downloadedUpdate.fileName })}
                      </span>
                      {downloadedUpdate.verified && (
                        <span className="ml-2 text-[11px] text-fg-subtle">{t('settings.updatesShaVerified')}</span>
                      )}
                      <p className="mt-0.5 truncate font-mono text-[11px] text-fg-subtle" title={downloadedUpdate.filePath}>
                        {downloadedUpdate.filePath}
                      </p>
                    </div>
                    <CopyButton compact text={downloadedUpdate.filePath} label={t('settings.updatesCopyPath')} />
                  </>
                ) : (
                  <span className="text-danger">{downloadUpdateError}</span>
                )}
              </div>
            )}

            {updateInfo?.updateAvailable && localizedChangelog && (
              <div>
                <button
                  type="button"
                  aria-expanded={changelogOpen}
                  aria-controls="update-changelog-panel"
                  onClick={() => setChangelogOpen((open) => !open)}
                  className="flex w-full cursor-pointer items-center justify-between gap-3 px-4 py-2.5 text-left transition-colors hover:bg-surface-2/60"
                >
                  <span className="flex min-w-0 items-center gap-1.5 text-xs font-medium text-fg">
                    {changelogOpen ? (
                      <CaretDown size={13} className="shrink-0 text-fg-subtle" aria-hidden="true" />
                    ) : (
                      <CaretRight size={13} className="shrink-0 text-fg-subtle" aria-hidden="true" />
                    )}
                    <span>{t('settings.updatesChangelogTitle')}</span>
                    <span className="font-mono text-[11px] font-normal text-fg-subtle">
                      v{updateInfo.latestVersion}
                    </span>
                  </span>
                  <span className="shrink-0 text-[11px] text-fg-subtle">
                    {t(changelogOpen ? 'settings.updatesChangelogCollapse' : 'settings.updatesChangelogExpand')}
                  </span>
                </button>
                {changelogOpen && (
                  <div
                    id="update-changelog-panel"
                    className="max-h-72 overflow-y-auto border-t border-line bg-surface-2/40 px-4 py-3"
                  >
                    <ReleaseNotesView markdown={localizedChangelog} />
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </Section>

      <Section index="03" title={t('settings.aboutTitle')}>
        {!config ? (
          <div className="space-y-2.5" aria-busy="true">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : (
          <dl className="divide-y divide-line rounded-md border border-line bg-surface text-xs">
            <div className="flex items-center justify-between gap-4 px-4 py-3">
              <dt className="text-fg-subtle">{t('settings.versionLabel')}</dt>
              <dd className="tabular font-mono text-fg">{status ? `v${status.version}` : t('common.none')}</dd>
            </div>
            <div className="flex items-center justify-between gap-4 px-4 py-3">
              <dt className="text-fg-subtle">{t('settings.statusLabel')}</dt>
              <dd className="flex items-center gap-2 text-fg">
                <span aria-hidden="true" className={cx('h-2 w-2 rounded-full', online ? 'bg-ok' : 'bg-danger')} />
                <span>{online ? t('settings.statusRunning') : t('settings.statusDisconnected')}</span>
                {status && <span className="tabular text-fg-subtle">· {formatDuration(status.uptimeSecs, locale)}</span>}
              </dd>
            </div>
            <div className="flex items-center justify-between gap-4 px-4 py-3">
              <dt className="text-fg-subtle">{t('settings.listenLabel')}</dt>
              <dd className="flex items-center gap-1.5 font-mono text-fg">
                <span>127.0.0.1:{config.proxyPort}</span>
                <CopyButton compact text={`http://127.0.0.1:${config.proxyPort}`} label={t('settings.copyProxyUrl')} />
              </dd>
            </div>
            {status?.configPath && (
              <div className="flex items-center justify-between gap-4 px-4 py-3">
                <dt className="shrink-0 text-fg-subtle">{t('settings.configPathLabel')}</dt>
                <dd className="flex min-w-0 items-center gap-1.5">
                  <code className="truncate font-mono text-fg-muted" title={status.configPath}>
                    {status.configPath}
                  </code>
                  <CopyButton compact text={status.configPath} label={t('settings.copyConfigPath')} />
                </dd>
              </div>
            )}
          </dl>
        )}
      </Section>
    </div>
  );
}
