import { ArrowsClockwise, ArrowSquareOut, CheckCircle } from '@phosphor-icons/react';
import { useStore } from '../store';
import { Badge, Button, CopyButton, Section, Segmented, Skeleton, Switch, cx } from '../components/ui';
import { useColorScheme, type ColorSchemePref } from '../components/WindowFrame';
import { formatDuration } from '../lib/format';
import { SUPPORTED_LOCALES, translate, useI18n } from '../lib/i18n';
import type { UiLanguage } from '../types';

export function Settings() {
  const { config, status, statusError, saveConfig, updateInfo, updateError, checkingUpdates, checkForUpdates } = useStore();
  const { pref, setPref, systemLocale, locale, t } = useI18n();
  const { pref: themePref, setPref: setThemePref } = useColorScheme();

  const online = !!status && !statusError;
  const autoCheckEnabled = config ? config.autoCheckUpdates !== false : true;
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
                  <a
                    href={updateInfo.releaseUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex h-7 shrink-0 items-center gap-1.5 rounded border border-transparent bg-brand-solid px-2.5 text-xs font-medium text-brand-on transition-colors hover:bg-brand-solid/90"
                  >
                    {t('settings.updatesDownloadBtn')}
                    <ArrowSquareOut size={13} aria-hidden="true" />
                  </a>
                )}
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={checkingUpdates}
                  icon={<ArrowsClockwise size={14} className={checkingUpdates ? 'animate-spin' : undefined} />}
                  onClick={() => void checkForUpdates(true)}
                >
                  {checkingUpdates ? t('settings.updatesChecking') : t('settings.updatesCheckBtn')}
                </Button>
              </div>
            </div>
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
                <span aria-hidden="true" className={cx('h-2 w-2 rounded-full', online ? 'bg-brand' : 'bg-danger')} />
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
