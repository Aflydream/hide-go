import { useStore } from '../store';
import { Badge, CopyButton, RadioCard, Section, Skeleton, cx } from '../components/ui';
import { useColorScheme, type ColorSchemePref } from '../components/WindowFrame';
import { formatDuration } from '../lib/format';
import { LOCALE_META, SUPPORTED_LOCALES, translate, useI18n } from '../lib/i18n';
import type { UiLanguage } from '../types';

export function Settings() {
  const { config, status, statusError, saveConfig } = useStore();
  const { pref, setPref, systemLocale, locale, t } = useI18n();
  const { pref: themePref, resolved: resolvedTheme, setPref: setThemePref } = useColorScheme();

  const systemLangName = t(LOCALE_META[systemLocale].nameKey);
  const currentThemeLabel = t(resolvedTheme === 'dark' ? 'settings.themeCurrentDark' : 'settings.themeCurrentLight');
  const online = !!status && !statusError;

  const handleLanguageSelect = (next: UiLanguage) => {
    setPref(next);
    if (config && config.language !== next) {
      const nextLocale = next === 'system' ? systemLocale : next;
      void saveConfig({ ...config, language: next }, translate(nextLocale, 'settings.langSaved'));
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-6 pb-10">
      <Section index="01" title={t('settings.langTitle')} description={t('settings.langDesc')}>
        <div className="space-y-2.5">
          <RadioCard<UiLanguage>
            name="ui-language"
            value="system"
            current={pref}
            onSelect={handleLanguageSelect}
            title={t('settings.langSystemTitle')}
            description={t('settings.langSystemDesc')}
            badge={<Badge tone="brand">{t('settings.langDetected', { lang: systemLangName })}</Badge>}
          />
          {SUPPORTED_LOCALES.map((loc) => (
            <RadioCard<UiLanguage>
              key={loc.code}
              name="ui-language"
              value={loc.code}
              current={pref}
              onSelect={handleLanguageSelect}
              title={loc.nativeName}
              description={t(loc.descriptionKey)}
            />
          ))}
        </div>
      </Section>

      <Section index="02" title={t('settings.themeTitle')} description={t('settings.themeDesc')}>
        <div className="space-y-2.5">
          <RadioCard<ColorSchemePref>
            name="ui-theme"
            value="system"
            current={themePref}
            onSelect={setThemePref}
            title={t('settings.themeSystemTitle')}
            description={t('settings.themeSystemDesc')}
            badge={<Badge>{currentThemeLabel}</Badge>}
          />
          <RadioCard<ColorSchemePref>
            name="ui-theme"
            value="light"
            current={themePref}
            onSelect={setThemePref}
            title={t('settings.themeLightTitle')}
            description={t('settings.themeLightDesc')}
          />
          <RadioCard<ColorSchemePref>
            name="ui-theme"
            value="dark"
            current={themePref}
            onSelect={setThemePref}
            title={t('settings.themeDarkTitle')}
            description={t('settings.themeDarkDesc')}
          />
        </div>
      </Section>

      <Section index="03" title={t('settings.aboutTitle')} description={t('settings.aboutDesc')}>
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
            <div className="flex items-center justify-between gap-4 px-4 py-3">
              <dt className="text-fg-subtle">{t('settings.systemLocaleLabel')}</dt>
              <dd className="font-mono text-fg-muted">{systemLangName}</dd>
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
