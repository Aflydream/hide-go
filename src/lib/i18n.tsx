import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  DEFAULT_FALLBACK_LOCALE,
  LOCALE_META,
  MESSAGES,
  SUPPORTED_LOCALES,
  type Locale,
  type MessageKey,
} from '../locales';
import type { HarnessKind, UiLanguage } from '../types';

export { LOCALE_META, SUPPORTED_LOCALES };
export type { Locale, MessageKey };
export type LocalePref = UiLanguage;

const LOCALE_STORAGE_KEY = 'hide-go-locale';

export function normalizeLocale(raw?: string | null): Locale {
  return raw && /^zh(?:$|[-_])/i.test(raw.trim()) ? 'zh-CN' : DEFAULT_FALLBACK_LOCALE;
}

export function detectSystemLocale(): Locale {
  if (typeof document !== 'undefined') {
    const meta = document.querySelector<HTMLMetaElement>('meta[name="hide-go-locale"]')?.content?.trim();
    if (meta && meta in MESSAGES) {
      return meta as Locale;
    }
  }
  if (typeof navigator !== 'undefined') {
    const candidate =
      (Array.isArray(navigator.languages) ? navigator.languages.find(Boolean) : undefined) ?? navigator.language;
    return normalizeLocale(candidate);
  }
  return DEFAULT_FALLBACK_LOCALE;
}

export function translate(locale: Locale, key: MessageKey, params?: Record<string, string | number>): string {
  const dict = MESSAGES[locale] ?? MESSAGES[DEFAULT_FALLBACK_LOCALE];
  const template = dict[key] ?? MESSAGES[DEFAULT_FALLBACK_LOCALE][key] ?? key;
  if (!params) return template;
  return template.replace(/\{([A-Za-z0-9_]+)\}/g, (match, k) =>
    Object.prototype.hasOwnProperty.call(params, k) && params[k] !== undefined ? String(params[k]) : match,
  );
}

function readStoredPref(): LocalePref {
  try {
    const raw = localStorage.getItem(LOCALE_STORAGE_KEY);
    if (raw === 'zh-CN' || raw === 'en') return raw;
  } catch {
    /* ignore */
  }
  return 'system';
}

export function getActiveLocale(): Locale {
  const pref = readStoredPref();
  return pref === 'system' ? detectSystemLocale() : pref;
}

function persistPref(pref: LocalePref) {
  try {
    if (pref === 'system') {
      localStorage.removeItem(LOCALE_STORAGE_KEY);
    } else {
      localStorage.setItem(LOCALE_STORAGE_KEY, pref);
    }
  } catch {
    /* ignore */
  }
}

interface I18nContextValue {
  pref: LocalePref;
  locale: Locale;
  systemLocale: Locale;
  setPref: (next: LocalePref) => void;
  syncPrefFromConfig: (next?: LocalePref) => void;
  t: (key: MessageKey, params?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<LocalePref>(readStoredPref);
  const [systemLocale, setSystemLocale] = useState<Locale>(detectSystemLocale);

  useEffect(() => {
    const onLanguageChange = () => setSystemLocale(detectSystemLocale());
    const onStorage = (e: StorageEvent) => {
      if (e.key === LOCALE_STORAGE_KEY) {
        setPrefState(readStoredPref());
      }
    };
    window.addEventListener('languagechange', onLanguageChange);
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener('languagechange', onLanguageChange);
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  const locale: Locale = pref === 'system' ? systemLocale : pref;

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = locale;
    }
  }, [locale]);

  const setPref = useCallback((next: LocalePref) => {
    setPrefState(next);
    persistPref(next);
  }, []);

  const syncPrefFromConfig = useCallback((next?: LocalePref) => {
    if (next === 'system' || next === 'zh-CN' || next === 'en') {
      setPrefState(next);
      persistPref(next);
    }
  }, []);

  const t = useCallback(
    (key: MessageKey, params?: Record<string, string | number>) => translate(locale, key, params),
    [locale],
  );

  const value = useMemo<I18nContextValue>(
    () => ({ pref, locale, systemLocale, setPref, syncPrefFromConfig, t }),
    [pref, locale, systemLocale, setPref, syncPrefFromConfig, t],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error('I18nProvider missing');
  return ctx;
}

const HARNESS_NOTE_KEYS: Partial<Record<HarnessKind, MessageKey>> = {
  'claude-code': 'harness.note.claude-code',
  codex: 'harness.note.codex',
  antigravity: 'harness.note.antigravity',
  zcode: 'harness.note.zcode',
  qoder: 'harness.note.qoder',
  cursor: 'harness.note.cursor',
  'grok-build': 'harness.note.grok-build',
  pi: 'harness.note.pi',
};

export function localizeHarnessIntegrationNote(
  kind: HarnessKind,
  rawNote: string | null | undefined,
  locale: Locale,
): string | null | undefined {
  if (locale === 'zh-CN' || !rawNote) return rawNote;
  const key = HARNESS_NOTE_KEYS[kind];
  return key ? translate(locale, key) : rawNote;
}

export function localizeHarnessTargets(targets: string[], locale: Locale): string[] {
  if (locale === 'zh-CN') return targets;
  const shellProfile = translate(locale, 'integrations.shellProfile');
  const envVars = translate(locale, 'integrations.envVars');
  const systemProxyChain = translate(locale, 'integrations.systemProxyChainTarget');
  return targets.map((t) =>
    t
      .replace(/系统代理链（运行期接管，退出自动还原）/g, systemProxyChain)
      .replace(/Shell 配置文件/g, shellProfile)
      .replace(/环境变量/g, envVars),
  );
}

const SETUP_STEP_KEYS: Record<string, MessageKey> = {
  bin: 'setup.step.bin',
  cfg: 'setup.step.cfg',
  shortcuts: 'setup.step.shortcuts',
  uninst: 'setup.step.uninst',
  path: 'setup.step.path',
  autostart: 'setup.step.autostart',
  scan: 'setup.step.scan',
  stop: 'setup.step.stop',
  harnesses: 'setup.step.harnesses',
  ca: 'setup.step.ca',
  files: 'setup.step.files',
  config: 'setup.step.config',
};

export function localizeSetupStepLabel(id: string, fallback: string, locale: Locale): string {
  if (locale === 'zh-CN') return fallback;
  if (id === 'dir') {
    if (fallback.includes('校验')) return translate(locale, 'setup.step.dirValidate');
    if (fallback.includes('创建')) return translate(locale, 'setup.step.dirCreate');
    return translate(locale, 'setup.step.dirPrepare');
  }
  if (id === 'sys') {
    if (fallback.includes('移除')) return translate(locale, 'setup.step.sysUninstall');
    if (fallback.includes('清单')) return translate(locale, 'setup.step.sysManifest');
    return translate(locale, 'setup.step.sysInstall');
  }
  const key = SETUP_STEP_KEYS[id];
  return key ? translate(locale, key) : fallback;
}

const EXACT_DETAIL_KEYS: Array<[string, MessageKey]> = [
  ['完成', 'setup.detail.done'],
  ['已完成', 'setup.detail.done'],
  ['已清理', 'setup.detail.removed'],
  ['目录不存在', 'setup.detail.dirNotFound'],
  ['主程序与后台服务', 'setup.detail.binaries'],
  ['失败', 'setup.stepDetailFailed'],
  ['处理中…', 'setup.stepDetailWorking'],
  ['等待中', 'setup.stepDetailPending'],
  ['已中止', 'setup.stepDetailAborted'],
];

export function localizeSetupStepDetail(detail: string | null | undefined, locale: Locale): string | undefined {
  if (!detail) return undefined;
  if (locale === 'zh-CN') return detail;
  for (const [needle, key] of EXACT_DETAIL_KEYS) {
    if (detail === needle) return translate(locale, key);
  }
  const foundMatch = /^发现\s+(\d+)\s+个$/.exec(detail);
  if (foundMatch) return translate(locale, 'setup.detail.foundCount', { count: foundMatch[1] });
  const shortcutMatch = /^已创建\s+(\d+)\s+个快捷方式(.*)$/.exec(detail);
  if (shortcutMatch) {
    const key = shortcutMatch[2].includes('PATH') ? 'setup.detail.shortcutsAndPath' : 'setup.detail.shortcutsOnly';
    return translate(locale, key, { count: shortcutMatch[1] });
  }
  const restoreMatch = /^已还原\s+(\d+)\s+项配置$/.exec(detail);
  if (restoreMatch) return translate(locale, 'setup.detail.restoredConfigs', { count: restoreMatch[1] });
  if (detail.startsWith('提示:') || detail.startsWith('提示：')) {
    return translate(locale, 'setup.detail.note', { text: detail.slice(3).trim() });
  }
  return detail;
}
