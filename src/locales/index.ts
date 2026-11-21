import zhCN from './zh-CN.json';
import en from './en.json';

export type Locale = 'zh-CN' | 'en';
export type Messages = typeof zhCN;
export type MessageKey = keyof Messages;

const enMessages: Messages = en;

export const DEFAULT_FALLBACK_LOCALE: Locale = 'en';

export const MESSAGES: Record<Locale, Messages> = {
  'zh-CN': zhCN,
  en: enMessages,
};

export interface LocaleMeta {
  code: Locale;
  nativeName: string;
  intlTag: string;
  nameKey: MessageKey;
  descriptionKey: MessageKey;
}

export const SUPPORTED_LOCALES: LocaleMeta[] = [
  {
    code: 'zh-CN',
    nativeName: '简体中文',
    intlTag: 'zh-CN',
    nameKey: 'locale.zhCnName',
    descriptionKey: 'locale.zhCnDesc',
  },
  {
    code: 'en',
    nativeName: 'English',
    intlTag: 'en-US',
    nameKey: 'locale.enName',
    descriptionKey: 'locale.enDesc',
  },
];

export const LOCALE_META: Record<Locale, LocaleMeta> = {
  'zh-CN': SUPPORTED_LOCALES[0],
  en: SUPPORTED_LOCALES[1],
};
