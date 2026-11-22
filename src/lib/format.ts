import type { AuditSignalKind, CoverTheme, FindingKind, HarnessKind, PrivacyMode, Severity, ToolCallSecretPolicy, TrafficCategory } from '../types';
import { LOCALE_META, translate, type Locale, type MessageKey } from './i18n';

export const HARNESS_ORDER: HarnessKind[] = ['claude-code', 'codex', 'antigravity', 'zcode', 'qoder', 'cursor', 'grok-build'];
export const COVER_THEMES: CoverTheme[] = ['botanical-garden', 'library-catalog', 'bakery-recipe'];
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const HARNESS_KEYS: Record<HarnessKind, MessageKey> = {
  'claude-code': 'harness.claude-code',
  codex: 'harness.codex',
  antigravity: 'harness.antigravity',
  zcode: 'harness.zcode',
  qoder: 'harness.qoder',
  cursor: 'harness.cursor',
  'grok-build': 'harness.grok-build',
  generic: 'harness.generic',
};

export function getHarnessLabel(kind: HarnessKind, locale: Locale): string {
  return HARNESS_KEYS[kind] ? translate(locale, HARNESS_KEYS[kind]) : kind;
}

const CATEGORY_KEYS: Record<TrafficCategory, MessageKey> = {
  'interactive-prompt': 'category.interactive-prompt',
  'tool-execution-sync': 'category.tool-execution-sync',
  'codebase-indexing': 'category.codebase-indexing',
  telemetry: 'category.telemetry',
};

export function getCategoryLabel(category: TrafficCategory, locale: Locale): string {
  return CATEGORY_KEYS[category] ? translate(locale, CATEGORY_KEYS[category]) : category;
}

const MODE_KEYS: Record<PrivacyMode, MessageKey> = {
  'audit-only': 'mode.auditOnly',
  'auto-desensitize': 'mode.autoDesensitize',
  'all-hide': 'mode.allHide',
};

export function getModeLabel(mode: PrivacyMode, locale: Locale): string {
  return MODE_KEYS[mode] ? translate(locale, MODE_KEYS[mode]) : mode;
}

const COVER_THEME_KEYS: Record<CoverTheme, MessageKey> = {
  'botanical-garden': 'coverTheme.botanical-garden',
  'library-catalog': 'coverTheme.library-catalog',
  'bakery-recipe': 'coverTheme.bakery-recipe',
};

export function getCoverThemeLabel(theme: CoverTheme, locale: Locale): string {
  return COVER_THEME_KEYS[theme] ? translate(locale, COVER_THEME_KEYS[theme]) : theme;
}

const POLICY_KEYS: Record<ToolCallSecretPolicy, MessageKey> = {
  never: 'toolPolicy.never',
  'file-edits-only': 'toolPolicy.file-edits-only',
  always: 'toolPolicy.always',
};

export function getPolicyLabel(policy: ToolCallSecretPolicy, locale: Locale): string {
  return POLICY_KEYS[policy] ? translate(locale, POLICY_KEYS[policy]) : policy;
}

const FINDING_KEYS: Record<FindingKind, MessageKey> = {
  'api-key': 'finding.api-key',
  'private-key': 'finding.private-key',
  'database-url': 'finding.database-url',
  'internal-ip': 'finding.internal-ip',
  'internal-domain': 'finding.internal-domain',
  'project-path': 'finding.project-path',
  'email-or-pii': 'finding.email-or-pii',
  'git-metadata': 'finding.git-metadata',
  'env-secret': 'finding.env-secret',
  'custom-keyword': 'finding.custom-keyword',
  'proprietary-code-symbol': 'finding.proprietary-code-symbol',
};

export function getFindingLabel(kind: FindingKind, locale: Locale): string {
  return FINDING_KEYS[kind] ? translate(locale, FINDING_KEYS[kind]) : kind;
}

const VAULT_CATEGORY_KEYS: Record<string, MessageKey> = {
  ApiKey: 'vaultCategory.ApiKey',
  PrivateKey: 'vaultCategory.PrivateKey',
  DatabaseUrl: 'vaultCategory.DatabaseUrl',
  InternalIp: 'vaultCategory.InternalIp',
  InternalDomain: 'vaultCategory.InternalDomain',
  ProjectPath: 'vaultCategory.ProjectPath',
  EmailOrPii: 'vaultCategory.EmailOrPii',
  EnvSecret: 'vaultCategory.EnvSecret',
  CustomKeyword: 'vaultCategory.CustomKeyword',
  IsomorphicSymbol: 'vaultCategory.IsomorphicSymbol',
  CoverComment: 'vaultCategory.CoverComment',
  StrictStringLiteral: 'vaultCategory.StrictStringLiteral',
  StrictLiteral: 'vaultCategory.StrictLiteral',
  CipherGarble: 'vaultCategory.CipherGarble',
};

export function getVaultCategoryLabel(category: string, locale: Locale): string {
  const key = VAULT_CATEGORY_KEYS[category];
  return key ? translate(locale, key) : category;
}

const SEVERITY_KEYS: Record<Severity, MessageKey> = {
  critical: 'severity.critical',
  high: 'severity.high',
  medium: 'severity.medium',
  low: 'severity.low',
};

export function getSeverityLabel(severity: Severity, locale: Locale): string {
  return SEVERITY_KEYS[severity] ? translate(locale, SEVERITY_KEYS[severity]) : severity;
}

const AUDIT_SIGNAL_KEYS: Record<AuditSignalKind, MessageKey> = {
  'telemetry-endpoint': 'auditSignal.telemetryEndpoint',
  'telemetry-payload': 'auditSignal.telemetryPayload',
  'archive-upload': 'auditSignal.archiveUpload',
  'bulk-codebase-upload': 'auditSignal.bulkCodebaseUpload',
  'large-outbound-payload': 'auditSignal.largeOutboundPayload',
  'sensitive-data-exfil': 'auditSignal.sensitiveDataExfil',
};

export function getAuditSignalLabel(kind: AuditSignalKind, locale: Locale): string {
  return AUDIT_SIGNAL_KEYS[kind] ? translate(locale, AUDIT_SIGNAL_KEYS[kind]) : kind;
}

/** Human description of what the gateway did with a request. */
export function describeAction(
  action: string,
  locale: Locale,
): { label: string; tone: 'brand' | 'warn' | 'danger' | 'neutral' | 'info' } {
  if (action === 'tls-handshake-failed') {
    return { label: translate(locale, 'action.tlsFailed'), tone: 'danger' };
  }
  if (
    action.includes('stream-error') ||
    action.includes('upstream_') ||
    action.includes('failed') ||
    action.includes('rejected') ||
    action.includes('invalid_upstream') ||
    action.includes('transformation_breaks')
  ) {
    return { label: translate(locale, 'action.failed'), tone: 'danger' };
  }
  if (action === 'telemetry-blocked') {
    return { label: translate(locale, 'action.telemetryBlocked'), tone: 'warn' };
  }
  if (action === 'telemetry-audited') {
    return { label: translate(locale, 'action.telemetryAudited'), tone: 'warn' };
  }
  if (action === 'upload-audited') {
    return { label: translate(locale, 'action.uploadAudited'), tone: 'warn' };
  }
  if (action === 'chaff-injected') {
    return { label: translate(locale, 'action.chaffInjected'), tone: 'warn' };
  }
  if (action === 'passed' || action === 'protobuf-passed' || action === 'protobuf-audited') {
    return { label: translate(locale, 'action.passed'), tone: 'neutral' };
  }
  if (action === 'desensitized' || action === 'protobuf-desensitized') {
    return { label: translate(locale, 'action.desensitized'), tone: 'brand' };
  }
  if (action.includes('all-hide') || action.includes('strict-literal')) {
    return { label: translate(locale, 'action.allHide'), tone: 'brand' };
  }
  return { label: action, tone: 'neutral' };
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const numberFormatters = new Map<Locale, Intl.NumberFormat>();

export function formatCount(n: number, locale: Locale): string {
  let formatter = numberFormatters.get(locale);
  if (!formatter) {
    formatter = new Intl.NumberFormat(LOCALE_META[locale].intlTag);
    numberFormatters.set(locale, formatter);
  }
  return formatter.format(n);
}

export function formatDuration(totalSecs: number, locale: Locale): string {
  const d = Math.floor(totalSecs / 86400);
  const h = Math.floor((totalSecs % 86400) / 3600);
  const m = Math.floor((totalSecs % 3600) / 60);
  if (d > 0) return translate(locale, 'time.daysHours', { d, h });
  if (h > 0) return translate(locale, 'time.hoursMinutes', { h, m });
  if (m > 0) return translate(locale, 'time.minutes', { m });
  return translate(locale, 'time.seconds', { s: totalSecs });
}

export function formatLatency(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(ms >= 10000 ? 0 : 1)} s` : `${ms} ms`;
}

/** Pretty-print JSON when the text is a JSON document; otherwise return it untouched. */
export function prettyJson(text: string): string {
  const t = text.trim();
  if (!t.startsWith('{') && !t.startsWith('[')) return text;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    return text;
  }
}

export function proxyBase(port: number): string {
  return `http://127.0.0.1:${port}`;
}
