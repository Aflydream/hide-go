import type {
  AuditSignalKind,
  CoverTheme,
  FindingKind,
  HarnessKind,
  PrivacyMode,
  RequestPurpose,
  Severity,
  ToolCallSecretPolicy,
  TrafficCategory,
} from '../types';
import { LOCALE_META, translate, type Locale, type MessageKey } from './i18n';

export const HARNESS_ORDER: HarnessKind[] = ['claude-code', 'codex', 'antigravity', 'zcode', 'qoder', 'cursor', 'grok-build'];
export const PURPOSE_ORDER: RequestPurpose[] = [
  'chat-inference',
  'tool-result-sync',
  'inline-completion',
  'token-count',
  'codebase-indexing',
  'file-upload',
  'telemetry',
  'feature-flags',
  'crash-report',
  'model-catalog',
  'auth-account',
  'realtime-sync',
  'update-extension',
  'other-api',
];
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
  'telemetry-header': 'auditSignal.telemetryHeader',
  'feature-flag-tracking': 'auditSignal.featureFlagTracking',
  'crash-diagnostics': 'auditSignal.crashDiagnostics',
  'archive-upload': 'auditSignal.archiveUpload',
  'bulk-codebase-upload': 'auditSignal.bulkCodebaseUpload',
  'large-outbound-payload': 'auditSignal.largeOutboundPayload',
  'sensitive-data-exfil': 'auditSignal.sensitiveDataExfil',
};

export function getAuditSignalLabel(kind: AuditSignalKind, locale: Locale): string {
  return AUDIT_SIGNAL_KEYS[kind] ? translate(locale, AUDIT_SIGNAL_KEYS[kind]) : kind;
}

const PURPOSE_KEYS: Record<RequestPurpose, MessageKey> = {
  'chat-inference': 'purpose.chat-inference',
  'tool-result-sync': 'purpose.tool-result-sync',
  'inline-completion': 'purpose.inline-completion',
  'token-count': 'purpose.token-count',
  'codebase-indexing': 'purpose.codebase-indexing',
  'file-upload': 'purpose.file-upload',
  telemetry: 'purpose.telemetry',
  'feature-flags': 'purpose.feature-flags',
  'crash-report': 'purpose.crash-report',
  'model-catalog': 'purpose.model-catalog',
  'auth-account': 'purpose.auth-account',
  'realtime-sync': 'purpose.realtime-sync',
  'update-extension': 'purpose.update-extension',
  'other-api': 'purpose.other-api',
};

export function getPurposeLabel(purpose: RequestPurpose | undefined, locale: Locale, fallbackCategory?: TrafficCategory): string {
  if (purpose && PURPOSE_KEYS[purpose]) {
    return translate(locale, PURPOSE_KEYS[purpose]);
  }
  return fallbackCategory ? getCategoryLabel(fallbackCategory, locale) : translate(locale, 'purpose.other-api');
}

export function getPurposeTone(purpose: RequestPurpose | undefined): 'brand' | 'warn' | 'danger' | 'info' | 'neutral' {
  switch (purpose) {
    case 'telemetry':
    case 'crash-report':
    case 'codebase-indexing':
    case 'file-upload':
      return 'warn';
    case 'feature-flags':
    case 'realtime-sync':
    case 'token-count':
    case 'model-catalog':
      return 'info';
    case 'chat-inference':
    case 'tool-result-sync':
    case 'inline-completion':
      return 'brand';
    default:
      return 'neutral';
  }
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

/**
 * Assemble clean human-readable text from a streaming SSE or NDJSON/JSONL response
 * (OpenAI Chat / Responses, Anthropic Messages, Gemini / Google Cloud Code, and Ollama).
 * Returns `null` when the payload is not a stream with extractable text deltas.
 */
export function extractSseReadableText(text: string): string | null {
  if (!text) return null;
  const isSse = text.includes('data: {') || text.includes('data:{');
  const trimmed = text.trim();
  const isNdjson = !isSse && trimmed.startsWith('{') && trimmed.includes('\n{');
  if (!isSse && !isNdjson) {
    return null;
  }
  const thoughts: string[] = [];
  const reply: string[] = [];
  let parsedEvents = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    let payload: string;
    if (isSse) {
      if (!line.startsWith('data:')) continue;
      payload = line.slice(5).trim();
      if (!payload || payload === '[DONE]' || !payload.startsWith('{')) continue;
    } else {
      if (!line.startsWith('{')) continue;
      payload = line;
    }
    try {
      const obj = JSON.parse(payload) as Record<string, unknown>;
      parsedEvents += 1;

      // Ollama NDJSON (`/api/chat` and `/api/generate`)
      if (isNdjson) {
        const msg = obj.message && typeof obj.message === 'object' ? (obj.message as Record<string, unknown>) : null;
        if (typeof msg?.thinking === 'string' && msg.thinking.length > 0) thoughts.push(msg.thinking);
        if (typeof msg?.content === 'string' && msg.content.length > 0) reply.push(msg.content);
        if (typeof obj.response === 'string' && obj.response.length > 0) reply.push(obj.response);
        continue;
      }

      // OpenAI Chat Completions
      const choices = obj.choices;
      if (Array.isArray(choices)) {
        for (const c of choices) {
          const delta = (c as Record<string, unknown>)?.delta as Record<string, unknown> | undefined;
          if (typeof delta?.reasoning_content === 'string') thoughts.push(delta.reasoning_content);
          if (typeof delta?.content === 'string') reply.push(delta.content);
        }
      }

      // OpenAI Responses API
      const evType = typeof obj.type === 'string' ? obj.type : '';
      if (typeof obj.delta === 'string') {
        if (evType.includes('reasoning')) {
          thoughts.push(obj.delta);
        } else if (evType.endsWith('.delta')) {
          reply.push(obj.delta);
        }
      }

      // Anthropic Messages
      if (evType === 'content_block_delta' && obj.delta && typeof obj.delta === 'object') {
        const d = obj.delta as Record<string, unknown>;
        if (typeof d.thinking === 'string') thoughts.push(d.thinking);
        if (typeof d.text === 'string') reply.push(d.text);
        if (typeof d.partial_json === 'string') reply.push(d.partial_json);
      }

      // Gemini & Google Cloud Code (`response.candidates`)
      const respObj = obj.response && typeof obj.response === 'object' ? (obj.response as Record<string, unknown>) : null;
      const candidates = Array.isArray(obj.candidates)
        ? obj.candidates
        : Array.isArray(respObj?.candidates)
          ? respObj.candidates
          : null;
      if (candidates) {
        for (const cand of candidates) {
          const content = (cand as Record<string, unknown>)?.content as Record<string, unknown> | undefined;
          const parts = content?.parts;
          if (Array.isArray(parts)) {
            for (const part of parts) {
              const p = part as Record<string, unknown>;
              if (typeof p.text === 'string' && p.text.length > 0) {
                if (p.thought === true) {
                  thoughts.push(p.text);
                } else {
                  reply.push(p.text);
                }
              }
            }
          }
        }
      }
    } catch {
      // Skip partial/truncated trailing event lines cleanly
    }
  }

  if (parsedEvents === 0 || (thoughts.length === 0 && reply.length === 0)) {
    return null;
  }
  const thoughtStr = thoughts.join('');
  const replyStr = reply.join('');
  if (thoughtStr && replyStr) {
    return `[Thinking]\n${thoughtStr}\n\n${replyStr}`;
  }
  return replyStr || `[Thinking]\n${thoughtStr}`;
}

function formatRoleLabel(role: unknown): string {
  const r = typeof role === 'string' ? role.toLowerCase() : 'message';
  if (r === 'user') return 'User';
  if (r === 'assistant' || r === 'model') return 'Assistant';
  if (r === 'system' || r === 'developer') return 'System';
  if (r === 'tool' || r === 'function') return 'Tool';
  return r.charAt(0).toUpperCase() + r.slice(1);
}

function collectContentBlocks(content: unknown): string[] {
  if (typeof content === 'string') return content ? [content] : [];
  if (!Array.isArray(content)) return [];
  const out: string[] = [];
  for (const item of content) {
    if (typeof item === 'string') {
      if (item) out.push(item);
      continue;
    }
    if (!item || typeof item !== 'object') continue;
    const b = item as Record<string, unknown>;
    const bType = typeof b.type === 'string' ? b.type : '';
    if (bType === 'thinking' && typeof b.thinking === 'string') {
      out.push(`[Thinking]\n${b.thinking}`);
    } else if (typeof b.text === 'string' && b.text) {
      out.push(b.thought === true ? `[Thinking]\n${b.text}` : b.text);
    } else if (bType === 'tool_use') {
      const name = typeof b.name === 'string' ? b.name : 'tool';
      out.push(`[Tool Call: ${name}]\n${JSON.stringify(b.input ?? {}, null, 2)}`);
    } else if (bType === 'tool_result') {
      const inner = typeof b.content === 'string' ? b.content : collectContentBlocks(b.content).join('\n');
      if (inner) out.push(`[Tool Result]\n${inner}`);
    } else if (b.functionCall && typeof b.functionCall === 'object') {
      const fc = b.functionCall as Record<string, unknown>;
      const name = typeof fc.name === 'string' ? fc.name : 'function';
      out.push(`[Tool Call: ${name}]\n${JSON.stringify(fc.args ?? {}, null, 2)}`);
    } else if (b.functionResponse && typeof b.functionResponse === 'object') {
      const fr = b.functionResponse as Record<string, unknown>;
      const name = typeof fr.name === 'string' ? fr.name : 'function';
      out.push(`[Tool Result: ${name}]\n${JSON.stringify(fr.response ?? {}, null, 2)}`);
    }
  }
  return out;
}

/**
 * Extract readable multi-turn conversation text from an LLM JSON request payload
 * (OpenAI Chat / Responses, Anthropic Messages, Gemini, and Google Cloud Code).
 * Places conversation turns first and any long system instruction at the end so prompts are
 * immediately visible while keeping every token available for highlighting.
 */
export function extractRequestReadableText(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith('{')) return null;
  let obj: Record<string, unknown>;
  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    obj = parsed as Record<string, unknown>;
  } catch {
    return null;
  }

  const turns: string[] = [];
  const systemBlocks: string[] = [];

  const innerReq = obj.request && typeof obj.request === 'object' ? (obj.request as Record<string, unknown>) : obj;

  // Gemini / Cloud Code (`contents` + `systemInstruction`)
  const sysInstr = innerReq.systemInstruction as Record<string, unknown> | undefined;
  if (sysInstr && typeof sysInstr === 'object' && Array.isArray(sysInstr.parts)) {
    const sysParts = collectContentBlocks(sysInstr.parts);
    if (sysParts.length) systemBlocks.push(sysParts.join('\n'));
  }
  if (Array.isArray(innerReq.contents)) {
    for (const entry of innerReq.contents) {
      if (!entry || typeof entry !== 'object') continue;
      const e = entry as Record<string, unknown>;
      const body = collectContentBlocks(e.parts).join('\n\n');
      if (body) turns.push(`[${formatRoleLabel(e.role)}]\n${body}`);
    }
  }

  // Anthropic `system` / OpenAI Responses `instructions`
  if (typeof obj.instructions === 'string' && obj.instructions.trim()) {
    systemBlocks.push(obj.instructions);
  }
  if (typeof obj.system === 'string' && obj.system.trim()) {
    systemBlocks.push(obj.system);
  } else if (Array.isArray(obj.system)) {
    const sysParts = collectContentBlocks(obj.system);
    if (sysParts.length) systemBlocks.push(sysParts.join('\n'));
  }

  // OpenAI Chat / Anthropic Messages (`messages`)
  if (Array.isArray(obj.messages)) {
    for (const entry of obj.messages) {
      if (!entry || typeof entry !== 'object') continue;
      const e = entry as Record<string, unknown>;
      const parts = collectContentBlocks(e.content);
      if (Array.isArray(e.tool_calls)) {
        for (const tc of e.tool_calls) {
          const fn = (tc as Record<string, unknown>)?.function as Record<string, unknown> | undefined;
          if (fn && typeof fn.name === 'string') {
            parts.push(`[Tool Call: ${fn.name}]\n${typeof fn.arguments === 'string' ? fn.arguments : JSON.stringify(fn.arguments ?? {})}`);
          }
        }
      }
      const body = parts.join('\n\n');
      if (!body) continue;
      if (e.role === 'system' || e.role === 'developer') {
        systemBlocks.push(body);
      } else {
        turns.push(`[${formatRoleLabel(e.role)}]\n${body}`);
      }
    }
  }

  // OpenAI Responses API (`input`)
  if (turns.length === 0 && obj.input !== undefined) {
    if (typeof obj.input === 'string' && obj.input.trim()) {
      turns.push(`[User]\n${obj.input}`);
    } else if (Array.isArray(obj.input)) {
      for (const item of obj.input) {
        if (typeof item === 'string' && item.trim()) {
          turns.push(`[User]\n${item}`);
          continue;
        }
        if (!item || typeof item !== 'object') continue;
        const it = item as Record<string, unknown>;
        if (it.type === 'function_call' && typeof it.name === 'string') {
          turns.push(`[Tool Call: ${it.name}]\n${typeof it.arguments === 'string' ? it.arguments : JSON.stringify(it.arguments ?? {})}`);
        } else if (it.type === 'function_call_output' && typeof it.output === 'string') {
          turns.push(`[Tool Result]\n${it.output}`);
        } else {
          const body = collectContentBlocks(it.content).join('\n\n');
          if (body) turns.push(`[${formatRoleLabel(it.role)}]\n${body}`);
        }
      }
    }
  }

  if (turns.length === 0) return null;
  if (systemBlocks.length > 0) {
    turns.push(`[System]\n${systemBlocks.join('\n\n')}`);
  }
  return turns.join('\n\n---\n\n');
}

export function proxyBase(port: number): string {
  return `http://127.0.0.1:${port}`;
}
