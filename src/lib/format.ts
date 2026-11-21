import type { CoverTheme, FindingKind, HarnessKind, PrivacyMode, Severity, ToolCallSecretPolicy, TrafficCategory } from '../types';

export const HARNESS_LABEL: Record<HarnessKind, string> = {
  'claude-code': 'Claude Code',
  codex: 'Codex',
  antigravity: 'Antigravity',
  zcode: 'ZCode',
  qoder: 'Qoder',
  cursor: 'Cursor',
  'grok-build': 'Grok Build',
  generic: '通用',
};

export const HARNESS_ORDER: HarnessKind[] = ['claude-code', 'codex', 'antigravity', 'zcode', 'qoder', 'cursor', 'grok-build'];

export const CATEGORY_LABEL: Record<TrafficCategory, string> = {
  'interactive-prompt': '对话推理',
  'tool-execution-sync': '工具回传',
  'codebase-indexing': '代码索引',
  telemetry: '遥测',
};

export const MODE_LABEL: Record<PrivacyMode, string> = {
  'audit-only': '仅审计',
  'auto-desensitize': '自动脱敏',
  'all-hide': 'All-Hide',
};

export const COVER_THEME_LABEL: Record<CoverTheme, string> = {
  'botanical-garden': '植物园温室',
  'library-catalog': '图书馆编目',
  'bakery-recipe': '烘焙坊配方',
};

export const POLICY_LABEL: Record<ToolCallSecretPolicy, string> = {
  never: '始终保留占位符',
  'file-edits-only': '仅文件写入时还原',
  always: '全部还原',
};

export const FINDING_LABEL: Record<FindingKind, string> = {
  'api-key': 'API 密钥',
  'private-key': '私钥',
  'database-url': '数据库连接串',
  'internal-ip': '内网 IP',
  'internal-domain': '内部域名',
  'project-path': '本机路径',
  'email-or-pii': '邮箱 / 身份',
  'git-metadata': '后台上传',
  'env-secret': '配置密钥',
  'custom-keyword': '自定义规则',
  'proprietary-code-symbol': '代码伪装',
};

export const VAULT_CATEGORY_LABEL: Record<string, string> = {
  ApiKey: 'API 密钥',
  PrivateKey: '私钥',
  DatabaseUrl: '数据库连接串',
  InternalIp: '内网 IP',
  InternalDomain: '内部域名',
  ProjectPath: '本机路径',
  EmailOrPii: '邮箱 / 身份',
  EnvSecret: '配置密钥',
  CustomKeyword: '自定义规则',
  IsomorphicSymbol: '伪装标识符',
  CoverComment: '伪装注释',
  StrictStringLiteral: '字符串字面量',
  StrictLiteral: '字面量',
  CipherGarble: '加密块',
};

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
export const SEVERITY_LABEL: Record<Severity, string> = { critical: '严重', high: '高', medium: '中', low: '低' };

/** Human description of what the gateway did with a request. */
export function describeAction(action: string): { label: string; tone: 'brand' | 'warn' | 'danger' | 'neutral' | 'info' } {
  if (
    action.includes('stream-error') ||
    action.includes('upstream_') ||
    action.includes('failed') ||
    action.includes('rejected') ||
    action.includes('invalid_upstream') ||
    action.includes('transformation_breaks')
  ) {
    return { label: '转发失败', tone: 'danger' };
  }
  if (action === 'telemetry-blocked') return { label: '遥测已拦截', tone: 'warn' };
  if (action === 'chaff-injected') return { label: '诱饵替换', tone: 'warn' };
  if (action === 'passed') return { label: '原样透传', tone: 'neutral' };
  if (action === 'desensitized') return { label: '已脱敏', tone: 'brand' };
  if (action.includes('all-hide') || action.includes('strict-literal')) return { label: 'All-Hide', tone: 'brand' };
  return { label: action, tone: 'neutral' };
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const NUMBER_FORMATTER = new Intl.NumberFormat('zh-CN');

export function formatCount(n: number): string {
  return NUMBER_FORMATTER.format(n);
}

export function formatDuration(totalSecs: number): string {
  const d = Math.floor(totalSecs / 86400);
  const h = Math.floor((totalSecs % 86400) / 3600);
  const m = Math.floor((totalSecs % 3600) / 60);
  if (d > 0) return `${d} 天 ${h} 小时`;
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分钟`;
  return `${totalSecs} 秒`;
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
