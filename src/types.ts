export type HarnessKind = 'claude-code' | 'codex' | 'antigravity' | 'zcode' | 'qoder' | 'cursor' | 'grok-build' | 'generic';

export type TrafficCategory = 'interactive-prompt' | 'codebase-indexing' | 'telemetry' | 'tool-execution-sync';

export type PrivacyMode = 'audit-only' | 'auto-desensitize' | 'all-hide';

export type CoverTheme = 'botanical-garden' | 'library-catalog' | 'bakery-recipe';

export type ToolCallSecretPolicy = 'never' | 'file-edits-only' | 'always';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface AllHideConfig {
  enableIsomorphicCamouflage: boolean;
  coverTheme: CoverTheme;
  enableCipherGarble: boolean;
  enableTelemetryChaff: boolean;
  strictLiteralMasking: boolean;
}

export type FindingKind =
  | 'api-key'
  | 'private-key'
  | 'database-url'
  | 'internal-ip'
  | 'internal-domain'
  | 'project-path'
  | 'email-or-pii'
  | 'git-metadata'
  | 'env-secret'
  | 'custom-keyword'
  | 'proprietary-code-symbol';

export interface LeakFinding {
  kind: FindingKind;
  label: string;
  originalPreview: string;
  replacementToken: string;
  severity: Severity;
  count: number;
}

export interface CustomRule {
  id: string;
  name: string;
  pattern: string;
  replacementHint: string;
  enabled: boolean;
}

export interface HideConfig {
  proxyPort: number;
  mode: PrivacyMode;
  allHide: AllHideConfig;
  blockSilentTelemetry: boolean;
  protectProjectPaths: boolean;
  protectSecretsAndKeys: boolean;
  protectInternalNetwork: boolean;
  projectSalt: string;
  toolCallSecretPolicy: ToolCallSecretPolicy;
  customRules: CustomRule[];
}

export interface TrafficSummary {
  id: string;
  timestamp: string;
  harness: HarnessKind;
  category: TrafficCategory;
  method: string;
  endpoint: string;
  appliedMode: PrivacyMode;
  actionTaken: string;
  status: number;
  latencyMs: number;
  simulated: boolean;
  requestBytes: number;
  responseBytes: number;
  findingCount: number;
  topSeverity: Severity | null;
  restoredCount: number;
  withheldCount: number;
}

export interface TrafficAuditRecord {
  id: string;
  timestamp: string;
  harness: HarnessKind;
  category: TrafficCategory;
  method: string;
  endpoint: string;
  upstreamVendor: string;
  appliedMode: PrivacyMode;
  actionTaken: string;
  status: number;
  latencyMs: number;
  simulated: boolean;
  localRequestPayload: string;
  vendorVisiblePayload: string;
  vendorRawResponse: string;
  localRestoredResponse: string;
  requestBytes: number;
  responseBytes: number;
  truncated: boolean;
  findings: LeakFinding[];
  restoredCount: number;
  withheldCount: number;
}

export interface HarnessProfile {
  kind: HarnessKind;
  name: string;
  vendorName: string;
  defaultUpstream: string;
  localProxyRoute: string;
  protocolFamily: string;
  description: string;
  riskSummary: string[];
  envSetupBash: string;
  envSetupPowershell: string;
  integrationNote: string | null;
  detectedActive: boolean;
}

export interface VaultEntry {
  token: string;
  originalMasked: string;
  originalRaw: string;
  category: string;
  hitCount: number;
  secret: boolean;
}

export interface GatewayStatus {
  status: string;
  version: string;
  uptimeSecs: number;
  configPath: string | null;
  totalRequests: number;
  totalFindings: number;
  totalRestored: number;
  totalWithheld: number;
  totalBlocked: number;
  activeVaultTokens: number;
}

export interface RuleValidation {
  valid: boolean;
  message?: string;
  matches?: string[];
}
