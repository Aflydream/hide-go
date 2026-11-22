export type HarnessKind = 'claude-code' | 'codex' | 'antigravity' | 'zcode' | 'qoder' | 'cursor' | 'grok-build' | 'generic';

export type TrafficCategory = 'interactive-prompt' | 'codebase-indexing' | 'telemetry' | 'tool-execution-sync';

export type PrivacyMode = 'audit-only' | 'auto-desensitize' | 'all-hide';

export type CoverTheme = 'botanical-garden' | 'library-catalog' | 'bakery-recipe';

export type ToolCallSecretPolicy = 'never' | 'file-edits-only' | 'always';

export type UiLanguage = 'system' | 'zh-CN' | 'en';

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
  language?: UiLanguage;
  autoCheckUpdates?: boolean;
  systemProxyChain?: boolean;
  mitmExtraHosts?: string[];
  mitmBypassHosts?: string[];
}

export interface ObservedConnectHost {
  host: string;
  port: number;
  mitm: boolean;
  tlsFailed: boolean;
  count: number;
  lastSeenAt: string;
}

export interface MitmHostsResponse {
  mitmExtraHosts: string[];
  mitmBypassHosts: string[];
  systemProxyChain: boolean;
  systemProxySupported: boolean;
  systemProxyActive: boolean;
  observedHosts: ObservedConnectHost[];
}

export interface UpdateCheckResult {
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
  releaseUrl: string;
  publishedAt?: string | null;
  checkedAt: string;
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

export type AutoConnectMode = 'configFile' | 'envVar' | 'manual';

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
  installed: boolean;
  installPaths: string[];
  configured: boolean;
  configuredVia: string | null;
  autoConnectMode: AutoConnectMode;
  requiresCaTrust?: boolean;
  autoConnectTargets?: string[];
  trafficCount: number;
  lastSeenAt: string | null;
}

export interface CaStatus {
  ready: boolean;
  caCertPath: string;
  caBundlePath: string;
  fingerprintSha1: string;
  fingerprintSha256: string;
  subject: string;
  notAfter: string;
  installedInOsStore: boolean;
  osTrustSupported: boolean;
  osTrustDetail: string;
}

export interface HarnessActionResult {
  kind: HarnessKind;
  ok: boolean;
  connected: boolean;
  message: string;
  changedTarget: string | null;
  backupPath: string | null;
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
