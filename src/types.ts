export type HarnessKind = 'claude-code' | 'codex' | 'antigravity' | 'zcode' | 'qoder' | 'cursor' | 'grok-build' | 'pi' | 'generic';

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
  protectPersonalInfo?: boolean;
  guardModelEnabled?: boolean;
  guardThreshold?: number;
  projectSalt: string;
  toolCallSecretPolicy: ToolCallSecretPolicy;
  customRules: CustomRule[];
  language?: UiLanguage;
  autoCheckUpdates?: boolean;
  systemProxyChain?: boolean;
  mitmExtraHosts?: string[];
  mitmBypassHosts?: string[];
}

export type HostRiskKind = 'telemetry' | 'upload-storage' | 'ai-api' | 'general';

export type RequestPurpose =
  | 'chat-inference'
  | 'tool-result-sync'
  | 'inline-completion'
  | 'token-count'
  | 'codebase-indexing'
  | 'file-upload'
  | 'telemetry'
  | 'feature-flags'
  | 'crash-report'
  | 'model-catalog'
  | 'auth-account'
  | 'realtime-sync'
  | 'update-extension'
  | 'other-api';

export type AuditSignalKind =
  | 'telemetry-endpoint'
  | 'telemetry-payload'
  | 'telemetry-header'
  | 'feature-flag-tracking'
  | 'crash-diagnostics'
  | 'archive-upload'
  | 'bulk-codebase-upload'
  | 'large-outbound-payload'
  | 'sensitive-data-exfil';

export type AuditSeverity = 'info' | 'warn' | 'high';

export interface AuditSignal {
  kind: AuditSignalKind;
  severity: AuditSeverity;
  detail: string;
}

export interface HarnessAuditSummary {
  harness: HarnessKind;
  totalRequests: number;
  telemetryEvents: number;
  bulkUploadEvents: number;
  sensitiveExfilEvents: number;
  outboundBytes: number;
  telemetryHosts: string[];
  uploadHosts: string[];
  purposeCounts?: Partial<Record<RequestPurpose, number>>;
}

export interface ObservedConnectHost {
  host: string;
  port: number;
  mitm: boolean;
  tlsFailed: boolean;
  riskKind?: HostRiskKind;
  purpose?: RequestPurpose;
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
  releaseNotesEn?: string | null;
  releaseNotesZh?: string | null;
  downloadUrl?: string | null;
  assetName?: string | null;
  assetSize?: number | null;
  sha256Url?: string | null;
}

export interface UpdateDownloadResult {
  version: string;
  fileName: string;
  filePath: string;
  bytes: number;
  sha256: string;
  verified: boolean;
  launched: boolean;
}

export interface TrafficSummary {
  id: string;
  timestamp: string;
  harness: HarnessKind;
  clientProcess?: string | null;
  category: TrafficCategory;
  purpose?: RequestPurpose;
  purposeConfidence?: number;
  purposeDetail?: string;
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
  auditSignals?: AuditSignal[];
  restoredCount: number;
  withheldCount: number;
}

export interface TrafficAuditRecord {
  id: string;
  timestamp: string;
  harness: HarnessKind;
  clientProcess?: string | null;
  category: TrafficCategory;
  purpose?: RequestPurpose;
  purposeConfidence?: number;
  purposeDetail?: string;
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
  auditSignals?: AuditSignal[];
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
  telemetryDetected?: number;
  bulkUploadDetected?: number;
  harnessAudit?: HarnessAuditSummary[];
}

export interface RuleValidation {
  valid: boolean;
  message?: string;
  matches?: string[];
}

export interface CompanionProcessInfo {
  pid: number;
  name: string;
  relation: 'child' | 'sibling' | string;
}

export interface RunningHarnessNotice {
  kind: HarnessKind;
  name: string;
  pids: number[];
  configured: boolean;
  hasTraffic: boolean;
  needsRestart: boolean;
  companions: CompanionProcessInfo[];
}

export interface PeerRelayInfo {
  port: number;
  processName?: string | null;
  pid?: number | null;
  status: 'chained' | 'overwrote-harness' | string;
  affectedHarnesses: HarnessKind[];
}

export interface ConflictAlert {
  id: string;
  source: 'peer-config' | 'live-payload' | string;
  peerName: string;
  pid?: number | null;
  port?: number | null;
  detail: string;
  canStopPeer: boolean;
}

export interface RuntimeHealthResponse {
  runningHarnesses: RunningHarnessNotice[];
  peerRelays: PeerRelayInfo[];
  conflicts: ConflictAlert[];
}

export type ConflictResolutionAction = 'stop-peer' | 'switch-hidego-audit' | 'dismiss';

export interface ConflictResolutionResult {
  ok: boolean;
  action: string;
  message: string;
}
