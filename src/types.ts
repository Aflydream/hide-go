export type HarnessKind =
  | 'claude-code'
  | 'codex'
  | 'antigravity'
  | 'zcode'
  | 'qoder'
  | 'cursor'
  | 'grok-build'
  | 'generic';

export type TrafficCategory =
  | 'interactive-prompt'
  | 'codebase-indexing'
  | 'telemetry'
  | 'tool-execution-sync';

export type PrivacyMode = 'audit-only' | 'auto-desensitize' | 'all-hide';

export type CoverTheme =
  | 'botanical-garden'
  | 'library-catalog'
  | 'bakery-recipe';

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
  severity: 'critical' | 'high' | 'medium' | 'low';
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
  customRules: CustomRule[];
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
  latencyMs: number;
  localRequestPayload: string;
  vendorVisiblePayload: string;
  vendorRawResponse: string;
  localRestoredResponse: string;
  findings: LeakFinding[];
  restoredCount: number;
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
  detectedActive: boolean;
}

export interface VaultEntry {
  token: string;
  originalMasked: string;
  originalRaw: string;
  category: string;
  hitCount: number;
}
