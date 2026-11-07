import React, { useEffect, useState, useCallback } from 'react';
import {
  Activity,
  Sliders,
  Terminal,
  BookMarked,
  Eye,
  ShieldCheck,
  EyeOff,
} from 'lucide-react';
import {
  HarnessKind,
  HarnessProfile,
  HideConfig,
  PrivacyMode,
  TrafficAuditRecord,
  TrafficCategory,
  VaultEntry,
} from './types';
import { TrafficMonitor } from './components/TrafficMonitor';
import { HarnessManager } from './components/HarnessManager';
import { PrivacyModeSelector } from './components/PrivacyModeSelector';
import { VaultInspector } from './components/VaultInspector';
import { LOGO_ICON_DATA_URL, LOGO_WORDMARK_DATA_URL } from './logoAssets';

type TabKey = 'traffic' | 'privacy' | 'harnesses' | 'vault';

const DEFAULT_CONFIG: HideConfig = {
  proxyPort: 18787,
  mode: 'audit-only',
  allHide: {
    enableIsomorphicCamouflage: true,
    coverTheme: 'botanical-garden',
    enableCipherGarble: true,
    enableTelemetryChaff: true,
    strictLiteralMasking: true,
  },
  blockSilentTelemetry: true,
  protectProjectPaths: true,
  protectSecretsAndKeys: true,
  protectInternalNetwork: true,
  projectSalt: 'hide-go-quantum-salt-2026',
  customRules: [
    {
      id: 'rule-1',
      name: '核心项目代号',
      pattern: 'ProjectTitan|AflyCore|QuantumPay',
      replacementHint: 'GreenhouseApp',
      enabled: true,
    },
    {
      id: 'rule-2',
      name: '内部私有仓库域名',
      pattern: '[a-zA-Z0-9-]+\\.corp\\.internal',
      replacementHint: 'node-01.garden.example',
      enabled: true,
    },
  ],
};

function getApiHeaders(json = false): Record<string, string> {
  const headers: Record<string, string> = {};
  const winToken = (window as unknown as { __HIDE_GO_TOKEN__?: string }).__HIDE_GO_TOKEN__;
  const queryToken = new URLSearchParams(window.location.search).get('token');
  const token = winToken || queryToken || '';
  if (token) {
    headers['X-Hide-Go-Token'] = token;
  }
  if (json) {
    headers['Content-Type'] = 'application/json';
  }
  return headers;
}

export const App: React.FC = () => {
  const initialTab = (new URLSearchParams(window.location.search).get('tab') as TabKey) || 'traffic';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [config, setConfig] = useState<HideConfig>(DEFAULT_CONFIG);
  const [records, setRecords] = useState<TrafficAuditRecord[]>([]);
  const [harnesses, setHarnesses] = useState<HarnessProfile[]>([]);
  const [vaultEntries, setVaultEntries] = useState<VaultEntry[]>([]);
  const [backendConnected, setBackendConnected] = useState<boolean>(false);
  const [syncError, setSyncError] = useState<string | null>(null);

  const fetchAllState = useCallback(async () => {
    try {
      const reqInit: RequestInit = {
        headers: getApiHeaders(),
        credentials: 'same-origin',
      };
      const [cfgRes, logsRes, harnRes, vaultRes] = await Promise.all([
        fetch('/api/config', reqInit),
        fetch('/api/logs', reqInit),
        fetch('/api/harnesses', reqInit),
        fetch('/api/vault', reqInit),
      ]);
      if (cfgRes.ok && logsRes.ok && harnRes.ok && vaultRes.ok) {
        const [cfgData, logsData, harnData, vaultData] = await Promise.all([
          cfgRes.json(),
          logsRes.json(),
          harnRes.json(),
          vaultRes.json(),
        ]);
        setConfig(cfgData);
        setRecords(logsData);
        setHarnesses(harnData);
        setVaultEntries(vaultData);
        setBackendConnected(true);
      } else {
        setBackendConnected(false);
      }
    } catch {
      setBackendConnected(false);
    }
  }, []);

  useEffect(() => {
    fetchAllState();
    const timer = setInterval(fetchAllState, 3500);
    return () => clearInterval(timer);
  }, [fetchAllState]);

  const handleUpdateConfig = async (nextConfig: HideConfig) => {
    const previousConfig = config;
    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: getApiHeaders(true),
        credentials: 'same-origin',
        body: JSON.stringify(nextConfig),
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const updated = await res.json();
      setConfig(updated);
      setBackendConnected(true);
      setSyncError(null);
    } catch {
      // Roll back to confirmed backend config and display explicit error alert
      setConfig(previousConfig);
      setBackendConnected(false);
      setSyncError('保存失败：无法将保护配置同步至本地网关，界面已回滚为后端实际生效状态。');
      try {
        const actualRes = await fetch('/api/config', {
          headers: getApiHeaders(),
          credentials: 'same-origin',
        });
        if (actualRes.ok) {
          const actualCfg = await actualRes.json();
          setConfig(actualCfg);
          setBackendConnected(true);
        }
      } catch {
        // Gateway remains unreachable
      }
    }
  };

  const handleQuickModeChange = (mode: PrivacyMode) => {
    handleUpdateConfig({
      ...config,
      mode,
    });
  };

  const handleSimulate = async (
    harness: HarnessKind,
    category: TrafficCategory,
    customPayload?: string
  ) => {
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: getApiHeaders(true),
        credentials: 'same-origin',
        body: JSON.stringify({
          harness,
          category,
          customPayload: customPayload ?? null,
        }),
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      setSyncError(null);
      await fetchAllState();
      setActiveTab('traffic');
    } catch {
      setBackendConnected(false);
      setSyncError('模拟请求发送失败：本地代理网关未响应或未授权。');
    }
  };

  const handleClearLogs = async () => {
    try {
      const res = await fetch('/api/logs', {
        method: 'DELETE',
        headers: getApiHeaders(),
        credentials: 'same-origin',
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      await fetchAllState();
    } catch {
      setBackendConnected(false);
      setSyncError('清空日志失败：本地代理网关未响应。');
    }
  };

  const handleClearVault = async () => {
    try {
      const res = await fetch('/api/vault', {
        method: 'DELETE',
        headers: getApiHeaders(),
        credentials: 'same-origin',
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      await fetchAllState();
    } catch {
      setBackendConnected(false);
      setSyncError('清空词表失败：本地代理网关未响应。');
    }
  };

  const totalFindings = records.reduce((acc, r) => acc + r.findings.length, 0);
  const totalRestored = records.reduce((acc, r) => acc + r.restoredCount, 0);

  return (
    <div className="h-screen w-screen overflow-hidden bg-canvas text-warm-900 flex select-none p-2 gap-2">
      {/* Left Navigation Sidebar */}
      <aside className="w-52 shrink-0 flex flex-col justify-between px-2 py-2.5">
        <div className="space-y-5">
          {/* Brand Logo */}
          <div className="px-2.5 flex items-center gap-2.5">
            <img
              src={LOGO_ICON_DATA_URL}
              alt="HG"
              className="w-6 h-6 object-contain shrink-0"
            />
            <img
              src={LOGO_WORDMARK_DATA_URL}
              alt="Hide-Go"
              className="h-[18px] w-auto object-contain"
            />
          </div>

          {/* Primary Navigation */}
          <nav className="space-y-1" aria-label="主导航">
            <button
              type="button"
              onClick={() => setActiveTab('traffic')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-[13px] transition-all duration-150 cursor-pointer ${
                activeTab === 'traffic'
                  ? 'bg-paper text-warm-900 font-semibold shadow-pill ring-1 ring-warm-200/80'
                  : 'text-warm-600 hover:bg-warm-200/40 hover:text-warm-900'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Activity
                  className={`w-4 h-4 ${
                    activeTab === 'traffic' ? 'text-brand' : 'text-warm-500'
                  }`}
                />
                <span>抓包检视</span>
              </span>
              <span className="font-mono text-[11px] text-warm-500 tabular-nums">
                {records.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('privacy')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-[13px] transition-all duration-150 cursor-pointer ${
                activeTab === 'privacy'
                  ? 'bg-paper text-warm-900 font-semibold shadow-pill ring-1 ring-warm-200/80'
                  : 'text-warm-600 hover:bg-warm-200/40 hover:text-warm-900'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Sliders
                  className={`w-4 h-4 ${
                    activeTab === 'privacy' ? 'text-brand' : 'text-warm-500'
                  }`}
                />
                <span>隐私引擎</span>
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-brand" />
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('harnesses')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-[13px] transition-all duration-150 cursor-pointer ${
                activeTab === 'harnesses'
                  ? 'bg-paper text-warm-900 font-semibold shadow-pill ring-1 ring-warm-200/80'
                  : 'text-warm-600 hover:bg-warm-200/40 hover:text-warm-900'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Terminal
                  className={`w-4 h-4 ${
                    activeTab === 'harnesses' ? 'text-brand' : 'text-warm-500'
                  }`}
                />
                <span>工具接入</span>
              </span>
              <span className="font-mono text-[11px] text-warm-500 tabular-nums">
                {harnesses.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('vault')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-[13px] transition-all duration-150 cursor-pointer ${
                activeTab === 'vault'
                  ? 'bg-paper text-warm-900 font-semibold shadow-pill ring-1 ring-warm-200/80'
                  : 'text-warm-600 hover:bg-warm-200/40 hover:text-warm-900'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <BookMarked
                  className={`w-4 h-4 ${
                    activeTab === 'vault' ? 'text-brand' : 'text-warm-500'
                  }`}
                />
                <span>映射词表</span>
              </span>
              <span className="font-mono text-[11px] text-warm-500 tabular-nums">
                {vaultEntries.length}
              </span>
            </button>
          </nav>
        </div>

        {/* Bottom Gateway Card */}
        <div className="bg-warm-50/90 border border-warm-200/90 rounded-xl p-3 space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${
                  backendConnected ? 'bg-brand' : 'bg-amber-500'
                }`}
              />
              <span className="text-xs font-medium text-warm-900">
                {backendConnected ? '本地网关就绪' : '正在连接网关'}
              </span>
            </div>
            <span className="text-[11px] font-mono text-warm-500 tabular-nums">
              :{config.proxyPort}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-warm-200/70">
            <div>
              <div className="text-[11px] text-warm-500">已过滤敏感项</div>
              <div className="text-sm font-mono font-semibold text-warm-900 tabular-nums mt-0.5">
                {totalFindings}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-warm-500">流式无损还原</div>
              <div className="text-sm font-mono font-semibold text-brand-dark tabular-nums mt-0.5">
                {totalRestored}
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Recessed Window Surface */}
      <div className="flex-1 bg-paper rounded-xl border border-warm-200 shadow-panel flex flex-col min-w-0 overflow-hidden">
        {/* Window Top Header */}
        <header className="h-12 shrink-0 px-5 border-b border-warm-200 flex items-center justify-between gap-4 bg-paper">
          <div className="flex items-center gap-3">
            <h1 className="text-[14px] font-semibold text-warm-900">
              {activeTab === 'traffic' && '抓包检视'}
              {activeTab === 'privacy' && '隐私引擎'}
              {activeTab === 'harnesses' && '工具接入'}
              {activeTab === 'vault' && '映射词表'}
            </h1>
            <span className="text-xs text-warm-500 hidden md:inline">
              {activeTab === 'traffic' && '实时比对本地发送载荷与云端模型实际接收内容'}
              {activeTab === 'privacy' && '配置出站脱敏等级、All-Hide 伪装词库与扫描规则'}
              {activeTab === 'harnesses' && '查看各 AI 编程客户端的本地代理地址与环境变量'}
              {activeTab === 'vault' && '检视当前驻留内存的占位符映射关系与自定义正则'}
            </span>
          </div>

          {/* Native-style Segmented Mode Control */}
          <div
            role="group"
            aria-label="全局隐私模式"
            className="inline-flex items-center bg-warm-100 p-0.5 rounded-lg border border-warm-200"
          >
            <button
              type="button"
              onClick={() => handleQuickModeChange('audit-only')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs transition-all duration-150 cursor-pointer ${
                config.mode === 'audit-only'
                  ? 'bg-paper text-warm-900 font-medium shadow-pill'
                  : 'text-warm-600 hover:text-warm-900'
              }`}
            >
              <Eye className="w-3.5 h-3.5 text-warm-500" />
              仅审计
            </button>
            <button
              type="button"
              onClick={() => handleQuickModeChange('auto-desensitize')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs transition-all duration-150 cursor-pointer ${
                config.mode === 'auto-desensitize'
                  ? 'bg-paper text-brand-dark font-semibold shadow-pill'
                  : 'text-warm-600 hover:text-warm-900'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5 text-brand" />
              自动脱敏
            </button>
            <button
              type="button"
              onClick={() => handleQuickModeChange('all-hide')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs transition-all duration-150 cursor-pointer ${
                config.mode === 'all-hide'
                  ? 'bg-warm-900 text-white font-medium shadow-pill'
                  : 'text-warm-600 hover:text-warm-900'
              }`}
            >
              <EyeOff className="w-3.5 h-3.5" />
              All-Hide
            </button>
          </div>
        </header>

        {syncError && (
          <div
            role="alert"
            className="shrink-0 px-5 py-2.5 bg-danger-bg border-b border-danger-border flex items-center justify-between gap-4 text-xs text-danger-text"
          >
            <span className="font-medium">{syncError}</span>
            <button
              type="button"
              onClick={() => setSyncError(null)}
              className="px-2 py-0.5 rounded border border-danger-border/60 hover:bg-paper/60 text-[11px] cursor-pointer"
            >
              关闭
            </button>
          </div>
        )}

        {/* Main View Content */}
        <main className="flex-1 min-h-0 overflow-y-auto">
          {activeTab === 'traffic' && (
            <TrafficMonitor
              records={records}
              currentMode={config.mode}
              onSimulate={handleSimulate}
              onClearLogs={handleClearLogs}
            />
          )}

          {activeTab === 'privacy' && (
            <PrivacyModeSelector
              config={config}
              onUpdateConfig={handleUpdateConfig}
            />
          )}

          {activeTab === 'harnesses' && (
            <HarnessManager
              profiles={harnesses}
              proxyPort={config.proxyPort}
              onSimulateHarness={(harness, category) =>
                handleSimulate(harness, category)
              }
            />
          )}

          {activeTab === 'vault' && (
            <VaultInspector
              entries={vaultEntries}
              config={config}
              onUpdateConfig={handleUpdateConfig}
              onClearVault={handleClearVault}
            />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
