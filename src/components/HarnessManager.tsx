import React, { useState } from 'react';
import {
  Copy,
  Check,
  Play,
  ArrowRight,
} from 'lucide-react';
import { HarnessKind, HarnessProfile, TrafficCategory } from '../types';

export interface HarnessManagerProps {
  profiles: HarnessProfile[];
  proxyPort: number;
  onSimulateHarness: (harness: HarnessKind, category: TrafficCategory) => void;
}

export const HarnessManager: React.FC<HarnessManagerProps> = ({
  profiles,
  proxyPort,
  onSimulateHarness,
}) => {
  const [selectedKind, setSelectedKind] = useState<HarnessKind>(
    profiles[0]?.kind ?? 'claude-code'
  );
  const [activeOs, setActiveOs] = useState<'bash' | 'powershell'>('bash');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const selectedProfile =
    profiles.find((p) => p.kind === selectedKind) ?? profiles[0] ?? null;

  const handleCopy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    setCopiedKey(key);
    window.setTimeout(() => {
      setCopiedKey((prev) => (prev === key ? null : prev));
    }, 2000);
  };

  return (
    <div className="flex h-full min-h-[calc(100vh-4.5rem)] divide-x divide-warm-200">
      {/* Left Client List (280px) */}
      <div className="w-72 shrink-0 bg-warm-50/40 flex flex-col">
        <div className="px-4 py-3 border-b border-warm-200 flex items-center justify-between">
          <span className="text-xs font-medium text-warm-600">
            支持的客户端 ({profiles.length})
          </span>
          <span className="text-[11px] font-mono text-brand-dark bg-brand-soft px-2 py-0.5 rounded">
            :{proxyPort}
          </span>
        </div>

        <div className="divide-y divide-warm-200/60 overflow-y-auto flex-1">
          {profiles.map((p) => {
            const isSelected = selectedProfile?.kind === p.kind;
            return (
              <button
                key={p.kind}
                type="button"
                onClick={() => setSelectedKind(p.kind)}
                className={`w-full text-left px-4 py-3.5 transition-colors duration-150 flex items-center justify-between gap-2 cursor-pointer relative ${
                  isSelected ? 'bg-paper shadow-pill z-10' : 'hover:bg-warm-100/60'
                }`}
              >
                {isSelected && (
                  <span className="absolute left-0 top-2.5 bottom-2.5 w-1 bg-brand rounded-r" />
                )}
                <div className="min-w-0">
                  <div className="text-[13px] font-semibold text-warm-900 truncate">
                    {p.name}
                  </div>
                  <div className="text-[11px] text-warm-500 truncate mt-0.5">
                    {p.vendorName}
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-1.5">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      p.detectedActive ? 'bg-brand' : 'bg-warm-300'
                    }`}
                  />
                  <span className="text-[11px] text-warm-500">
                    {p.detectedActive ? '在线' : '待命'}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right Selected Client Workbench */}
      <div className="flex-1 bg-paper p-6 overflow-y-auto">
        {selectedProfile ? (
          <div className="max-w-3xl space-y-6">
            {/* Client Title & Simulation Actions */}
            <div className="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-warm-200">
              <div className="space-y-1">
                <div className="flex items-center gap-2.5">
                  <h2 className="text-lg font-semibold text-warm-900">
                    {selectedProfile.name}
                  </h2>
                  <span className="text-xs px-2 py-0.5 rounded bg-warm-100 text-warm-600">
                    {selectedProfile.vendorName}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-warm-100 text-warm-600">
                    {selectedProfile.protocolFamily}
                  </span>
                </div>
                <p className="text-xs text-warm-500 leading-relaxed">
                  {selectedProfile.description}
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    onSimulateHarness(selectedProfile.kind, 'interactive-prompt')
                  }
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-warm-900 hover:bg-warm-600 text-white transition-colors cursor-pointer"
                >
                  <Play className="w-3 h-3" />
                  模拟对话请求
                </button>
                <button
                  type="button"
                  onClick={() =>
                    onSimulateHarness(selectedProfile.kind, 'codebase-indexing')
                  }
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-warm-100 hover:bg-warm-200 text-warm-900 transition-colors cursor-pointer"
                >
                  <Play className="w-3 h-3 text-warm-600" />
                  模拟后台索引
                </button>
              </div>
            </div>

            {/* Proxy Route Mapping Box */}
            <div className="space-y-2">
              <label className="block text-xs font-semibold text-warm-900">
                本地网关转发路由
              </label>
              <div className="bg-warm-50/80 border border-warm-200 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3 font-mono text-xs min-w-0">
                  <div>
                    <div className="text-[11px] font-sans text-warm-500">本地代理入口</div>
                    <div className="text-brand-dark font-semibold mt-0.5">
                      {selectedProfile.localProxyRoute.replace(
                        /:18787\b/,
                        `:${proxyPort}`
                      )}
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-warm-400 shrink-0" />
                  <div className="min-w-0">
                    <div className="text-[11px] font-sans text-warm-500">上游厂商地址</div>
                    <div className="text-warm-700 truncate mt-0.5">
                      {selectedProfile.defaultUpstream}
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() =>
                    handleCopy(
                      selectedProfile.localProxyRoute.replace(
                        /:18787\b/,
                        `:${proxyPort}`
                      ),
                      `route-${selectedProfile.kind}`
                    )
                  }
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-paper hover:bg-warm-100 text-warm-900 border border-warm-200 shadow-pill transition-colors cursor-pointer"
                >
                  {copiedKey === `route-${selectedProfile.kind}` ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-brand" />
                      <span className="text-brand-dark">已复制地址</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-warm-500" />
                      <span>复制代理地址</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Terminal Setup Block */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-warm-900">
                  终端环境变量一键注入
                </label>
                <div className="inline-flex bg-warm-100 p-0.5 rounded-lg border border-warm-200">
                  <button
                    type="button"
                    onClick={() => setActiveOs('bash')}
                    className={`px-2.5 py-1 rounded-md text-xs transition-all cursor-pointer ${
                      activeOs === 'bash'
                        ? 'bg-paper text-warm-900 font-medium shadow-pill'
                        : 'text-warm-600 hover:text-warm-900'
                    }`}
                  >
                    macOS / Linux (Bash/Zsh)
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveOs('powershell')}
                    className={`px-2.5 py-1 rounded-md text-xs transition-all cursor-pointer ${
                      activeOs === 'powershell'
                        ? 'bg-paper text-warm-900 font-medium shadow-pill'
                        : 'text-warm-600 hover:text-warm-900'
                    }`}
                  >
                    Windows (PowerShell)
                  </button>
                </div>
              </div>

              <div className="bg-warm-900 text-warm-50 rounded-xl overflow-hidden border border-warm-900">
                <div className="px-4 py-2 bg-white/5 border-b border-white/10 flex items-center justify-between">
                  <span className="text-[11px] font-mono text-warm-300">
                    在启动 {selectedProfile.name} 前于终端执行以下命令
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      const snippet = (
                        activeOs === 'bash'
                          ? selectedProfile.envSetupBash
                          : selectedProfile.envSetupPowershell
                      ).replace(/:18787\b/g, `:${proxyPort}`);
                      handleCopy(snippet, `env-${selectedProfile.kind}`);
                    }}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-white/10 hover:bg-white/20 text-white transition-colors cursor-pointer"
                  >
                    {copiedKey === `env-${selectedProfile.kind}` ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-brand" />
                        <span>已复制命令</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-warm-300" />
                        <span>复制命令</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-4 text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed select-all">
                  <code>
                    {(activeOs === 'bash'
                      ? selectedProfile.envSetupBash
                      : selectedProfile.envSetupPowershell
                    ).replace(/:18787\b/g, `:${proxyPort}`)}
                  </code>
                </pre>
              </div>
            </div>

            {/* Data Footprint */}
            <div className="space-y-2">
              <label className="block text-xs font-semibold text-warm-900">
                该客户端默认采集与上传的数据范围
              </label>
              <div className="bg-warm-50/70 border border-warm-200 rounded-xl divide-y divide-warm-200">
                {selectedProfile.riskSummary.map((risk, idx) => (
                  <div
                    key={idx}
                    className="px-4 py-3 flex items-center gap-3 text-xs text-warm-600"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0" />
                    <span>{risk}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};

export default HarnessManager;
