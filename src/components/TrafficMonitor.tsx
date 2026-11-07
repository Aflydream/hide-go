import React, { useState } from 'react';
import {
  ArrowRight,
  Trash2,
  Send,
  ChevronDown,
} from 'lucide-react';
import {
  HarnessKind,
  TrafficAuditRecord,
  TrafficCategory,
  PrivacyMode,
} from '../types';

interface TrafficMonitorProps {
  records: TrafficAuditRecord[];
  currentMode: PrivacyMode;
  onSimulate: (
    harness: HarnessKind,
    category: TrafficCategory,
    customPayload?: string
  ) => void;
  onClearLogs: () => void;
}

const HARNESS_OPTIONS: { value: HarnessKind; label: string }[] = [
  { value: 'claude-code', label: 'Claude Code' },
  { value: 'codex', label: 'OpenAI Codex' },
  { value: 'antigravity', label: 'Antigravity' },
  { value: 'zcode', label: 'ZCode' },
  { value: 'qoder', label: 'Qoder' },
  { value: 'cursor', label: 'Cursor' },
  { value: 'grok-build', label: 'Grok Build' },
];

const CATEGORY_OPTIONS: { value: TrafficCategory; label: string }[] = [
  { value: 'interactive-prompt', label: '对话与代码推理' },
  { value: 'codebase-indexing', label: '后台代码索引' },
  { value: 'telemetry', label: '静默遥测上报' },
  { value: 'tool-execution-sync', label: '工具执行回传' },
];

export const TrafficMonitor: React.FC<TrafficMonitorProps> = ({
  records,
  onSimulate,
  onClearLogs,
}) => {
  const [selectedId, setSelectedId] = useState<string | null>(
    records[0]?.id ?? null
  );
  const [directionTab, setDirectionTab] = useState<'outbound' | 'inbound'>('outbound');
  const [simHarness, setSimHarness] = useState<HarnessKind>('claude-code');
  const [simCategory, setSimCategory] =
    useState<TrafficCategory>('interactive-prompt');
  const [customInput, setCustomInput] = useState<string>('');
  const [showCustomSandbox, setShowCustomSandbox] = useState<boolean>(false);

  const activeRecord =
    records.find((r) => r.id === selectedId) ?? records[0] ?? null;

  const renderStatusBadge = (mode: PrivacyMode, actionTaken: string) => {
    if (actionTaken === 'chaff-injected') {
      return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-amber-800 bg-amber-50 px-2 py-0.5 rounded-md border border-amber-200/80">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
          噪音替换
        </span>
      );
    }
    if (mode === 'all-hide') {
      return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-white bg-warm-900 px-2 py-0.5 rounded-md">
          <span className="w-1.5 h-1.5 rounded-full bg-brand" />
          All-Hide
        </span>
      );
    }
    if (mode === 'auto-desensitize') {
      return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-brand-dark bg-brand-soft px-2 py-0.5 rounded-md border border-brand/20">
          <span className="w-1.5 h-1.5 rounded-full bg-brand" />
          已脱敏
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-warm-600 bg-warm-100 px-2 py-0.5 rounded-md">
        <span className="w-1.5 h-1.5 rounded-full bg-warm-400" />
        透传审计
      </span>
    );
  };

  return (
    <div className="flex flex-col h-full">
      {/* Top Replay Toolbar */}
      <div className="shrink-0 bg-warm-50/70 border-b border-warm-200 px-5 py-2.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <select
              aria-label="选择模拟客户端"
              value={simHarness}
              onChange={(e) => setSimHarness(e.target.value as HarnessKind)}
              className="bg-paper border border-warm-200 rounded-lg px-2.5 py-1.5 text-xs font-medium text-warm-900 focus:outline-none focus:border-brand cursor-pointer"
            >
              {HARNESS_OPTIONS.map((h) => (
                <option key={h.value} value={h.value}>
                  {h.label}
                </option>
              ))}
            </select>

            <select
              aria-label="选择流量类型"
              value={simCategory}
              onChange={(e) => setSimCategory(e.target.value as TrafficCategory)}
              className="bg-paper border border-warm-200 rounded-lg px-2.5 py-1.5 text-xs text-warm-900 focus:outline-none focus:border-brand cursor-pointer"
            >
              {CATEGORY_OPTIONS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>

            <button
              type="button"
              onClick={() =>
                onSimulate(
                  simHarness,
                  simCategory,
                  customInput.trim() ? customInput : undefined
                )
              }
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-warm-900 hover:bg-warm-600 text-white transition-colors duration-150 cursor-pointer"
            >
              <Send className="w-3 h-3" />
              模拟请求
            </button>

            <button
              type="button"
              onClick={() => setShowCustomSandbox((v) => !v)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs text-warm-600 hover:text-warm-900 hover:bg-warm-200/50 transition-colors duration-150 cursor-pointer"
            >
              <span>自定义载荷</span>
              <ChevronDown
                className={`w-3.5 h-3.5 transition-transform ${
                  showCustomSandbox ? 'rotate-180' : ''
                }`}
              />
            </button>
          </div>

          <button
            type="button"
            onClick={onClearLogs}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs text-warm-500 hover:text-red-600 hover:bg-red-50 transition-colors duration-150 cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            清空记录
          </button>
        </div>

        {showCustomSandbox && (
          <div className="mt-2.5 pt-2.5 border-t border-warm-200/80">
            <textarea
              rows={3}
              value={customInput}
              onChange={(e) => setCustomInput(e.target.value)}
              placeholder={`粘贴包含密钥、内网地址或业务代码的请求内容...\npub fn execute_quantum_settlement(api_key: &str) {\n    let db = "postgres://admin:RealSecret123@10.16.88.9:5432/prod_vault";\n}`}
              className="w-full bg-paper border border-warm-200 rounded-lg p-2.5 text-xs font-mono text-warm-900 focus:outline-none focus:border-brand"
            />
          </div>
        )}
      </div>

      {/* Master-Detail Split View */}
      <div className="flex-1 flex min-h-0 divide-x divide-warm-200">
        {/* Left Request Stream (330px fixed width on desktop) */}
        <div className="w-80 xl:w-96 shrink-0 flex flex-col min-h-0 bg-warm-50/30">
          <div className="px-4 py-2 border-b border-warm-200 flex items-center justify-between text-[11px] text-warm-500">
            <span>捕获会话 ({records.length})</span>
            <span className="font-mono">脱敏项 / 还原项</span>
          </div>

          <div className="divide-y divide-warm-200/70 overflow-y-auto flex-1">
            {records.length === 0 ? (
              <div className="p-8 text-center text-warm-400 text-xs">
                暂无请求，点击左上方「模拟请求」体验实时脱敏
              </div>
            ) : (
              records.map((rec) => {
                const isSelected = activeRecord?.id === rec.id;
                return (
                  <button
                    key={rec.id}
                    type="button"
                    onClick={() => setSelectedId(rec.id)}
                    className={`w-full text-left px-4 py-3 transition-colors duration-150 flex flex-col gap-1.5 cursor-pointer relative ${
                      isSelected
                        ? 'bg-paper shadow-pill z-10'
                        : 'hover:bg-warm-100/50'
                    }`}
                  >
                    {isSelected && (
                      <span className="absolute left-0 top-2 bottom-2 w-1 bg-brand rounded-r" />
                    )}

                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-[13px] font-semibold text-warm-900 truncate">
                          {rec.harness}
                        </span>
                        <span className="text-[11px] font-mono text-warm-400 tabular-nums">
                          {rec.latencyMs}ms
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-warm-400 tabular-nums shrink-0">
                        {rec.timestamp.split(' ')[0]}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-warm-500 truncate">
                      {rec.method} {rec.endpoint}
                    </div>

                    <div className="flex items-center justify-between gap-2 pt-0.5">
                      {renderStatusBadge(rec.appliedMode, rec.actionTaken)}
                      <div className="text-[11px] font-mono tabular-nums">
                        <span className="text-warm-600">
                          脱敏 <strong className="text-warm-900">{rec.findings.length}</strong>
                        </span>
                        <span className="text-warm-300 mx-1.5">·</span>
                        <span className="text-brand-dark">
                          还原 <strong>{rec.restoredCount}</strong>
                        </span>
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right Detail Workbench */}
        <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-paper">
          {activeRecord ? (
            <>
              {/* Inspector Header & Direction Switcher */}
              <div className="px-5 py-3 border-b border-warm-200 flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2.5">
                    <span className="text-sm font-semibold text-warm-900">
                      {activeRecord.harness}
                    </span>
                    <ArrowRight className="w-3.5 h-3.5 text-warm-400" />
                    <span className="text-xs font-mono text-warm-600">
                      {activeRecord.upstreamVendor}
                    </span>
                    {renderStatusBadge(activeRecord.appliedMode, activeRecord.actionTaken)}
                  </div>
                  <div className="text-xs font-mono text-warm-400 mt-0.5 truncate">
                    {activeRecord.method} {activeRecord.endpoint} ({activeRecord.category})
                  </div>
                </div>

                {/* Outbound vs Inbound Segmented Switcher */}
                <div className="inline-flex bg-warm-100 p-0.5 rounded-lg border border-warm-200">
                  <button
                    type="button"
                    onClick={() => setDirectionTab('outbound')}
                    className={`px-3 py-1 rounded-md text-xs transition-all duration-150 cursor-pointer ${
                      directionTab === 'outbound'
                        ? 'bg-paper text-warm-900 font-semibold shadow-pill'
                        : 'text-warm-600 hover:text-warm-900'
                    }`}
                  >
                    出站请求对比 (本机 → 厂商)
                  </button>
                  <button
                    type="button"
                    onClick={() => setDirectionTab('inbound')}
                    className={`px-3 py-1 rounded-md text-xs transition-all duration-150 cursor-pointer ${
                      directionTab === 'inbound'
                        ? 'bg-paper text-warm-900 font-semibold shadow-pill'
                        : 'text-warm-600 hover:text-warm-900'
                    }`}
                  >
                    入站响应还原 (云端 → 本机 · {activeRecord.restoredCount})
                  </button>
                </div>
              </div>

              {/* Rewritten Entities Strip */}
              {activeRecord.findings.length > 0 && (
                <div className="px-5 py-2.5 bg-warm-50/70 border-b border-warm-200 flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] font-medium text-warm-500 mr-1">
                    本次替换 ({activeRecord.findings.length}):
                  </span>
                  {activeRecord.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-paper border border-warm-200 text-xs font-mono"
                    >
                      <span className="font-sans text-[11px] text-warm-500">
                        {f.label}
                      </span>
                      <code className="text-red-600 line-through text-[11px]">
                        {f.originalPreview}
                      </code>
                      <ArrowRight className="w-3 h-3 text-warm-400" />
                      <code className="text-brand-dark font-semibold text-[11px]">
                        {f.replacementToken}
                      </code>
                    </div>
                  ))}
                </div>
              )}

              {/* Full-Height Dual Code Diff Editor */}
              {directionTab === 'outbound' ? (
                <div className="flex-1 grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-warm-200 min-h-0">
                  <div className="flex flex-col min-h-0">
                    <div className="px-4 py-2 bg-warm-50/50 border-b border-warm-200 flex items-center justify-between">
                      <span className="text-xs font-medium text-warm-900">
                        本地客户端原始发送
                      </span>
                      <span className="text-[11px] text-warm-500">
                        包含真实密钥与路径 · 未出本机
                      </span>
                    </div>
                    <pre className="p-4 text-xs font-mono text-warm-900 overflow-y-auto whitespace-pre-wrap break-all flex-1 bg-paper leading-relaxed select-text">
                      {activeRecord.localRequestPayload}
                    </pre>
                  </div>

                  <div className="flex flex-col min-h-0">
                    <div className="px-4 py-2 bg-brand-soft/60 border-b border-warm-200 flex items-center justify-between">
                      <span className="text-xs font-semibold text-brand-dark">
                        大模型厂商实际收到
                      </span>
                      <span className="text-[11px] text-brand-dark font-mono">
                        {activeRecord.appliedMode === 'all-hide'
                          ? 'All-Hide 同构伪装 / 乱码'
                          : activeRecord.appliedMode === 'auto-desensitize'
                          ? '敏感项已替换为占位符'
                          : '原样透传'}
                      </span>
                    </div>
                    <pre className="p-4 text-xs font-mono text-warm-900 overflow-y-auto whitespace-pre-wrap break-all flex-1 bg-brand-soft/15 leading-relaxed select-text">
                      {activeRecord.vendorVisiblePayload}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="flex-1 grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-warm-200 min-h-0">
                  <div className="flex flex-col min-h-0">
                    <div className="px-4 py-2 bg-warm-50/50 border-b border-warm-200 flex items-center justify-between">
                      <span className="text-xs font-medium text-warm-900">
                        云端模型原始返回流 (SSE)
                      </span>
                      <span className="text-[11px] text-warm-500">
                        模型基于占位符/伪装词生成的响应
                      </span>
                    </div>
                    <pre className="p-4 text-xs font-mono text-warm-600 overflow-y-auto whitespace-pre-wrap break-all flex-1 bg-paper leading-relaxed select-text">
                      {activeRecord.vendorRawResponse}
                    </pre>
                  </div>

                  <div className="flex flex-col min-h-0">
                    <div className="px-4 py-2 bg-brand-soft/60 border-b border-warm-200 flex items-center justify-between">
                      <span className="text-xs font-semibold text-brand-dark">
                        本地客户端最终接收
                      </span>
                      <span className="text-[11px] text-brand-dark font-mono">
                        已实时还原 {activeRecord.restoredCount} 处真实符号
                      </span>
                    </div>
                    <pre className="p-4 text-xs font-mono text-warm-900 overflow-y-auto whitespace-pre-wrap break-all flex-1 bg-brand-soft/15 leading-relaxed select-text">
                      {activeRecord.localRestoredResponse}
                    </pre>
                  </div>
                </div>
              )}
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
};
