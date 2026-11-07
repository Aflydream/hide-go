import React, { useState } from 'react';
import {
  Search,
  Eye,
  EyeOff,
  Trash2,
  Plus,
  RefreshCw,
  ArrowRight,
} from 'lucide-react';
import { CustomRule, HideConfig, VaultEntry } from '../types';

export interface VaultInspectorProps {
  entries: VaultEntry[];
  config: HideConfig;
  onUpdateConfig: (next: HideConfig) => void;
  onClearVault: () => void;
}

export const VaultInspector: React.FC<VaultInspectorProps> = ({
  entries,
  config,
  onUpdateConfig,
  onClearVault,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [revealedTokens, setRevealedTokens] = useState<Record<string, boolean>>({});
  const [revealAll, setRevealAll] = useState(false);

  const [ruleName, setRuleName] = useState('');
  const [rulePattern, setRulePattern] = useState('');
  const [ruleReplacementHint, setRuleReplacementHint] = useState('');
  const [ruleError, setRuleError] = useState<string | null>(null);

  const toggleTokenReveal = (token: string) => {
    setRevealedTokens((prev) => ({
      ...prev,
      [token]: !prev[token],
    }));
  };

  const filteredEntries = entries.filter((entry) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      entry.token.toLowerCase().includes(q) ||
      entry.category.toLowerCase().includes(q) ||
      entry.originalMasked.toLowerCase().includes(q) ||
      entry.originalRaw.toLowerCase().includes(q)
    );
  });

  const handleAddRule = (e: React.FormEvent) => {
    e.preventDefault();
    setRuleError(null);

    const trimmedName = ruleName.trim();
    const trimmedPattern = rulePattern.trim();
    const trimmedHint = ruleReplacementHint.trim() || 'CUSTOM_ENTITY';

    if (!trimmedName || !trimmedPattern) {
      setRuleError('请填写规则名称与正则表达式。');
      return;
    }

    try {
      new RegExp(trimmedPattern);
    } catch {
      setRuleError('正则表达式语法无效，请检查括号或转义字符。');
      return;
    }

    const newRule: CustomRule = {
      id: `rule-${Date.now()}`,
      name: trimmedName,
      pattern: trimmedPattern,
      replacementHint: trimmedHint,
      enabled: true,
    };

    onUpdateConfig({
      ...config,
      customRules: [newRule, ...config.customRules],
    });

    setRuleName('');
    setRulePattern('');
    setRuleReplacementHint('');
  };

  const handleToggleRule = (id: string) => {
    onUpdateConfig({
      ...config,
      customRules: config.customRules.map((r) =>
        r.id === id ? { ...r, enabled: !r.enabled } : r
      ),
    });
  };

  const handleDeleteRule = (id: string) => {
    onUpdateConfig({
      ...config,
      customRules: config.customRules.filter((r) => r.id !== id),
    });
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 divide-y xl:divide-y-0 xl:divide-x divide-warm-200 min-h-[calc(100vh-4.5rem)]">
      {/* Left 7 Cols: Active In-Memory Dictionary */}
      <div className="xl:col-span-7 flex flex-col bg-paper">
        <div className="px-5 py-3 bg-warm-50/60 border-b border-warm-200 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <h2 className="text-xs font-semibold text-warm-900">
              进程内存映射表
            </h2>
            <span className="text-[11px] font-mono text-brand-dark bg-brand-soft px-2 py-0.5 rounded tabular-nums">
              {entries.length} 项
            </span>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search
                className="w-3.5 h-3.5 text-warm-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="搜索占位符或原值..."
                aria-label="搜索映射表"
                className="w-48 pl-8 pr-2.5 py-1 rounded-lg bg-paper border border-warm-200 text-xs text-warm-900 placeholder-warm-400 focus:outline-none focus:border-brand"
              />
            </div>

            <button
              type="button"
              onClick={() => setRevealAll((prev) => !prev)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-paper hover:bg-warm-100 text-warm-700 border border-warm-200 transition-colors cursor-pointer"
            >
              {revealAll ? (
                <>
                  <EyeOff className="w-3.5 h-3.5 text-warm-500" />
                  <span>隐藏明文</span>
                </>
              ) : (
                <>
                  <Eye className="w-3.5 h-3.5 text-warm-500" />
                  <span>显示明文</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={onClearVault}
              disabled={entries.length === 0}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-paper hover:bg-red-50 disabled:opacity-40 text-red-600 border border-warm-200 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>重置</span>
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 z-10 bg-warm-50 border-b border-warm-200">
              <tr className="text-[11px] font-medium text-warm-500 whitespace-nowrap">
                <th className="py-2.5 px-5">外发占位符 / 伪装词</th>
                <th className="py-2.5 px-4">本地真实值</th>
                <th className="py-2.5 px-3">分类</th>
                <th className="py-2.5 px-4 text-right">命中</th>
                <th className="py-2.5 px-5 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-warm-200/70 text-xs">
              {filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-warm-400">
                    暂无匹配的映射记录
                  </td>
                </tr>
              ) : (
                filteredEntries.map((entry) => {
                  const isRevealed = revealAll || !!revealedTokens[entry.token];
                  return (
                    <tr
                      key={entry.token}
                      className="hover:bg-warm-50/60 transition-colors"
                    >
                      <td className="py-2.5 px-5 font-mono font-semibold text-brand-dark break-all">
                        {entry.token}
                      </td>
                      <td className="py-2.5 px-4 font-mono whitespace-nowrap">
                        {isRevealed ? (
                          <span className="text-red-700 bg-red-50 px-2 py-0.5 rounded border border-red-200/80 break-all whitespace-normal">
                            {entry.originalRaw}
                          </span>
                        ) : (
                          <span className="text-warm-500">
                            {entry.originalMasked}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="text-[11px] text-warm-600 bg-warm-100 px-2 py-0.5 rounded">
                          {entry.category}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-right font-mono text-warm-700 tabular-nums whitespace-nowrap">
                        {entry.hitCount}
                      </td>
                      <td className="py-2.5 px-5 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => toggleTokenReveal(entry.token)}
                          className="text-xs text-warm-500 hover:text-warm-900 cursor-pointer"
                        >
                          {isRevealed ? '隐藏' : '查看'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Right 5 Cols: Custom Regex Rules */}
      <div className="xl:col-span-5 bg-warm-50/30 p-5 space-y-5">
        <div>
          <h3 className="text-xs font-semibold text-warm-900">
            自定义敏感词与正则规则 ({config.customRules.length})
          </h3>
          <p className="text-xs text-warm-500 mt-0.5">
            添加公司内部项目代号、私有仓库域名或特殊密钥前缀，匹配内容将自动进入左侧内存映射表。
          </p>
        </div>

        <form
          onSubmit={handleAddRule}
          className="bg-paper border border-warm-200 rounded-xl p-4 space-y-3 shadow-panel"
        >
          <div>
            <label
              htmlFor="custom-rule-name"
              className="block text-xs font-medium text-warm-700 mb-1"
            >
              规则名称
            </label>
            <input
              id="custom-rule-name"
              type="text"
              value={ruleName}
              onChange={(e) => setRuleName(e.target.value)}
              placeholder="例如：内部项目代号"
              className="w-full px-3 py-1.5 rounded-lg bg-warm-50/60 border border-warm-200 text-xs text-warm-900 placeholder-warm-400 focus:outline-none focus:bg-paper focus:border-brand"
            />
          </div>

          <div>
            <label
              htmlFor="custom-rule-pattern"
              className="block text-xs font-medium text-warm-700 mb-1"
            >
              正则表达式 (Regex)
            </label>
            <input
              id="custom-rule-pattern"
              type="text"
              value={rulePattern}
              onChange={(e) => setRulePattern(e.target.value)}
              placeholder="例如：ProjectChimera|chimera_[a-z0-9_]+"
              className="w-full px-3 py-1.5 rounded-lg bg-warm-50/60 border border-warm-200 font-mono text-xs text-warm-900 placeholder-warm-400 focus:outline-none focus:bg-paper focus:border-brand"
            />
          </div>

          <div>
            <label
              htmlFor="custom-rule-hint"
              className="block text-xs font-medium text-warm-700 mb-1"
            >
              替换词前缀
            </label>
            <div className="flex gap-2">
              <input
                id="custom-rule-hint"
                type="text"
                value={ruleReplacementHint}
                onChange={(e) => setRuleReplacementHint(e.target.value)}
                placeholder="例如：GreenhouseApp"
                className="w-full px-3 py-1.5 rounded-lg bg-warm-50/60 border border-warm-200 font-mono text-xs text-warm-900 placeholder-warm-400 focus:outline-none focus:bg-paper focus:border-brand"
              />
              <button
                type="submit"
                className="shrink-0 inline-flex items-center gap-1 px-3.5 py-1.5 rounded-lg text-xs font-medium bg-warm-900 hover:bg-warm-600 text-white transition-colors cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>添加</span>
              </button>
            </div>
          </div>

          {ruleError && (
            <div
              role="alert"
              className="text-xs text-red-700 bg-red-50 border border-red-200 px-3 py-2 rounded-lg"
            >
              {ruleError}
            </div>
          )}
        </form>

        <div className="space-y-2.5">
          {config.customRules.map((rule) => (
            <div
              key={rule.id}
              className={`p-3.5 rounded-xl border transition-colors ${
                rule.enabled
                  ? 'bg-paper border-warm-200 shadow-panel'
                  : 'bg-warm-100/50 border-warm-200/60 opacity-60'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-semibold text-warm-900">
                      {rule.name}
                    </span>
                    <ArrowRight className="w-3 h-3 text-warm-400" />
                    <span className="text-[11px] font-mono text-brand-dark bg-brand-soft px-2 py-0.5 rounded">
                      {rule.replacementHint}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-warm-500 mt-1 truncate">
                    /{rule.pattern}/g
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleToggleRule(rule.id)}
                    className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                      rule.enabled
                        ? 'bg-brand-soft text-brand-dark'
                        : 'bg-warm-200/70 text-warm-600'
                    }`}
                  >
                    {rule.enabled ? '已启用' : '已停用'}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDeleteRule(rule.id)}
                    aria-label={`删除规则 ${rule.name}`}
                    className="p-1 rounded-md text-warm-400 hover:text-red-600 hover:bg-red-50 transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default VaultInspector;
