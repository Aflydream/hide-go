import React from 'react';
import { CoverTheme, HideConfig, PrivacyMode } from '../types';

export interface PrivacyModeSelectorProps {
  config: HideConfig;
  onUpdateConfig: (next: HideConfig) => void;
}

const MODE_OPTIONS: Array<{
  mode: PrivacyMode;
  title: string;
  tagline: string;
  description: string;
  localSample: string;
  vendorSample: string;
}> = [
  {
    mode: 'audit-only',
    title: '仅审计 (Audit Only)',
    tagline: '记录客户端上传行为，不改动任何代码或提示词',
    description:
      '旁路嗅探 Claude Code、Cursor 等客户端在后台上传了哪些文件与环境变量，原样转发给服务商。适合首次排查数据暴露范围。',
    localSample: 'let db = "postgres://admin:Sec99@10.16.8.9/vault";',
    vendorSample: 'let db = "postgres://admin:Sec99@10.16.8.9/vault";',
  },
  {
    mode: 'auto-desensitize',
    title: '自动双向脱敏 (Semantic Masking)',
    tagline: '保留完整代码逻辑，敏感字面量与密钥零出境',
    description:
      '自动将密钥、内网 IP、本机路径与私有代号替换为同类型占位符；模型照常完成推理，SSE 流式响应返回本地时自动还原为真实值。',
    localSample: 'let db = "postgres://admin:Sec99@10.16.8.9/vault";',
    vendorSample: 'let db = "postgres://db_user_01:pass_01@10.254.0.2/schema_01";',
  },
  {
    mode: 'all-hide',
    title: 'All-Hide 深度伪装',
    tagline: '同构伪装领域代码 + 高熵乱码 + 索引噪音投喂',
    description:
      '将业务类名、函数名同构映射为无关的日常生活脚本（如温室浇水、烘焙配方），敏感注释编码为乱码，并对后台全量代码索引返回诱饵代码。',
    localSample: 'OrderRiskEngine::verify_margin(wallet_secret)',
    vendorSample: 'OrchidMistController::adjust_humidity([[CIPHER:7A9E]])',
  },
];

const COVER_THEMES: Array<{
  id: CoverTheme;
  name: string;
  desc: string;
  beforeAfter: string;
}> = [
  {
    id: 'botanical-garden',
    name: '植物园温室',
    desc: '将核心算法与交易鉴权映射为温室灌溉、土壤湿度调节与兰花养护',
    beforeAfter: 'OrderRiskEngine.checkMargin() → OrchidMistController.adjustSoilHumidity()',
  },
  {
    id: 'library-catalog',
    name: '图书馆借阅',
    desc: '将微服务与数据库读写映射为索书号检索、借阅登记与归档流程',
    beforeAfter: 'PaymentLedger.commitTx() → ArchiveShelfIndex.registerLoanSlip()',
  },
  {
    id: 'bakery-recipe',
    name: '烘焙坊温控',
    desc: '将量化策略与加密签名映射为酸面团发酵、烤箱蒸汽与温控曲线',
    beforeAfter: 'CryptoSigner.deriveHmac() → SourdoughOven.calibrateSteamCurve()',
  },
];

interface SwitchProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
}

const NativeSwitch: React.FC<SwitchProps> = ({ checked, onChange, label }) => (
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    aria-label={label}
    onClick={() => onChange(!checked)}
    className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-150 focus:outline-none ${
      checked ? 'bg-brand' : 'bg-warm-300'
    }`}
  >
    <span
      className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition duration-150 ${
        checked ? 'translate-x-4' : 'translate-x-0'
      }`}
    />
  </button>
);

export const PrivacyModeSelector: React.FC<PrivacyModeSelectorProps> = ({
  config,
  onUpdateConfig,
}) => {
  const handleSelectMode = (mode: PrivacyMode) => {
    onUpdateConfig({ ...config, mode });
  };

  const handleToggleAllHideField = (
    field: keyof HideConfig['allHide'],
    value: boolean | CoverTheme
  ) => {
    onUpdateConfig({
      ...config,
      allHide: {
        ...config.allHide,
        [field]: value,
      },
    });
  };

  const handleToggleCoreRule = (
    field:
      | 'protectSecretsAndKeys'
      | 'protectProjectPaths'
      | 'protectInternalNetwork'
      | 'blockSilentTelemetry',
    value: boolean
  ) => {
    onUpdateConfig({
      ...config,
      [field]: value,
    });
  };

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-8">
      {/* Group 1: Two-Column Mode Selector */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-4 space-y-1.5">
          <h2 className="text-sm font-semibold text-warm-900">
            处理模式
          </h2>
          <p className="text-xs text-warm-500 leading-relaxed">
            决定本地网关如何改写出站请求。切换后对所有已接入客户端立即生效，无需重启终端。
          </p>
        </div>

        <div
          role="radiogroup"
          aria-label="处理模式"
          className="lg:col-span-8 bg-warm-50/70 border border-warm-200 rounded-xl divide-y divide-warm-200 overflow-hidden"
        >
          {MODE_OPTIONS.map((opt) => {
            const isSelected = config.mode === opt.mode;
            return (
              <div
                key={opt.mode}
                onClick={() => handleSelectMode(opt.mode)}
                role="radio"
                aria-checked={isSelected}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    handleSelectMode(opt.mode);
                  }
                }}
                className={`p-4 transition-colors duration-150 cursor-pointer ${
                  isSelected ? 'bg-paper' : 'hover:bg-paper/60'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <span
                      className={`mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center shrink-0 ${
                        isSelected
                          ? 'border-brand bg-brand'
                          : 'border-warm-400 bg-paper'
                      }`}
                    >
                      {isSelected && (
                        <span className="w-1.5 h-1.5 rounded-full bg-white" />
                      )}
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-[13px] font-semibold text-warm-900">
                          {opt.title}
                        </span>
                        {isSelected && (
                          <span className="text-[11px] font-medium text-brand-dark bg-brand-soft px-2 py-0.5 rounded">
                            当前使用
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-warm-600 mt-0.5">
                        {opt.tagline}
                      </p>
                      <p className="text-xs text-warm-500 mt-1.5 leading-relaxed">
                        {opt.description}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Inline Transformation Preview */}
                <div className="mt-3 ml-7 grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono bg-warm-50 border border-warm-200/80 rounded-lg p-2.5">
                  <div className="truncate">
                    <span className="text-warm-400 mr-1.5">本地:</span>
                    <span className="text-warm-800">{opt.localSample}</span>
                  </div>
                  <div className="truncate">
                    <span className="text-brand-dark mr-1.5">外发:</span>
                    <span className="text-brand-dark font-semibold">{opt.vendorSample}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <hr className="border-warm-200" />

      {/* Group 2: All-Hide Engine Settings */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-4 space-y-2">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-warm-900">
              All-Hide 混淆策略
            </h2>
            {config.mode !== 'all-hide' && (
              <span className="text-[11px] text-warm-500 bg-warm-100 px-2 py-0.5 rounded">
                预设
              </span>
            )}
          </div>
          <p className="text-xs text-warm-500 leading-relaxed">
            当模式切换为 All-Hide 时，以下三种混淆层将组合工作，使服务商无法通过代码结构或上下文还原你的真实项目。
          </p>
          {config.mode !== 'all-hide' && (
            <button
              type="button"
              onClick={() => handleSelectMode('all-hide')}
              className="mt-1 inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-medium bg-warm-900 hover:bg-warm-600 text-white transition-colors cursor-pointer"
            >
              立即开启 All-Hide
            </button>
          )}
        </div>

        <div className="lg:col-span-8 space-y-4">
          <div className="bg-warm-50/70 border border-warm-200 rounded-xl divide-y divide-warm-200">
            <div className="p-4 flex items-center justify-between gap-4">
              <div>
                <div className="text-[13px] font-medium text-warm-900">
                  同构领域伪装 (Isomorphic Camouflage)
                </div>
                <p className="text-xs text-warm-500 mt-0.5">
                  保留 AST 语法结构，将业务类名与函数名映射为无关领域词汇，返回时自动还原。
                </p>
              </div>
              <NativeSwitch
                checked={config.allHide.enableIsomorphicCamouflage}
                onChange={(v) =>
                  handleToggleAllHideField('enableIsomorphicCamouflage', v)
                }
                label="同构领域伪装"
              />
            </div>

            <div className="p-4 flex items-center justify-between gap-4">
              <div>
                <div className="text-[13px] font-medium text-warm-900">
                  高熵乱码编码 (Cipher Garble)
                </div>
                <p className="text-xs text-warm-500 mt-0.5">
                  将私有字面量、注释块与协议载荷进行可逆编码，使服务商日志呈现为不可读乱码块。
                </p>
              </div>
              <NativeSwitch
                checked={config.allHide.enableCipherGarble}
                onChange={(v) =>
                  handleToggleAllHideField('enableCipherGarble', v)
                }
                label="高熵乱码编码"
              />
            </div>

            <div className="p-4 flex items-center justify-between gap-4">
              <div>
                <div className="text-[13px] font-medium text-warm-900">
                  后台索引与遥测噪音投喂 (Telemetry Chaff)
                </div>
                <p className="text-xs text-warm-500 mt-0.5">
                  拦截客户端的全量代码索引与遥测请求，返回自动生成的无关诱饵代码，防止客户端报错。
                </p>
              </div>
              <NativeSwitch
                checked={config.allHide.enableTelemetryChaff}
                onChange={(v) =>
                  handleToggleAllHideField('enableTelemetryChaff', v)
                }
                label="后台索引与遥测噪音投喂"
              />
            </div>
          </div>

          {/* Cover Theme Picker */}
          <div className="bg-warm-50/70 border border-warm-200 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-warm-900">
                伪装词库主题
              </span>
              <span className="text-[11px] font-mono text-warm-500">
                {config.allHide.coverTheme}
              </span>
            </div>

            <div
              role="radiogroup"
              aria-label="伪装词库主题"
              className="grid grid-cols-1 md:grid-cols-3 gap-2.5"
            >
              {COVER_THEMES.map((theme) => {
                const selected = config.allHide.coverTheme === theme.id;
                return (
                  <button
                    key={theme.id}
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    onClick={() => handleToggleAllHideField('coverTheme', theme.id)}
                    className={`text-left p-3 rounded-lg border transition-all duration-150 flex flex-col justify-between gap-2 cursor-pointer ${
                      selected
                        ? 'bg-paper border-brand shadow-pill'
                        : 'bg-paper/60 border-warm-200 hover:border-warm-300'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-warm-900">
                          {theme.name}
                        </span>
                        {selected && (
                          <span className="w-2 h-2 rounded-full bg-brand" />
                        )}
                      </div>
                      <p className="text-[11px] text-warm-500 mt-1 leading-relaxed">
                        {theme.desc}
                      </p>
                    </div>
                    <div className="text-[10px] font-mono text-warm-600 bg-warm-50 px-2 py-1 rounded border border-warm-200/70 truncate">
                      {theme.beforeAfter}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      <hr className="border-warm-200" />

      {/* Group 3: Granular Inspection Rules */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-4 space-y-1.5">
          <h2 className="text-sm font-semibold text-warm-900">
            扫描过滤项
          </h2>
          <p className="text-xs text-warm-500 leading-relaxed">
            细粒度控制哪些类型的项目信息需要被本地扫描器识别并纳入内存映射表。
          </p>
        </div>

        <div className="lg:col-span-8 bg-warm-50/70 border border-warm-200 rounded-xl divide-y divide-warm-200">
          <div className="p-4 flex items-center justify-between gap-4">
            <div>
              <div className="text-[13px] font-medium text-warm-900">
                凭证与私钥过滤
              </div>
              <p className="text-xs text-warm-500 mt-0.5">
                自动识别 API Key、JWT、PEM 私钥、数据库连接串与 .env 敏感变量。
              </p>
            </div>
            <NativeSwitch
              checked={config.protectSecretsAndKeys}
              onChange={(v) => handleToggleCoreRule('protectSecretsAndKeys', v)}
              label="凭证与私钥过滤"
            />
          </div>

          <div className="p-4 flex items-center justify-between gap-4">
            <div>
              <div className="text-[13px] font-medium text-warm-900">
                本机路径与 Git 仓库信息
              </div>
              <p className="text-xs text-warm-500 mt-0.5">
                隐藏操作系统用户名、工作区绝对路径、私有 Git 远端地址与提交者邮箱。
              </p>
            </div>
            <NativeSwitch
              checked={config.protectProjectPaths}
              onChange={(v) => handleToggleCoreRule('protectProjectPaths', v)}
              label="本机路径与 Git 仓库信息"
            />
          </div>

          <div className="p-4 flex items-center justify-between gap-4">
            <div>
              <div className="text-[13px] font-medium text-warm-900">
                内网拓扑与私有域名
              </div>
              <p className="text-xs text-warm-500 mt-0.5">
                替换 RFC1918 内网 IPv4 地址段及 .corp / .internal / .local 等内部域名。
              </p>
            </div>
            <NativeSwitch
              checked={config.protectInternalNetwork}
              onChange={(v) =>
                handleToggleCoreRule('protectInternalNetwork', v)
              }
              label="内网拓扑与私有域名"
            />
          </div>

          <div className="p-4 flex items-center justify-between gap-4">
            <div>
              <div className="text-[13px] font-medium text-warm-900">
                拦截静默遥测请求
              </div>
              <p className="text-xs text-warm-500 mt-0.5">
                直接过滤非用户主动发起的后台行为统计、崩溃栈上传与设备指纹采集。
              </p>
            </div>
            <NativeSwitch
              checked={config.blockSilentTelemetry}
              onChange={(v) => handleToggleCoreRule('blockSilentTelemetry', v)}
              label="拦截静默遥测请求"
            />
          </div>

          <div className="p-4 flex items-center justify-between gap-4">
            <div>
              <div className="text-[13px] font-medium text-warm-900">
                严格字面量掩码
              </div>
              <p className="text-xs text-warm-500 mt-0.5">
                扫描代码中的长字符串常量、SQL 表名和业务提示词并生成可逆占位符。
              </p>
            </div>
            <NativeSwitch
              checked={config.allHide.strictLiteralMasking}
              onChange={(v) =>
                handleToggleAllHideField('strictLiteralMasking', v)
              }
              label="严格字面量掩码"
            />
          </div>
        </div>
      </section>
    </div>
  );
};

export default PrivacyModeSelector;
