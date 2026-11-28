# 更新日志

[English](CHANGELOG.md) | **简体中文**

本文件记录 Hide-Go 各版本的主要变更。

## [0.3.6] - 2026-11-28

### 新增
- 内置本地统计请求分类器（`classifier.rs`），综合 JSON AST 结构特征、Shannon 字节熵、请求头/路径/主机形态、上传不对称度与重复端点节奏，对 14 类 `RequestPurpose` 进行 Softmax 置信度评分（`purposeConfidence`）
- 未知前缀高熵凭据扫描器（`scanner.rs`），在严格排除元数据键与低复杂度字符误报的前提下识别随机密钥赋值
- 内置混合上下文守护模型（`guard_model.rs`），结合精确数学校验（GB 11643-1999 身份证 Mod 11-2、银行卡 Luhn 校验与号码格式）及双层滑动窗口 MLP 打分器（支持 `protectPersonalInfo`、`guardModelEnabled` 与 `0.65` / `0.80` / `0.90` 灵敏度预设），补齐中英文自然语言凭据、Cookie、CLI 凭据及个人隐私漏检，同时抑制 token 计数标签、时间戳、提交哈希、版本号、base64 图片与示例占位误报，并在 `desensitizer.rs` 中提供格式保持的密钥派生 PII 占位替换
- 新增中文更新日志（`CHANGELOG.zh-CN.md`），在 GitHub Release 顶部提供中文跳转切换链接，并在控制台检测到新版本时按当前界面语言展示默认折叠、可展开的更新日志

### 变更
- 重构 `All-Hide` 同构领域伪装引擎（`all_hide.rs`），生成符合语法和角色特征的自然覆盖标识符（保留 `Config`/`Error`/`Service` 等类型后缀及动词前缀）、无十六进制标签的自然组合注释、保留格式占位符的自然覆盖字符串（自动跳过导入路径、MIME 类型、HTTP 方法与文件路径）、动态请求 schema 工具/参数名保护以及多模块索引干扰包，确保 AI 编码代理能够清晰阅读和修改代码并实现无损还原
- 统一 HTTP、MITM、Protobuf 与原始 `CONNECT` 透传隧道审计管线至 `RequestClassifier`，新增针对未知直连主机的非对称大流量加密上传检测
- 全面优化热路径性能：`guard_model.rs` 引入单遍 `RegexSet` 预过滤、预编译负向线索集、零堆分配栈校验器、O(K log K) 区间融合与大压缩块/候选数上限；`scanner.rs` 新增 28 字节令牌连续段快速预判；`classifier.rs` 对超 128 KB JSON 改用有界首尾结构探测；`desensitizer.rs`/`vault.rs` 增加零扫描快速退出；`all_hide.rs` 全面切换至 O(log N) 二分查找区间匹配

### 修复
- 在 `SemanticDesensitizer` 完成密钥与路径脱敏后，保护 Anthropic 顶层 `system` 提示词及 OpenAI `system` / `developer` 消息不被 `All-Hide` 标识符与字面量伪装改写
- 在 NDJSON 流式还原的尾部合成帧中移除 `tool_calls` 与 `done_reason`，避免 EOF 刷新前瞻缓冲时重复触发工具调用
- 为 `/api/logs` 与 `/api/vault` 的弱 `ETag` 加入进程级随机启动标识，避免网关重启后向已打开的控制台返回过期的 `304 Not Modified`
- 在启用 `systemProxyChain` 且调用 `DELETE /api/ca/trust` 取消信任根证书后同步刷新托管的 Windows 用户代理/CA 环境变量

## [0.3.5] - 2026-11-22

### 新增
- 14 类请求用途分类（`RequestPurpose`：`chat-inference`、`tool-result-sync`、`inline-completion`、`token-count`、`codebase-indexing`、`file-upload`、`telemetry`、`feature-flags`、`crash-report`、`model-catalog`、`auth-account`、`realtime-sync`、`update-extension`、`other-api`），提供单条请求 `purposeDetail`、`HarnessAuditSummary.purposeCounts`、`ObservedConnectHost.purpose` 以及流量页用途筛选下拉框
- 多层遥测检测：覆盖 camelCase/PascalCase RPC 动词（如 `:recordCodeAssistMetrics`、`AnalyticsService/ReportEvent`）、遥测 SDK 请求头（`TelemetryHeader`）、实验/特性开关上报（`FeatureFlagTracking`）、崩溃诊断上报（`CrashDiagnostics`）、长连接透传遥测 `CONNECT` 隧道实时入库、MITM WebSocket 通道记录以及明文 HTTP / 二进制上传审计检查
- `CodeView` 新增可读 SSE/NDJSON 流式视图与对话视图切换（在保留原始报文的同时重组 OpenAI、Anthropic、Gemini、Google Cloud Code 与 Ollama 流式及多轮 JSON 内容）、下一处命中跳转导航，以及敏感项卡片的复制与正文定位操作
- 行级流式 NDJSON / JSONL 响应还原器（`ndjson_restorer.rs`），支持 `application/x-ndjson`、`application/jsonl` 与 `application/stream+json` 上游跨分片占位符还原
- 流量页实时流暂停/恢复控制（含待接收新记录计数）、稳定选中状态、防抖搜索、`/` 搜索快捷键以及 URL 筛选深链（`tool`、`action`、`purpose`）

### 变更
- 对未发生变化的 `GET /api/logs` 和 `GET /api/vault` 轮询返回弱 `ETag` / `304 Not Modified`，减少空闲轮询的 JSON 序列化与 React 重渲染开销
- `GET /api/status` 审计汇总直接遍历内存记录而不再克隆载荷正文，并在密钥库列表与计数中隐藏仅用于还原的路径别名条目
- 将客户端工具扫描范围收敛至总览页与集成页、配置保存后立即刷新状态、支持从总览页活跃工具卡片直达对应筛选流量，并在 `CodeView` 中高亮密钥派生占位符格式

### 修复
- 总览页快捷复制端点正确显示 `/codex/v1` 与 `/grok-build/v1` 基础地址
- 切换流量记录行时清除残留的加载错误提示，并使自定义规则替换预览和域名风格提示校验与网关的密钥派生令牌格式保持一致

## [0.3.1] - 2026-11-22

### 新增
- 审计风险引擎（`audit.rs`），覆盖 HTTP、MITM 与原始 `CONNECT` 透传隧道，检测遥测端点与载荷、压缩包/多段表单打包上传、批量代码库同步、超大出站载荷以及遥测或批量上传中的敏感数据
- `GET /api/status` 新增按工具汇总的审计状态（`telemetryDetected`、`bulkUploadDetected`、`harnessAudit`），`GET /api/mitm/hosts` 新增主机风险标签（`telemetry` / `upload-storage`），流量页新增紧凑审计摘要条、风险信号标签与遥测/批量上传筛选

### 变更
- 启用 `systemProxyChain` 时在 WinInet 之外同步管理可逆的 Windows 用户环境变量（`HTTPS_PROXY`、`HTTP_PROXY`、`NO_PROXY` 及本地 CA 证书路径，通过 `HKCU\Environment` + `WM_SETTINGCHANGE` 生效），使 Go/桌面语言服务自动继承代理与 CA 配置，并在断开、关闭、退出控制台、注销、重启恢复或卸载时自动清理还原
- 将 `daily-cloudcode-pa.googleapis.com`、`autopush-cloudcode-pa.googleapis.com`、`staging-cloudcode-pa.googleapis.com` 与 `jetski-webchannel.googleapis.com` 纳入内置 AI MITM 主机与 Antigravity 归属识别
- `AutoDesensitize` 零命中时保持 JSON 字节完全一致并报告 `passed`；注册 Windows 路径分隔符与盘符大小写还原别名；扩展 OpenAI Responses 增量事件覆盖范围（`reasoning_text`、`audio_transcript`、`code_interpreter_call_code`）

### 修复
- 修复 Google Cloud Code `{"response":{"candidates":[...]}}` SSE 流与 JSON 数组分片中的跨块占位符还原，在 `thought` 与 `text` 切换时保持通道对齐
- 保护 Google Cloud Code 结构字段（`project`、`requestId`、`traceId`、`responseId`）、Gemini `functionCall` 名称及签名思考块（`thoughtSignature`），不再在还原阶段跳过任意 JSON `"data"` 字段
- 修复 Protobuf/gRPC 3 帧以上跨帧占位符还原，收紧可打印子消息递归避免漏掉短 IP 或破坏 `": sk-..."` 文本，在压缩回退时清除压缩标志，拆分点分 gRPC 路径以准确识别遥测/索引，并对 Protobuf 与流式 RPC 载荷执行完整审计信号分析
- `PrivacyVault::clear()` 同步清理 `Matcher` 缓存快照，对非字符串 JSON 密钥强制执行 `allow_secret`，消除 O(N²) 淘汰扫描，修复百分号编码密钥边界检查，并防止对 `work/<tag>` 路径占位符二次脱敏
- 将桌面端优雅关闭等待上限收敛为 1.5 秒并注册 Windows 控制台控制与 Unix `SIGTERM` 清理钩子，确保关闭 Hide-Go 时不会因长连接挂起或残留系统代理
- 修复 Windows 上仅存旧版 `settings.json` 代理条目但未启用 `systemProxyChain` 时仍将 Antigravity 显示为已配置的问题，并在信任本地根证书后立即刷新托管的用户 CA 环境变量

## [0.3.0] - 2026-11-22

### 新增
- 内置更新检查功能（`GET /api/updates/check` 与默认开启的 `auto_check_updates`），提供设置页开关与侧边栏新版本提示点
- Windows 独立单文件安装程序，内置安装界面、语言包及经过 SHA-256 校验的运行时归档
- 集成原生 Win32 API：目录选择对话框（`IFileOpenDialog`）、快捷方式（`IShellLinkW`）、当前用户卸载注册表项、PE VersionInfo 及应用清单（`asInvoker`、`PerMonitorV2`、`longPathAware`）
- 发布工作流新增可选的 Windows 运行时二进制与安装程序 Authenticode 代码签名步骤
- 集成页提供可一键复制的 OpenAI 兼容（`/codex/v1`）与 Anthropic 兼容（`/claude-code`）Base URL 端点及传输/CA 状态徽章
- 无 Schema 的 Protobuf、gRPC（`application/grpc*`）与 ConnectRPC（`application/connect+proto`、`application/connect+json`）线协议出站脱敏与流式入站还原，支持全双工双向流、`gzip`/`deflate` 帧解压、跨帧令牌重组及 HTTP/2 trailer 透传
- 可逆的 Windows WinInet 系统代理链（`system_proxy_chain`），保留原有上游代理并在断开、关闭或卸载时自动恢复
- 新增 `GET /api/mitm/hosts` 接口与集成页紧凑控件，支持切换系统代理链、管理自定义 `mitmExtraHosts`、查看近期观测到的 `CONNECT` 主机，并在流量日志中呈现 MITM TLS 握手失败记录

### 变更
- 基于实例运行时密钥与 `project_salt` 派生出站占位符、覆盖标识符与覆盖注释，并在转发前剥离代理元数据请求头
- 使用 `RegexSet` 预过滤内置检测规则，通过 256 项根节点前缀树表与百分号编码密钥重脱敏提升密钥库查找性能
- 出站 HTTP 转发及 `HTTPS CONNECT` / WebSocket 隧道自动遵循当前环境或 Windows 系统代理，同时绕过环回/局域网目标与 Hide-Go 自身监听端口
- 将 OpenAI Codex 集成切换为 Base URL 反向代理模式（`[model_providers.*].base_url` / `openai_base_url` 与 `OPENAI_BASE_URL`），无需信任根证书
- 通过可逆系统代理链、IDE 代理配置以及覆盖 `cloudcode-pa` 与 `antigravity-pa` Google API 主机的 Protobuf/gRPC/REST MITM 接入 Antigravity
- 使用 `Segmented` 与 `Switch` 控件精简设置页布局

### 修复
- 即使 `~/.codex/config.toml` 未显式声明顶层 `model_provider`，也能正确更新活跃的 `[model_providers.*].base_url` 条目，并通过 `harness_upstreams` 与 `allowed_loopback_proxy_targets` 串联环回上游
- 修复 Claude Code 断开连接时将 `settings.json` 中的 `ANTHROPIC_BASE_URL` 写回 `~/.hide-go/env.ps1` 的问题，并在接入时清理冲突的托管环境变量条目
- 避免原生 `<dialog>` 按 `Esc` 关闭时触发两次 `onClose`，并将 `@starting-style` 规则移至顶层 CSS
- 通过系统区域设置检测本地化安装程序启动错误弹窗标题，移除硬编码文案

## [0.2.4] - 2026-11-21

### 新增
- 内置敏感凭据检测规则：AWS STS（`ASIA`）、Google/Firebase（`AIza`）、Stripe、GitLab、Slack、HuggingFace、npm、PyPI、Groq、Perplexity、Replicate、SendGrid、阿里云（`LTAI`）、腾讯云（`AKID`）、钉钉/飞书/企微/Discord Webhook、JWT、`Authorization` 请求头、带凭据 HTTP(S) URL 以及更多数据库/消息队列 URI 协议
- 支持带前缀和 camelCase 凭据键名（如 `GITHUB_WEBHOOK_SECRET`、`stripeWebhookSecret`）、WSL2 `/mnt/<drive>/Users/...` 路径、正斜杠 Windows 工作区路径及 Tailscale/CGNAT（`100.64.0.0/10`）内网 IP
- `All-Hide` 模式新增 `# ` 行注释支持，并扩展 Rust/TypeScript/Python/Go 标准库符号保留表

### 变更
- 使用带缓存与边界检查的 `Matcher::remask_secrets` 替代逐字符串已知密钥重扫描，并在审计发现中记录作用域密钥重脱敏
- `FileEditsOnly` 工具调用内容字段改为大小写不敏感匹配（`CodeContent`、`TargetContent`、`ReplacementContent`、`code_edit` 等），并补充常见文件编辑工具别名
- 数据库 URL 占位符按协议使用对应默认端口，缺失资源启动错误中附带实际检查的资源目录路径

### 修复
- 通过 `FindFirstFileW` 检查 Windows 重解析点标签，使 `Hide-Go-Setup` 与 `hide-go-desktop` 可在 OneDrive 云文件与 WOF 压缩目录中正常运行，同时继续拦截符号链接与 NTFS 联接点
- 降低编码代理场景误报：忽略分页/计数/元数据键名（`nextPageToken`、`max_token`、`secretArn`、`public_key`）、环境变量模板（`$VAR`、`${VAR}`）、代码引用（`process.env.*`）、`.env.local` / `settings.local.json`、Retina 资源文件名（`icon@2x.png`）、非法 IPv4 段、Windows 系统目录及数据库 URL 尾部引号

## [0.2.3] - 2026-11-21

### 新增
- `Hide-Go-Setup` 拆分桌面快捷方式与开始菜单/应用程序菜单独立开关，并支持 `--no-desktop-shortcut` 与 `--no-start-menu` 命令行参数

### 变更
- 将应用拆分为共享动态库（`hide_engine`、`hide_chrome`）、轻量原生启动器及外部 `resources/` 目录（`ui/`、`setup/`、`locales/`、`icons/`）
- 安装包内置经 SHA-256 校验的 `data/app.tar.gz` 归档，将 Windows 安装包体积压缩至约 5.8 MB
- 在 `install-manifest.json` 中记录安装路径，卸载时清理共享库与空 `resources/` 目录且不触碰无关文件

### 修复
- Windows 任务栏与 Alt+Tab 切换器正确显示 Hide-Go 应用图标，并为 `.lnk` 快捷方式写入显式 `,0` 图标索引

## [0.2.2] - 2026-11-21

### 变更
- 将 `Hide-Go-Setup` 拆分为按平台压缩的归档包（Windows `.zip`，macOS 与 Linux `.tar.gz`），通过 `payload-manifest.json` SHA-256 摘要校验独立 `payload/` 二进制文件
- GitHub Releases 统一仅发布安装程序归档，不再附带独立桌面二进制文件
- 在 `[profile.release]` 中开启符号剥离与 Thin LTO，移除 `hide-go-desktop` 未使用的 `cdylib`/`staticlib` 输出

## [0.2.1] - 2026-11-21

### 新增
- 桌面控制台与 `hide-go-setup` 安装/卸载向导支持中英双语（`zh-CN`、`en`），全部文案外置至 `src/locales/*.json`
- Windows、macOS 与 Linux 自动检测操作系统语言，非中文区域默认使用英文
- 控制台新增**设置**页，支持语言切换（`system`、`zh-CN`、`en`）、浅色/深色外观切换，以及查看网关版本、监听地址与配置路径
- 安装程序新增语言切换器与本地化原生窗口/目录选择器标题，并将所选 `language` 写入 `config.json` 供桌面端继承

### 变更
- 对前端日志与工具聚合计算进行记忆化缓存，并为轮询 Hook、提示条与复制按钮补齐定时器和卸载清理
- 将 `hide-setup` 中重复的规范路径比较收敛为共享辅助函数 `same_path`

## [0.2.0] - 2026-11-20

### 新增
- 独立的 `hide-go-setup` 安装与卸载向导，支持目录选择、快捷方式、`PATH` 配置、开机自启、客户端自动接入以及 `--silent` 静默命令行模式
- 基于 `hide-chrome` 的无边框原生 WebView 窗口壳（桌面控制台与安装程序共用），在 WebView 不可用时自动回退到浏览器打开
- 面向 AI API 主机的选择性 `HTTPS CONNECT` TLS 检查与本地根证书管理（`/api/ca/*`），对 OAuth 及非 AI 源保持原始 TCP 透传
- 自动本地检测、一键接入与可逆备份（`/api/harnesses/*`），覆盖 Claude Code、Codex、Antigravity、ZCode、Qoder、Cursor 与 Grok Build
- 支持 HTTP/2（`h2` ALPN）、WebSocket（`wss://`）透传、`multipart/form-data` 二进制 RPC 透传以及有界 `gzip`/`deflate` 载荷解压
- 桌面控制台支持浅色/深色主题切换（`color-scheme`）与原生 `<dialog>` 弹窗

### 变更
- 按厂商域名隔离 `PrivacyVault` 占位符映射并缓存 Aho-Corasick 匹配器，防止跨厂商流量探测其他域的令牌
- 桌面端与安装程序 HTML 响应改用逐请求 CSP nonce，移除 `script-src` 中的 `'unsafe-inline'`
- 允许用户显式配置的上游（`HIDE_GO_UPSTREAM_URL` 与 `harness_upstreams`）指向 RFC1918 私有局域网地址，同时拦截云元数据地址与代理自循环
- `config.json`、CA 私钥与客户端备份采用原子写入并设置仅当前用户可访问的受限文件权限
- 托管的 Shell 与 PowerShell 代理脚本增加本地 TCP 端口探测保护，避免关闭 Hide-Go 后终端断网

### 修复
- 保留 Gemini `thoughtSignature` / `thought_signature` 字段，不再将 `token` 键下的布尔值或短字符串（`< 6` 字符）误判为密钥占位符
- 兼容 SSE EOF 处的单换行 `data: [DONE]`，并在 `max_tokens` 截断流式工具调用 JSON 片段时回退为文本还原
- 还原 OpenAI Responses 的 `response.reasoning_summary_text.delta` 与 `response.refusal.delta` SSE 事件，并对自定义工具、MCP 及嵌套 JSON 参数强制执行 `ToolCallSecretPolicy`
- 在引号字面量扫描中跳过英文缩写（如 `don't`），并收窄内部占位符前缀检查（`svc-node-`）以减少误伤
- 代理响应中保留上游 `Access-Control-*` 与非会话类 `Set-Cookie` 请求头

## [0.1.1] - 2026-11-13

### 新增
- 不依赖 Tauri 的独立 `hide-go-desktop` 二进制，在 `127.0.0.1` 直接提供编译期嵌入的控制台界面
- 新增 `ToolCallSecretPolicy`，在工具调用命令中保持凭据占位符不被明文展开
- 协议感知 SSE 流式还原器，支持 OpenAI Chat/Responses、Anthropic Messages 与 Gemini 候选流
- 控制台新增策略配置、自定义规则、流量对比、密钥库查看与客户端接入视图
- 为全部 Windows、macOS 与 Linux 发布产物生成 `.sha256` 校验文件

### 变更
- 默认 `project_salt` 改为每次安装随机生成，不再使用静态字符串
- 管理接口（`/api/*`）改为强制本地环回源校验与 `X-Hide-Go-Token` / Bearer 鉴权，不再使用 Cookie
- 代理在遇到无法解析的压缩/非 UTF-8 请求体或畸形 SSE 流时采用安全失败（fail-closed）策略
- 客户端接入片段统一配置反向代理路由，不再依赖 `HTTP_PROXY` 或 `HTTPS_PROXY` 标记

### 修复
- 在无引号环境变量密钥扫描中忽略类型标注（如 `String`、`Option<String>`），同时保留对含空格引号密钥的匹配
- 脱敏与重封装过程中保留 API 工具 schema、工具名以及带签名的 `thinking` 块
- 防止对 `C:\workspace\user_*` 占位路径进行二次脱敏
- 按 part 索引路由 Gemini SSE 文本分片，使同一候选中的多个文本段独立还原
- 为被拒绝的请求与中断的 SSE 流记录审计日志，且不再将临时的 `HIDE_GO_PORT` 覆盖值写回 `config.json`
- 流量对比视图支持匹配 JSON 转义后的密钥库令牌，并在异步校验期间保留最新的规则开关状态
