use crate::config::{HarnessKind, TrafficCategory};
use serde::{Deserialize, Serialize};

/// Whether Hide-Go can automatically wire this harness to the local proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutoConnectMode {
    ConfigFile,
    EnvVar,
    Manual,
}

/// Metadata, interception profile, and live detection state for a supported AI Coding Harness
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessProfile {
    pub kind: HarnessKind,
    pub name: String,
    pub vendor_name: String,
    pub default_upstream: String,
    pub local_proxy_route: String,
    pub protocol_family: String,
    pub description: String,
    pub risk_summary: Vec<String>,
    pub env_setup_bash: String,
    pub env_setup_powershell: String,
    /// Known limitation of routing this tool through a local gateway, if any.
    pub integration_note: Option<String>,
    /// True only when live gateway traffic has been observed for this harness.
    pub detected_active: bool,
    /// True when the CLI binary, desktop app, or user config dir is found on this machine.
    pub installed: bool,
    /// Binary or configuration paths discovered on this machine.
    pub install_paths: Vec<String>,
    /// True when a local config file or persistent env var already routes through Hide-Go.
    pub configured: bool,
    /// Where the Hide-Go gateway route is configured, if detected.
    pub configured_via: Option<String>,
    /// How automatic integration works for this harness.
    pub auto_connect_mode: AutoConnectMode,
    /// True when this harness requires local Root CA trust (HTTPS CONNECT MITM or TLS bundle).
    #[serde(default)]
    pub requires_ca_trust: bool,
    /// Concrete local targets (files, user env vars, OS CA store) touched by one-click connect.
    #[serde(default)]
    pub auto_connect_targets: Vec<String>,
    /// Number of requests observed for this harness during this gateway session.
    pub traffic_count: u64,
    /// Local timestamp (`HH:MM:SS`) of the most recent request, if any.
    pub last_seen_at: Option<String>,
}

/// Returns rich, accurate profiles for all 7 supported AI coding harnesses
pub fn get_all_harness_profiles(proxy_port: u16) -> Vec<HarnessProfile> {
    let base = format!("http://127.0.0.1:{}", proxy_port);

    vec![
        HarnessProfile {
            kind: HarnessKind::ClaudeCode,
            name: "Claude Code".to_string(),
            vendor_name: "Anthropic PBC".to_string(),
            default_upstream: "https://api.anthropic.com".to_string(),
            local_proxy_route: "/claude-code".to_string(),
            protocol_family: "Anthropic Messages API (/v1/messages)".to_string(),
            description: "Anthropic 官方终端 Agent 工具，支持全仓库读写、Bash 工具调用与多文件上下文直传。"
                .to_string(),
            risk_summary: vec![
                "自动注入 CLAUDE.md、工作区绝对路径、Git 分支与最近提交记录".to_string(),
                "Bash / Read 工具执行结果可能将 .env、密钥配置文件原样回传云端".to_string(),
                "高频发送后台遥测事件 (/api/event_logging/batch)".to_string(),
            ],
            env_setup_bash: format!(
                "export ANTHROPIC_BASE_URL=\"{}/claude-code\"\nexport NO_PROXY=\"localhost,127.0.0.1,::1\"\nclaude",
                base
            ),
            env_setup_powershell: format!(
                "$env:ANTHROPIC_BASE_URL=\"{}/claude-code\"\n$env:NO_PROXY=\"localhost,127.0.0.1,::1\"\nclaude",
                base
            ),
            integration_note: Some(
                "写入 ~/.claude/settings.json 的 env.ANTHROPIC_BASE_URL（保留已有本地网关作为上级转发），并在存在代理变量时补充 NO_PROXY。"
                    .to_string(),
            ),
            detected_active: false,
            installed: false,
            install_paths: Vec::new(),
            configured: false,
            configured_via: None,
            auto_connect_mode: AutoConnectMode::ConfigFile,
            requires_ca_trust: false,
            auto_connect_targets: vec![
                "~/.claude/settings.json (env.ANTHROPIC_BASE_URL / NO_PROXY)".to_string(),
            ],
            traffic_count: 0,
            last_seen_at: None,
        },
        HarnessProfile {
            kind: HarnessKind::Codex,
            name: "OpenAI Codex CLI".to_string(),
            vendor_name: "OpenAI LP".to_string(),
            default_upstream: "https://api.openai.com".to_string(),
            local_proxy_route: "/codex".to_string(),
            protocol_family: "OpenAI Responses & Chat Completions API (/v1/responses, /v1/chat/completions)".to_string(),
            description: "OpenAI 命令行编码智能体，通过 Responses API 同步本地沙箱执行输出与代码补丁。"
                .to_string(),
            risk_summary: vec![
                "Responses API 会携带完整本地文件树与终端标准输出/错误日志".to_string(),
                "环境变量与数据库连接串极易在命令执行回显中外泄".to_string(),
                "长会话状态持久化在云端存储中保留原始项目符号".to_string(),
            ],
            env_setup_bash: format!(
                "export OPENAI_BASE_URL=\"{}/codex/v1\"\nexport NO_PROXY=\"localhost,127.0.0.1,::1\"\ncodex",
                base
            ),
            env_setup_powershell: format!(
                "$env:OPENAI_BASE_URL=\"{}/codex/v1\"\n$env:NO_PROXY=\"localhost,127.0.0.1,::1\"\ncodex",
                base
            ),
            integration_note: Some(
                "通过 Base URL 反向代理接入（无需安装根证书）：修改 ~/.codex/config.toml 中当前生效的 [model_providers.*].base_url（或顶层 openai_base_url）与 OPENAI_BASE_URL，并保留已有上游地址（含本地中转网关）进行链式转发。"
                    .to_string(),
            ),
            detected_active: false,
            installed: false,
            install_paths: Vec::new(),
            configured: false,
            configured_via: None,
            auto_connect_mode: AutoConnectMode::ConfigFile,
            requires_ca_trust: false,
            auto_connect_targets: vec![
                "~/.codex/config.toml ([model_providers.*].base_url / openai_base_url)".to_string(),
                "~/.hide-go/env.ps1 / Shell 配置文件 (OPENAI_BASE_URL)".to_string(),
            ],
            traffic_count: 0,
            last_seen_at: None,
        },
        HarnessProfile {
            kind: HarnessKind::Antigravity,
            name: "Antigravity".to_string(),
            vendor_name: "Google DeepMind / Multi-Model Gateway".to_string(),
            default_upstream: "https://generativelanguage.googleapis.com".to_string(),
            local_proxy_route: "/antigravity".to_string(),
            protocol_family: "Gemini / CloudCode gRPC · Protobuf · REST API".to_string(),
            description: "全自主多步规划 Agent 环境，支持 gRPC/Protobuf 与 Gemini REST 流式推理及子智能体工具调用。"
                .to_string(),
            risk_summary: vec![
                "子智能体并发调研时可能批量上传数十个核心业务源码文件".to_string(),
                "系统提示词中包含宿主机用户名、工作区目录结构与 Git 远端地址".to_string(),
                "长上下文与流式 gRPC/Protobuf 帧中可能携带原始密钥、内网地址与项目路径".to_string(),
            ],
            env_setup_bash: format!(
                "export HTTPS_PROXY=\"{}\"\nexport NO_PROXY=\"localhost,127.0.0.1,::1\"\nexport GOOGLE_GEMINI_BASE_URL=\"{}/antigravity\"",
                base, base
            ),
            env_setup_powershell: format!(
                "$env:HTTPS_PROXY=\"{}\"\n$env:NO_PROXY=\"localhost,127.0.0.1,::1\"\n$env:GOOGLE_GEMINI_BASE_URL=\"{}/antigravity\"",
                base, base
            ),
            integration_note: Some(
                "自动启用可逆系统代理链（自动串接现有代理，退出或断开时原样恢复）并同步写入 Antigravity User/settings.json 与终端环境变量，支持 gRPC/Protobuf 及 REST 流量实时脱敏与还原；拦截 HTTPS AI 域名需信任本地根证书。"
                    .to_string(),
            ),
            detected_active: false,
            installed: false,
            install_paths: Vec::new(),
            configured: false,
            configured_via: None,
            auto_connect_mode: AutoConnectMode::ConfigFile,
            requires_ca_trust: true,
            auto_connect_targets: vec![
                "系统代理链（运行期接管，退出自动还原）".to_string(),
                "Antigravity User/settings.json (http.proxy, terminal.integrated.env.*)".to_string(),
                "~/.hide-go/env.ps1 / Shell 配置文件 (HTTPS_PROXY, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE)".to_string(),
            ],
            traffic_count: 0,
            last_seen_at: None,
        },
        HarnessProfile {
            kind: HarnessKind::Zcode,
            name: "ZCode".to_string(),
            vendor_name: "ZCode AI Cloud".to_string(),
            default_upstream: "https://api.zcode.ai".to_string(),
            local_proxy_route: "/zcode".to_string(),
            protocol_family: "OpenAI-Compatible Agent Protocol (/v1/chat/completions)".to_string(),
            description: "新一代轻量级极速编码智能体，支持本地 AST 感知与快速多文件协同编辑。"
                .to_string(),
            risk_summary: vec![
                "自动抓取当前打开文件及相邻模块导入图谱上传至推理节点".to_string(),
                "内置代码库语义检索请求包含专有业务类名与内部函数签名".to_string(),
                "诊断日志同步可能附带本地编译错误中的绝对路径与敏感字面量".to_string(),
            ],
            env_setup_bash: format!(
                "export ZCODE_HTTP_PROXY=\"{}\"\nexport ZCODE_NO_PROXY=\"localhost,127.0.0.1,::1\"\nexport HTTPS_PROXY=\"{}\"",
                base, base
            ),
            env_setup_powershell: format!(
                "$env:ZCODE_HTTP_PROXY=\"{}\"\n$env:ZCODE_NO_PROXY=\"localhost,127.0.0.1,::1\"\n$env:HTTPS_PROXY=\"{}\"",
                base, base
            ),
            integration_note: Some(
                "通过 ~/.hide-go/env.ps1 或 Shell 配置文件写入 ZCODE_HTTP_PROXY、ZCODE_NO_PROXY、ZCODE_AGENT_CA_CERT 与 HTTPS_PROXY / NODE_EXTRA_CA_CERTS。"
                    .to_string(),
            ),
            detected_active: false,
            installed: false,
            install_paths: Vec::new(),
            configured: false,
            configured_via: None,
            auto_connect_mode: AutoConnectMode::EnvVar,
            requires_ca_trust: true,
            auto_connect_targets: vec![
                "~/.hide-go/env.ps1 / Shell 配置文件 (ZCODE_HTTP_PROXY, ZCODE_NO_PROXY, ZCODE_AGENT_CA_CERT, HTTPS_PROXY, NODE_EXTRA_CA_CERTS)".to_string(),
            ],
            traffic_count: 0,
            last_seen_at: None,
        },
        HarnessProfile {
            kind: HarnessKind::Qoder,
            name: "Qoder".to_string(),
            vendor_name: "Qoder AI IDE & Indexing Cloud".to_string(),
            default_upstream: "https://api1.qoder.sh".to_string(),
            local_proxy_route: "/qoder".to_string(),
            protocol_family: "Qoder Agent & Codebase Vector Sync API".to_string(),
            description: "面向大型工程的 AI 研发 IDE，内置全量代码库向量索引器与自主任务执行器。"
                .to_string(),
            risk_summary: vec![
                "后台静默触发全仓库代码切片向量化上传 (/v1/index/upload)".to_string(),
                "跨模块调用链分析会将核心算法实现与内部 RPC 协议发送至云端".to_string(),
                "持续心跳与行为遥测记录开发者编辑历史".to_string(),
            ],
            env_setup_bash: format!(
                "export HTTPS_PROXY=\"{}\"\nexport NO_PROXY=\"localhost,127.0.0.1,::1\"\nqoder",
                base
            ),
            env_setup_powershell: format!(
                "$env:HTTPS_PROXY=\"{}\"\n$env:NO_PROXY=\"localhost,127.0.0.1,::1\"\nqoder",
                base
            ),
            integration_note: Some(
                "同时写入 Qoder 与 QoderCN 的 User/settings.json 代理设置及终端环境变量，拦截 api1.qoder.sh 与 gateway.qoder.com.cn 等主机。"
                    .to_string(),
            ),
            detected_active: false,
            installed: false,
            install_paths: Vec::new(),
            configured: false,
            configured_via: None,
            auto_connect_mode: AutoConnectMode::ConfigFile,
            requires_ca_trust: true,
            auto_connect_targets: vec![
                "Qoder & QoderCN User/settings.json (app.configAdvancedProxyMode/URL, http.proxy, terminal.integrated.env.*)".to_string(),
                "~/.hide-go/env.ps1 / Shell 配置文件 (HTTPS_PROXY, NODE_EXTRA_CA_CERTS)".to_string(),
            ],
            traffic_count: 0,
            last_seen_at: None,
        },
        HarnessProfile {
            kind: HarnessKind::Cursor,
            name: "Cursor".to_string(),
            vendor_name: "Anysphere Inc.".to_string(),
            default_upstream: "https://api2.cursor.sh".to_string(),
            local_proxy_route: "/cursor".to_string(),
            protocol_family: "Cursor Composer / Tab / OpenAI Custom Base URL".to_string(),
            description: "主流 AI 原生代码编辑器，包含 Composer 多文件代理、Tab 预测补全与云端 Merkle 树代码库索引。"
                .to_string(),
            risk_summary: vec![
                "Merkle 树代码库同步机制定期向云端上传代码库分块快照".to_string(),
                "Tab 补全在每次按键停顿时高频发送光标周围代码上下文".to_string(),
                "Composer Agent 自动读取工作区配置文件与终端历史记录".to_string(),
            ],
            env_setup_bash: format!(
                "export HTTPS_PROXY=\"{}\"\nexport NO_PROXY=\"localhost,127.0.0.1,::1\"",
                base
            ),
            env_setup_powershell: format!(
                "$env:HTTPS_PROXY=\"{}\"\n$env:NO_PROXY=\"localhost,127.0.0.1,::1\"",
                base
            ),
            integration_note: Some(
                "配置 Cursor User/settings.json 代理项（含 cursor.general.disableHttp2=true）及终端环境变量（HTTPS_PROXY / NODE_EXTRA_CA_CERTS）。"
                    .to_string(),
            ),
            detected_active: false,
            installed: false,
            install_paths: Vec::new(),
            configured: false,
            configured_via: None,
            auto_connect_mode: AutoConnectMode::ConfigFile,
            requires_ca_trust: true,
            auto_connect_targets: vec![
                "Cursor User/settings.json (http.proxy, http.proxySupport, cursor.general.disableHttp2, terminal.integrated.env.*)".to_string(),
                "~/.hide-go/env.ps1 / Shell 配置文件 (HTTPS_PROXY, NODE_EXTRA_CA_CERTS)".to_string(),
            ],
            traffic_count: 0,
            last_seen_at: None,
        },
        HarnessProfile {
            kind: HarnessKind::GrokBuild,
            name: "Grok Build".to_string(),
            vendor_name: "xAI Corp.".to_string(),
            default_upstream: "https://api.x.ai".to_string(),
            local_proxy_route: "/grok-build".to_string(),
            protocol_family: "xAI Grok Chat & Tool Execution API (/v1/chat/completions)".to_string(),
            description: "xAI 推出的超高速推理与构建智能体，专注于大型仓库实时诊断、构建修复与命令自动化。"
                .to_string(),
            risk_summary: vec![
                "构建失败自动诊断会上传完整编译器堆栈、环境变量与构建脚本".to_string(),
                "工具调用直接读取本地 Git 状态、容器配置及私有镜像仓库凭证".to_string(),
                "高频流式推理请求中包含未脱敏的内网服务端点与认证 Token".to_string(),
            ],
            env_setup_bash: format!(
                "export GROK_XAI_API_BASE_URL=\"{}/grok-build/v1\"\nexport GROK_CLI_CHAT_PROXY_BASE_URL=\"{}/grok-build\"\nexport HTTPS_PROXY=\"{}\"\nexport NO_PROXY=\"localhost,127.0.0.1,::1\"\ngrok",
                base, base, base
            ),
            env_setup_powershell: format!(
                "$env:GROK_XAI_API_BASE_URL=\"{}/grok-build/v1\"\n$env:GROK_CLI_CHAT_PROXY_BASE_URL=\"{}/grok-build\"\n$env:HTTPS_PROXY=\"{}\"\n$env:NO_PROXY=\"localhost,127.0.0.1,::1\"\ngrok",
                base, base, base
            ),
            integration_note: Some(
                "通过 ~/.hide-go/env.ps1 或 Shell 配置文件写入 GROK_XAI_API_BASE_URL、GROK_CLI_CHAT_PROXY_BASE_URL 与 HTTPS_PROXY；支持 gzip/deflate 请求体解压脱敏，未知压缩编码可在「仅审计」模式直通。"
                    .to_string(),
            ),
            detected_active: false,
            installed: false,
            install_paths: Vec::new(),
            configured: false,
            configured_via: None,
            auto_connect_mode: AutoConnectMode::EnvVar,
            requires_ca_trust: true,
            auto_connect_targets: vec![
                "~/.hide-go/env.ps1 / Shell 配置文件 (GROK_XAI_API_BASE_URL, GROK_CLI_CHAT_PROXY_BASE_URL, GROK_CLI_BASE_URL, HTTPS_PROXY, NODE_EXTRA_CA_CERTS)".to_string(),
            ],
            traffic_count: 0,
            last_seen_at: None,
        },
    ]
}

/// Model-inference endpoints. Requests to these are always forwarded upstream, never
/// answered locally, whatever their body contains.
pub fn is_inference_endpoint(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/v1/messages",
        "/chat/completions",
        "/v1/completions",
        "/v1/responses",
        ":generatecontent",
        ":streamgeneratecontent",
        "/v1/complete",
    ]
    .iter()
    .any(|e| p.contains(e))
        && !p.contains("/count_tokens")
}

/// Inspects the URL path prefix and User-Agent to determine both `HarnessKind` and
/// `TrafficCategory`. Classification is path-based on purpose: request bodies are user
/// content, and a tool schema that merely mentions `event_type` must not turn a chat request
/// into "telemetry" that gets answered locally.
pub fn detect_harness_and_category(path: &str, user_agent: Option<&str>, body: &str) -> (HarnessKind, TrafficCategory) {
    let path_lower = path.to_lowercase();
    let ua_lower = user_agent.unwrap_or_default().to_lowercase();

    let harness = if path_lower.starts_with("/claude-code") {
        HarnessKind::ClaudeCode
    } else if path_lower.starts_with("/codex") {
        HarnessKind::Codex
    } else if path_lower.starts_with("/antigravity") {
        HarnessKind::Antigravity
    } else if path_lower.starts_with("/zcode") {
        HarnessKind::Zcode
    } else if path_lower.starts_with("/qoder") {
        HarnessKind::Qoder
    } else if path_lower.starts_with("/cursor") {
        HarnessKind::Cursor
    } else if path_lower.starts_with("/grok-build") {
        HarnessKind::GrokBuild
    } else if ua_lower.contains("claude-cli") || ua_lower.contains("claude-code") {
        HarnessKind::ClaudeCode
    } else if ua_lower.contains("codex") {
        HarnessKind::Codex
    } else if ua_lower.contains("antigravity") {
        HarnessKind::Antigravity
    } else if ua_lower.contains("zcode") {
        HarnessKind::Zcode
    } else if ua_lower.contains("qoder") {
        HarnessKind::Qoder
    } else if ua_lower.contains("cursor") {
        HarnessKind::Cursor
    } else if ua_lower.contains("grok") || ua_lower.contains("xai") {
        HarnessKind::GrokBuild
    } else {
        HarnessKind::Generic
    };

    let segments: Vec<&str> = path_lower
        .split(['/', '?', ':', '.'])
        .filter(|s| !s.is_empty())
        .collect();
    let has_segment = |names: &[&str]| segments.iter().any(|s| names.contains(s));

    let category = if is_inference_endpoint(&path_lower) {
        if body.contains("\"tool_result\"")
            || body.contains("\"function_call_output\"")
            || body.contains("\"functionResponse\"")
            || body.contains("\"role\":\"tool\"")
            || body.contains("\"role\": \"tool\"")
        {
            TrafficCategory::ToolExecutionSync
        } else {
            TrafficCategory::InteractivePrompt
        }
    } else if has_segment(&[
        "telemetry",
        "event_logging",
        "analytics",
        "metrics",
        "events",
        "traces",
        "logs",
        "rgstr",
    ]) || path_lower.contains("event_logging")
        || crate::audit::has_telemetry_path(path)
        || crate::audit::has_crash_diagnostic_path(path, None)
    {
        TrafficCategory::Telemetry
    } else if has_segment(&[
        "embeddings",
        "embedding",
        "index",
        "indexing",
        "index-sync",
        "codebase",
        "merkle",
        "vector",
        "repo-service",
        "repositoryservice",
        "upload-chunks",
    ]) || path_lower.contains("codebase_sync")
    {
        TrafficCategory::CodebaseIndexing
    } else {
        TrafficCategory::InteractivePrompt
    };

    (harness, category)
}
