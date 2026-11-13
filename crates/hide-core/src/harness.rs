use crate::config::{HarnessKind, TrafficCategory};
use serde::{Deserialize, Serialize};

/// Metadata and interception profile for a supported AI Coding Harness
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
    pub detected_active: bool,
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
                "export ANTHROPIC_BASE_URL=\"{}/claude-code\"\nclaude",
                base
            ),
            env_setup_powershell: format!(
                "$env:ANTHROPIC_BASE_URL=\"{}/claude-code\"\nclaude",
                base
            ),
            integration_note: None,
            detected_active: true,
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
                "export OPENAI_BASE_URL=\"{}/codex/v1\"\ncodex",
                base
            ),
            env_setup_powershell: format!(
                "$env:OPENAI_BASE_URL=\"{}/codex/v1\"\ncodex",
                base
            ),
            integration_note: None,
            detected_active: true,
        },
        HarnessProfile {
            kind: HarnessKind::Antigravity,
            name: "Antigravity".to_string(),
            vendor_name: "Google DeepMind / Multi-Model Gateway".to_string(),
            default_upstream: "https://generativelanguage.googleapis.com".to_string(),
            local_proxy_route: "/antigravity".to_string(),
            protocol_family: "Google Gemini / Multi-Agent Stream Protocol".to_string(),
            description: "全自主多步规划 Agent 环境，具备深度仓库检索、跨文件重构与后台子智能体协同能力。"
                .to_string(),
            risk_summary: vec![
                "子智能体并发调研时可能批量上传数十个核心业务源码文件".to_string(),
                "系统提示词中包含宿主机用户名、工作区目录结构与 Git 远端地址".to_string(),
                "长上下文窗口一次性聚合大量私有架构设计与内部接口定义".to_string(),
            ],
            env_setup_bash: format!("export ANTIGRAVITY_API_BASE=\"{}/antigravity\"", base),
            env_setup_powershell: format!("$env:ANTIGRAVITY_API_BASE=\"{}/antigravity\"", base),
            integration_note: Some("需客户端支持自定义 Gemini Base URL；Hide-Go 不是 HTTPS CONNECT 代理，不能通过 HTTPS_PROXY 接入。".to_string()),
            detected_active: true,
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
                "export ZCODE_API_BASE=\"{}/zcode/v1\"\nexport OPENAI_BASE_URL=\"{}/zcode/v1\"",
                base, base
            ),
            env_setup_powershell: format!(
                "$env:ZCODE_API_BASE=\"{}/zcode/v1\"\n$env:OPENAI_BASE_URL=\"{}/zcode/v1\"",
                base, base
            ),
            integration_note: None,
            detected_active: true,
        },
        HarnessProfile {
            kind: HarnessKind::Qoder,
            name: "Qoder".to_string(),
            vendor_name: "Qoder AI IDE & Indexing Cloud".to_string(),
            default_upstream: "https://api.qoder.com".to_string(),
            local_proxy_route: "/qoder".to_string(),
            protocol_family: "Qoder Agent & Codebase Vector Sync API".to_string(),
            description: "面向大型工程的 AI 研发 IDE，内置全量代码库向量索引器与自主任务执行器。"
                .to_string(),
            risk_summary: vec![
                "后台静默触发全仓库代码切片向量化上传 (/v1/index/upload)".to_string(),
                "跨模块调用链分析会将核心算法实现与内部 RPC 协议发送至云端".to_string(),
                "持续心跳与行为遥测记录开发者编辑历史".to_string(),
            ],
            env_setup_bash: format!("export QODER_BASE_URL=\"{}/qoder\"\nqoder", base),
            env_setup_powershell: format!("$env:QODER_BASE_URL=\"{}/qoder\"\nqoder", base),
            integration_note: Some("仅当客户端允许覆盖 API Base URL 时可接入；内置索引通道若不读取该变量将不会经过网关。".to_string()),
            detected_active: true,
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
                "# Cursor Settings -> Models -> Override OpenAI Base URL:\n{}/cursor/v1",
                base
            ),
            env_setup_powershell: format!(
                "# Cursor Settings -> Models -> Override OpenAI Base URL:\n{}/cursor/v1",
                base
            ),
            integration_note: Some("Cursor 的自定义 Base URL 请求由 Cursor 服务器转发，无法直接访问 127.0.0.1；需要通过你自己的 HTTPS 隧道暴露网关，并自行承担暴露风险。".to_string()),
            detected_active: true,
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
                "export XAI_BASE_URL=\"{}/grok-build/v1\"\ngrok-build",
                base
            ),
            env_setup_powershell: format!(
                "$env:XAI_BASE_URL=\"{}/grok-build/v1\"\ngrok-build",
                base
            ),
            integration_note: None,
            detected_active: true,
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

    let segments: Vec<&str> = path_lower.split(['/', '?', ':']).filter(|s| !s.is_empty()).collect();
    let has_segment = |names: &[&str]| segments.iter().any(|s| names.contains(s));

    let category = if is_inference_endpoint(&path_lower) {
        if body.contains("\"tool_result\"")
            || body.contains("\"function_call_output\"")
            || body.contains("\"role\":\"tool\"")
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
        "upload-chunks",
    ]) || path_lower.contains("codebase_sync")
    {
        TrafficCategory::CodebaseIndexing
    } else {
        TrafficCategory::InteractivePrompt
    };

    (harness, category)
}
