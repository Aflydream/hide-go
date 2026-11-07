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
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-0078D6)](#下载运行)
[![Release](https://img.shields.io/github/v/release/Aflydream/hide-go?color=10b981)](https://github.com/Aflydream/hide-go/releases)
[![License](https://img.shields.io/badge/License-MIT-slate)](LICENSE)

[English](./README.md) | **简体中文**

[下载安装](#下载运行) · [它是怎么拦的](#三种工作模式) · [支持的工具](#已适配的-7-款工具) · [源码构建](#本地编译)

</div>

---

用 Claude Code、Cursor、Codex 写代码确实快，但如果你抓包看一眼它们往外发的请求，多半会吓一跳：很多时候你只是让它改一行报错，客户端已经在后台把你的 `.env`、Git 远端地址、内网数据库 IP、甚至整个工程目录树打包发往了云端（比如 `/api/event_logging` 或后台静默的 `repo-indexing`）。

**Hide-Go** 卡在本地工具和云端厂商之间。它是一个不到 10MB 的 Rust 单文件桌面程序，在请求出境前把真机密换成假数据或伪装代码，等大模型流式返回时再在本地毫秒级还原回去。

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
| **2. 自动双向脱敏** | 日常写业务代码，防密钥/内网拓扑外泄 | 含真实 DB 连接串、API Key、绝对路径 | 替换为**同格式的合法假数据**，模型返回时自动换回真值 |
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
// [BotanicalSensor-01] Calibrate greenhouse soil humidity
// 路径: /workspace/sandbox_proj/src/module_01.rs
pub fn check_orchid_soil_moisture(
    terrarium_sensor_id: &str,
) -> bool {
    let db = "postgres://db_user_01:pass_01@10.254.0.2:5432/app_01";
    let key = "sk-sem-placeholder-key-0001";
    compute_foliage_hydration_index(terrarium_sensor_id, db, key)
}
```

</td>
</tr>
</table>

> **为什么模型还能正常改代码？**
> 因为 `pub fn`、参数类型、返回值和调用关系（AST 结构）完全没变。模型顺着“兰花土壤湿度”帮你修好逻辑并发回 SSE 数据流时，Hide-Go 的 `StreamRestorer` 会在本地把 `check_orchid_soil_moisture` 实时换回 `verify_margin_liquidation`。

---

## All-Hide 的三个子开关

除了把标识符映射成其它行业词表，All-Hide 面板里还可以单独组合下面三项：

* 🌱 **同构领域伪装（Isomorphic Camouflage）**：内置 `植物园温室管理`、`公共图书馆编目`、`烘焙坊温控配方` 三套词库，按项目 Salt 确定性哈希映射函数名、结构体、变量和注释。
* ⠿ **高熵盲文乱码（Cipher Garble）**：把载荷用动态异或加盲文点阵块编码成 `⟦HIDE-CIPHER::⠷⠩⡬⡺⢵⣑⡬...⟧`，专门对付厂商侧的明文日志审计与正则爬虫，返回本地时自动解码。
* 🎭 **静默遥测与索引投毒（Telemetry & Indexing Chaff）**：很多 IDE 一旦直接封死遥测或 `repo-indexing` 接口就会弹窗报错。开启后，Hide-Go 遇到后台静默上传请求时，会现场生成一份体积相近的假代码喂给厂商，既防泄露又不报错。

---

## 已适配的 7 款工具

程序内置了以下工具的请求指纹识别与专属路由（桌面端内可一键复制环境变量脚本）：

| 工具名称 | 本地代理路由 | 重点拦截项 |
| :--- | :--- | :--- |
| **Claude Code** | `http://127.0.0.1:18787/claude-code` | `CLAUDE.md` 注入、目录读取回传、`/api/event_logging` 遥测 |
| **OpenAI Codex** | `http://127.0.0.1:18787/codex` | 沙箱环境上下文、终端执行日志中的密钥 |
| **Antigravity** | `http://127.0.0.1:18787/antigravity` | 工作区挂载资源路径、跨文件代码片段 |
| **ZCode** | `http://127.0.0.1:18787/zcode` | 打开文件快照、自动补全上下文 |
| **Qoder** | `http://127.0.0.1:18787/qoder` | 后台全量代码库向量索引上传（Codebase Indexing） |
| **Cursor** | `http://127.0.0.1:18787/cursor` | Composer 多文件上下文、`repo-service` 分块上传 |
| **Grok Build** | `http://127.0.0.1:18787/grok-build` | 构建源码打包传输、构建报错日志中的内网地址 |

<details>
<summary><b>📋 点击展开：命令行一键接入示例（Bash / PowerShell）</b></summary>

**Linux / macOS (Bash / Zsh)**
```bash
# Claude Code
export ANTHROPIC_BASE_URL="http://127.0.0.1:18787/claude-code"

# OpenAI Codex
export OPENAI_BASE_URL="http://127.0.0.1:18787/codex"

# Grok Build
export XAI_BASE_URL="http://127.0.0.1:18787/grok-build"
```

**Windows (PowerShell)**
```powershell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:18787/claude-code"
$env:OPENAI_BASE_URL    = "http://127.0.0.1:18787/codex"
$env:XAI_BASE_URL       = "http://127.0.0.1:18787/grok-build"
```

</details>

---

## 下载运行

直接从 [Releases 页面](https://github.com/Aflydream/hide-go/releases) 下载对应系统的单文件程序。前端界面已经通过 `include_bytes!` 编译进同一个二进制文件，不需要装 Node.js：

* **Windows (x64)**：下载 `hide-go-desktop-windows-x64.exe` 双击运行
* **macOS (Apple Silicon)**：
  ```bash
  chmod +x hide-go-desktop-macos-arm64 && ./hide-go-desktop-macos-arm64
  ```
* **Linux (x86_64)**：
  ```bash
  chmod +x hide-go-desktop-linux-x86_64 && ./hide-go-desktop-linux-x86_64
  ```

运行后会自动监听 `127.0.0.1:18787` 并拉起桌面控制台窗口。如果只想在服务器后台跑纯网关守护进程，加环境变量 `HIDE_GO_HEADLESS=1` 即可。

---

## 本地编译

环境要求：Rust `1.80+`，Node.js `20+`（仅在修改前端界面重新生成静态资源时需要）。

```bash
# 1. 运行核心单元测试（7 大工具识别、双向脱敏、同构伪装、SSE 跨包流式还原）
cargo test --workspace

# 2. 打包前端并编译进单文件桌面程序
npm install && npm run build
cargo build --release -p hide-go-desktop
```

### 代码结构

```text
hide-go/
├── crates/hide-core/          # Rust 核心引擎
│   └── src/
│       ├── scanner.rs         # 密钥、私钥、DB 连接串、内网 IP 与路径正则扫描
│       ├── vault.rs           # 线程安全双向语义字典 (Token <-> 原文)
│       ├── desensitizer.rs    # 格式保持假数据生成器
│       ├── all_hide.rs        # 同构伪装词表、盲文乱码编码器、Chaff 生成器
│       ├── stream_restorer.rs # SSE 流式滑动窗口跨 Chunk 边界还原器
│       └── proxy.rs           # Axum 异步反向代理与沙箱仿真器
├── src/                       # 桌面端 UI (四栏实时对照台、规则与保险箱管理)
└── src-tauri/                 # 单文件静态资源内嵌与原生窗口启动器
```
