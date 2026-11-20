use crate::ca::{CaManager, CaTrustAdapter, RealCaTrustAdapter};
use crate::config::{HarnessKind, HideConfig};
use crate::harness::{get_all_harness_profiles, AutoConnectMode, HarnessProfile};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
#[cfg(any(windows, test))]
use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static HARNESS_MUTEX: Mutex<()> = Mutex::new(());
static TEMP_WRITE_SEQ: AtomicU64 = AtomicU64::new(1);

const SHARED_PROXY_VARS: &[&str] = &[
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
];
const DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1,::1";
const VSCODE_HTTP_NO_PROXY: &[&str] = &["localhost", "127.0.0.1", "::1", ".local"];

fn ensure_not_symlink(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!("安全拦截: 拒绝写入符号链接路径 {}", path.display())),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("检查目标路径 {} 失败: {e}", path.display())),
    }
}

fn write_atomic_secure(path: &Path, bytes: &[u8]) -> Result<(), String> {
    ensure_not_symlink(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("路径 {} 缺少父目录", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| format!("创建目录 {} 失败: {e}", parent.display()))?;

    let seq = TEMP_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp_path = parent.join(format!(".{file_name}.hidego.tmp.{}.{seq}", std::process::id()));

    let write_res = (|| -> Result<(), String> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .map_err(|e| format!("创建临时文件 {} 失败: {e}", tmp_path.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("写入临时文件 {} 失败: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("同步临时文件 {} 失败: {e}", tmp_path.display()))?;
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp_path, path).map_err(|e| format!("原子替换 {} 失败: {e}", path.display()))
    })();

    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

fn is_valid_snapshot_rel(rel: &str) -> bool {
    let p = Path::new(rel);
    !rel.is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)))
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_env_assignment(name: &str, value: Option<&str>) -> Result<(), String> {
    if !is_valid_env_name(name) {
        return Err(format!("非法环境变量名: {name}"));
    }
    if let Some(v) = value {
        if v.contains(['\0', '\r', '\n']) {
            return Err(format!("环境变量 {name} 包含非法控制字符"));
        }
    }
    Ok(())
}

/// Summary returned after connecting or disconnecting an AI harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessActionResult {
    pub kind: HarnessKind,
    pub ok: bool,
    pub connected: bool,
    pub message: String,
    pub changed_target: Option<String>,
    pub backup_path: Option<String>,
}

/// Windows Uninstall registry metadata entry for installed app discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallEntry {
    pub display_name: String,
    pub install_location: Option<String>,
    pub display_icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct FileBackupEntry {
    path: String,
    had_file: bool,
    had_env_object: bool,
    raw_snapshot_rel: Option<String>,
    #[serde(default)]
    prev_keys: HashMap<String, Option<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct HarnessBackup {
    // Legacy single-target fields (kept for backward compatibility when disconnecting old backups)
    #[serde(default)]
    had_file: bool,
    #[serde(default)]
    had_env_object: bool,
    #[serde(default)]
    prev_value: Option<String>,
    #[serde(default)]
    env_var: Option<String>,
    // Wave 2A structured fields
    #[serde(default)]
    files: Vec<FileBackupEntry>,
    #[serde(default)]
    prev_env_vars: HashMap<String, Option<String>>,
    #[serde(default)]
    shared_env_vars: Vec<String>,
    #[serde(default)]
    wrote_config_upstream: bool,
    #[serde(default)]
    prev_config_upstream: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SharedEnvLeaseEntry {
    prev_value: Option<String>,
    owners: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SharedEnvLeases {
    vars: HashMap<String, SharedEnvLeaseEntry>,
}

struct HarnessSpec {
    kind: HarnessKind,
    binaries: &'static [&'static str],
    home_paths: &'static [&'static str],
    appdata_paths: &'static [&'static str],
    local_appdata_paths: &'static [&'static str],
    mac_apps: &'static [&'static str],
    registry_keywords: &'static [&'static str],
    requires_ca_trust: bool,
}

const SPECS: &[HarnessSpec] = &[
    HarnessSpec {
        kind: HarnessKind::ClaudeCode,
        binaries: &["claude"],
        home_paths: &[
            ".claude/settings.json",
            ".claude.json",
            ".claude/local/claude",
            ".claude/local/claude.exe",
            ".local/bin/claude",
            ".local/bin/claude.exe",
        ],
        appdata_paths: &["npm/claude.cmd"],
        local_appdata_paths: &["Programs/claude", "AnthropicClaude"],
        mac_apps: &["/Applications/Claude.app"],
        registry_keywords: &["claude"],
        requires_ca_trust: false,
    },
    HarnessSpec {
        kind: HarnessKind::Codex,
        binaries: &["codex"],
        home_paths: &[
            ".codex/config.toml",
            ".codex",
            ".local/bin/codex",
            ".local/bin/codex.exe",
        ],
        appdata_paths: &["npm/codex.cmd"],
        local_appdata_paths: &["Programs/OpenAI/Codex/bin/codex.exe", "Programs/OpenAI/Codex"],
        mac_apps: &["/Applications/Codex.app"],
        registry_keywords: &["openai codex", "codex"],
        requires_ca_trust: true,
    },
    HarnessSpec {
        kind: HarnessKind::Antigravity,
        binaries: &["antigravity", "agy"],
        home_paths: &[".gemini/antigravity", ".antigravity"],
        appdata_paths: &["Antigravity IDE/User/settings.json", "Antigravity/User/settings.json"],
        local_appdata_paths: &["Programs/Antigravity", "Programs/antigravity", "agy/bin/agy.exe"],
        mac_apps: &["/Applications/Antigravity.app", "/Applications/Antigravity IDE.app"],
        registry_keywords: &["antigravity"],
        requires_ca_trust: true,
    },
    HarnessSpec {
        kind: HarnessKind::Zcode,
        binaries: &["zcode"],
        home_paths: &[".zcode/v2/setting.json", ".zcode", ".config/zcode"],
        appdata_paths: &["ZCode"],
        local_appdata_paths: &["Programs/ZCode", "@zcodedesktop-updater"],
        mac_apps: &["/Applications/ZCode.app"],
        registry_keywords: &["zcode"],
        requires_ca_trust: true,
    },
    HarnessSpec {
        kind: HarnessKind::Qoder,
        binaries: &["qoder"],
        home_paths: &[
            ".qoder",
            ".qoder-cn",
            ".config/Qoder/User/settings.json",
            ".config/QoderCN/User/settings.json",
            "Library/Application Support/Qoder/User/settings.json",
            "Library/Application Support/QoderCN/User/settings.json",
        ],
        appdata_paths: &["Qoder/User/settings.json", "QoderCN/User/settings.json"],
        local_appdata_paths: &["Programs/Qoder", "Programs/QoderCN"],
        mac_apps: &["/Applications/Qoder.app", "/Applications/Qoder CN.app"],
        registry_keywords: &["qoder"],
        requires_ca_trust: true,
    },
    HarnessSpec {
        kind: HarnessKind::Cursor,
        binaries: &["cursor"],
        home_paths: &[
            ".cursor",
            ".config/Cursor/User/settings.json",
            "Library/Application Support/Cursor/User/settings.json",
        ],
        appdata_paths: &["Cursor/User/settings.json"],
        local_appdata_paths: &["Programs/cursor/Cursor.exe", "Programs/Cursor"],
        mac_apps: &["/Applications/Cursor.app"],
        registry_keywords: &["cursor"],
        requires_ca_trust: true,
    },
    HarnessSpec {
        kind: HarnessKind::GrokBuild,
        binaries: &["grok", "grok-build"],
        home_paths: &[
            ".grok/config.toml",
            ".grok",
            ".grok/bin/grok.exe",
            ".grok/bin/grok",
            ".grokbot",
            ".grok-build",
            ".config/grok-build",
        ],
        appdata_paths: &["Grok Bot"],
        local_appdata_paths: &["Programs/Grok Bot"],
        mac_apps: &["/Applications/Grok Bot.app"],
        registry_keywords: &["grok bot", "grok-build"],
        requires_ca_trust: true,
    },
];

fn spec_for(kind: HarnessKind) -> Option<&'static HarnessSpec> {
    SPECS.iter().find(|s| s.kind == kind)
}

pub fn harness_slug(kind: HarnessKind) -> &'static str {
    match kind {
        HarnessKind::ClaudeCode => "claude-code",
        HarnessKind::Codex => "codex",
        HarnessKind::Antigravity => "antigravity",
        HarnessKind::Zcode => "zcode",
        HarnessKind::Qoder => "qoder",
        HarnessKind::Cursor => "cursor",
        HarnessKind::GrokBuild => "grok-build",
        HarnessKind::Generic => "generic",
    }
}

pub fn parse_harness_slug(slug: &str) -> Option<HarnessKind> {
    match slug.trim().to_ascii_lowercase().as_str() {
        "claude-code" | "claude_code" | "claudecode" => Some(HarnessKind::ClaudeCode),
        "codex" => Some(HarnessKind::Codex),
        "antigravity" => Some(HarnessKind::Antigravity),
        "zcode" => Some(HarnessKind::Zcode),
        "qoder" => Some(HarnessKind::Qoder),
        "cursor" => Some(HarnessKind::Cursor),
        "grok-build" | "grok_build" | "grokbuild" => Some(HarnessKind::GrokBuild),
        _ => None,
    }
}

/// Abstract environment & host-paths adapter so detection and connection are
/// fully testable without touching the real user profile or Windows registry.
pub trait HostAdapter {
    fn home_dir(&self) -> Option<PathBuf>;
    fn appdata_dir(&self) -> Option<PathBuf>;
    fn local_appdata_dir(&self) -> Option<PathBuf>;
    fn backup_dir(&self) -> Option<PathBuf>;
    fn path_dirs(&self) -> Vec<PathBuf>;
    fn process_env(&self, name: &str) -> Option<String>;
    fn user_env_get(&self, name: &str) -> Option<String>;
    fn user_env_set(&self, name: &str, value: &str) -> Result<(), String>;
    fn user_env_remove(&self, name: &str) -> Result<(), String>;
    fn windows_uninstall_entries(&self) -> Vec<UninstallEntry> {
        Vec::new()
    }
}

/// Production host adapter backed by the real filesystem, PATH, and user environment.
pub struct RealHostAdapter;

impl HostAdapter for RealHostAdapter {
    fn home_dir(&self) -> Option<PathBuf> {
        let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        if cfg!(windows) {
            env("USERPROFILE").or_else(|| env("HOME"))
        } else {
            env("HOME")
        }
    }

    fn appdata_dir(&self) -> Option<PathBuf> {
        let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        if cfg!(windows) {
            env("APPDATA")
        } else if cfg!(target_os = "macos") {
            self.home_dir().map(|h| h.join("Library/Application Support"))
        } else {
            env("XDG_CONFIG_HOME").or_else(|| self.home_dir().map(|h| h.join(".config")))
        }
    }

    fn local_appdata_dir(&self) -> Option<PathBuf> {
        let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        if cfg!(windows) {
            env("LOCALAPPDATA")
        } else if cfg!(target_os = "macos") {
            self.home_dir().map(|h| h.join("Library/Application Support"))
        } else {
            env("XDG_DATA_HOME").or_else(|| self.home_dir().map(|h| h.join(".local/share")))
        }
    }

    fn backup_dir(&self) -> Option<PathBuf> {
        HideConfig::default_path()
            .and_then(|p| p.parent().map(|d| d.join("harness-backups")))
            .or_else(|| self.appdata_dir().map(|d| d.join("hide-go").join("harness-backups")))
    }

    fn path_dirs(&self) -> Vec<PathBuf> {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default()
    }

    fn process_env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn user_env_get(&self, name: &str) -> Option<String> {
        #[cfg(windows)]
        {
            self.home_dir()
                .and_then(|home| read_windows_managed_env_var(&home, name))
        }
        #[cfg(not(windows))]
        {
            self.home_dir().and_then(|home| read_shell_rc_var(&home, name))
        }
    }

    fn user_env_set(&self, name: &str, value: &str) -> Result<(), String> {
        #[cfg(windows)]
        {
            let home = self
                .home_dir()
                .ok_or_else(|| "cannot resolve home directory".to_string())?;
            write_windows_managed_env_var(&home, name, Some(value))
        }
        #[cfg(not(windows))]
        {
            let home = self
                .home_dir()
                .ok_or_else(|| "cannot resolve home directory".to_string())?;
            write_shell_rc_var(&home, name, Some(value))
        }
    }

    fn user_env_remove(&self, name: &str) -> Result<(), String> {
        #[cfg(windows)]
        {
            let home = self
                .home_dir()
                .ok_or_else(|| "cannot resolve home directory".to_string())?;
            write_windows_managed_env_var(&home, name, None)
        }
        #[cfg(not(windows))]
        {
            let home = self
                .home_dir()
                .ok_or_else(|| "cannot resolve home directory".to_string())?;
            write_shell_rc_var(&home, name, None)
        }
    }

    fn windows_uninstall_entries(&self) -> Vec<UninstallEntry> {
        #[cfg(windows)]
        {
            query_windows_uninstall_entries()
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }
}

/// Build a child `Command` that suppresses transient console windows on Windows GUI apps.
pub fn hidden_command(program: &str) -> std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut cmd = std::process::Command::new(program);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new(program)
    }
}

#[cfg(any(windows, test))]
const WIN_MANAGED_ENV_START: &str = "# >>> hide-go-env >>>";
#[cfg(any(windows, test))]
const WIN_MANAGED_ENV_END: &str = "# <<< hide-go-env <<<";

#[cfg(any(windows, test))]
fn escape_powershell_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(any(windows, test))]
fn escape_cmd_value(value: &str) -> String {
    // In `set "NAME=VALUE"`, `%` still triggers variable expansion in batch scripts unless doubled,
    // and double quotes are forbidden inside `set "NAME=VALUE"`.
    value.replace('"', "").replace('%', "%%")
}

#[cfg(any(windows, test))]
fn managed_env_ps1_path(home: &Path) -> PathBuf {
    home.join(".hide-go").join("env.ps1")
}

#[cfg(any(windows, test))]
fn managed_env_cmd_path(home: &Path) -> PathBuf {
    home.join(".hide-go").join("env.cmd")
}

#[cfg(any(windows, test))]
fn candidate_powershell_profiles(home: &Path) -> Vec<PathBuf> {
    let docs = home.join("Documents");
    let mut out = Vec::new();
    for dir in [docs.join("PowerShell"), docs.join("WindowsPowerShell")] {
        let profile = dir.join("Microsoft.PowerShell_profile.ps1");
        if dir.exists() || profile.exists() {
            out.push(profile);
        }
    }
    if out.is_empty() {
        out.push(docs.join("WindowsPowerShell").join("Microsoft.PowerShell_profile.ps1"));
    }
    out
}

#[cfg(any(windows, test))]
fn parse_managed_ps1_vars(content: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("$env:") else {
            continue;
        };
        let Some((name, rhs)) = rest.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !is_valid_env_name(name) {
            continue;
        }
        let rhs = rhs.trim();
        if let Some(inner) = rhs.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            vars.insert(name.to_string(), inner.replace("''", "'"));
        }
    }
    vars
}

#[cfg(any(windows, test))]
fn read_windows_managed_env_var(home: &Path, name: &str) -> Option<String> {
    if !is_valid_env_name(name) {
        return None;
    }
    let content = std::fs::read_to_string(managed_env_ps1_path(home)).ok()?;
    parse_managed_ps1_vars(&content).remove(name)
}

#[cfg(any(windows, test))]
fn sync_powershell_profile_source_block(home: &Path, enable: bool) -> Result<(), String> {
    let ps1_path = managed_env_ps1_path(home);
    let escaped_path = escape_powershell_single_quoted(&ps1_path.to_string_lossy());
    let snippet = format!(
        "{WIN_MANAGED_ENV_START}\nif (Test-Path '{escaped_path}') {{ . '{escaped_path}' }}\n{WIN_MANAGED_ENV_END}\n"
    );

    for profile in candidate_powershell_profiles(home) {
        let existing = match std::fs::read_to_string(&profile) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !enable {
                    continue;
                }
                String::new()
            }
            Err(e) => return Err(format!("读取 PowerShell Profile {} 失败: {e}", profile.display())),
        };

        let mut kept: Vec<&str> = Vec::new();
        let mut skipping = false;
        for line in existing.lines() {
            if line.trim() == WIN_MANAGED_ENV_START {
                skipping = true;
                continue;
            }
            if skipping {
                if line.trim() == WIN_MANAGED_ENV_END {
                    skipping = false;
                }
                continue;
            }
            kept.push(line);
        }
        let mut next = kept.join("\n");
        if !next.is_empty() && !next.ends_with('\n') {
            next.push('\n');
        }
        if enable {
            next.push_str(&snippet);
        }
        if !enable && next.trim().is_empty() && profile.exists() {
            let _ = std::fs::remove_file(&profile);
            continue;
        }
        if enable || profile.exists() {
            write_atomic_secure(&profile, next.as_bytes())?;
        }
    }
    Ok(())
}

fn extract_local_port_from_url(raw: &str) -> Option<u16> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    match url.host_str() {
        Some("127.0.0.1" | "localhost") => url.port().filter(|&p| p > 0),
        _ => None,
    }
}

#[cfg(any(windows, test))]
fn extract_local_proxy_port(vars: &BTreeMap<String, String>) -> Option<u16> {
    const PROXY_KEYS: &[&str] = &[
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ZCODE_HTTP_PROXY",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "GROK_XAI_API_BASE_URL",
        "GROK_CLI_CHAT_PROXY_BASE_URL",
        "GROK_CLI_BASE_URL",
    ];
    for key in PROXY_KEYS {
        if let Some(val) = vars.get(*key) {
            if let Some(port) = extract_local_port_from_url(val) {
                return Some(port);
            }
        }
    }
    None
}

/// Persist Windows harness env variables purely in `~/.hide-go/env.ps1`, `~/.hide-go/env.cmd`,
/// and a guarded PowerShell `$PROFILE` source block — zero Windows Registry modifications.
#[cfg(any(windows, test))]
fn write_windows_managed_env_var(home: &Path, name: &str, value: Option<&str>) -> Result<(), String> {
    validate_env_assignment(name, value)?;
    let ps1_path = managed_env_ps1_path(home);
    let cmd_path = managed_env_cmd_path(home);

    let existing = std::fs::read_to_string(&ps1_path).unwrap_or_default();
    let mut vars = parse_managed_ps1_vars(&existing);
    match value {
        Some(v) => {
            vars.insert(name.to_string(), v.to_string());
        }
        None => {
            vars.remove(name);
        }
    }

    if vars.is_empty() {
        for p in [&ps1_path, &cmd_path] {
            if p.exists() {
                std::fs::remove_file(p).map_err(|e| format!("移除 {} 失败: {e}", p.display()))?;
            }
        }
        sync_powershell_profile_source_block(home, false)?;
        return Ok(());
    }

    let mut ps1 = String::from("# Hide-Go managed environment variables (no Windows Registry edits)\n");
    let mut cmd = String::from("@echo off\r\nREM Hide-Go managed environment variables\r\n");
    if let Some(port) = extract_local_proxy_port(&vars) {
        ps1.push_str(&format!(
            "$__hgAlive = $false\n\
             try {{\n  \
               $__hgTcp = [System.Net.Sockets.TcpClient]::new()\n  \
               $__hgAr = $__hgTcp.BeginConnect('127.0.0.1', {port}, $null, $null)\n  \
               if ($__hgAr.AsyncWaitHandle.WaitOne(50, $false)) {{ $__hgTcp.EndConnect($__hgAr); $__hgAlive = $true }}\n  \
               $__hgTcp.Close()\n\
             }} catch {{}}\n\
             if ($__hgAlive) {{\n"
        ));
        for (k, v) in &vars {
            ps1.push_str(&format!("  $env:{k} = '{}'\n", escape_powershell_single_quoted(v)));
            cmd.push_str(&format!("set \"{k}={}\"\r\n", escape_cmd_value(v)));
        }
        ps1.push_str("}\n");
    } else {
        for (k, v) in &vars {
            ps1.push_str(&format!("$env:{k} = '{}'\n", escape_powershell_single_quoted(v)));
            cmd.push_str(&format!("set \"{k}={}\"\r\n", escape_cmd_value(v)));
        }
    }
    write_atomic_secure(&ps1_path, ps1.as_bytes())?;
    write_atomic_secure(&cmd_path, cmd.as_bytes())?;
    sync_powershell_profile_source_block(home, true)?;
    Ok(())
}

#[cfg(windows)]
fn resolved_powershell_path() -> Option<PathBuf> {
    for var in ["SystemRoot", "WINDIR"] {
        if let Ok(root) = std::env::var(var) {
            let candidate = PathBuf::from(root)
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
fn query_windows_uninstall_entries() -> Vec<UninstallEntry> {
    let Some(ps_exe) = resolved_powershell_path() else {
        return Vec::new();
    };
    let script = r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$paths = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$items = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  ForEach-Object {
    [PSCustomObject]@{
      displayName = [string]$_.DisplayName
      installLocation = if ($_.InstallLocation) { [string]$_.InstallLocation } else { $null }
      displayIcon = if ($_.DisplayIcon) { [string]$_.DisplayIcon } else { $null }
    }
  }
$items | ConvertTo-Json -Compress
"#;
    let Ok(out) = hidden_command(&ps_exe.to_string_lossy())
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| serde_json::from_value::<UninstallEntry>(v).ok())
            .collect(),
        Ok(obj @ Value::Object(_)) => serde_json::from_value::<UninstallEntry>(obj).ok().into_iter().collect(),
        _ => Vec::new(),
    }
}

#[cfg(any(not(windows), test))]
fn shell_rc_marker_start(name: &str) -> String {
    format!("# >>> hide-go {name} >>>")
}

#[cfg(any(not(windows), test))]
fn shell_rc_marker_end(name: &str) -> String {
    format!("# <<< hide-go {name} <<<")
}

#[cfg(any(not(windows), test))]
fn candidate_shell_rcs(home: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = [".zshrc", ".bashrc", ".bash_profile", ".profile"]
        .iter()
        .map(|f| home.join(f))
        .filter(|p| p.exists())
        .collect();
    if files.is_empty() {
        #[cfg(target_os = "macos")]
        files.push(home.join(".zshrc"));
        #[cfg(not(target_os = "macos"))]
        files.push(home.join(".profile"));
    }
    files
}

#[cfg(any(not(windows), test))]
fn parse_shell_exported_value(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return inner.replace("'\\''", "'");
    }
    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return inner.replace("\\\"", "\"");
    }
    trimmed.to_string()
}

#[cfg(any(not(windows), test))]
fn read_shell_rc_var(home: &Path, name: &str) -> Option<String> {
    if !is_valid_env_name(name) {
        return None;
    }
    let start = shell_rc_marker_start(name);
    let end = shell_rc_marker_end(name);
    let prefix = format!("export {name}=");
    for path in candidate_shell_rcs(home) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut inside = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == start {
                inside = true;
                continue;
            }
            if trimmed == end {
                inside = false;
                continue;
            }
            if inside {
                if let Some(rest) = trimmed.strip_prefix(&prefix) {
                    return Some(parse_shell_exported_value(rest));
                }
            }
        }
    }
    None
}

#[cfg(any(not(windows), test))]
fn write_shell_rc_var(home: &Path, name: &str, value: Option<&str>) -> Result<(), String> {
    validate_env_assignment(name, value)?;
    let start = shell_rc_marker_start(name);
    let end = shell_rc_marker_end(name);
    for path in candidate_shell_rcs(home) {
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let mut kept: Vec<&str> = Vec::new();
        let mut skipping = false;
        for line in existing.lines() {
            if line.trim() == start {
                skipping = true;
                continue;
            }
            if skipping {
                if line.trim() == end {
                    skipping = false;
                }
                continue;
            }
            kept.push(line);
        }
        let mut next = kept.join("\n");
        if !next.is_empty() && !next.ends_with('\n') {
            next.push('\n');
        }
        if let Some(v) = value {
            // POSIX single-quote escaping guarantees `$()`, backticks, and spaces stay inert.
            let escaped = v.replace('\'', "'\\''");
            if let Some(port) = extract_local_port_from_url(v) {
                next.push_str(&format!(
                    "{start}\nif ! command -v nc >/dev/null 2>&1 || nc -z -w 1 127.0.0.1 {port} >/dev/null 2>&1; then\n  export {name}='{escaped}'\nfi\n{end}\n"
                ));
            } else {
                next.push_str(&format!("{start}\nexport {name}='{escaped}'\n{end}\n"));
            }
        }
        write_atomic_secure(&path, next.as_bytes())?;
    }
    Ok(())
}

fn find_binary_in_dirs(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    for dir in dirs {
        for ext in exts {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn clean_display_icon_path(raw: &str) -> Option<PathBuf> {
    let mut s = raw.trim().trim_matches('"').trim();
    if let Some((path_part, suffix)) = s.rsplit_once(',') {
        if !suffix.trim().is_empty() && suffix.trim().chars().all(|c| c.is_ascii_digit() || c == '-') {
            s = path_part.trim().trim_matches('"');
        }
    }
    (!s.is_empty()).then(|| PathBuf::from(s))
}

fn discover_paths(spec: &HarnessSpec, host: &dyn HostAdapter) -> Vec<String> {
    let mut found = BTreeSet::new();
    let path_dirs = host.path_dirs();
    for bin in spec.binaries {
        if let Some(p) = find_binary_in_dirs(bin, &path_dirs) {
            found.insert(p.to_string_lossy().into_owned());
        }
    }
    if let Some(home) = host.home_dir() {
        for rel in spec.home_paths {
            let p = home.join(rel);
            if p.exists() {
                found.insert(p.to_string_lossy().into_owned());
            }
        }
    }
    if let Some(appdata) = host.appdata_dir() {
        for rel in spec.appdata_paths {
            let p = appdata.join(rel);
            if p.exists() {
                found.insert(p.to_string_lossy().into_owned());
            }
        }
    }
    if let Some(local) = host.local_appdata_dir() {
        for rel in spec.local_appdata_paths {
            let p = local.join(rel);
            if p.exists() {
                found.insert(p.to_string_lossy().into_owned());
            }
        }
    }
    for entry in host.windows_uninstall_entries() {
        let lower_name = entry.display_name.to_ascii_lowercase();
        if spec.registry_keywords.iter().any(|kw| lower_name.contains(kw)) {
            if let Some(icon) = entry.display_icon.as_deref().and_then(clean_display_icon_path) {
                if icon.exists() {
                    found.insert(icon.to_string_lossy().into_owned());
                }
            }
            if let Some(loc) = entry
                .install_location
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let p = Path::new(loc);
                if p.exists() {
                    found.insert(p.to_string_lossy().into_owned());
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    for app in spec.mac_apps {
        let p = Path::new(app);
        if p.exists() {
            found.insert(p.to_string_lossy().into_owned());
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = spec.mac_apps;
    found.into_iter().collect()
}

fn points_to_local_gateway(value: &str, route_prefix: &str, proxy_port: u16) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    let route_lower = route_prefix.to_ascii_lowercase();
    let prefix_ip = format!("http://127.0.0.1:{proxy_port}");
    let prefix_host = format!("http://localhost:{proxy_port}");
    let Some(rest) = lower
        .strip_prefix(&prefix_ip)
        .or_else(|| lower.strip_prefix(&prefix_host))
    else {
        return false;
    };
    rest.starts_with(&route_lower)
        && rest[route_lower.len()..]
            .chars()
            .next()
            .is_none_or(|c| matches!(c, '/' | '?' | '#'))
}

/// Returns `true` only when `url` already targets Hide-Go itself (`proxy_port` on loopback
/// or a known Hide-Go harness route prefix on loopback), so external loopback gateways such as
/// `cc-switch` on a different port are preserved as upstream targets rather than skipped.
fn points_to_hidego_gateway(url: &str, route_prefix: &str, proxy_port: u16) -> bool {
    if points_to_local_gateway(url, route_prefix, proxy_port) {
        return true;
    }
    let trimmed = url.trim().to_ascii_lowercase();
    for base in [
        format!("http://127.0.0.1:{proxy_port}"),
        format!("http://localhost:{proxy_port}"),
    ] {
        if let Some(rest) = trimmed.strip_prefix(&base) {
            if rest.is_empty() || rest.starts_with(['/', '?', '#']) {
                return true;
            }
        }
    }
    false
}

/// Strip `//` line comments, `/* ... */` block comments, and trailing commas outside JSON strings
/// so VS Code / Electron `User/settings.json` (JSONC) files parse cleanly with `serde_json`.
fn strip_jsonc_comments_and_trailing_commas(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut no_comments = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            no_comments.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if b == b'"' {
            in_string = true;
            no_comments.push(b);
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        no_comments.push(b);
        i += 1;
    }

    // Second pass: drop trailing commas immediately preceding `}` or `]` outside strings.
    let mut out = Vec::with_capacity(no_comments.len());
    let mut j = 0;
    in_string = false;
    escaped = false;
    while j < no_comments.len() {
        let b = no_comments[j];
        if in_string {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            j += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push(b);
            j += 1;
            continue;
        }
        if b == b',' {
            let mut k = j + 1;
            while k < no_comments.len() && no_comments[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < no_comments.len() && matches!(no_comments[k], b'}' | b']') {
                j += 1;
                continue;
            }
        }
        out.push(b);
        j += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn parse_jsonc_value(raw: &str) -> Result<Value, String> {
    let raw = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
    let cleaned = strip_jsonc_comments_and_trailing_commas(raw);
    if cleaned.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    serde_json::from_str::<Value>(&cleaned).map_err(|e| format!("JSON/JSONC 解析失败: {e}"))
}

fn contains_jsonc_syntax(raw: &str) -> bool {
    raw.contains("//") || raw.contains("/*")
}

fn merge_no_proxy(existing: Option<&str>) -> String {
    let mut items: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(prev) = existing {
        for part in prev.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let key = part.to_ascii_lowercase();
            if seen.insert(key) {
                items.push(part.to_string());
            }
        }
    }
    for req in DEFAULT_NO_PROXY.split(',') {
        let key = req.to_ascii_lowercase();
        if seen.insert(key) {
            items.push(req.to_string());
        }
    }
    items.join(",")
}

fn merge_vscode_no_proxy(existing: Option<&Value>) -> Value {
    let mut items: Vec<Value> = Vec::new();
    let mut seen = BTreeSet::new();

    match existing {
        Some(Value::Array(arr)) => {
            for val in arr {
                if let Some(s) = val.as_str() {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let key = trimmed.to_ascii_lowercase();
                    if seen.insert(key) {
                        items.push(Value::String(trimmed.to_string()));
                    }
                } else {
                    items.push(val.clone());
                }
            }
        }
        Some(Value::String(s)) => {
            for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let key = part.to_ascii_lowercase();
                if seen.insert(key) {
                    items.push(Value::String(part.to_string()));
                }
            }
        }
        _ => {}
    }

    for &req in VSCODE_HTTP_NO_PROXY {
        let key = req.to_ascii_lowercase();
        if seen.insert(key) {
            items.push(Value::String(req.to_string()));
        }
    }

    Value::Array(items)
}

// --- Surgical comment-preserving TOML helpers (keeps Cargo.toml offline & locked) ---

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '#' => return &line[..idx],
                _ => {}
            }
        }
    }
    line
}

fn parse_toml_table_header(code: &str) -> Option<Vec<String>> {
    let trimmed = code.trim();
    if trimmed.starts_with("[[") || !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return None;
    }
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    let mut rest = inner;
    while !rest.is_empty() {
        rest = rest.trim_start();
        let part = if let Some(after_q) = rest.strip_prefix('"') {
            let end = after_q.find('"')?;
            let val = after_q[..end].to_string();
            rest = &after_q[end + 1..];
            val
        } else if let Some(after_q) = rest.strip_prefix('\'') {
            let end = after_q.find('\'')?;
            let val = after_q[..end].to_string();
            rest = &after_q[end + 1..];
            val
        } else {
            let end = rest.find('.').unwrap_or(rest.len());
            let val = rest[..end].trim().to_string();
            rest = &rest[end..];
            val
        };
        parts.push(part);
        rest = rest.trim_start();
        if let Some(after_dot) = rest.strip_prefix('.') {
            rest = after_dot;
        } else {
            break;
        }
    }
    Some(parts)
}

fn parse_toml_string_literal(raw_val: &str) -> Option<String> {
    let s = raw_val.trim();
    if let Some(rest) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut escaped = false;
        for ch in rest.chars() {
            if escaped {
                match ch {
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    other => out.push(other),
                }
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return Some(out);
            } else {
                out.push(ch);
            }
        }
        None
    } else if let Some(rest) = s.strip_prefix('\'') {
        let end = rest.find('\'')?;
        Some(rest[..end].to_string())
    } else {
        None
    }
}

fn read_toml_string_key(raw: &str, target_section: &[&str], target_key: &str) -> Option<String> {
    let raw = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
    let mut section: Vec<String> = Vec::new();
    let mut multiline_delim: Option<&str> = None;
    for line in raw.lines() {
        if let Some(delim) = multiline_delim {
            if line.contains(delim) {
                multiline_delim = None;
            }
            continue;
        }
        let code = strip_toml_comment(line).trim();
        if code.is_empty() {
            continue;
        }
        if let Some(header) = parse_toml_table_header(code) {
            section = header;
            continue;
        }
        if let Some((_, v)) = code.split_once('=') {
            let vt = v.trim();
            if let Some(delim) = ["\"\"\"", "'''"].iter().copied().find(|d| vt.starts_with(d)) {
                let after = &vt[delim.len()..];
                if !after.contains(delim) {
                    multiline_delim = Some(delim);
                }
                continue;
            }
        }
        if section.len() == target_section.len() && section.iter().zip(target_section).all(|(a, b)| a == b) {
            if let Some((k, v)) = code.split_once('=') {
                let key = k.trim().trim_matches('"').trim_matches('\'');
                if key == target_key {
                    return parse_toml_string_literal(v);
                }
            }
        }
    }
    None
}

fn format_toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\0' => {}
            other => escaped.push(other),
        }
    }
    format!("\"{escaped}\"")
}

fn format_toml_header(section: &[&str]) -> String {
    let joined: Vec<String> = section
        .iter()
        .map(|seg| {
            if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                (*seg).to_string()
            } else {
                format_toml_basic_string(seg)
            }
        })
        .collect();
    format!("[{}]", joined.join("."))
}

fn set_toml_string_key(raw: &str, target_section: &[&str], target_key: &str, value: &str) -> String {
    let has_bom = raw.starts_with('\u{FEFF}');
    let raw_body = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
    let eol = if raw_body.contains("\r\n") { "\r\n" } else { "\n" };
    let formatted_val = format_toml_basic_string(value);
    let mut lines: Vec<String> = raw_body.lines().map(str::to_string).collect();

    let mut section: Vec<String> = Vec::new();
    let mut seen_target_section = target_section.is_empty();
    let mut last_target_line: Option<usize> = None;
    let mut first_section_line: Option<usize> = None;
    let mut multiline_delim: Option<&str> = None;

    for (idx, line) in lines.iter_mut().enumerate() {
        if let Some(delim) = multiline_delim {
            if line.contains(delim) {
                multiline_delim = None;
            }
            continue;
        }
        let code_slice = strip_toml_comment(line);
        let trimmed = code_slice.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(header) = parse_toml_table_header(trimmed) {
            if first_section_line.is_none() {
                first_section_line = Some(idx);
            }
            section = header;
            if section.len() == target_section.len() && section.iter().zip(target_section).all(|(a, b)| a == b) {
                seen_target_section = true;
                last_target_line = Some(idx);
            }
            continue;
        }
        if let Some((_, v)) = trimmed.split_once('=') {
            let vt = v.trim();
            if let Some(delim) = ["\"\"\"", "'''"].iter().copied().find(|d| vt.starts_with(d)) {
                let after = &vt[delim.len()..];
                if !after.contains(delim) {
                    multiline_delim = Some(delim);
                }
                continue;
            }
        }
        if section.len() == target_section.len() && section.iter().zip(target_section).all(|(a, b)| a == b) {
            last_target_line = Some(idx);
            if let Some(eq_pos) = code_slice.find('=') {
                let key = code_slice[..eq_pos].trim().trim_matches('"').trim_matches('\'');
                if key == target_key {
                    let comment = &line[code_slice.len()..];
                    let trimmed_left = code_slice[..=eq_pos].trim_end();
                    let sep = if comment.is_empty() { "" } else { " " };
                    *line = format!("{trimmed_left} {formatted_val}{sep}{comment}");
                    let mut joined = lines.join(eol);
                    if raw_body.ends_with('\n') || joined.is_empty() {
                        joined.push_str(eol);
                    }
                    return if has_bom { format!("\u{FEFF}{joined}") } else { joined };
                }
            }
        }
    }

    let new_line = format!("{target_key} = {formatted_val}");
    if target_section.is_empty() {
        let insert_idx = last_target_line
            .map(|i| i + 1)
            .or(first_section_line)
            .unwrap_or(lines.len());
        lines.insert(insert_idx, new_line);
    } else if seen_target_section {
        let insert_idx = last_target_line.map_or(lines.len(), |i| i + 1);
        lines.insert(insert_idx, new_line);
    } else {
        if !lines.is_empty() && !lines.last().is_some_and(|l| l.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push(format_toml_header(target_section));
        lines.push(new_line);
    }

    let mut joined = lines.join(eol);
    if !joined.ends_with(eol) {
        joined.push_str(eol);
    }
    if has_bom {
        format!("\u{FEFF}{joined}")
    } else {
        joined
    }
}

fn remove_toml_key(raw: &str, target_section: &[&str], target_key: &str) -> String {
    let has_bom = raw.starts_with('\u{FEFF}');
    let raw_body = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
    let eol = if raw_body.contains("\r\n") { "\r\n" } else { "\n" };
    let mut section: Vec<String> = Vec::new();
    let mut multiline_delim: Option<&str> = None;
    let mut kept = Vec::new();

    for line in raw_body.lines() {
        if let Some(delim) = multiline_delim {
            if line.contains(delim) {
                multiline_delim = None;
            }
            kept.push(line);
            continue;
        }
        let code_slice = strip_toml_comment(line);
        let trimmed = code_slice.trim();
        if let Some(header) = parse_toml_table_header(trimmed) {
            section = header;
            kept.push(line);
            continue;
        }
        if let Some((_, v)) = trimmed.split_once('=') {
            let vt = v.trim();
            if let Some(delim) = ["\"\"\"", "'''"].iter().copied().find(|d| vt.starts_with(d)) {
                let after = &vt[delim.len()..];
                if !after.contains(delim) {
                    multiline_delim = Some(delim);
                }
                kept.push(line);
                continue;
            }
        }
        if section.len() == target_section.len() && section.iter().zip(target_section).all(|(a, b)| a == b) {
            if let Some(eq_pos) = code_slice.find('=') {
                let key = code_slice[..eq_pos].trim().trim_matches('"').trim_matches('\'');
                if key == target_key {
                    continue;
                }
            }
        }
        kept.push(line);
    }

    let mut joined = kept.join(eol);
    if (raw_body.ends_with('\n') && !joined.is_empty()) || joined.is_empty() {
        joined.push_str(eol);
    }
    if has_bom {
        format!("\u{FEFF}{joined}")
    } else {
        joined
    }
}

fn normalize_codex_upstream(raw_url: &str) -> (String, bool) {
    let trimmed = raw_url.trim().trim_end_matches('/');
    if let Some(stripped) = trimmed.strip_suffix("/v1") {
        (stripped.trim_end_matches('/').to_string(), true)
    } else {
        (trimmed.to_string(), false)
    }
}

// --- Candidate file helpers per harness ---

fn antigravity_settings_candidates(host: &dyn HostAdapter) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(appdata) = host.appdata_dir() {
        out.push(appdata.join("Antigravity IDE").join("User").join("settings.json"));
        out.push(appdata.join("Antigravity").join("User").join("settings.json"));
    }
    out
}

fn qoder_settings_candidates(host: &dyn HostAdapter) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(appdata) = host.appdata_dir() {
        out.push(appdata.join("Qoder").join("User").join("settings.json"));
        out.push(appdata.join("QoderCN").join("User").join("settings.json"));
    }
    out
}

fn cursor_settings_path(host: &dyn HostAdapter) -> Option<PathBuf> {
    host.appdata_dir()
        .map(|d| d.join("Cursor").join("User").join("settings.json"))
}

fn check_vscode_proxy_file(path: &Path, proxy_port: u16, check_qoder_advanced: bool) -> bool {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(val) = parse_jsonc_value(&raw) else {
        return false;
    };
    let Some(obj) = val.as_object() else {
        return false;
    };
    if let Some(http_proxy) = obj.get("http.proxy").and_then(Value::as_str) {
        if points_to_local_gateway(http_proxy, "", proxy_port) {
            return true;
        }
    }
    if check_qoder_advanced {
        let mode_manual = obj
            .get("app.configAdvancedProxyMode")
            .and_then(Value::as_str)
            .is_some_and(|m| m.eq_ignore_ascii_case("manual"));
        if mode_manual {
            if let Some(adv_url) = obj.get("app.configAdvancedProxyURL").and_then(Value::as_str) {
                if points_to_local_gateway(adv_url, "", proxy_port) {
                    return true;
                }
            }
        }
    }
    false
}

fn check_env_either(host: &dyn HostAdapter, var: &str, route_prefix: &str, proxy_port: u16) -> Option<String> {
    if let Some(val) = host.user_env_get(var) {
        if points_to_local_gateway(&val, route_prefix, proxy_port) {
            return Some(format!("用户环境变量 {var}"));
        }
    }
    if let Some(val) = host.process_env(var) {
        if points_to_local_gateway(&val, route_prefix, proxy_port) {
            return Some(format!("当前进程环境变量 {var}"));
        }
    }
    None
}

fn check_configured(
    spec: &HarnessSpec,
    profile: &HarnessProfile,
    proxy_port: u16,
    host: &dyn HostAdapter,
) -> (bool, Option<String>) {
    match spec.kind {
        HarnessKind::ClaudeCode => {
            if let Some(home) = host.home_dir() {
                let settings_path = home.join(".claude").join("settings.json");
                if let Ok(raw) = std::fs::read_to_string(&settings_path) {
                    if let Ok(val) = parse_jsonc_value(&raw) {
                        if let Some(url) = val.pointer("/env/ANTHROPIC_BASE_URL").and_then(Value::as_str) {
                            if points_to_local_gateway(url, &profile.local_proxy_route, proxy_port) {
                                return (true, Some(settings_path.to_string_lossy().into_owned()));
                            }
                        }
                    }
                }
            }
            if let Some(via) = check_env_either(host, "ANTHROPIC_BASE_URL", "/claude-code", proxy_port) {
                return (true, Some(via));
            }
        }
        HarnessKind::Codex => {
            if let Some(home) = host.home_dir() {
                let toml_path = home.join(".codex").join("config.toml");
                if let Ok(raw) = std::fs::read_to_string(&toml_path) {
                    let provider = read_toml_string_key(&raw, &[], "model_provider");
                    let provider_url = provider
                        .as_deref()
                        .and_then(|p| read_toml_string_key(&raw, &["model_providers", p], "base_url"));
                    let top_url = read_toml_string_key(&raw, &[], "openai_base_url");
                    if provider_url
                        .as_deref()
                        .is_some_and(|u| points_to_local_gateway(u, "/codex", proxy_port))
                        || top_url
                            .as_deref()
                            .is_some_and(|u| points_to_local_gateway(u, "/codex", proxy_port))
                    {
                        return (true, Some(toml_path.to_string_lossy().into_owned()));
                    }
                }
            }
            if let Some(via) = check_env_either(host, "OPENAI_BASE_URL", "/codex", proxy_port) {
                return (true, Some(via));
            }
        }
        HarnessKind::Antigravity => {
            for path in antigravity_settings_candidates(host) {
                if check_vscode_proxy_file(&path, proxy_port, false) {
                    return (true, Some(path.to_string_lossy().into_owned()));
                }
            }
            if backup_file_path(host, HarnessKind::Antigravity).is_some_and(|p| p.exists()) {
                if let Some(via) = check_env_either(host, "HTTPS_PROXY", "", proxy_port) {
                    return (true, Some(via));
                }
            }
        }
        HarnessKind::Zcode => {
            if let Some(via) = check_env_either(host, "ZCODE_HTTP_PROXY", "", proxy_port) {
                return (true, Some(via));
            }
        }
        HarnessKind::Qoder => {
            for path in qoder_settings_candidates(host) {
                if check_vscode_proxy_file(&path, proxy_port, true) {
                    return (true, Some(path.to_string_lossy().into_owned()));
                }
            }
        }
        HarnessKind::Cursor => {
            if let Some(path) = cursor_settings_path(host) {
                if check_vscode_proxy_file(&path, proxy_port, false) {
                    return (true, Some(path.to_string_lossy().into_owned()));
                }
            }
        }
        HarnessKind::GrokBuild => {
            for (var, route) in [
                ("GROK_XAI_API_BASE_URL", "/grok-build/v1"),
                ("GROK_CLI_CHAT_PROXY_BASE_URL", "/grok-build"),
                ("GROK_CLI_BASE_URL", "/grok-build"),
            ] {
                if let Some(via) = check_env_either(host, var, route, proxy_port) {
                    return (true, Some(via));
                }
            }
        }
        HarnessKind::Generic => {}
    }
    (false, None)
}

/// Detect all 7 harnesses against the real local machine and live gateway telemetry.
pub fn detect_all_harness_profiles(
    proxy_port: u16,
    live_stats: &HashMap<HarnessKind, (u64, String)>,
) -> Vec<HarnessProfile> {
    detect_all_harness_profiles_with(&RealHostAdapter, proxy_port, live_stats)
}

pub fn detect_all_harness_profiles_with(
    host: &dyn HostAdapter,
    proxy_port: u16,
    live_stats: &HashMap<HarnessKind, (u64, String)>,
) -> Vec<HarnessProfile> {
    let mut profiles = get_all_harness_profiles(proxy_port);
    for profile in &mut profiles {
        if let Some(spec) = spec_for(profile.kind) {
            profile.install_paths = discover_paths(spec, host);
            profile.installed = !profile.install_paths.is_empty();
            let (configured, via) = check_configured(spec, profile, proxy_port, host);
            profile.configured = configured;
            profile.configured_via = via;
        }
        if let Some((count, last_seen)) = live_stats.get(&profile.kind) {
            profile.traffic_count = *count;
            profile.last_seen_at = Some(last_seen.clone());
            profile.detected_active = *count > 0;
        }
    }
    profiles
}

fn backup_file_path(host: &dyn HostAdapter, kind: HarnessKind) -> Option<PathBuf> {
    host.backup_dir()
        .map(|d| d.join(format!("{}.json", harness_slug(kind))))
}

fn shared_leases_path(backup_dir: &Path) -> PathBuf {
    backup_dir.join("shared-env.json")
}

enum BackupLoadState {
    Missing,
    Loaded(HarnessBackup),
    Corrupt,
}

fn load_backup(path: &Path) -> Option<HarnessBackup> {
    match load_backup_state(path) {
        BackupLoadState::Loaded(b) => Some(b),
        _ => None,
    }
}

fn load_backup_state(path: &Path) -> BackupLoadState {
    match std::fs::read_to_string(path) {
        Ok(s) => match serde_json::from_str(&s) {
            Ok(b) => BackupLoadState::Loaded(b),
            Err(_) => BackupLoadState::Corrupt,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BackupLoadState::Missing,
        Err(_) => BackupLoadState::Corrupt,
    }
}

fn save_backup(path: &Path, backup: &HarnessBackup) -> Result<(), String> {
    let body = serde_json::to_string_pretty(backup).map_err(|e| e.to_string())?;
    write_atomic_secure(path, body.as_bytes()).map_err(|e| format!("failed to write backup: {e}"))
}

fn load_shared_leases(backup_dir: &Path) -> SharedEnvLeases {
    std::fs::read_to_string(shared_leases_path(backup_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_shared_leases(backup_dir: &Path, leases: &SharedEnvLeases) -> Result<(), String> {
    let path = shared_leases_path(backup_dir);
    if leases.vars.is_empty() {
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        return Ok(());
    }
    let body = serde_json::to_string_pretty(leases).map_err(|e| e.to_string())?;
    write_atomic_secure(&path, body.as_bytes()).map_err(|e| format!("failed to write shared env leases: {e}"))
}

fn write_raw_snapshot(backup_dir: &Path, rel: &str, bytes: &[u8]) -> Result<(), String> {
    if !is_valid_snapshot_rel(rel) {
        return Err(format!("非法备份快照路径: {rel}"));
    }
    let target = backup_dir.join(rel);
    write_atomic_secure(&target, bytes).map_err(|e| format!("failed to write snapshot: {e}"))
}

fn acquire_shared_env_vars(
    host: &dyn HostAdapter,
    backup: &mut HarnessBackup,
    slug: &str,
    vars: &[(&str, &str)],
) -> Result<(), String> {
    let Some(bdir) = host.backup_dir() else {
        for &(name, val) in vars {
            let eff = if name == "NO_PROXY" {
                merge_no_proxy(host.user_env_get(name).as_deref())
            } else {
                val.to_string()
            };
            host.user_env_set(name, &eff)?;
            if !backup.shared_env_vars.iter().any(|v| v == name) {
                backup.shared_env_vars.push(name.to_string());
            }
        }
        return Ok(());
    };

    let mut leases = load_shared_leases(&bdir);
    for &(name, val) in vars {
        let entry = leases
            .vars
            .entry(name.to_string())
            .or_insert_with(|| SharedEnvLeaseEntry {
                prev_value: host.user_env_get(name),
                owners: BTreeSet::new(),
            });
        if entry.owners.is_empty() {
            entry.prev_value = host.user_env_get(name);
        }
        entry.owners.insert(slug.to_string());

        let effective = if name == "NO_PROXY" {
            merge_no_proxy(entry.prev_value.as_deref())
        } else {
            val.to_string()
        };
        host.user_env_set(name, &effective)?;
        if !backup.shared_env_vars.iter().any(|v| v == name) {
            backup.shared_env_vars.push(name.to_string());
        }
    }
    save_shared_leases(&bdir, &leases)
}

fn release_shared_env_vars(host: &dyn HostAdapter, slug: &str, vars: &[String]) -> Result<(), String> {
    let Some(bdir) = host.backup_dir() else {
        return Ok(());
    };
    let mut leases = load_shared_leases(&bdir);
    for name in vars {
        let Some(entry) = leases.vars.get_mut(name) else {
            continue;
        };
        entry.owners.remove(slug);
        if entry.owners.is_empty() {
            let prev = entry.prev_value.clone();
            leases.vars.remove(name);
            match prev {
                Some(v) => host.user_env_set(name, &v)?,
                None => host.user_env_remove(name)?,
            }
        }
    }
    save_shared_leases(&bdir, &leases)
}

struct PreparedCaInfo {
    cert_path: Option<String>,
    bundle_path: Option<String>,
    warning: Option<String>,
}

fn ensure_ca_ready_for_harness(
    ca_dir: Option<PathBuf>,
    trust_adapter: Arc<dyn CaTrustAdapter>,
    install_os_trust: bool,
) -> Result<PreparedCaInfo, String> {
    let mgr = match ca_dir {
        Some(dir) => CaManager::load_or_create(dir, trust_adapter)?,
        None => CaManager::ephemeral(trust_adapter)?,
    };
    let cert_path = mgr.ca_cert_path().map(|p| p.to_string_lossy().into_owned());
    let bundle_path = mgr
        .ca_bundle_path()
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| cert_path.clone());

    let mut warning = None;
    let st = mgr.status();
    if install_os_trust {
        if st.os_trust_supported && !st.installed_in_os_store {
            if let Err(err) = mgr.install_trust() {
                if cfg!(windows) || cfg!(target_os = "macos") {
                    return Err(err);
                }
                warning = Some(err);
            }
        }
    } else if !st.installed_in_os_store {
        warning = Some(if st.os_trust_supported {
            "本地根证书尚未受系统信任，请在界面点击「安装并信任根证书」，否则 HTTPS 对话与搜索将校验失败".to_string()
        } else {
            "本地根证书尚未受系统信任，请点击「导出证书」并手动导入系统受信任根证书存储，否则 HTTPS 对话与搜索将校验失败"
                .to_string()
        });
    }
    Ok(PreparedCaInfo {
        cert_path,
        bundle_path,
        warning,
    })
}

fn update_config_upstream(
    config_path: Option<&Path>,
    slug: &str,
    route_prefix: &str,
    proxy_port: u16,
    new_upstream: Option<String>,
) -> Result<(bool, Option<String>), String> {
    let Some(path) = config_path else {
        return Ok((false, None));
    };
    let Some(upstream) =
        new_upstream.filter(|u| !u.is_empty() && !points_to_hidego_gateway(u, route_prefix, proxy_port))
    else {
        return Ok((false, None));
    };
    let mut cfg = HideConfig::load_or_create(path);
    let prev = cfg.harness_upstreams.insert(slug.to_string(), upstream);
    cfg.save(path).map_err(|e| format!("保存 HideConfig 失败: {e}"))?;
    Ok((true, prev))
}

fn restore_config_upstream(config_path: Option<&Path>, slug: &str, backup: &HarnessBackup) -> Result<(), String> {
    if !backup.wrote_config_upstream {
        return Ok(());
    }
    let Some(path) = config_path else {
        return Ok(());
    };
    if !path.exists() {
        return Ok(());
    }
    let mut cfg = HideConfig::load_or_create(path);
    match &backup.prev_config_upstream {
        Some(prev) => {
            cfg.harness_upstreams.insert(slug.to_string(), prev.clone());
        }
        None => {
            cfg.harness_upstreams.remove(slug);
        }
    }
    cfg.save(path).map_err(|e| format!("恢复 HideConfig 失败: {e}"))
}

const fn vscode_terminal_env_key() -> &'static str {
    if cfg!(windows) {
        "terminal.integrated.env.windows"
    } else if cfg!(target_os = "macos") {
        "terminal.integrated.env.osx"
    } else {
        "terminal.integrated.env.linux"
    }
}

fn apply_vscode_settings_file(
    path: &Path,
    slug: &str,
    index: usize,
    backup_dir: Option<&Path>,
    save_snapshot: bool,
    updates: &[(&str, Value)],
    terminal_env_updates: &[(&str, String)],
) -> Result<FileBackupEntry, String> {
    let had_file = path.exists();
    let (raw_original, mut root) = if had_file {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
        let val = parse_jsonc_value(&raw)
            .map_err(|e| format!("无法解析现有的 {} ({e})，为安全起见未修改", path.display()))?;
        (Some(raw), val)
    } else {
        (None, Value::Object(Map::new()))
    };

    let Some(root_map) = root.as_object_mut() else {
        return Err(format!("{} 根节点不是 JSON 对象", path.display()));
    };

    let mut prev_keys = HashMap::new();
    for (k, v) in updates {
        prev_keys.insert((*k).to_string(), root_map.get(*k).cloned());
        root_map.insert((*k).to_string(), v.clone());
    }

    prev_keys.insert("http.noProxy".to_string(), root_map.get("http.noProxy").cloned());
    let merged_no_proxy = merge_vscode_no_proxy(root_map.get("http.noProxy"));
    root_map.insert("http.noProxy".to_string(), merged_no_proxy);

    if !terminal_env_updates.is_empty() {
        let term_key = vscode_terminal_env_key();
        prev_keys.insert(term_key.to_string(), root_map.get(term_key).cloned());
        let env_entry = root_map
            .entry(term_key.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(env_map) = env_entry.as_object_mut() {
            for (k, v) in terminal_env_updates {
                env_map.insert((*k).to_string(), Value::String(v.clone()));
            }
        }
    }

    let raw_snapshot_rel = if save_snapshot {
        if let (Some(bdir), Some(raw)) = (backup_dir, &raw_original) {
            let rel = format!("snapshots/{slug}__{index}.raw");
            write_raw_snapshot(bdir, &rel, raw.as_bytes())?;
            Some(rel)
        } else {
            None
        }
    } else {
        None
    };

    let pretty = serde_json::to_string_pretty(&root).map_err(|e| format!("序列化 {} 失败: {e}", path.display()))?;
    write_atomic_secure(path, format!("{pretty}\n").as_bytes())
        .map_err(|e| format!("写入 {} 失败: {e}", path.display()))?;

    Ok(FileBackupEntry {
        path: path.to_string_lossy().into_owned(),
        had_file,
        had_env_object: false,
        raw_snapshot_rel,
        prev_keys,
    })
}

fn restore_vscode_settings_file(entry: &FileBackupEntry, backup_dir: Option<&Path>) -> Result<(), String> {
    let path = Path::new(&entry.path);
    if !entry.had_file {
        if path.exists() {
            ensure_not_symlink(path)?;
            std::fs::remove_file(path).map_err(|e| format!("移除 {} 失败: {e}", path.display()))?;
        }
        if let (Some(bdir), Some(rel)) = (
            backup_dir,
            entry.raw_snapshot_rel.as_deref().filter(|r| is_valid_snapshot_rel(r)),
        ) {
            let _ = std::fs::remove_file(bdir.join(rel));
        }
        return Ok(());
    }
    if !path.exists() {
        return Ok(());
    }
    let current_raw = std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let mut current_val = parse_jsonc_value(&current_raw).map_err(|e| format!("解析 {} 失败: {e}", path.display()))?;
    let Some(cur_map) = current_val.as_object_mut() else {
        return Err(format!("{} 根节点不是 JSON 对象", path.display()));
    };

    // If we have a raw snapshot (e.g. JSONC with user comments) and non-managed keys were not altered,
    // restore the original bytes losslessly.
    if let (Some(bdir), Some(rel)) = (
        backup_dir,
        entry.raw_snapshot_rel.as_deref().filter(|r| is_valid_snapshot_rel(r)),
    ) {
        let snap_path = bdir.join(rel);
        if let Ok(snap_bytes) = std::fs::read(&snap_path) {
            let snap_str = String::from_utf8_lossy(&snap_bytes);
            if contains_jsonc_syntax(&snap_str) {
                if let Ok(Value::Object(snap_map)) = parse_jsonc_value(&snap_str) {
                    let managed: BTreeSet<&str> = entry.prev_keys.keys().map(String::as_str).collect();
                    let cur_other: HashMap<&String, &Value> =
                        cur_map.iter().filter(|(k, _)| !managed.contains(k.as_str())).collect();
                    let snap_other: HashMap<&String, &Value> =
                        snap_map.iter().filter(|(k, _)| !managed.contains(k.as_str())).collect();
                    if cur_other == snap_other {
                        write_atomic_secure(path, &snap_bytes)
                            .map_err(|e| format!("恢复 {} 失败: {e}", path.display()))?;
                        let _ = std::fs::remove_file(snap_path);
                        return Ok(());
                    }
                }
            }
        }
    }

    for (k, prev) in &entry.prev_keys {
        match prev {
            Some(v) => {
                cur_map.insert(k.clone(), v.clone());
            }
            None => {
                cur_map.remove(k);
            }
        }
    }
    let pretty =
        serde_json::to_string_pretty(&current_val).map_err(|e| format!("序列化 {} 失败: {e}", path.display()))?;
    write_atomic_secure(path, format!("{pretty}\n").as_bytes())
        .map_err(|e| format!("写入 {} 失败: {e}", path.display()))?;
    if let (Some(bdir), Some(rel)) = (
        backup_dir,
        entry.raw_snapshot_rel.as_deref().filter(|r| is_valid_snapshot_rel(r)),
    ) {
        let _ = std::fs::remove_file(bdir.join(rel));
    }
    Ok(())
}

fn set_harness_env_var(
    host: &dyn HostAdapter,
    backup: &mut HarnessBackup,
    name: &str,
    value: &str,
) -> Result<(), String> {
    if !backup.prev_env_vars.contains_key(name) {
        backup.prev_env_vars.insert(name.to_string(), host.user_env_get(name));
    }
    host.user_env_set(name, value)
}

fn restore_harness_env_vars(host: &dyn HostAdapter, backup: &HarnessBackup) -> Result<(), String> {
    for (name, prev) in &backup.prev_env_vars {
        match prev {
            Some(v) => host.user_env_set(name, v)?,
            None => host.user_env_remove(name)?,
        }
    }
    if let Some(legacy_var) = &backup.env_var {
        if !backup.prev_env_vars.contains_key(legacy_var) {
            match &backup.prev_value {
                Some(v) => host.user_env_set(legacy_var, v)?,
                None => host.user_env_remove(legacy_var)?,
            }
        }
    }
    Ok(())
}

fn fail_action(kind: HarnessKind, connected: bool, message: impl Into<String>) -> HarnessActionResult {
    HarnessActionResult {
        kind,
        ok: false,
        connected,
        message: message.into(),
        changed_target: None,
        backup_path: None,
    }
}

/// Automatically configure a supported harness to route via `http://127.0.0.1:<port>`,
/// preserving original settings in Hide-Go's backup folder.
pub fn connect_harness(kind: HarnessKind, proxy_port: u16) -> HarnessActionResult {
    connect_harness_with_deps(
        &RealHostAdapter,
        Arc::new(RealCaTrustAdapter),
        CaManager::default_ca_dir(),
        HideConfig::default_path(),
        kind,
        proxy_port,
    )
}

pub fn connect_harness_with(host: &dyn HostAdapter, kind: HarnessKind, proxy_port: u16) -> HarnessActionResult {
    let ca_dir = host.backup_dir().and_then(|d| d.parent().map(|p| p.join("ca")));
    let config_path = host
        .backup_dir()
        .and_then(|d| d.parent().map(|p| p.join("config.json")));
    connect_harness_with_deps(
        host,
        Arc::new(RealCaTrustAdapter),
        ca_dir,
        config_path,
        kind,
        proxy_port,
    )
}

pub fn connect_harness_with_deps(
    host: &dyn HostAdapter,
    trust_adapter: Arc<dyn CaTrustAdapter>,
    ca_dir: Option<PathBuf>,
    config_path: Option<PathBuf>,
    kind: HarnessKind,
    proxy_port: u16,
) -> HarnessActionResult {
    let _guard = HARNESS_MUTEX.lock();
    let Some(spec) = spec_for(kind) else {
        return fail_action(kind, false, "不支持自动接入该工具类型");
    };

    let slug = harness_slug(kind);
    let route_prefix = format!("/{slug}");
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let backup_dir = host.backup_dir();
    let backup_path = backup_file_path(host, kind);

    // Preserve first pre-Hide-Go backup if already connected & reconnecting.
    let existing_backup = backup_path.as_deref().and_then(load_backup);
    let is_fresh_connect = existing_backup.is_none();
    let mut backup = existing_backup.unwrap_or_default();

    // Generate local Root CA + trust bundle without mutating OS Root CA stores / Registry automatically.
    let ca_info = if spec.requires_ca_trust {
        match ensure_ca_ready_for_harness(ca_dir, trust_adapter, false) {
            Ok(info) => info,
            Err(err) => return fail_action(kind, false, err),
        }
    } else {
        PreparedCaInfo {
            cert_path: None,
            bundle_path: None,
            warning: None,
        }
    };
    let ca_cert_path = ca_info.cert_path;
    let ca_bundle_path = ca_info.bundle_path;
    let ca_warning = ca_info.warning;

    let terminal_env_updates =
        build_vscode_terminal_env(&proxy_url, ca_cert_path.as_deref(), ca_bundle_path.as_deref());

    let fail_with_rollback = |backup: &HarnessBackup, err: String| -> HarnessActionResult {
        if is_fresh_connect {
            rollback_failed_connect(host, config_path.as_deref(), kind, backup);
        }
        fail_action(kind, !is_fresh_connect, err)
    };

    let mut targets_summary: Vec<String> = Vec::new();

    match kind {
        HarnessKind::ClaudeCode => {
            let Some(home) = host.home_dir() else {
                return fail_action(kind, false, "无法定位用户主目录");
            };
            let settings_path = home.join(".claude").join("settings.json");
            let had_file = settings_path.exists();
            let raw_original = if had_file {
                match std::fs::read_to_string(&settings_path) {
                    Ok(raw) => Some(raw),
                    Err(e) => return fail_action(kind, false, format!("读取 {} 失败: {e}", settings_path.display())),
                }
            } else {
                None
            };
            let mut root: Value = match &raw_original {
                Some(raw) => match parse_jsonc_value(raw) {
                    Ok(v) => v,
                    Err(e) => {
                        return fail_action(
                            kind,
                            false,
                            format!("无法解析现有的 {} ({e})，为安全起见未修改", settings_path.display()),
                        )
                    }
                },
                None => Value::Object(Map::new()),
            };
            let Some(root_map) = root.as_object_mut() else {
                return fail_action(kind, false, "Claude settings.json 根节点不是 JSON 对象");
            };

            let had_env_object = root_map.get("env").is_some_and(Value::is_object);
            let prev_anthropic = root_map
                .get("env")
                .and_then(Value::as_object)
                .and_then(|m| m.get("ANTHROPIC_BASE_URL"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let prev_no_proxy = root_map
                .get("env")
                .and_then(Value::as_object)
                .and_then(|m| m.get("NO_PROXY"))
                .cloned();

            let claude_url = format!("{proxy_url}/claude-code");
            if is_fresh_connect {
                backup.had_file = had_file;
                backup.had_env_object = had_env_object;
                backup.prev_value = prev_anthropic.clone();
                backup.env_var = Some("ANTHROPIC_BASE_URL".to_string());

                let mut prev_keys = HashMap::new();
                prev_keys.insert(
                    "ANTHROPIC_BASE_URL".to_string(),
                    prev_anthropic.clone().map(Value::String),
                );
                prev_keys.insert("NO_PROXY".to_string(), prev_no_proxy);

                let snap_rel = if let (Some(bdir), Some(raw)) = (&backup_dir, &raw_original) {
                    let rel = format!("snapshots/{slug}__0.raw");
                    if let Err(e) = write_raw_snapshot(bdir, &rel, raw.as_bytes()) {
                        return fail_with_rollback(&backup, e);
                    }
                    Some(rel)
                } else {
                    None
                };
                backup.files.push(FileBackupEntry {
                    path: settings_path.to_string_lossy().into_owned(),
                    had_file,
                    had_env_object,
                    raw_snapshot_rel: snap_rel,
                    prev_keys,
                });

                if let Some(prev) = prev_anthropic
                    .as_deref()
                    .filter(|u| !points_to_hidego_gateway(u, &route_prefix, proxy_port))
                {
                    match update_config_upstream(
                        config_path.as_deref(),
                        slug,
                        &route_prefix,
                        proxy_port,
                        Some(prev.to_string()),
                    ) {
                        Ok((wrote, prev_cfg)) => {
                            backup.wrote_config_upstream = wrote;
                            backup.prev_config_upstream = prev_cfg;
                        }
                        Err(e) => return fail_with_rollback(&backup, e),
                    }
                }
            }

            let env_obj = root_map
                .entry("env".to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            let Some(env_map) = env_obj.as_object_mut() else {
                return fail_with_rollback(&backup, "Claude settings.json 中的 env 字段不是对象".to_string());
            };
            env_map.insert("ANTHROPIC_BASE_URL".to_string(), Value::String(claude_url.clone()));

            let has_proxy_env = [
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "https_proxy",
                "http_proxy",
                "all_proxy",
            ]
            .iter()
            .any(|k| env_map.contains_key(*k) || host.user_env_get(k).is_some() || host.process_env(k).is_some());
            if has_proxy_env {
                let existing_np = env_map.get("NO_PROXY").and_then(Value::as_str).map(str::to_string);
                env_map.insert(
                    "NO_PROXY".to_string(),
                    Value::String(merge_no_proxy(existing_np.as_deref())),
                );
            }

            let Ok(pretty) = serde_json::to_string_pretty(&root) else {
                return fail_with_rollback(&backup, "序列化 Claude settings.json 失败".to_string());
            };
            if let Err(e) = write_atomic_secure(&settings_path, format!("{pretty}\n").as_bytes()) {
                return fail_with_rollback(&backup, format!("写入失败: {e}"));
            }
            targets_summary.push(settings_path.to_string_lossy().into_owned());
        }
        HarnessKind::Codex => {
            let Some(home) = host.home_dir() else {
                return fail_action(kind, false, "无法定位用户主目录");
            };
            let toml_path = home.join(".codex").join("config.toml");
            let had_toml = toml_path.exists();
            let raw_toml = if had_toml {
                match std::fs::read_to_string(&toml_path) {
                    Ok(s) => s,
                    Err(e) => return fail_action(kind, false, format!("读取 {} 失败: {e}", toml_path.display())),
                }
            } else {
                String::new()
            };

            let provider = read_toml_string_key(&raw_toml, &[], "model_provider");
            let orig_toml_url = if let Some(p) = provider.as_deref() {
                read_toml_string_key(&raw_toml, &["model_providers", p], "base_url")
            } else {
                read_toml_string_key(&raw_toml, &[], "openai_base_url")
            };
            let orig_env_url = host.user_env_get("OPENAI_BASE_URL");
            let effective_orig = orig_toml_url
                .as_deref()
                .filter(|u| !u.trim().is_empty() && !points_to_hidego_gateway(u, &route_prefix, proxy_port))
                .or_else(|| {
                    orig_env_url
                        .as_deref()
                        .filter(|u| !u.trim().is_empty() && !points_to_hidego_gateway(u, &route_prefix, proxy_port))
                });

            let (codex_local_url, upstream_to_save) = match effective_orig {
                Some(orig) => {
                    let (base, had_v1) = normalize_codex_upstream(orig);
                    let local = if had_v1 {
                        format!("{proxy_url}/codex/v1")
                    } else {
                        format!("{proxy_url}/codex")
                    };
                    (local, Some(base))
                }
                None => (format!("{proxy_url}/codex/v1"), None),
            };

            if is_fresh_connect {
                let snap_rel = if had_toml {
                    if let Some(bdir) = &backup_dir {
                        let rel = format!("snapshots/{slug}__0.raw");
                        if let Err(e) = write_raw_snapshot(bdir, &rel, raw_toml.as_bytes()) {
                            return fail_with_rollback(&backup, e);
                        }
                        Some(rel)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let mut prev_keys = HashMap::new();
                if let Some(p) = provider.as_deref() {
                    prev_keys.insert("toml_provider".to_string(), Some(Value::String(p.to_string())));
                }
                prev_keys.insert(
                    "toml_key".to_string(),
                    Some(Value::String(
                        if provider.is_some() {
                            "base_url"
                        } else {
                            "openai_base_url"
                        }
                        .to_string(),
                    )),
                );
                prev_keys.insert("toml_prev_url".to_string(), orig_toml_url.clone().map(Value::String));
                prev_keys.insert(
                    "toml_written_url".to_string(),
                    Some(Value::String(codex_local_url.clone())),
                );

                backup.files.push(FileBackupEntry {
                    path: toml_path.to_string_lossy().into_owned(),
                    had_file: had_toml,
                    had_env_object: false,
                    raw_snapshot_rel: snap_rel,
                    prev_keys,
                });
                if let Some(up) = upstream_to_save {
                    match update_config_upstream(config_path.as_deref(), slug, &route_prefix, proxy_port, Some(up)) {
                        Ok((wrote, prev_cfg)) => {
                            backup.wrote_config_upstream = wrote;
                            backup.prev_config_upstream = prev_cfg;
                        }
                        Err(e) => return fail_with_rollback(&backup, e),
                    }
                }
            }

            let updated_toml = match provider.as_deref() {
                Some(p) => set_toml_string_key(&raw_toml, &["model_providers", p], "base_url", &codex_local_url),
                None => set_toml_string_key(&raw_toml, &[], "openai_base_url", &codex_local_url),
            };
            if let Err(e) = write_atomic_secure(&toml_path, updated_toml.as_bytes()) {
                return fail_with_rollback(&backup, format!("写入 {} 失败: {e}", toml_path.display()));
            }
            targets_summary.push(toml_path.to_string_lossy().into_owned());

            if let Err(e) = set_harness_env_var(host, &mut backup, "OPENAI_BASE_URL", &codex_local_url) {
                return fail_with_rollback(&backup, e);
            }
            if let Some(bundle) = ca_bundle_path.as_deref() {
                if let Err(e) = set_harness_env_var(host, &mut backup, "CODEX_CA_CERTIFICATE", bundle) {
                    return fail_with_rollback(&backup, e);
                }
            }
            if let Err(e) = apply_shared_proxy_and_ca_leases(
                host,
                &mut backup,
                slug,
                &proxy_url,
                ca_cert_path.as_deref(),
                ca_bundle_path.as_deref(),
            ) {
                return fail_with_rollback(&backup, e);
            }
            targets_summary.push("Managed Env (OPENAI_BASE_URL, HTTPS_PROXY, CODEX_CA_CERTIFICATE)".to_string());
        }
        HarnessKind::Antigravity => {
            let candidates = antigravity_settings_candidates(host);
            let mut matched_paths: Vec<PathBuf> = candidates
                .iter()
                .filter(|p| p.exists() || p.parent().and_then(Path::parent).is_some_and(Path::exists))
                .cloned()
                .collect();
            if matched_paths.is_empty() && !candidates.is_empty() {
                if let Some(first) = candidates.first() {
                    if first.parent().and_then(Path::parent).is_some_and(Path::exists) {
                        matched_paths.push(first.clone());
                    }
                }
            }
            let updates = [
                ("http.proxy", Value::String(proxy_url.clone())),
                ("http.proxySupport", Value::String("override".to_string())),
            ];
            for (idx, path) in matched_paths.iter().enumerate() {
                let entry = match apply_vscode_settings_file(
                    path,
                    slug,
                    idx,
                    backup_dir.as_deref(),
                    is_fresh_connect,
                    &updates,
                    &terminal_env_updates,
                ) {
                    Ok(e) => e,
                    Err(e) => return fail_with_rollback(&backup, e),
                };
                if is_fresh_connect {
                    backup.files.push(entry);
                }
                targets_summary.push(path.to_string_lossy().into_owned());
            }
            if let Err(e) = apply_shared_proxy_and_ca_leases(
                host,
                &mut backup,
                slug,
                &proxy_url,
                ca_cert_path.as_deref(),
                ca_bundle_path.as_deref(),
            ) {
                return fail_with_rollback(&backup, e);
            }
            targets_summary.push("Managed Env (HTTPS_PROXY, NODE_EXTRA_CA_CERTS)".to_string());
        }
        HarnessKind::Zcode => {
            if let Err(e) = set_harness_env_var(host, &mut backup, "ZCODE_HTTP_PROXY", &proxy_url) {
                return fail_with_rollback(&backup, e);
            }
            let zcode_no_proxy = merge_no_proxy(host.user_env_get("ZCODE_NO_PROXY").as_deref());
            if let Err(e) = set_harness_env_var(host, &mut backup, "ZCODE_NO_PROXY", &zcode_no_proxy) {
                return fail_with_rollback(&backup, e);
            }
            if let Some(bundle) = ca_bundle_path.as_deref() {
                if let Err(e) = set_harness_env_var(host, &mut backup, "ZCODE_AGENT_CA_CERT", bundle) {
                    return fail_with_rollback(&backup, e);
                }
            }
            if let Err(e) = apply_shared_proxy_and_ca_leases(
                host,
                &mut backup,
                slug,
                &proxy_url,
                ca_cert_path.as_deref(),
                ca_bundle_path.as_deref(),
            ) {
                return fail_with_rollback(&backup, e);
            }
            targets_summary.push("Managed Env (ZCODE_HTTP_PROXY, ZCODE_AGENT_CA_CERT, HTTPS_PROXY)".to_string());
        }
        HarnessKind::Qoder => {
            let candidates = qoder_settings_candidates(host);
            let mut targets: Vec<PathBuf> = candidates
                .iter()
                .filter(|p| p.exists() || p.parent().and_then(Path::parent).is_some_and(Path::exists))
                .cloned()
                .collect();
            if targets.is_empty() {
                if let Some(first) = candidates.into_iter().next() {
                    targets.push(first);
                }
            }
            let updates = [
                ("app.configAdvancedProxyMode", Value::String("manual".to_string())),
                ("app.configAdvancedProxyURL", Value::String(proxy_url.clone())),
                ("http.proxy", Value::String(proxy_url.clone())),
                ("http.proxySupport", Value::String("override".to_string())),
            ];
            for (idx, path) in targets.iter().enumerate() {
                let entry = match apply_vscode_settings_file(
                    path,
                    slug,
                    idx,
                    backup_dir.as_deref(),
                    is_fresh_connect,
                    &updates,
                    &terminal_env_updates,
                ) {
                    Ok(e) => e,
                    Err(e) => return fail_with_rollback(&backup, e),
                };
                if is_fresh_connect {
                    backup.files.push(entry);
                }
                targets_summary.push(path.to_string_lossy().into_owned());
            }
            if let Err(e) = apply_shared_proxy_and_ca_leases(
                host,
                &mut backup,
                slug,
                &proxy_url,
                ca_cert_path.as_deref(),
                ca_bundle_path.as_deref(),
            ) {
                return fail_with_rollback(&backup, e);
            }
            targets_summary.push("Managed Env (HTTPS_PROXY, NODE_EXTRA_CA_CERTS)".to_string());
        }
        HarnessKind::Cursor => {
            let Some(settings_path) = cursor_settings_path(host) else {
                return fail_action(kind, false, "无法定位 Cursor 配置目录");
            };
            let updates = [
                ("http.proxy", Value::String(proxy_url.clone())),
                ("http.proxySupport", Value::String("override".to_string())),
                ("cursor.general.disableHttp2", Value::Bool(true)),
            ];
            let entry = match apply_vscode_settings_file(
                &settings_path,
                slug,
                0,
                backup_dir.as_deref(),
                is_fresh_connect,
                &updates,
                &terminal_env_updates,
            ) {
                Ok(e) => e,
                Err(e) => return fail_with_rollback(&backup, e),
            };
            if is_fresh_connect {
                backup.files.push(entry);
            }
            targets_summary.push(settings_path.to_string_lossy().into_owned());

            if let Err(e) = apply_shared_proxy_and_ca_leases(
                host,
                &mut backup,
                slug,
                &proxy_url,
                ca_cert_path.as_deref(),
                ca_bundle_path.as_deref(),
            ) {
                return fail_with_rollback(&backup, e);
            }
            targets_summary.push("Managed Env (HTTPS_PROXY, NODE_EXTRA_CA_CERTS)".to_string());
        }
        HarnessKind::GrokBuild => {
            let xai_base = format!("{proxy_url}/grok-build/v1");
            let cli_base = format!("{proxy_url}/grok-build");
            if let Err(e) = set_harness_env_var(host, &mut backup, "GROK_XAI_API_BASE_URL", &xai_base) {
                return fail_with_rollback(&backup, e);
            }
            if let Err(e) = set_harness_env_var(host, &mut backup, "GROK_CLI_CHAT_PROXY_BASE_URL", &cli_base) {
                return fail_with_rollback(&backup, e);
            }
            if let Err(e) = set_harness_env_var(host, &mut backup, "GROK_CLI_BASE_URL", &cli_base) {
                return fail_with_rollback(&backup, e);
            }
            if let Err(e) = apply_shared_proxy_and_ca_leases(
                host,
                &mut backup,
                slug,
                &proxy_url,
                ca_cert_path.as_deref(),
                ca_bundle_path.as_deref(),
            ) {
                return fail_with_rollback(&backup, e);
            }
            targets_summary.push("Managed Env (GROK_XAI_API_BASE_URL, GROK_CLI_*, HTTPS_PROXY)".to_string());
        }
        HarnessKind::Generic => return fail_action(kind, false, "不支持自动接入通用类型"),
    }

    if let Some(bp) = &backup_path {
        if let Err(e) = save_backup(bp, &backup) {
            return fail_with_rollback(&backup, e);
        }
    }

    let mut message = format!("已接入 {}（{}）", kind.display_name(), targets_summary.join(" + "));
    if let Some(warn) = ca_warning {
        message.push_str(&format!("；提示: {warn}"));
    }

    HarnessActionResult {
        kind,
        ok: true,
        connected: true,
        message,
        changed_target: targets_summary.into_iter().next(),
        backup_path: backup_path.map(|p| p.to_string_lossy().into_owned()),
    }
}

fn build_vscode_terminal_env(
    proxy_url: &str,
    ca_cert_path: Option<&str>,
    ca_bundle_path: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut out = vec![
        ("HTTPS_PROXY", proxy_url.to_string()),
        ("HTTP_PROXY", proxy_url.to_string()),
        ("NO_PROXY", DEFAULT_NO_PROXY.to_string()),
    ];
    if let Some(cert) = ca_cert_path {
        out.push(("NODE_EXTRA_CA_CERTS", cert.to_string()));
    }
    if let Some(bundle) = ca_bundle_path {
        out.push(("SSL_CERT_FILE", bundle.to_string()));
    }
    out
}

fn rollback_failed_connect(
    host: &dyn HostAdapter,
    config_path: Option<&Path>,
    kind: HarnessKind,
    backup: &HarnessBackup,
) {
    let slug = harness_slug(kind);
    let backup_dir = host.backup_dir();
    match kind {
        HarnessKind::Codex => {
            if let Some(entry) = backup.files.first() {
                let _ = restore_codex_file_from_entry(entry, backup_dir.as_deref());
            }
        }
        HarnessKind::Antigravity | HarnessKind::Qoder | HarnessKind::Cursor => {
            for entry in &backup.files {
                let _ = restore_vscode_settings_file(entry, backup_dir.as_deref());
            }
        }
        HarnessKind::ClaudeCode => {
            if let Some(entry) = backup.files.first() {
                let path = Path::new(&entry.path);
                if !entry.had_file {
                    let _ = std::fs::remove_file(path);
                } else if let (Some(bdir), Some(rel)) = (
                    backup_dir.as_deref(),
                    entry.raw_snapshot_rel.as_deref().filter(|r| is_valid_snapshot_rel(r)),
                ) {
                    if let Ok(bytes) = std::fs::read(bdir.join(rel)) {
                        let _ = write_atomic_secure(path, &bytes);
                    }
                }
            }
        }
        _ => {}
    }
    let _ = restore_harness_env_vars(host, backup);
    if !backup.shared_env_vars.is_empty() {
        let _ = release_shared_env_vars(host, slug, &backup.shared_env_vars);
    }
    let _ = restore_config_upstream(config_path, slug, backup);
}

fn apply_shared_proxy_and_ca_leases(
    host: &dyn HostAdapter,
    backup: &mut HarnessBackup,
    slug: &str,
    proxy_url: &str,
    ca_cert_path: Option<&str>,
    ca_bundle_path: Option<&str>,
) -> Result<(), String> {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("HTTPS_PROXY", proxy_url),
        ("HTTP_PROXY", proxy_url),
        ("NO_PROXY", DEFAULT_NO_PROXY),
    ];
    if let Some(cert) = ca_cert_path {
        pairs.push(("NODE_EXTRA_CA_CERTS", cert));
    }
    if let Some(bundle) = ca_bundle_path {
        pairs.push(("SSL_CERT_FILE", bundle));
    }
    acquire_shared_env_vars(host, backup, slug, &pairs)
}

/// Disconnect a harness and restore its backed-up original settings/environment variable.
pub fn disconnect_harness(kind: HarnessKind) -> HarnessActionResult {
    disconnect_harness_with_deps(&RealHostAdapter, HideConfig::default_path(), kind)
}

pub fn disconnect_harness_with(host: &dyn HostAdapter, kind: HarnessKind) -> HarnessActionResult {
    let config_path = host
        .backup_dir()
        .and_then(|d| d.parent().map(|p| p.join("config.json")));
    disconnect_harness_with_deps(host, config_path, kind)
}

pub fn disconnect_harness_with_deps(
    host: &dyn HostAdapter,
    config_path: Option<PathBuf>,
    kind: HarnessKind,
) -> HarnessActionResult {
    let _guard = HARNESS_MUTEX.lock();
    if spec_for(kind).is_none() {
        return fail_action(kind, false, "未知工具类型");
    }
    let slug = harness_slug(kind);
    let backup_dir = host.backup_dir();
    let backup_path = backup_file_path(host, kind);
    let backup_str = backup_path.as_ref().map(|p| p.to_string_lossy().into_owned());
    let fail_keep = |message: String| HarnessActionResult {
        kind,
        ok: false,
        connected: true,
        message,
        changed_target: None,
        backup_path: backup_str.clone(),
    };

    let backup = match backup_path.as_deref().map(load_backup_state) {
        Some(BackupLoadState::Corrupt) => {
            scrub_hidego_artifacts_on_corrupt_backup(host, config_path.as_deref(), kind);
            if let Some(bp) = &backup_path {
                let _ = std::fs::remove_file(bp);
            }
            return HarnessActionResult {
                kind,
                ok: true,
                connected: false,
                message: format!(
                    "检测到 {} 备份文件损坏，已防御性清理 Hide-Go 代理注入并重置连接状态",
                    kind.display_name()
                ),
                changed_target: None,
                backup_path: None,
            };
        }
        Some(BackupLoadState::Loaded(b)) => b,
        _ => HarnessBackup::default(),
    };

    match kind {
        HarnessKind::ClaudeCode => {
            let Some(home) = host.home_dir() else {
                return fail_keep("无法定位用户主目录".to_string());
            };
            let settings_path = home.join(".claude").join("settings.json");
            let file_entry = backup.files.first();
            let had_file = file_entry.is_none_or(|f| f.had_file);

            if !had_file {
                if settings_path.exists() {
                    if let Err(e) = ensure_not_symlink(&settings_path) {
                        return fail_keep(e);
                    }
                    if let Err(e) = std::fs::remove_file(&settings_path) {
                        return fail_keep(format!("移除 {} 失败: {e}", settings_path.display()));
                    }
                }
            } else if settings_path.exists() {
                let raw = match std::fs::read_to_string(&settings_path) {
                    Ok(raw) => raw,
                    Err(e) => return fail_keep(format!("读取 {} 失败: {e}", settings_path.display())),
                };
                let mut root = match parse_jsonc_value(&raw) {
                    Ok(v) => v,
                    Err(e) => return fail_keep(format!("解析 {} 失败: {e}", settings_path.display())),
                };
                let Some(root_map) = root.as_object_mut() else {
                    return fail_keep("Claude settings.json 根节点不是 JSON 对象".to_string());
                };
                if let Some(env_val) = root_map.get_mut("env") {
                    let Some(env_map) = env_val.as_object_mut() else {
                        return fail_keep("Claude settings.json 中的 env 字段不是对象".to_string());
                    };
                    let prev_anthropic = file_entry
                        .and_then(|f| f.prev_keys.get("ANTHROPIC_BASE_URL"))
                        .and_then(|v| v.as_ref())
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| backup.prev_value.clone());
                    match prev_anthropic {
                        Some(prev) => {
                            env_map.insert("ANTHROPIC_BASE_URL".to_string(), Value::String(prev));
                        }
                        None => {
                            env_map.remove("ANTHROPIC_BASE_URL");
                        }
                    }
                    if let Some(prev_np) = file_entry.and_then(|f| f.prev_keys.get("NO_PROXY")) {
                        match prev_np {
                            Some(v) => {
                                env_map.insert("NO_PROXY".to_string(), v.clone());
                            }
                            None => {
                                env_map.remove("NO_PROXY");
                            }
                        }
                    }
                    if env_map.is_empty() && !backup.had_env_object {
                        root_map.remove("env");
                    }
                }
                let pretty = match serde_json::to_string_pretty(&root) {
                    Ok(p) => p,
                    Err(e) => return fail_keep(format!("序列化 Claude settings.json 失败: {e}")),
                };
                if let Err(e) = write_atomic_secure(&settings_path, format!("{pretty}\n").as_bytes()) {
                    return fail_keep(format!("写入 {} 失败: {e}", settings_path.display()));
                }
            }
            if let (Some(bdir), Some(rel)) = (
                &backup_dir,
                file_entry
                    .and_then(|f| f.raw_snapshot_rel.as_deref())
                    .filter(|r| is_valid_snapshot_rel(r)),
            ) {
                let _ = std::fs::remove_file(bdir.join(rel));
            }
        }
        HarnessKind::Codex => {
            if let Some(entry) = backup.files.first() {
                if let Err(e) = restore_codex_file_from_entry(entry, backup_dir.as_deref()) {
                    return fail_keep(e);
                }
            }
        }
        HarnessKind::Antigravity | HarnessKind::Qoder | HarnessKind::Cursor => {
            for entry in &backup.files {
                if let Err(e) = restore_vscode_settings_file(entry, backup_dir.as_deref()) {
                    return fail_keep(e);
                }
            }
        }
        HarnessKind::Zcode | HarnessKind::GrokBuild => {}
        HarnessKind::Generic => return fail_action(kind, false, "未知工具类型"),
    }

    if let Err(e) = restore_harness_env_vars(host, &backup) {
        return fail_keep(e);
    }
    let shared_to_release = if backup.shared_env_vars.is_empty() {
        SHARED_PROXY_VARS.iter().map(|s| (*s).to_string()).collect()
    } else {
        backup.shared_env_vars.clone()
    };
    if let Err(e) = release_shared_env_vars(host, slug, &shared_to_release) {
        return fail_keep(e);
    }
    if let Err(e) = restore_config_upstream(config_path.as_deref(), slug, &backup) {
        return fail_keep(e);
    }
    if let Some(bp) = &backup_path {
        let _ = std::fs::remove_file(bp);
    }

    HarnessActionResult {
        kind,
        ok: true,
        connected: false,
        message: format!("已断开并恢复 {} 原始配置", kind.display_name()),
        changed_target: backup.files.first().map(|f| f.path.clone()),
        backup_path: None,
    }
}

fn restore_codex_file_from_entry(entry: &FileBackupEntry, backup_dir: Option<&Path>) -> Result<(), String> {
    let toml_path = Path::new(&entry.path);
    if !entry.had_file {
        if toml_path.exists() {
            ensure_not_symlink(toml_path)?;
            std::fs::remove_file(toml_path).map_err(|e| format!("移除 {} 失败: {e}", toml_path.display()))?;
        }
        if let (Some(bdir), Some(rel)) = (
            backup_dir,
            entry.raw_snapshot_rel.as_deref().filter(|r| is_valid_snapshot_rel(r)),
        ) {
            let _ = std::fs::remove_file(bdir.join(rel));
        }
        return Ok(());
    }

    if let (Some(bdir), Some(rel)) = (
        backup_dir,
        entry.raw_snapshot_rel.as_deref().filter(|r| is_valid_snapshot_rel(r)),
    ) {
        let snap_path = bdir.join(rel);
        if snap_path.exists() {
            let snap_bytes = std::fs::read(&snap_path).map_err(|e| format!("读取备份快照失败: {e}"))?;
            let snap_str = String::from_utf8_lossy(&snap_bytes);
            let current_raw = std::fs::read_to_string(toml_path).unwrap_or_default();
            let provider = entry
                .prev_keys
                .get("toml_provider")
                .and_then(|v| v.as_ref())
                .and_then(Value::as_str);
            let key = entry
                .prev_keys
                .get("toml_key")
                .and_then(|v| v.as_ref())
                .and_then(Value::as_str)
                .unwrap_or(if provider.is_some() {
                    "base_url"
                } else {
                    "openai_base_url"
                });
            let written_url = entry
                .prev_keys
                .get("toml_written_url")
                .and_then(|v| v.as_ref())
                .and_then(Value::as_str);

            let section: Vec<&str> = match provider {
                Some(p) => vec!["model_providers", p],
                None => Vec::new(),
            };

            let untouched_outside_managed =
                written_url.is_some_and(|w| set_toml_string_key(&snap_str, &section, key, w) == current_raw);

            if untouched_outside_managed || current_raw.is_empty() {
                write_atomic_secure(toml_path, &snap_bytes)
                    .map_err(|e| format!("恢复 {} 失败: {e}", toml_path.display()))?;
            } else {
                let prev_url = entry
                    .prev_keys
                    .get("toml_prev_url")
                    .and_then(|v| v.as_ref())
                    .and_then(Value::as_str);
                let restored = match prev_url {
                    Some(prev) => set_toml_string_key(&current_raw, &section, key, prev),
                    None => remove_toml_key(&current_raw, &section, key),
                };
                write_atomic_secure(toml_path, restored.as_bytes())
                    .map_err(|e| format!("外科恢复 {} 失败: {e}", toml_path.display()))?;
            }
            let _ = std::fs::remove_file(snap_path);
            return Ok(());
        }
    }
    Ok(())
}

fn looks_like_hidego_local_url(val: &str, route_prefix: Option<&str>) -> bool {
    let lower = val.trim().to_ascii_lowercase();
    if !(lower.starts_with("http://127.0.0.1:") || lower.starts_with("http://localhost:")) {
        return false;
    }
    match route_prefix {
        Some(route) => {
            let route_l = route.to_ascii_lowercase();
            lower.contains(&route_l)
        }
        None => true,
    }
}

fn scrub_vscode_settings_hidego_only(path: &Path) {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(mut val) = parse_jsonc_value(&raw) else {
        return;
    };
    let Some(map) = val.as_object_mut() else {
        return;
    };
    let mut changed = false;
    if map
        .get("http.proxy")
        .and_then(Value::as_str)
        .is_some_and(|u| looks_like_hidego_local_url(u, None))
    {
        map.remove("http.proxy");
        map.remove("http.proxySupport");
        map.remove("cursor.general.disableHttp2");
        if let Some(Value::Array(arr)) = map.get_mut("http.noProxy") {
            arr.retain(|v| {
                !v.as_str()
                    .is_some_and(|s| VSCODE_HTTP_NO_PROXY.iter().any(|d| s.trim().eq_ignore_ascii_case(d)))
            });
            if arr.is_empty() {
                map.remove("http.noProxy");
            }
        }
        changed = true;
    }
    if map
        .get("app.configAdvancedProxyURL")
        .and_then(Value::as_str)
        .is_some_and(|u| looks_like_hidego_local_url(u, None))
    {
        map.remove("app.configAdvancedProxyURL");
        map.remove("app.configAdvancedProxyMode");
        changed = true;
    }
    let term_key = vscode_terminal_env_key();
    if let Some(Value::Object(term_map)) = map.get_mut(term_key) {
        if term_map
            .get("HTTPS_PROXY")
            .and_then(Value::as_str)
            .is_some_and(|u| looks_like_hidego_local_url(u, None))
        {
            for k in SHARED_PROXY_VARS {
                term_map.remove(*k);
            }
            changed = true;
        }
        if term_map.is_empty() {
            map.remove(term_key);
        }
    }
    if changed {
        if let Ok(pretty) = serde_json::to_string_pretty(&val) {
            let _ = write_atomic_secure(path, format!("{pretty}\n").as_bytes());
        }
    }
}

fn scrub_hidego_artifacts_on_corrupt_backup(host: &dyn HostAdapter, config_path: Option<&Path>, kind: HarnessKind) {
    let slug = harness_slug(kind);
    match kind {
        HarnessKind::ClaudeCode => {
            if let Some(home) = host.home_dir() {
                let settings_path = home.join(".claude").join("settings.json");
                if let Ok(raw) = std::fs::read_to_string(&settings_path) {
                    if let Ok(mut root) = parse_jsonc_value(&raw) {
                        if let Some(env_map) = root.get_mut("env").and_then(Value::as_object_mut) {
                            if env_map
                                .get("ANTHROPIC_BASE_URL")
                                .and_then(Value::as_str)
                                .is_some_and(|u| looks_like_hidego_local_url(u, Some("/claude-code")))
                            {
                                env_map.remove("ANTHROPIC_BASE_URL");
                                if let Ok(pretty) = serde_json::to_string_pretty(&root) {
                                    let _ = write_atomic_secure(&settings_path, format!("{pretty}\n").as_bytes());
                                }
                            }
                        }
                    }
                }
            }
        }
        HarnessKind::Codex => {
            if let Some(home) = host.home_dir() {
                let toml_path = home.join(".codex").join("config.toml");
                if let Ok(raw) = std::fs::read_to_string(&toml_path) {
                    let provider = read_toml_string_key(&raw, &[], "model_provider");
                    let next = match provider.as_deref() {
                        Some(p) => {
                            if read_toml_string_key(&raw, &["model_providers", p], "base_url")
                                .as_deref()
                                .is_some_and(|u| looks_like_hidego_local_url(u, Some("/codex")))
                            {
                                Some(remove_toml_key(&raw, &["model_providers", p], "base_url"))
                            } else {
                                None
                            }
                        }
                        None => {
                            if read_toml_string_key(&raw, &[], "openai_base_url")
                                .as_deref()
                                .is_some_and(|u| looks_like_hidego_local_url(u, Some("/codex")))
                            {
                                Some(remove_toml_key(&raw, &[], "openai_base_url"))
                            } else {
                                None
                            }
                        }
                    };
                    if let Some(cleaned) = next {
                        let _ = write_atomic_secure(&toml_path, cleaned.as_bytes());
                    }
                }
            }
            for var in ["OPENAI_BASE_URL", "CODEX_CA_CERTIFICATE"] {
                if host
                    .user_env_get(var)
                    .as_deref()
                    .is_some_and(|v| looks_like_hidego_local_url(v, Some("/codex")) || var == "CODEX_CA_CERTIFICATE")
                {
                    let _ = host.user_env_remove(var);
                }
            }
        }
        HarnessKind::Antigravity => {
            for path in antigravity_settings_candidates(host) {
                scrub_vscode_settings_hidego_only(&path);
            }
        }
        HarnessKind::Qoder => {
            for path in qoder_settings_candidates(host) {
                scrub_vscode_settings_hidego_only(&path);
            }
        }
        HarnessKind::Cursor => {
            if let Some(path) = cursor_settings_path(host) {
                scrub_vscode_settings_hidego_only(&path);
            }
        }
        HarnessKind::Zcode => {
            for var in ["ZCODE_HTTP_PROXY", "ZCODE_NO_PROXY", "ZCODE_AGENT_CA_CERT"] {
                let _ = host.user_env_remove(var);
            }
        }
        HarnessKind::GrokBuild => {
            for var in [
                "GROK_XAI_API_BASE_URL",
                "GROK_CLI_CHAT_PROXY_BASE_URL",
                "GROK_CLI_BASE_URL",
            ] {
                let _ = host.user_env_remove(var);
            }
        }
        HarnessKind::Generic => {}
    }

    let shared: Vec<String> = SHARED_PROXY_VARS.iter().map(|s| (*s).to_string()).collect();
    let _ = release_shared_env_vars(host, slug, &shared);
    if let Some(path) = config_path {
        if path.exists() {
            let mut cfg = HideConfig::load_or_create(path);
            if cfg.harness_upstreams.remove(slug).is_some() {
                let _ = cfg.save(path);
            }
        }
    }
}

/// Automatically connect every installed harness that supports automatic configuration.
pub fn connect_all_detected(proxy_port: u16) -> Vec<HarnessActionResult> {
    connect_all_detected_with_deps(
        &RealHostAdapter,
        Arc::new(RealCaTrustAdapter),
        CaManager::default_ca_dir(),
        HideConfig::default_path(),
        proxy_port,
    )
}

pub fn connect_all_detected_with(host: &dyn HostAdapter, proxy_port: u16) -> Vec<HarnessActionResult> {
    let ca_dir = host.backup_dir().and_then(|d| d.parent().map(|p| p.join("ca")));
    let config_path = host
        .backup_dir()
        .and_then(|d| d.parent().map(|p| p.join("config.json")));
    connect_all_detected_with_deps(host, Arc::new(RealCaTrustAdapter), ca_dir, config_path, proxy_port)
}

pub fn connect_all_detected_with_deps(
    host: &dyn HostAdapter,
    trust_adapter: Arc<dyn CaTrustAdapter>,
    ca_dir: Option<PathBuf>,
    config_path: Option<PathBuf>,
    proxy_port: u16,
) -> Vec<HarnessActionResult> {
    let profiles = detect_all_harness_profiles_with(host, proxy_port, &HashMap::new());
    profiles
        .into_iter()
        .filter(|p| p.installed && p.auto_connect_mode != AutoConnectMode::Manual)
        .map(|p| {
            connect_harness_with_deps(
                host,
                trust_adapter.clone(),
                ca_dir.clone(),
                config_path.clone(),
                p.kind,
                proxy_port,
            )
        })
        .collect()
}

/// Restore every harness currently backed up by Hide-Go (used during uninstall).
pub fn disconnect_all_managed() -> Vec<HarnessActionResult> {
    disconnect_all_managed_with_deps(&RealHostAdapter, HideConfig::default_path())
}

pub fn disconnect_all_managed_with(host: &dyn HostAdapter) -> Vec<HarnessActionResult> {
    let config_path = host
        .backup_dir()
        .and_then(|d| d.parent().map(|p| p.join("config.json")));
    disconnect_all_managed_with_deps(host, config_path)
}

pub fn disconnect_all_managed_with_deps(
    host: &dyn HostAdapter,
    config_path: Option<PathBuf>,
) -> Vec<HarnessActionResult> {
    let Some(dir) = host.backup_dir() else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for spec in SPECS {
        let bp = dir.join(format!("{}.json", harness_slug(spec.kind)));
        if bp.exists() {
            results.push(disconnect_harness_with_deps(host, config_path.clone(), spec.kind));
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::MockCaTrustAdapter;
    use std::cell::RefCell;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("hide-go-test-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct MockHost {
        root: PathBuf,
        bin_dir: PathBuf,
        env: RefCell<HashMap<String, String>>,
        uninstall_entries: RefCell<Vec<UninstallEntry>>,
    }

    impl MockHost {
        fn new(dir: &Path) -> Self {
            let bin_dir = dir.join("bin");
            std::fs::create_dir_all(&bin_dir).unwrap();
            Self {
                root: dir.to_path_buf(),
                bin_dir,
                env: RefCell::new(HashMap::new()),
                uninstall_entries: RefCell::new(Vec::new()),
            }
        }
    }

    impl HostAdapter for MockHost {
        fn home_dir(&self) -> Option<PathBuf> {
            Some(self.root.clone())
        }
        fn appdata_dir(&self) -> Option<PathBuf> {
            Some(self.root.join("appdata"))
        }
        fn local_appdata_dir(&self) -> Option<PathBuf> {
            Some(self.root.join("localappdata"))
        }
        fn backup_dir(&self) -> Option<PathBuf> {
            Some(self.root.join("hide-go").join("harness-backups"))
        }
        fn path_dirs(&self) -> Vec<PathBuf> {
            vec![self.bin_dir.clone()]
        }
        fn process_env(&self, name: &str) -> Option<String> {
            self.env.borrow().get(name).cloned()
        }
        fn user_env_get(&self, name: &str) -> Option<String> {
            self.env.borrow().get(name).cloned()
        }
        fn user_env_set(&self, name: &str, value: &str) -> Result<(), String> {
            self.env.borrow_mut().insert(name.to_string(), value.to_string());
            Ok(())
        }
        fn user_env_remove(&self, name: &str) -> Result<(), String> {
            self.env.borrow_mut().remove(name);
            Ok(())
        }
        fn windows_uninstall_entries(&self) -> Vec<UninstallEntry> {
            self.uninstall_entries.borrow().clone()
        }
    }

    fn connect_isolated(
        host: &MockHost,
        ca: Arc<MockCaTrustAdapter>,
        kind: HarnessKind,
        port: u16,
    ) -> HarnessActionResult {
        connect_harness_with_deps(
            host,
            ca,
            Some(host.root.join("hide-go").join("ca")),
            Some(host.root.join("hide-go").join("config.json")),
            kind,
            port,
        )
    }

    fn disconnect_isolated(host: &MockHost, kind: HarnessKind) -> HarnessActionResult {
        disconnect_harness_with_deps(host, Some(host.root.join("hide-go").join("config.json")), kind)
    }

    #[test]
    fn detection_reports_uninstalled_and_inactive_without_fake_positives() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        let profiles = detect_all_harness_profiles_with(&host, 18787, &HashMap::new());
        assert!(profiles
            .iter()
            .all(|p| !p.installed && !p.configured && !p.detected_active));
    }

    #[test]
    fn windows_uninstall_registry_discovers_nonstandard_install_dirs() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        let zcode_dir = tmp.path().join("custom_apps").join("zcode");
        std::fs::create_dir_all(&zcode_dir).unwrap();
        let exe = zcode_dir.join("ZCode.exe");
        std::fs::write(&exe, b"stub").unwrap();
        host.uninstall_entries.borrow_mut().push(UninstallEntry {
            display_name: "ZCode 3.17.1".to_string(),
            install_location: Some(zcode_dir.to_string_lossy().into_owned()),
            display_icon: Some(format!("\"{}\",0", exe.display())),
        });

        let profiles = detect_all_harness_profiles_with(&host, 18787, &HashMap::new());
        let zcode = profiles.iter().find(|p| p.kind == HarnessKind::Zcode).unwrap();
        assert!(zcode.installed);
        assert!(zcode.install_paths.iter().any(|p| p.contains("ZCode.exe")));
    }

    #[test]
    fn claude_code_connect_adds_no_proxy_when_proxy_exists_and_restores_cleanly() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let settings_path = claude_dir.join("settings.json");
        std::fs::write(
            &settings_path,
            r#"{"theme":"dark","env":{"ANTHROPIC_BASE_URL":"https://custom.example","HTTPS_PROXY":"http://127.0.0.1:18765","OTHER":"1"}}"#,
        )
        .unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        let res = connect_isolated(&host, ca.clone(), HarnessKind::ClaudeCode, 18787);
        assert!(res.ok && res.connected);

        let after: Value = serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert_eq!(after["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18787/claude-code");
        assert!(after["env"]["NO_PROXY"].as_str().unwrap().contains("127.0.0.1"));

        let cfg = HideConfig::load_or_create(&tmp.path().join("hide-go").join("config.json"));
        assert_eq!(
            cfg.harness_upstreams.get("claude-code").map(String::as_str),
            Some("https://custom.example")
        );

        let profiles_after = detect_all_harness_profiles_with(&host, 18787, &HashMap::new());
        let claude_after = profiles_after
            .iter()
            .find(|p| p.kind == HarnessKind::ClaudeCode)
            .unwrap();
        assert!(claude_after.configured);

        let disc = disconnect_isolated(&host, HarnessKind::ClaudeCode);
        assert!(disc.ok && !disc.connected);
        let restored: Value = serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert_eq!(restored["theme"], "dark");
        assert_eq!(restored["env"]["OTHER"], "1");
        assert_eq!(restored["env"]["ANTHROPIC_BASE_URL"], "https://custom.example");
        assert!(restored["env"].get("NO_PROXY").is_none());

        let cfg_after = HideConfig::load_or_create(&tmp.path().join("hide-go").join("config.json"));
        assert!(!cfg_after.harness_upstreams.contains_key("claude-code"));
    }

    #[test]
    fn codex_connect_edits_active_toml_provider_preserves_comments_and_restores() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".codex")).unwrap();
        let toml_path = tmp.path().join(".codex").join("config.toml");
        let original_toml = concat!(
            "# user codex config\n",
            "model_provider = \"custom\"\n",
            "model = \"gpt-5.3-codex\"\n\n",
            "[model_providers.custom]\n",
            "name = \"custom\"\n",
            "base_url = \"https://agentrouter.org/v1\" # keep comment\n",
            "wire_api = \"responses\"\n",
        );
        std::fs::write(&toml_path, original_toml).unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        let conn = connect_isolated(&host, ca, HarnessKind::Codex, 18787);
        assert!(conn.ok && conn.connected);

        let edited = std::fs::read_to_string(&toml_path).unwrap();
        assert!(edited.contains("# user codex config"));
        assert!(edited.contains("base_url = \"http://127.0.0.1:18787/codex/v1\" # keep comment"));
        assert!(edited.contains("wire_api = \"responses\""));
        assert!(host.env.borrow().contains_key("CODEX_CA_CERTIFICATE"));
        assert_eq!(
            host.env.borrow().get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18787")
        );

        let cfg = HideConfig::load_or_create(&tmp.path().join("hide-go").join("config.json"));
        assert_eq!(
            cfg.harness_upstreams.get("codex").map(String::as_str),
            Some("https://agentrouter.org")
        );

        let profiles = detect_all_harness_profiles_with(&host, 18787, &HashMap::new());
        let codex = profiles.iter().find(|p| p.kind == HarnessKind::Codex).unwrap();
        assert!(codex.configured);
        assert!(codex.requires_ca_trust);

        let disc = disconnect_isolated(&host, HarnessKind::Codex);
        assert!(disc.ok && !disc.connected);
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), original_toml);
        assert!(!host.env.borrow().contains_key("CODEX_CA_CERTIFICATE"));
        assert!(!host.env.borrow().contains_key("HTTPS_PROXY"));
        let cfg_after = HideConfig::load_or_create(&tmp.path().join("hide-go").join("config.json"));
        assert!(!cfg_after.harness_upstreams.contains_key("codex"));
    }

    #[test]
    fn cursor_and_qoder_jsonc_and_shared_env_refcounting_roundtrip() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        host.env
            .borrow_mut()
            .insert("NO_PROXY".to_string(), "corp.internal,10.0.0.0/8".to_string());

        let cursor_dir = tmp.path().join("appdata").join("Cursor").join("User");
        std::fs::create_dir_all(&cursor_dir).unwrap();
        let cursor_settings = cursor_dir.join("settings.json");
        let original_cursor_jsonc = concat!(
            "{\n",
            "  // User comment preserved losslessly\n",
            "  \"editor.fontSize\": 15,\n",
            "}\n",
        );
        std::fs::write(&cursor_settings, original_cursor_jsonc).unwrap();

        let qoder_cn_dir = tmp.path().join("appdata").join("QoderCN").join("User");
        std::fs::create_dir_all(&qoder_cn_dir).unwrap();
        let qoder_cn_settings = qoder_cn_dir.join("settings.json");
        std::fs::write(&qoder_cn_settings, r#"{"app.configAdvancedProxyMode":"system"}"#).unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        assert!(connect_isolated(&host, ca.clone(), HarnessKind::Cursor, 18787).ok);
        assert!(connect_isolated(&host, ca.clone(), HarnessKind::Qoder, 18787).ok);

        let cur_val: Value = serde_json::from_str(&std::fs::read_to_string(&cursor_settings).unwrap()).unwrap();
        assert_eq!(cur_val["http.proxy"], "http://127.0.0.1:18787");
        assert_eq!(cur_val["http.proxySupport"], "override");
        assert_eq!(cur_val["cursor.general.disableHttp2"], true);
        assert!(cur_val.get("http.proxyStrictSSL").is_none());

        let qoder_val: Value = serde_json::from_str(&std::fs::read_to_string(&qoder_cn_settings).unwrap()).unwrap();
        assert_eq!(qoder_val["app.configAdvancedProxyMode"], "manual");
        assert_eq!(qoder_val["app.configAdvancedProxyURL"], "http://127.0.0.1:18787");
        assert_eq!(qoder_val["http.proxy"], "http://127.0.0.1:18787");
        assert_eq!(
            host.env.borrow().get("NO_PROXY").map(String::as_str),
            Some("corp.internal,10.0.0.0/8,localhost,127.0.0.1,::1")
        );

        let profiles = detect_all_harness_profiles_with(&host, 18787, &HashMap::new());
        assert!(
            profiles
                .iter()
                .find(|p| p.kind == HarnessKind::Cursor)
                .unwrap()
                .configured
        );
        assert!(
            profiles
                .iter()
                .find(|p| p.kind == HarnessKind::Qoder)
                .unwrap()
                .configured
        );

        // Disconnecting Cursor alone MUST keep shared HTTPS_PROXY/NODE_EXTRA_CA_CERTS active for Qoder!
        assert!(disconnect_isolated(&host, HarnessKind::Cursor).ok);
        assert_eq!(
            std::fs::read_to_string(&cursor_settings).unwrap(),
            original_cursor_jsonc
        );
        assert_eq!(
            host.env.borrow().get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18787")
        );

        // Disconnecting Qoder (last owner) restores shared env vars completely!
        assert!(disconnect_isolated(&host, HarnessKind::Qoder).ok);
        let qoder_restored: Value =
            serde_json::from_str(&std::fs::read_to_string(&qoder_cn_settings).unwrap()).unwrap();
        assert_eq!(qoder_restored["app.configAdvancedProxyMode"], "system");
        assert!(qoder_restored.get("app.configAdvancedProxyURL").is_none());
        assert!(!host.env.borrow().contains_key("HTTPS_PROXY"));
        assert_eq!(
            host.env.borrow().get("NO_PROXY").map(String::as_str),
            Some("corp.internal,10.0.0.0/8")
        );
    }

    #[test]
    fn antigravity_zcode_and_grok_connect_and_disconnect_roundtrip() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        let ag_user = tmp.path().join("appdata").join("Antigravity IDE").join("User");
        std::fs::create_dir_all(&ag_user).unwrap();
        std::fs::write(ag_user.join("settings.json"), "{}").unwrap();
        std::fs::create_dir_all(tmp.path().join(".zcode")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".grok")).unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        assert!(connect_isolated(&host, ca.clone(), HarnessKind::Antigravity, 18787).ok);
        assert!(connect_isolated(&host, ca.clone(), HarnessKind::Zcode, 18787).ok);
        assert!(connect_isolated(&host, ca.clone(), HarnessKind::GrokBuild, 18787).ok);

        assert_eq!(
            host.env.borrow().get("ZCODE_HTTP_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18787")
        );
        assert!(host.env.borrow().contains_key("ZCODE_AGENT_CA_CERT"));
        assert_eq!(
            host.env.borrow().get("GROK_XAI_API_BASE_URL").map(String::as_str),
            Some("http://127.0.0.1:18787/grok-build/v1")
        );

        let profiles = detect_all_harness_profiles_with(&host, 18787, &HashMap::new());
        assert!(
            profiles
                .iter()
                .find(|p| p.kind == HarnessKind::Antigravity)
                .unwrap()
                .configured
        );
        assert!(
            profiles
                .iter()
                .find(|p| p.kind == HarnessKind::Zcode)
                .unwrap()
                .configured
        );
        assert!(
            profiles
                .iter()
                .find(|p| p.kind == HarnessKind::GrokBuild)
                .unwrap()
                .configured
        );

        disconnect_all_managed_with_deps(&host, Some(tmp.path().join("hide-go").join("config.json")));
        assert!(!host.env.borrow().contains_key("ZCODE_HTTP_PROXY"));
        assert!(!host.env.borrow().contains_key("GROK_XAI_API_BASE_URL"));
        assert!(!host.env.borrow().contains_key("HTTPS_PROXY"));
        assert_eq!(
            std::fs::read_to_string(ag_user.join("settings.json")).unwrap().trim(),
            "{}"
        );
    }

    #[test]
    fn connect_all_connects_installed_tools_including_cursor() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".codex")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".cursor")).unwrap();
        host.env
            .borrow_mut()
            .insert("OPENAI_BASE_URL".to_string(), "https://relay.example/v1".to_string());

        let ca = Arc::new(MockCaTrustAdapter::new());
        let results = connect_all_detected_with_deps(
            &host,
            ca,
            Some(tmp.path().join("hide-go").join("ca")),
            Some(tmp.path().join("hide-go").join("config.json")),
            19999,
        );
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.ok));
        assert_eq!(
            host.env.borrow().get("OPENAI_BASE_URL").map(String::as_str),
            Some("http://127.0.0.1:19999/codex/v1")
        );

        disconnect_all_managed_with_deps(&host, Some(tmp.path().join("hide-go").join("config.json")));
        assert_eq!(
            host.env.borrow().get("OPENAI_BASE_URL").map(String::as_str),
            Some("https://relay.example/v1")
        );
        assert!(!tmp
            .path()
            .join("appdata")
            .join("Cursor")
            .join("User")
            .join("settings.json")
            .exists());
    }

    #[test]
    fn shell_rc_managed_block_roundtrips_cleanly() {
        let tmp = TempDir::new();
        let rc = tmp.path().join(".profile");
        std::fs::write(&rc, "export PATH=\"$HOME/.local/bin:$PATH\"\n").unwrap();

        write_shell_rc_var(tmp.path(), "OPENAI_BASE_URL", Some("http://127.0.0.1:18787/codex/v1")).unwrap();
        assert_eq!(
            read_shell_rc_var(tmp.path(), "OPENAI_BASE_URL").as_deref(),
            Some("http://127.0.0.1:18787/codex/v1")
        );
        write_shell_rc_var(tmp.path(), "OPENAI_BASE_URL", None).unwrap();
        assert_eq!(read_shell_rc_var(tmp.path(), "OPENAI_BASE_URL"), None);
        assert_eq!(
            std::fs::read_to_string(&rc).unwrap(),
            "export PATH=\"$HOME/.local/bin:$PATH\"\n"
        );
    }

    #[test]
    fn configured_check_requires_matching_port_and_ignores_toml_comments() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".codex")).unwrap();
        let toml_path = tmp.path().join(".codex").join("config.toml");
        std::fs::write(
            &toml_path,
            "# base_url = \"http://127.0.0.1:18787/codex/v1\"\nmodel = \"gpt-5\"\n",
        )
        .unwrap();
        host.env.borrow_mut().insert(
            "GROK_XAI_API_BASE_URL".to_string(),
            "http://127.0.0.1:18787/grok-build/v1".to_string(),
        );

        let on_18787 = detect_all_harness_profiles_with(&host, 18787, &HashMap::new());
        let codex_18787 = on_18787.iter().find(|p| p.kind == HarnessKind::Codex).unwrap();
        let grok_18787 = on_18787.iter().find(|p| p.kind == HarnessKind::GrokBuild).unwrap();
        assert!(!codex_18787.configured);
        assert!(grok_18787.configured);

        let on_19999 = detect_all_harness_profiles_with(&host, 19999, &HashMap::new());
        let grok_19999 = on_19999.iter().find(|p| p.kind == HarnessKind::GrokBuild).unwrap();
        assert!(!grok_19999.configured);
    }

    #[test]
    fn shell_rc_reader_stops_at_end_marker() {
        let tmp = TempDir::new();
        let rc = tmp.path().join(".profile");
        std::fs::write(
            &rc,
            concat!(
                "# >>> hide-go OPENAI_BASE_URL >>>\n",
                "# empty block\n",
                "# <<< hide-go OPENAI_BASE_URL <<<\n",
                "export OPENAI_BASE_URL=\"https://manual.example/v1\"\n"
            ),
        )
        .unwrap();
        assert_eq!(read_shell_rc_var(tmp.path(), "OPENAI_BASE_URL"), None);
    }

    #[test]
    fn claude_disconnect_propagates_corrupt_settings_and_keeps_backup() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let settings_path = claude_dir.join("settings.json");
        std::fs::write(&settings_path, "{}").unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        let conn = connect_isolated(&host, ca, HarnessKind::ClaudeCode, 18787);
        assert!(conn.ok);
        let bp = PathBuf::from(conn.backup_path.unwrap());
        assert!(bp.exists());

        std::fs::write(&settings_path, "{corrupt json").unwrap();
        let disc = disconnect_isolated(&host, HarnessKind::ClaudeCode);
        assert!(!disc.ok);
        assert!(disc.connected);
        assert!(bp.exists());
    }

    #[test]
    fn windows_managed_env_scripts_avoid_registry_and_roundtrip_cleanly() {
        let tmp = TempDir::new();
        let docs_ps = tmp.path().join("Documents").join("PowerShell");
        std::fs::create_dir_all(&docs_ps).unwrap();

        write_windows_managed_env_var(tmp.path(), "HTTPS_PROXY", Some("http://127.0.0.1:18787")).unwrap();
        write_windows_managed_env_var(tmp.path(), "TEST_QUOTE", Some("a'b")).unwrap();
        assert_eq!(
            read_windows_managed_env_var(tmp.path(), "HTTPS_PROXY").as_deref(),
            Some("http://127.0.0.1:18787")
        );
        assert_eq!(
            read_windows_managed_env_var(tmp.path(), "TEST_QUOTE").as_deref(),
            Some("a'b")
        );

        let ps1 = std::fs::read_to_string(managed_env_ps1_path(tmp.path())).unwrap();
        assert!(ps1.contains("$env:HTTPS_PROXY = 'http://127.0.0.1:18787'"), "{ps1}");
        assert!(ps1.contains("$env:TEST_QUOTE = 'a''b'"), "{ps1}");
        assert!(managed_env_cmd_path(tmp.path()).exists());
        let prof = std::fs::read_to_string(docs_ps.join("Microsoft.PowerShell_profile.ps1")).unwrap();
        assert!(prof.contains(WIN_MANAGED_ENV_START), "{prof}");

        assert!(write_windows_managed_env_var(tmp.path(), "BAD-NAME", Some("x")).is_err());
        assert!(write_windows_managed_env_var(tmp.path(), "HTTPS_PROXY", Some("a\nb")).is_err());

        write_windows_managed_env_var(tmp.path(), "HTTPS_PROXY", None).unwrap();
        write_windows_managed_env_var(tmp.path(), "TEST_QUOTE", None).unwrap();
        assert!(!managed_env_ps1_path(tmp.path()).exists());
        assert!(!managed_env_cmd_path(tmp.path()).exists());
        assert!(!docs_ps.join("Microsoft.PowerShell_profile.ps1").exists());
    }

    #[test]
    fn shell_rc_single_quotes_prevent_command_injection() {
        let tmp = TempDir::new();
        let rc = tmp.path().join(".profile");
        std::fs::write(&rc, "").unwrap();
        let payload = "http://127.0.0.1:18787/$(whoami)'test";
        write_shell_rc_var(tmp.path(), "HTTPS_PROXY", Some(payload)).unwrap();
        let written = std::fs::read_to_string(&rc).unwrap();
        assert!(
            written.contains("export HTTPS_PROXY='http://127.0.0.1:18787/$(whoami)'\\''test'"),
            "{written}"
        );
        assert_eq!(read_shell_rc_var(tmp.path(), "HTTPS_PROXY").as_deref(), Some(payload));
        assert!(write_shell_rc_var(tmp.path(), "HTTPS_PROXY", Some("bad\nline")).is_err());
    }

    #[test]
    fn claude_and_codex_chain_with_cc_switch_loopback_upstream() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".claude")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".codex")).unwrap();

        let claude_settings = tmp.path().join(".claude").join("settings.json");
        std::fs::write(
            &claude_settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:15721"}}"#,
        )
        .unwrap();
        let codex_toml = tmp.path().join(".codex").join("config.toml");
        std::fs::write(
            &codex_toml,
            "model_provider = \"ccswitch\"\n[model_providers.ccswitch]\nbase_url = \"http://127.0.0.1:15721/v1\"\n",
        )
        .unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        assert!(connect_isolated(&host, ca.clone(), HarnessKind::ClaudeCode, 18787).ok);
        assert!(connect_isolated(&host, ca, HarnessKind::Codex, 18787).ok);

        let cfg = HideConfig::load_or_create(&tmp.path().join("hide-go").join("config.json"));
        assert_eq!(
            cfg.harness_upstreams.get("claude-code").map(String::as_str),
            Some("http://127.0.0.1:15721")
        );
        assert_eq!(
            cfg.harness_upstreams.get("codex").map(String::as_str),
            Some("http://127.0.0.1:15721")
        );

        assert!(disconnect_isolated(&host, HarnessKind::ClaudeCode).ok);
        assert!(disconnect_isolated(&host, HarnessKind::Codex).ok);
        let claude_after: Value = serde_json::from_str(&std::fs::read_to_string(&claude_settings).unwrap()).unwrap();
        assert_eq!(claude_after["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:15721");
        assert!(std::fs::read_to_string(&codex_toml)
            .unwrap()
            .contains("base_url = \"http://127.0.0.1:15721/v1\""));
    }

    #[test]
    fn codex_disconnect_surgically_preserves_user_edits_made_while_connected() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".codex")).unwrap();
        let toml_path = tmp.path().join(".codex").join("config.toml");
        std::fs::write(
            &toml_path,
            "model_provider = \"custom\"\nmodel = \"gpt-5.3\"\n[model_providers.custom]\nbase_url = \"https://api.example/v1\"\n",
        )
        .unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        assert!(connect_isolated(&host, ca, HarnessKind::Codex, 18787).ok);
        let during = std::fs::read_to_string(&toml_path)
            .unwrap()
            .replace("gpt-5.3", "gpt-5.4");
        std::fs::write(&toml_path, during).unwrap();

        assert!(disconnect_isolated(&host, HarnessKind::Codex).ok);
        let after = std::fs::read_to_string(&toml_path).unwrap();
        assert!(after.contains("model = \"gpt-5.4\""), "{after}");
        assert!(after.contains("base_url = \"https://api.example/v1\""), "{after}");
    }

    #[test]
    fn corrupt_backup_json_defensively_scrubs_hidego_without_bricking() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".claude")).unwrap();
        let claude_settings = tmp.path().join(".claude").join("settings.json");
        std::fs::write(&claude_settings, "{}").unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());
        let conn = connect_isolated(&host, ca, HarnessKind::ClaudeCode, 18787);
        assert!(conn.ok);
        let bp = PathBuf::from(conn.backup_path.unwrap());
        std::fs::write(&bp, "{corrupted backup").unwrap();

        let disc = disconnect_isolated(&host, HarnessKind::ClaudeCode);
        assert!(disc.ok && !disc.connected);
        assert!(!bp.exists());
        let after: Value = serde_json::from_str(&std::fs::read_to_string(&claude_settings).unwrap()).unwrap();
        assert!(after["env"].get("ANTHROPIC_BASE_URL").is_none());
    }

    #[test]
    fn vscode_http_no_proxy_merges_and_restores_without_registry_writes() {
        let tmp = TempDir::new();
        let host = MockHost::new(tmp.path());

        let cursor_dir = tmp.path().join("appdata").join("Cursor").join("User");
        let qoder_dir = tmp.path().join("appdata").join("Qoder").join("User");
        let qoder_cn_dir = tmp.path().join("appdata").join("QoderCN").join("User");
        let ag_dir = tmp.path().join("appdata").join("Antigravity IDE").join("User");
        for dir in [&cursor_dir, &qoder_dir, &qoder_cn_dir, &ag_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }

        let cursor_settings = cursor_dir.join("settings.json");
        let orig_cursor = concat!(
            "{\n",
            "  // keep user bypass rules\n",
            "  \"http.noProxy\": [\"corp.internal\", \"localhost\"],\n",
            "  \"editor.tabSize\": 2,\n",
            "}\n",
        );
        std::fs::write(&cursor_settings, orig_cursor).unwrap();

        let qoder_settings = qoder_dir.join("settings.json");
        std::fs::write(&qoder_settings, r#"{"http.noProxy":["10.0.0.1"]}"#).unwrap();

        let qoder_cn_settings = qoder_cn_dir.join("settings.json");
        std::fs::write(&qoder_cn_settings, "{}").unwrap();

        let ag_settings = ag_dir.join("settings.json");
        std::fs::write(&ag_settings, r#"{"http.noProxy":["dev.internal","127.0.0.1"]}"#).unwrap();

        let ca = Arc::new(MockCaTrustAdapter::new());

        let cursor_res = connect_isolated(&host, ca.clone(), HarnessKind::Cursor, 18787);
        assert!(cursor_res.ok && cursor_res.connected);
        assert!(
            cursor_res.message.contains("安装并信任根证书"),
            "expected CA trust reminder in message: {}",
            cursor_res.message
        );
        // Connecting must never silently mutate OS CA store / Registry.
        let ca_mgr = CaManager::load_or_create(tmp.path().join("hide-go").join("ca"), ca.clone()).unwrap();
        assert!(!ca_mgr.status().installed_in_os_store);

        let qoder_res = connect_isolated(&host, ca.clone(), HarnessKind::Qoder, 18787);
        assert!(qoder_res.ok && qoder_res.connected);
        assert!(qoder_res.message.contains("安装并信任根证书"));

        let ag_res = connect_isolated(&host, ca.clone(), HarnessKind::Antigravity, 18787);
        assert!(ag_res.ok && ag_res.connected);
        assert!(ag_res.message.contains("安装并信任根证书"));

        // Reconnect while already connected must not duplicate http.noProxy entries.
        let cursor_re = connect_isolated(&host, ca.clone(), HarnessKind::Cursor, 18787);
        assert!(cursor_re.ok);

        let cur_val: Value = parse_jsonc_value(&std::fs::read_to_string(&cursor_settings).unwrap()).unwrap();
        assert_eq!(
            cur_val["http.noProxy"],
            serde_json::json!(["corp.internal", "localhost", "127.0.0.1", "::1", ".local"])
        );
        let q_val: Value = serde_json::from_str(&std::fs::read_to_string(&qoder_settings).unwrap()).unwrap();
        assert_eq!(
            q_val["http.noProxy"],
            serde_json::json!(["10.0.0.1", "localhost", "127.0.0.1", "::1", ".local"])
        );
        let qcn_val: Value = serde_json::from_str(&std::fs::read_to_string(&qoder_cn_settings).unwrap()).unwrap();
        assert_eq!(
            qcn_val["http.noProxy"],
            serde_json::json!(["localhost", "127.0.0.1", "::1", ".local"])
        );
        let ag_val: Value = serde_json::from_str(&std::fs::read_to_string(&ag_settings).unwrap()).unwrap();
        assert_eq!(
            ag_val["http.noProxy"],
            serde_json::json!(["dev.internal", "127.0.0.1", "localhost", "::1", ".local"])
        );

        // Once CA is trusted, reconnecting should not emit the untrusted CA reminder.
        ca_mgr.install_trust().unwrap();
        let trusted_res = connect_isolated(&host, ca.clone(), HarnessKind::Cursor, 18787);
        assert!(!trusted_res.message.contains("安装并信任根证书"));

        // Disconnect restores original http.noProxy (and removes it when originally absent).
        assert!(disconnect_isolated(&host, HarnessKind::Cursor).ok);
        assert_eq!(std::fs::read_to_string(&cursor_settings).unwrap(), orig_cursor);

        assert!(disconnect_isolated(&host, HarnessKind::Qoder).ok);
        let q_restored: Value = serde_json::from_str(&std::fs::read_to_string(&qoder_settings).unwrap()).unwrap();
        assert_eq!(q_restored["http.noProxy"], serde_json::json!(["10.0.0.1"]));
        let qcn_restored: Value = serde_json::from_str(&std::fs::read_to_string(&qoder_cn_settings).unwrap()).unwrap();
        assert!(qcn_restored.get("http.noProxy").is_none());

        assert!(disconnect_isolated(&host, HarnessKind::Antigravity).ok);
        let ag_restored: Value = serde_json::from_str(&std::fs::read_to_string(&ag_settings).unwrap()).unwrap();
        assert_eq!(
            ag_restored["http.noProxy"],
            serde_json::json!(["dev.internal", "127.0.0.1"])
        );

        // Windows managed env scripts must leave no leftover files after all disconnects.
        assert!(!managed_env_ps1_path(tmp.path()).exists());
        assert!(!managed_env_cmd_path(tmp.path()).exists());
    }

    #[test]
    fn managed_env_scripts_include_port_liveness_guard_when_proxy_port_present() {
        let tmp = TempDir::new();
        let docs_ps = tmp.path().join("Documents").join("PowerShell");
        std::fs::create_dir_all(&docs_ps).unwrap();
        let rc = tmp.path().join(".profile");
        std::fs::write(&rc, "").unwrap();

        write_windows_managed_env_var(tmp.path(), "HTTPS_PROXY", Some("http://127.0.0.1:18787")).unwrap();
        let ps1 = std::fs::read_to_string(managed_env_ps1_path(tmp.path())).unwrap();
        assert!(ps1.contains("$__hgAlive"), "expected Windows liveness probe: {ps1}");
        assert!(ps1.contains("BeginConnect('127.0.0.1', 18787"), "{ps1}");
        assert!(ps1.contains("$env:HTTPS_PROXY = 'http://127.0.0.1:18787'"), "{ps1}");

        write_shell_rc_var(tmp.path(), "HTTPS_PROXY", Some("http://127.0.0.1:18787")).unwrap();
        let rc_text = std::fs::read_to_string(&rc).unwrap();
        assert!(
            rc_text.contains("nc -z -w 1 127.0.0.1 18787"),
            "expected shell liveness probe: {rc_text}"
        );
        assert_eq!(
            read_shell_rc_var(tmp.path(), "HTTPS_PROXY").as_deref(),
            Some("http://127.0.0.1:18787")
        );
    }
}
