#[cfg(windows)]
use hide_chrome::{hidden_command_path, windows_system_executable};
use hide_core::ca::{CaManager, RealCaTrustAdapter};
use hide_core::config::{HideConfig, UiLanguage};
use hide_core::harness::HarnessProfile;
use hide_core::harness_detect::{detect_all_harness_profiles, disconnect_all_managed, HarnessActionResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupStepStatus {
    pub id: String,
    pub label: String,
    pub state: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOptions {
    pub install_dir: Option<String>,
    pub create_shortcuts: bool,
    pub add_to_path: bool,
    pub autostart_daemon: bool,
    #[serde(default)]
    pub language: Option<UiLanguage>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallOptions {
    pub install_dir: Option<String>,
    pub remove_config: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallManifest {
    pub version: String,
    pub install_dir: String,
    pub shortcuts: Vec<String>,
    pub path_added: bool,
    pub autostart_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOutcome {
    pub ok: bool,
    pub install_dir: String,
    pub desktop_binary: String,
    pub daemon_binary: String,
    pub uninstaller_binary: String,
    pub shortcuts_created: Vec<String>,
    pub path_updated: bool,
    pub autostart_enabled: bool,
    pub harnesses: Vec<HarnessProfile>,
    pub steps: Vec<SetupStepStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallOutcome {
    pub ok: bool,
    pub removed_paths: Vec<String>,
    pub disconnected_harnesses: Vec<HarnessActionResult>,
    pub steps: Vec<SetupStepStatus>,
    pub error: Option<String>,
    #[serde(skip)]
    pub pending_cleanup_dir: Option<PathBuf>,
}

pub struct EmbeddedPayloads<'a> {
    pub desktop_bin: Option<&'a [u8]>,
    pub daemon_bin: Option<&'a [u8]>,
    pub icon_ico: &'a [u8],
    pub icon_png: &'a [u8],
    pub version: &'a str,
}

pub fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

pub fn desktop_bin_name() -> &'static str {
    if cfg!(windows) {
        "hide-go-desktop.exe"
    } else {
        "hide-go-desktop"
    }
}

pub fn daemon_bin_name() -> &'static str {
    if cfg!(windows) {
        "hide-go-daemon.exe"
    } else {
        "hide-go-daemon"
    }
}

pub fn uninstall_bin_name() -> &'static str {
    if cfg!(windows) {
        "hide-go-uninstall.exe"
    } else {
        "hide-go-uninstall"
    }
}

pub fn home_dir() -> Option<PathBuf> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        env("USERPROFILE").or_else(|| env("HOME"))
    } else {
        env("HOME")
    }
}

pub fn default_install_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(home_dir)
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("Hide-Go")
    }
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("Applications")
            .join("Hide-Go")
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|h| h.join(".local").join("share")))
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("hide-go")
    }
}

pub fn manifest_path(install_dir: &Path) -> PathBuf {
    install_dir.join("install-manifest.json")
}

pub fn is_reparse_or_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| {
        #[cfg(windows)]
        {
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        }
        #[cfg(not(windows))]
        {
            meta.file_type().is_symlink()
        }
    })
}

fn normalize_path_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !matches!(
                    out.components().next_back(),
                    Some(Component::RootDir | Component::Prefix(_))
                ) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| c == '\0' || c == '\r' || c == '\n' || c.is_control())
}

pub fn validate_install_dir(dir: &Path) -> Result<(), String> {
    let raw = dir.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("安装目录不能为空".into());
    }
    if has_control_chars(trimmed) {
        return Err("安装目录包含非法控制字符".into());
    }
    if !dir.is_absolute() {
        return Err("安装目录必须是绝对路径".into());
    }
    if trimmed.starts_with(r"\\?\") || trimmed.starts_with(r"\\.\") {
        return Err("不支持设备或特殊前缀路径".into());
    }

    let norm = normalize_path_lexical(dir);
    if norm.parent().is_none() {
        return Err("不能将 Hide-Go 直接安装到磁盘根目录".into());
    }

    let mut blocked_exact: Vec<PathBuf> = Vec::new();
    if let Some(home) = home_dir() {
        blocked_exact.push(home.join("Desktop"));
        blocked_exact.push(home.join("Documents"));
        blocked_exact.push(home.join("Downloads"));
        blocked_exact.push(home);
    }
    for key in [
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "SYSTEMROOT",
        "WINDIR",
        "TMP",
        "TEMP",
    ] {
        if let Some(val) = std::env::var_os(key).filter(|v| !v.is_empty()) {
            blocked_exact.push(PathBuf::from(val));
        }
    }
    blocked_exact.push(std::env::temp_dir());
    for unix_sys in [
        "/Applications",
        "/Users",
        "/home",
        "/tmp",
        "/var",
        "/etc",
        "/usr",
        "/usr/local",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
    ] {
        blocked_exact.push(PathBuf::from(unix_sys));
    }

    for blocked in &blocked_exact {
        if same_path(&norm, &normalize_path_lexical(blocked)) {
            return Err(format!("拒绝使用系统或用户关键目录作为安装目录: {}", norm.display()));
        }
    }

    #[cfg(windows)]
    {
        for key in ["SYSTEMROOT", "WINDIR"] {
            if let Some(win_dir) = std::env::var_os(key).filter(|v| !v.is_empty()) {
                let win_norm = normalize_path_lexical(&PathBuf::from(win_dir));
                let norm_s = norm.to_string_lossy().to_ascii_lowercase();
                let win_s = win_norm.to_string_lossy().to_ascii_lowercase();
                if norm_s == win_s || norm_s.starts_with(&format!("{win_s}\\")) {
                    return Err("不能将 Hide-Go 安装到 Windows 系统目录下".into());
                }
            }
        }
    }

    if norm.exists() && is_reparse_or_symlink(&norm) {
        return Err("安装目录不能是符号链接或目录联接点".into());
    }
    if let Some(parent) = norm.parent() {
        if parent.exists() && is_reparse_or_symlink(parent) {
            return Err("安装目录的父路径包含符号链接或联接点".into());
        }
    }
    Ok(())
}

static ATOMIC_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn atomic_write_bytes(dest: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    if is_reparse_or_symlink(dest) {
        return Err(format!("目标路径 {} 是符号链接，拒绝写入", dest.display()));
    }
    let parent = dest
        .parent()
        .ok_or_else(|| format!("目标路径 {} 缺少父目录", dest.display()))?;
    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "payload".into());
    let seq = ATOMIC_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("创建临时文件 {} 失败: {e}", tmp.display()))?;
    if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("写入 {} 失败: {e}", dest.display()));
    }
    drop(file);
    if executable {
        if let Err(e) = set_executable(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("替换目标文件 {} 失败: {e}", dest.display()));
    }
    Ok(())
}

fn atomic_copy_file(src: &Path, dest: &Path, executable: bool) -> Result<(), String> {
    if is_reparse_or_symlink(src) {
        return Err(format!("源文件 {} 是符号链接，拒绝复制", src.display()));
    }
    let bytes = std::fs::read(src).map_err(|e| format!("读取 {} 失败: {e}", src.display()))?;
    atomic_write_bytes(dest, &bytes, executable)
}

#[cfg(any(target_os = "macos", not(windows), test))]
fn shell_single_quote(s: &str) -> Result<String, String> {
    if has_control_chars(s) {
        return Err("路径包含非法换行或控制字符".into());
    }
    Ok(format!("'{}'", s.replace('\'', "'\"'\"'")))
}

#[cfg(any(target_os = "macos", test))]
fn xml_escape(s: &str) -> Result<String, String> {
    if has_control_chars(s) {
        return Err("配置值包含非法控制字符".into());
    }
    Ok(s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

#[cfg(any(all(not(windows), not(target_os = "macos")), test))]
fn desktop_entry_escape(s: &str) -> Result<String, String> {
    if has_control_chars(s) {
        return Err("桌面快捷方式路径包含非法控制字符".into());
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '$' => out.push_str(r"\$"),
            '`' => out.push_str(r"\`"),
            '%' => out.push_str("%%"),
            _ => out.push(ch),
        }
    }
    Ok(out)
}

pub fn detect_existing_install() -> Option<InstallManifest> {
    let default_dir = default_install_dir();
    let mut candidates = vec![default_dir];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if manifest_path(parent).is_file() && !candidates.iter().any(|c| same_path(c, parent)) {
                candidates.push(parent.to_path_buf());
            }
        }
    }
    for dir in candidates {
        let mp = manifest_path(&dir);
        if is_reparse_or_symlink(&mp) {
            continue;
        }
        if let Ok(raw) = std::fs::read_to_string(&mp) {
            if let Ok(manifest) = serde_json::from_str::<InstallManifest>(&raw) {
                return Some(manifest);
            }
        }
    }
    None
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let na = norm(a);
    let nb = norm(b);
    #[cfg(windows)]
    {
        na.to_string_lossy().eq_ignore_ascii_case(&nb.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        na == nb
    }
}

/// Abstract host OS side effects (shortcuts, PATH, autostart, uninstall registration,
/// process stop) so installer logic can be tested cleanly inside a TempDir.
pub trait SystemOps {
    fn stop_running_processes(&self);
    fn create_shortcuts(
        &self,
        install_dir: &Path,
        desktop_bin: &Path,
        uninstall_bin: &Path,
    ) -> Result<Vec<String>, String>;
    fn register_uninstaller(
        &self,
        install_dir: &Path,
        uninstall_bin: &Path,
        icon_path: &Path,
        version: &str,
    ) -> Result<(), String>;
    fn add_to_path(&self, dir: &Path) -> Result<(), String>;
    fn remove_from_path(&self, dir: &Path) -> Result<(), String>;
    fn set_autostart(&self, daemon_bin: &Path, enabled: bool) -> Result<(), String>;
    fn unregister_uninstaller(&self) -> Result<(), String>;
    fn remove_shortcuts(&self, manifest: &InstallManifest) -> Vec<String>;
    fn disconnect_harnesses(&self) -> Vec<HarnessActionResult>;
    fn remove_ca_trust(&self, ca_dir: &Path) -> Result<String, String>;
}

pub struct RealSystemOps;

impl SystemOps for RealSystemOps {
    fn stop_running_processes(&self) {
        hide_chrome::terminate_other_hide_go_processes();
    }

    fn create_shortcuts(
        &self,
        install_dir: &Path,
        desktop_bin: &Path,
        uninstall_bin: &Path,
    ) -> Result<Vec<String>, String> {
        #[cfg(windows)]
        {
            let mut created = Vec::new();
            let icon = install_dir.join("icon.ico");
            if let Some(desktop_dir) = windows_desktop_dir().or_else(|| home_dir().map(|h| h.join("Desktop"))) {
                let desktop_lnk = desktop_dir.join("Hide-Go.lnk");
                create_windows_shortcut(
                    &desktop_lnk,
                    desktop_bin,
                    "",
                    install_dir,
                    &icon,
                    "Hide-Go 本地隐私网关",
                )?;
                created.push(desktop_lnk.to_string_lossy().into_owned());
            }
            if let Some(appdata) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()).map(PathBuf::from) {
                let menu_dir = appdata.join("Microsoft/Windows/Start Menu/Programs/Hide-Go");
                let app_lnk = menu_dir.join("Hide-Go.lnk");
                create_windows_shortcut(&app_lnk, desktop_bin, "", install_dir, &icon, "Hide-Go 本地隐私网关")?;
                created.push(app_lnk.to_string_lossy().into_owned());

                let uninst_lnk = menu_dir.join("卸载 Hide-Go.lnk");
                create_windows_shortcut(
                    &uninst_lnk,
                    uninstall_bin,
                    "--uninstall",
                    install_dir,
                    &icon,
                    "卸载 Hide-Go",
                )?;
                created.push(uninst_lnk.to_string_lossy().into_owned());
            }
            Ok(created)
        }
        #[cfg(target_os = "macos")]
        {
            let _ = uninstall_bin;
            let mut created = Vec::new();
            if let Some(home) = home_dir() {
                let app_dir = home.join("Applications/Hide-Go.app/Contents");
                let macos_dir = app_dir.join("MacOS");
                std::fs::create_dir_all(&macos_dir).map_err(|e| e.to_string())?;
                let launcher = macos_dir.join("Hide-Go");
                let quoted_bin = shell_single_quote(&desktop_bin.to_string_lossy())?;
                let script = format!("#!/bin/sh\nexec {quoted_bin} \"$@\"\n");
                atomic_write_bytes(&launcher, script.as_bytes(), true)?;
                let safe_ver = xml_escape(env!("CARGO_PKG_VERSION"))?;
                let plist = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                     <plist version=\"1.0\"><dict>\n\
                     <key>CFBundleName</key><string>Hide-Go</string>\n\
                     <key>CFBundleIdentifier</key><string>com.aflydream.hidego</string>\n\
                     <key>CFBundleExecutable</key><string>Hide-Go</string>\n\
                     <key>CFBundleVersion</key><string>{safe_ver}</string>\n\
                     </dict></plist>\n",
                );
                atomic_write_bytes(&app_dir.join("Info.plist"), plist.as_bytes(), false)?;
                created.push(home.join("Applications/Hide-Go.app").to_string_lossy().into_owned());
                let _ = install_dir;
            }
            Ok(created)
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let _ = uninstall_bin;
            let mut created = Vec::new();
            if let Some(home) = home_dir() {
                let icon_target = home.join(".local/share/icons/hicolor/128x128/apps/hide-go.png");
                if let Some(parent) = icon_target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create icon dir: {e}"))?;
                }
                atomic_copy_file(&install_dir.join("icon.png"), &icon_target, false)
                    .map_err(|e| format!("failed to copy desktop icon: {e}"))?;

                let desktop_entry = home.join(".local/share/applications/hide-go.desktop");
                if let Some(parent) = desktop_entry.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let exec_escaped = desktop_entry_escape(&desktop_bin.to_string_lossy())?;
                let icon_str = icon_target.to_string_lossy();
                if has_control_chars(&icon_str) {
                    return Err("图标路径包含非法控制字符".into());
                }
                let body = format!(
                    "[Desktop Entry]\nType=Application\nName=Hide-Go\nComment=AI Harness Privacy Firewall\nExec=\"{exec_escaped}\"\nIcon={icon_str}\nTerminal=false\nCategories=Development;Security;\n",
                );
                atomic_write_bytes(&desktop_entry, body.as_bytes(), false)?;
                created.push(desktop_entry.to_string_lossy().into_owned());
                created.push(icon_target.to_string_lossy().into_owned());
            }
            Ok(created)
        }
    }

    fn register_uninstaller(
        &self,
        install_dir: &Path,
        uninstall_bin: &Path,
        icon_path: &Path,
        version: &str,
    ) -> Result<(), String> {
        // Zero Windows Registry writes: desktop uninstall is invoked via Start Menu shortcut
        // or the uninstaller binary directly using install-manifest.json.
        let _ = (install_dir, uninstall_bin, icon_path, version);
        Ok(())
    }

    fn add_to_path(&self, dir: &Path) -> Result<(), String> {
        #[cfg(windows)]
        {
            // Zero Windows Registry writes: avoid touching HKCU\Environment\Path on Windows.
            let _ = dir;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            unix_update_user_path(dir, true)
        }
    }

    fn remove_from_path(&self, dir: &Path) -> Result<(), String> {
        #[cfg(windows)]
        {
            let _ = dir;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            unix_update_user_path(dir, false)
        }
    }

    fn set_autostart(&self, daemon_bin: &Path, enabled: bool) -> Result<(), String> {
        #[cfg(windows)]
        {
            let Some(lnk_path) = windows_startup_shortcut_path() else {
                return Ok(());
            };
            if enabled {
                if is_reparse_or_symlink(daemon_bin) {
                    return Err("守护进程可执行文件是符号链接，拒绝创建自启快捷方式".into());
                }
                let working_dir = daemon_bin.parent().unwrap_or_else(|| Path::new("."));
                let icon = working_dir.join("icon.ico");
                create_windows_shortcut(
                    &lnk_path,
                    daemon_bin,
                    "",
                    working_dir,
                    &icon,
                    "Hide-Go 本地隐私网关守护进程",
                )?;
            } else if lnk_path.exists() && !is_reparse_or_symlink(&lnk_path) {
                std::fs::remove_file(&lnk_path).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        #[cfg(target_os = "macos")]
        {
            let Some(home) = home_dir() else {
                return Ok(());
            };
            let plist_path = home.join("Library/LaunchAgents/com.aflydream.hidego.plist");
            if enabled {
                if let Some(parent) = plist_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let escaped_bin = xml_escape(&daemon_bin.to_string_lossy())?;
                let plist = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                     <plist version=\"1.0\"><dict>\n\
                     <key>Label</key><string>com.aflydream.hidego</string>\n\
                     <key>ProgramArguments</key><array><string>{escaped_bin}</string></array>\n\
                     <key>RunAtLoad</key><true/>\n\
                     <key>KeepAlive</key><true/>\n\
                     </dict></plist>\n",
                );
                atomic_write_bytes(&plist_path, plist.as_bytes(), false)?;
            } else if plist_path.exists() && !is_reparse_or_symlink(&plist_path) {
                std::fs::remove_file(&plist_path).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let Some(home) = home_dir() else {
                return Ok(());
            };
            let autostart_file = home.join(".config/autostart/hide-go-daemon.desktop");
            if enabled {
                if let Some(parent) = autostart_file.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let exec_escaped = desktop_entry_escape(&daemon_bin.to_string_lossy())?;
                let body = format!(
                    "[Desktop Entry]\nType=Application\nName=Hide-Go Daemon\nExec=\"{exec_escaped}\"\nX-GNOME-Autostart-enabled=true\n",
                );
                atomic_write_bytes(&autostart_file, body.as_bytes(), false)?;
            } else if autostart_file.exists() && !is_reparse_or_symlink(&autostart_file) {
                std::fs::remove_file(&autostart_file).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }

    fn unregister_uninstaller(&self) -> Result<(), String> {
        // Zero Windows Registry writes or deletions.
        Ok(())
    }

    fn remove_shortcuts(&self, manifest: &InstallManifest) -> Vec<String> {
        let mut removed = Vec::new();
        for item in &manifest.shortcuts {
            let p = PathBuf::from(item);
            if is_reparse_or_symlink(&p) || !is_allowed_shortcut_path(&p) {
                continue;
            }
            #[cfg(target_os = "macos")]
            if p.is_dir() && p.file_name().is_some_and(|n| n == "Hide-Go.app") {
                if std::fs::remove_dir_all(&p).is_ok() {
                    removed.push(item.clone());
                }
                continue;
            }
            if p.is_file() && std::fs::remove_file(&p).is_ok() {
                removed.push(item.clone());
                if let Some(parent) = p.parent() {
                    if !is_reparse_or_symlink(parent)
                        && parent.file_name().is_some_and(|n| n == "Hide-Go")
                        && std::fs::read_dir(parent).is_ok_and(|mut d| d.next().is_none())
                    {
                        let _ = std::fs::remove_dir(parent);
                    }
                }
            }
        }
        removed
    }

    fn disconnect_harnesses(&self) -> Vec<HarnessActionResult> {
        disconnect_all_managed()
    }

    fn remove_ca_trust(&self, ca_dir: &Path) -> Result<String, String> {
        if ca_dir.join("hide-go-ca.crt").is_file() && ca_dir.join("hide-go-ca.key").is_file() {
            let mgr = CaManager::load_or_create(ca_dir.to_path_buf(), Arc::new(RealCaTrustAdapter))?;
            let status = mgr.status();
            if status.installed_in_os_store {
                let removed = mgr.remove_trust()?;
                return Ok(removed.os_trust_detail);
            }
        }
        Ok("无需移除系统根证书".to_string())
    }
}

#[cfg(windows)]
fn windows_system_powershell() -> PathBuf {
    windows_system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
}

#[cfg(windows)]
fn windows_startup_shortcut_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .map(|appdata| appdata.join("Microsoft/Windows/Start Menu/Programs/Startup/Hide-Go Daemon.lnk"))
}

fn is_allowed_shortcut_path(p: &Path) -> bool {
    if !p.is_absolute() || has_control_chars(&p.to_string_lossy()) {
        return false;
    }
    let norm = normalize_path_lexical(p);
    #[cfg(windows)]
    {
        let ext_ok = norm
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
        if !ext_ok {
            return false;
        }
        let mut allowed_roots = Vec::new();
        if let Some(d) = windows_desktop_dir().or_else(|| home_dir().map(|h| h.join("Desktop"))) {
            allowed_roots.push(normalize_path_lexical(&d));
        }
        if let Some(appdata) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()).map(PathBuf::from) {
            allowed_roots.push(normalize_path_lexical(
                &appdata.join("Microsoft/Windows/Start Menu/Programs"),
            ));
        }
        let norm_low = norm.to_string_lossy().to_ascii_lowercase();
        allowed_roots.iter().any(|root| {
            let root_low = root.to_string_lossy().to_ascii_lowercase();
            norm_low.starts_with(&format!("{root_low}\\"))
        })
    }
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .map(|h| same_path(&norm, &normalize_path_lexical(&h.join("Applications/Hide-Go.app"))))
            .unwrap_or(false)
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        let Some(home) = home_dir() else {
            return false;
        };
        let allowed = [
            home.join(".local/share/applications/hide-go.desktop"),
            home.join(".local/share/icons/hicolor/128x128/apps/hide-go.png"),
            home.join(".config/autostart/hide-go-daemon.desktop"),
        ];
        allowed.iter().any(|a| same_path(&norm, &normalize_path_lexical(a)))
    }
}

#[cfg(windows)]
fn create_windows_shortcut(
    lnk_path: &Path,
    target: &Path,
    args: &str,
    working_dir: &Path,
    icon_path: &Path,
    description: &str,
) -> Result<(), String> {
    if is_reparse_or_symlink(lnk_path) {
        return Err(format!("快捷方式路径 {} 是符号链接，拒绝覆盖", lnk_path.display()));
    }
    if let Some(parent) = lnk_path.parent() {
        if parent.exists() && is_reparse_or_symlink(parent) {
            return Err(format!("快捷方式目录 {} 是符号链接，拒绝写入", parent.display()));
        }
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create shortcut folder: {e}"))?;
    }
    let script = "\
        $ws = New-Object -ComObject WScript.Shell; \
        $s = $ws.CreateShortcut($env:HIDE_GO_LNK_PATH); \
        $s.TargetPath = $env:HIDE_GO_LNK_TARGET; \
        $s.Arguments = $env:HIDE_GO_LNK_ARGS; \
        $s.WorkingDirectory = $env:HIDE_GO_LNK_WORKDIR; \
        $s.IconLocation = $env:HIDE_GO_LNK_ICON; \
        $s.Description = $env:HIDE_GO_LNK_DESC; \
        $s.Save()";
    let ps = windows_system_powershell();
    let out = hidden_command_path(&ps)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("HIDE_GO_LNK_PATH", lnk_path)
        .env("HIDE_GO_LNK_TARGET", target)
        .env("HIDE_GO_LNK_ARGS", args)
        .env("HIDE_GO_LNK_WORKDIR", working_dir)
        .env("HIDE_GO_LNK_ICON", icon_path)
        .env("HIDE_GO_LNK_DESC", description)
        .output()
        .map_err(|e| format!("powershell shortcut creation failed: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_desktop_dir() -> Option<PathBuf> {
    let ps = windows_system_powershell();
    let out = hidden_command_path(&ps)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Environment]::GetFolderPath('Desktop')",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!dir.is_empty()).then(|| PathBuf::from(dir))
}

#[cfg(not(windows))]
fn unix_update_user_path(dir: &Path, add: bool) -> Result<(), String> {
    let Some(home) = home_dir() else {
        return Ok(());
    };
    let quoted_dir = if add {
        Some(shell_single_quote(&dir.to_string_lossy())?)
    } else {
        None
    };
    let start = "# >>> hide-go PATH >>>";
    let end = "# <<< hide-go PATH <<<";
    let files: Vec<PathBuf> = [".zshrc", ".bashrc", ".profile"]
        .iter()
        .map(|f| home.join(f))
        .filter(|p| p.exists() && !is_reparse_or_symlink(p))
        .collect();
    let targets = if files.is_empty() {
        vec![home.join(".profile")]
    } else {
        files
    };
    for path in targets {
        if is_reparse_or_symlink(&path) {
            continue;
        }
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
        if let Some(quoted) = &quoted_dir {
            next.push_str(&format!("{start}\nexport PATH={quoted}:\"$PATH\"\n{end}\n"));
        }
        atomic_write_bytes(&path, next.as_bytes(), false)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(debug_assertions)]
fn find_fallback_binary(file_name: &str) -> Option<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return None;
    };
    let exe_dir = exe.parent()?;
    let candidates = [
        exe_dir.join(file_name),
        exe_dir.join("release").join(file_name),
        PathBuf::from("target/release").join(file_name),
        PathBuf::from("target/debug").join(file_name),
    ];
    candidates
        .into_iter()
        .find(|p| p.is_file() && !is_reparse_or_symlink(p))
}

fn write_binary(embedded: Option<&[u8]>, file_name: &str, dest: &Path) -> Result<(), String> {
    if let Some(bytes) = embedded {
        atomic_write_bytes(dest, bytes, true)?;
    } else {
        #[cfg(debug_assertions)]
        {
            if let Some(src) = find_fallback_binary(file_name) {
                atomic_copy_file(&src, dest, true)?;
                return Ok(());
            }
        }
        return Err(format!("安装包缺少 {file_name} 载荷且未找到本地构建文件"));
    }
    Ok(())
}

fn load_existing_config(config_path: Option<&Path>) -> Option<HideConfig> {
    config_path
        .filter(|p| p.is_file())
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<HideConfig>(s.trim_start_matches('\u{feff}')).ok())
}

pub fn configured_proxy_port(config_path: Option<&Path>) -> u16 {
    load_existing_config(config_path)
        .map(|c| c.proxy_port)
        .unwrap_or_else(|| HideConfig::default().proxy_port)
}

pub fn configured_language(config_path: Option<&Path>) -> UiLanguage {
    load_existing_config(config_path)
        .map(|c| c.language)
        .unwrap_or_default()
}

pub fn perform_install(opts: &InstallOptions, payloads: &EmbeddedPayloads<'_>) -> InstallOutcome {
    perform_install_with(opts, payloads, &RealSystemOps, HideConfig::default_path().as_deref())
}

pub fn perform_install_with(
    opts: &InstallOptions,
    payloads: &EmbeddedPayloads<'_>,
    sys: &dyn SystemOps,
    config_path: Option<&Path>,
) -> InstallOutcome {
    let install_dir = opts
        .install_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_install_dir);

    let mut steps = Vec::new();
    let desktop_dest = install_dir.join(desktop_bin_name());
    let daemon_dest = install_dir.join(daemon_bin_name());
    let uninstall_dest = install_dir.join(uninstall_bin_name());

    let fail = |steps: Vec<SetupStepStatus>, err: String| InstallOutcome {
        ok: false,
        install_dir: install_dir.to_string_lossy().into_owned(),
        desktop_binary: desktop_dest.to_string_lossy().into_owned(),
        daemon_binary: daemon_dest.to_string_lossy().into_owned(),
        uninstaller_binary: uninstall_dest.to_string_lossy().into_owned(),
        shortcuts_created: Vec::new(),
        path_updated: false,
        autostart_enabled: false,
        harnesses: Vec::new(),
        steps,
        error: Some(err),
    };

    if let Err(e) = validate_install_dir(&install_dir) {
        steps.push(SetupStepStatus {
            id: "dir".into(),
            label: "校验安装目录".into(),
            state: "error",
            detail: Some(e.clone()),
        });
        return fail(steps, e);
    }

    let mp = manifest_path(&install_dir);
    let existing_manifest = if is_reparse_or_symlink(&mp) {
        None
    } else {
        std::fs::read_to_string(&mp)
            .ok()
            .and_then(|raw| serde_json::from_str::<InstallManifest>(&raw).ok())
    };

    // 1. Stop any running instance and prepare install directory
    sys.stop_running_processes();
    if let Err(e) = std::fs::create_dir_all(&install_dir) {
        steps.push(SetupStepStatus {
            id: "dir".into(),
            label: "创建安装目录".into(),
            state: "error",
            detail: Some(e.to_string()),
        });
        return fail(steps, format!("无法创建安装目录 {}: {e}", install_dir.display()));
    }
    if is_reparse_or_symlink(&install_dir) {
        let msg = "安装目录不能是符号链接或目录联接点".to_string();
        steps.push(SetupStepStatus {
            id: "dir".into(),
            label: "创建安装目录".into(),
            state: "error",
            detail: Some(msg.clone()),
        });
        return fail(steps, msg);
    }
    steps.push(SetupStepStatus {
        id: "dir".into(),
        label: "准备安装目录".into(),
        state: "done",
        detail: Some(install_dir.to_string_lossy().into_owned()),
    });

    // 2. Write desktop + daemon binaries + icon + self uninstaller copy
    let icon_ico = install_dir.join("icon.ico");
    let icon_png = install_dir.join("icon.png");
    let bin_res = write_binary(payloads.desktop_bin, desktop_bin_name(), &desktop_dest)
        .and_then(|_| write_binary(payloads.daemon_bin, daemon_bin_name(), &daemon_dest))
        .and_then(|_| atomic_write_bytes(&icon_ico, payloads.icon_ico, false))
        .and_then(|_| atomic_write_bytes(&icon_png, payloads.icon_png, false))
        .and_then(|_| {
            let self_exe = std::env::current_exe().map_err(|e| format!("定位当前安装器路径失败: {e}"))?;
            if !same_path(&self_exe, &uninstall_dest) {
                atomic_copy_file(&self_exe, &uninstall_dest, true)
                    .map_err(|e| format!("写入卸载程序 {} 失败: {e}", uninstall_dest.display()))?;
            }
            Ok(())
        });
    if let Err(e) = bin_res {
        steps.push(SetupStepStatus {
            id: "bin".into(),
            label: "写入程序文件".into(),
            state: "error",
            detail: Some(e.clone()),
        });
        return fail(steps, e);
    }
    steps.push(SetupStepStatus {
        id: "bin".into(),
        label: "写入程序文件".into(),
        state: "done",
        detail: Some("主程序与后台服务".into()),
    });

    // 3. Ensure initial config.json exists without clobbering user's existing settings
    if let Some(cfg_path) = config_path {
        let mut cfg = HideConfig::load_or_create(cfg_path);
        let needs_save = !cfg_path.exists()
            || opts.language.is_some_and(|lang| {
                let changed = cfg.language != lang;
                cfg.language = lang;
                changed
            });
        if needs_save {
            if let Err(e) = cfg.save(cfg_path) {
                steps.push(SetupStepStatus {
                    id: "cfg".into(),
                    label: "初始化配置文件".into(),
                    state: "error",
                    detail: Some(e.to_string()),
                });
                return fail(steps, format!("无法创建配置文件 {}: {e}", cfg_path.display()));
            }
        }
    }

    // 4. Shortcuts + Uninstaller + PATH + Autostart
    let shortcuts_created = if opts.create_shortcuts {
        match sys.create_shortcuts(&install_dir, &desktop_dest, &uninstall_dest) {
            Ok(list) => list,
            Err(e) => {
                steps.push(SetupStepStatus {
                    id: "shortcuts".into(),
                    label: "创建快捷方式".into(),
                    state: "error",
                    detail: Some(e.clone()),
                });
                return fail(steps, e);
            }
        }
    } else {
        Vec::new()
    };

    if let Err(e) = sys.register_uninstaller(&install_dir, &uninstall_dest, &icon_ico, payloads.version) {
        steps.push(SetupStepStatus {
            id: "uninst".into(),
            label: "注册系统卸载入口".into(),
            state: "error",
            detail: Some(e.clone()),
        });
        return fail(steps, e);
    }

    let path_updated = if opts.add_to_path {
        if let Err(e) = sys.add_to_path(&install_dir) {
            steps.push(SetupStepStatus {
                id: "path".into(),
                label: "写入用户 PATH".into(),
                state: "error",
                detail: Some(e.clone()),
            });
            return fail(steps, e);
        }
        true
    } else {
        false
    };

    if let Err(e) = sys.set_autostart(&daemon_dest, opts.autostart_daemon) {
        steps.push(SetupStepStatus {
            id: "autostart".into(),
            label: "配置开机自启".into(),
            state: "error",
            detail: Some(e.clone()),
        });
        return fail(steps, e);
    }

    let manifest_shortcuts = if opts.create_shortcuts {
        shortcuts_created.clone()
    } else {
        existing_manifest
            .as_ref()
            .map(|m| m.shortcuts.clone())
            .unwrap_or_default()
    };
    let manifest = InstallManifest {
        version: payloads.version.to_string(),
        install_dir: install_dir.to_string_lossy().into_owned(),
        shortcuts: manifest_shortcuts,
        path_added: path_updated || existing_manifest.as_ref().is_some_and(|m| m.path_added),
        autostart_enabled: opts.autostart_daemon,
    };
    let manifest_res = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("序列化安装清单失败: {e}"))
        .and_then(|json| {
            atomic_write_bytes(&manifest_path(&install_dir), json.as_bytes(), false)
                .map_err(|e| format!("写入安装清单失败: {e}"))
        });
    if let Err(e) = manifest_res {
        steps.push(SetupStepStatus {
            id: "sys".into(),
            label: "写入安装清单".into(),
            state: "error",
            detail: Some(e.clone()),
        });
        return fail(steps, e);
    }

    let sys_detail = if shortcuts_created.is_empty() && !path_updated {
        "已完成".to_string()
    } else {
        format!(
            "已创建 {} 个快捷方式{}",
            shortcuts_created.len(),
            if path_updated { " · 已加入 PATH" } else { "" }
        )
    };
    steps.push(SetupStepStatus {
        id: "sys".into(),
        label: "配置快捷方式与系统入口".into(),
        state: "done",
        detail: Some(sys_detail),
    });

    // 5. Real AI Harness scan using configured proxy port
    let scan_port = configured_proxy_port(config_path);
    let harnesses = detect_all_harness_profiles(scan_port, &HashMap::new());
    let installed_count = harnesses.iter().filter(|h| h.installed).count();
    steps.push(SetupStepStatus {
        id: "scan".into(),
        label: "检测本机 AI 工具".into(),
        state: "done",
        detail: Some(format!("发现 {installed_count} 个")),
    });

    InstallOutcome {
        ok: true,
        install_dir: install_dir.to_string_lossy().into_owned(),
        desktop_binary: desktop_dest.to_string_lossy().into_owned(),
        daemon_binary: daemon_dest.to_string_lossy().into_owned(),
        uninstaller_binary: uninstall_dest.to_string_lossy().into_owned(),
        shortcuts_created,
        path_updated,
        autostart_enabled: opts.autostart_daemon,
        harnesses,
        steps,
        error: None,
    }
}

pub fn perform_uninstall(opts: &UninstallOptions) -> UninstallOutcome {
    perform_uninstall_with(opts, &RealSystemOps, HideConfig::default_path().as_deref())
}

pub fn perform_uninstall_with(
    opts: &UninstallOptions,
    sys: &dyn SystemOps,
    config_path: Option<&Path>,
) -> UninstallOutcome {
    let mut steps = Vec::new();
    let mut removed_paths = Vec::new();
    let mut errors = Vec::new();

    // 1. Stop running processes
    sys.stop_running_processes();
    steps.push(SetupStepStatus {
        id: "stop".into(),
        label: "停止 Hide-Go 进程".into(),
        state: "done",
        detail: Some("完成".into()),
    });

    // 2. Restore backed-up harness configs
    let disconnected_harnesses = sys.disconnect_harnesses();
    let failed_harnesses: Vec<&str> = disconnected_harnesses
        .iter()
        .filter(|r| !r.ok)
        .map(|r| r.message.as_str())
        .collect();
    if failed_harnesses.is_empty() {
        steps.push(SetupStepStatus {
            id: "harnesses".into(),
            label: "还原 AI 工具配置".into(),
            state: "done",
            detail: Some(format!("已还原 {} 项配置", disconnected_harnesses.len())),
        });
    } else {
        let msg = failed_harnesses.join("; ");
        errors.push(format!("还原 AI 工具配置失败: {msg}"));
        steps.push(SetupStepStatus {
            id: "harnesses".into(),
            label: "还原 AI 工具配置".into(),
            state: "error",
            detail: Some(msg),
        });
    }

    // 2.5 Best-effort OS Root CA trust removal before config directory cleanup
    if let Some(ca_dir) = config_path.and_then(|p| p.parent()).map(|d| d.join("ca")) {
        match sys.remove_ca_trust(&ca_dir) {
            Ok(detail) => steps.push(SetupStepStatus {
                id: "ca".into(),
                label: "移除本地根证书信任".into(),
                state: "done",
                detail: Some(detail),
            }),
            Err(err) => steps.push(SetupStepStatus {
                id: "ca".into(),
                label: "移除本地根证书信任".into(),
                state: "done",
                detail: Some(format!("提示: {err}")),
            }),
        }
    }

    // 3. Locate manifest / install directory
    let existing = detect_existing_install();
    let install_dir = opts
        .install_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| existing.as_ref().map(|m| PathBuf::from(&m.install_dir)))
        .unwrap_or_else(default_install_dir);

    let dir_validation_err = validate_install_dir(&install_dir).err();
    let mp = manifest_path(&install_dir);
    let valid_manifest = if dir_validation_err.is_none() && !is_reparse_or_symlink(&mp) {
        std::fs::read_to_string(&mp)
            .ok()
            .and_then(|raw| serde_json::from_str::<InstallManifest>(&raw).ok())
            .filter(|m| !m.install_dir.trim().is_empty() && same_path(Path::new(&m.install_dir), &install_dir))
    } else {
        None
    };

    let manifest_for_ops = valid_manifest.clone().or(existing).unwrap_or(InstallManifest {
        version: env!("CARGO_PKG_VERSION").to_string(),
        install_dir: install_dir.to_string_lossy().into_owned(),
        shortcuts: Vec::new(),
        path_added: true,
        autostart_enabled: true,
    });

    // 4. Clean OS integrations
    removed_paths.extend(sys.remove_shortcuts(&manifest_for_ops));
    let mut sys_errors = Vec::new();
    if let Err(e) = sys.remove_from_path(&install_dir) {
        sys_errors.push(format!("清理 PATH 失败: {e}"));
    }
    if let Err(e) = sys.set_autostart(&install_dir.join(daemon_bin_name()), false) {
        sys_errors.push(format!("移除开机自启失败: {e}"));
    }
    if let Err(e) = sys.unregister_uninstaller() {
        sys_errors.push(format!("移除系统卸载项失败: {e}"));
    }
    if sys_errors.is_empty() {
        steps.push(SetupStepStatus {
            id: "sys".into(),
            label: "移除快捷方式与启动项".into(),
            state: "done",
            detail: Some("完成".into()),
        });
    } else {
        let msg = sys_errors.join("; ");
        errors.push(msg.clone());
        steps.push(SetupStepStatus {
            id: "sys".into(),
            label: "移除快捷方式与启动项".into(),
            state: "error",
            detail: Some(msg),
        });
    }

    // 5. Remove installed files (manifest-gated; never recursive-delete unknown files)
    let mut file_errors = Vec::new();
    let running_from_install_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| same_path(parent, &install_dir)))
        .unwrap_or(false);
    let mut pending_cleanup_dir = None;

    if let Some(err) = dir_validation_err {
        file_errors.push(err);
    } else if valid_manifest.is_none() {
        file_errors.push("未找到有效 install-manifest.json，拒绝删除未知目录文件".into());
    } else {
        let mut safe_remove_file = |p: &Path| {
            if is_reparse_or_symlink(p) {
                file_errors.push(format!("拒绝删除符号链接: {}", p.display()));
                return;
            }
            if p.exists() {
                match std::fs::remove_file(p) {
                    Ok(()) => removed_paths.push(p.to_string_lossy().into_owned()),
                    Err(e) => file_errors.push(format!("删除 {} 失败: {e}", p.display())),
                }
            }
        };

        for name in [desktop_bin_name(), daemon_bin_name(), "icon.ico", "icon.png"] {
            safe_remove_file(&install_dir.join(name));
        }

        if running_from_install_dir {
            pending_cleanup_dir = Some(install_dir.clone());
        } else {
            safe_remove_file(&mp);
            safe_remove_file(&install_dir.join(uninstall_bin_name()));
            if install_dir.exists()
                && !is_reparse_or_symlink(&install_dir)
                && std::fs::read_dir(&install_dir).is_ok_and(|mut d| d.next().is_none())
            {
                if let Err(e) = std::fs::remove_dir(&install_dir) {
                    file_errors.push(format!("清理空安装目录 {} 失败: {e}", install_dir.display()));
                }
            }
        }
    }

    if file_errors.is_empty() {
        let detail = if install_dir.exists() && !running_from_install_dir {
            format!("{}（已保留目录内其他文件）", install_dir.display())
        } else {
            install_dir.to_string_lossy().into_owned()
        };
        steps.push(SetupStepStatus {
            id: "files".into(),
            label: "清理程序文件".into(),
            state: "done",
            detail: Some(detail),
        });
    } else {
        let msg = file_errors.join("; ");
        errors.push(msg.clone());
        steps.push(SetupStepStatus {
            id: "files".into(),
            label: "清理程序文件".into(),
            state: "error",
            detail: Some(msg),
        });
    }

    // 6. Optional user config removal (plus desktop WebView2 cache when removing real config)
    if opts.remove_config {
        if let Some(cfg_dir) = config_path.and_then(|p| p.parent()) {
            if is_reparse_or_symlink(cfg_dir) {
                let msg = format!("拒绝删除符号链接配置目录: {}", cfg_dir.display());
                errors.push(msg.clone());
                steps.push(SetupStepStatus {
                    id: "config".into(),
                    label: "删除个人配置与规则".into(),
                    state: "error",
                    detail: Some(msg),
                });
            } else if cfg_dir.exists() {
                match std::fs::remove_dir_all(cfg_dir) {
                    Ok(()) => {
                        removed_paths.push(cfg_dir.to_string_lossy().into_owned());
                        steps.push(SetupStepStatus {
                            id: "config".into(),
                            label: "删除个人配置与规则".into(),
                            state: "done",
                            detail: Some("已清理".into()),
                        });
                    }
                    Err(e) => {
                        let msg = format!("删除配置目录 {} 失败: {e}", cfg_dir.display());
                        errors.push(msg.clone());
                        steps.push(SetupStepStatus {
                            id: "config".into(),
                            label: "删除个人配置与规则".into(),
                            state: "error",
                            detail: Some(msg),
                        });
                    }
                }
            } else {
                steps.push(SetupStepStatus {
                    id: "config".into(),
                    label: "删除个人配置与规则".into(),
                    state: "done",
                    detail: Some("目录不存在".into()),
                });
            }
        }
        if config_path.is_some() && HideConfig::default_path().as_deref() == config_path {
            if let Some(wv_dir) = default_webview_data_dir() {
                if let Err(e) = clean_webview_data_dir(&wv_dir) {
                    errors.push(e);
                } else if !wv_dir.exists() {
                    removed_paths.push(wv_dir.to_string_lossy().into_owned());
                }
            }
        }
    }

    UninstallOutcome {
        ok: errors.is_empty(),
        removed_paths,
        disconnected_harnesses,
        steps,
        error: (!errors.is_empty()).then(|| errors.join("；")),
        pending_cleanup_dir,
    }
}

fn default_webview_data_dir() -> Option<PathBuf> {
    #[cfg(not(target_os = "macos"))]
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    #[cfg(windows)]
    {
        env("LOCALAPPDATA")
            .or_else(home_dir)
            .map(|p| p.join("Hide-Go").join("WebView2"))
    }
    #[cfg(target_os = "macos")]
    {
        home_dir().map(|h| h.join("Library/Application Support/hide-go/webview"))
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        env("XDG_DATA_HOME")
            .or_else(|| home_dir().map(|h| h.join(".local/share")))
            .map(|p| p.join("hide-go").join("webview"))
    }
}

fn clean_webview_data_dir(wv_dir: &Path) -> Result<(), String> {
    if !wv_dir.exists() {
        return Ok(());
    }
    if is_reparse_or_symlink(wv_dir) {
        return Err(format!("拒绝删除符号链接 WebView 目录: {}", wv_dir.display()));
    }
    std::fs::remove_dir_all(wv_dir).map_err(|e| format!("清理 WebView 数据目录 {} 失败: {e}", wv_dir.display()))?;
    if let Some(parent) = wv_dir.parent() {
        if !is_reparse_or_symlink(parent) && std::fs::read_dir(parent).is_ok_and(|mut d| d.next().is_none()) {
            let _ = std::fs::remove_dir(parent);
        }
    }
    Ok(())
}

pub fn schedule_self_cleanup(install_dir: &Path) {
    if validate_install_dir(install_dir).is_err() || is_reparse_or_symlink(install_dir) {
        return;
    }
    let mp = manifest_path(install_dir);
    if is_reparse_or_symlink(&mp) || !mp.is_file() {
        return;
    }
    let valid = std::fs::read_to_string(&mp)
        .ok()
        .and_then(|raw| serde_json::from_str::<InstallManifest>(&raw).ok())
        .is_some_and(|m| !m.install_dir.trim().is_empty() && same_path(Path::new(&m.install_dir), install_dir));
    if !valid {
        return;
    }
    let uninst = install_dir.join(uninstall_bin_name());

    #[cfg(windows)]
    {
        let Ok(tmp_dir) = hide_chrome::create_private_temp_dir("hide-go-cleanup") else {
            return;
        };
        let script_path = tmp_dir.join("cleanup.ps1");
        let ps_body = "\
param(\r\n\
    [Parameter(Mandatory=$true)][string]$UninstallExe,\r\n\
    [Parameter(Mandatory=$true)][string]$ManifestPath,\r\n\
    [Parameter(Mandatory=$true)][string]$InstallDir\r\n\
)\r\n\
for ($i = 0; $i -lt 20; $i++) {\r\n\
    Start-Sleep -Milliseconds 300\r\n\
    if (Test-Path -LiteralPath $ManifestPath) {\r\n\
        $item = Get-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue\r\n\
        if ($item -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {\r\n\
            Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue\r\n\
        }\r\n\
    }\r\n\
    if (Test-Path -LiteralPath $UninstallExe) {\r\n\
        $item = Get-Item -LiteralPath $UninstallExe -Force -ErrorAction SilentlyContinue\r\n\
        if ($item -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {\r\n\
            Remove-Item -LiteralPath $UninstallExe -Force -ErrorAction SilentlyContinue\r\n\
        }\r\n\
    }\r\n\
    if (Test-Path -LiteralPath $InstallDir) {\r\n\
        $dirItem = Get-Item -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue\r\n\
        if ($dirItem -and -not ($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {\r\n\
            $entries = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue)\r\n\
            if ($entries.Count -eq 0) {\r\n\
                try { [System.IO.Directory]::Delete($InstallDir, $false) } catch {}\r\n\
            }\r\n\
        }\r\n\
    }\r\n\
    if (-not (Test-Path -LiteralPath $UninstallExe)) {\r\n\
        break\r\n\
    }\r\n\
}\r\n\
$self = $MyInvocation.MyCommand.Path\r\n\
if ($self -and (Test-Path -LiteralPath $self)) {\r\n\
    $parent = Split-Path -Parent $self\r\n\
    Remove-Item -LiteralPath $self -Force -ErrorAction SilentlyContinue\r\n\
    if ($parent -and (Test-Path -LiteralPath $parent)) {\r\n\
        $left = @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue)\r\n\
        if ($left.Count -eq 0) {\r\n\
            try { [System.IO.Directory]::Delete($parent, $false) } catch {}\r\n\
        }\r\n\
    }\r\n\
}\r\n";
        if std::fs::write(&script_path, ps_body).is_err() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return;
        }
        let ps = windows_system_powershell();
        let _ = hidden_command_path(&ps)
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script_path)
            .arg(&uninst)
            .arg(&mp)
            .arg(install_dir)
            .spawn();
    }
    #[cfg(not(windows))]
    {
        if mp.exists() && !is_reparse_or_symlink(&mp) {
            let _ = std::fs::remove_file(&mp);
        }
        if uninst.exists() && !is_reparse_or_symlink(&uninst) {
            let _ = std::fs::remove_file(&uninst);
        }
        if install_dir.exists() && std::fs::read_dir(install_dir).is_ok_and(|mut d| d.next().is_none()) {
            let _ = std::fs::remove_dir(install_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("hide-setup-test-{}", uuid::Uuid::new_v4().simple()));
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

    #[derive(Default)]
    struct MockOps {
        shortcuts_created: RefCell<Vec<String>>,
        path_added: RefCell<bool>,
        autostart: RefCell<bool>,
        registered: RefCell<bool>,
        disconnected_called: RefCell<bool>,
    }

    impl SystemOps for MockOps {
        fn stop_running_processes(&self) {}
        fn create_shortcuts(
            &self,
            install_dir: &Path,
            _desktop_bin: &Path,
            _uninstall_bin: &Path,
        ) -> Result<Vec<String>, String> {
            let p = install_dir.join("Mock.lnk");
            std::fs::write(&p, b"lnk").unwrap();
            let list = vec![p.to_string_lossy().into_owned()];
            *self.shortcuts_created.borrow_mut() = list.clone();
            Ok(list)
        }
        fn register_uninstaller(
            &self,
            _install_dir: &Path,
            _uninstall_bin: &Path,
            _icon_path: &Path,
            _version: &str,
        ) -> Result<(), String> {
            *self.registered.borrow_mut() = true;
            Ok(())
        }
        fn add_to_path(&self, _dir: &Path) -> Result<(), String> {
            *self.path_added.borrow_mut() = true;
            Ok(())
        }
        fn remove_from_path(&self, _dir: &Path) -> Result<(), String> {
            *self.path_added.borrow_mut() = false;
            Ok(())
        }
        fn set_autostart(&self, _daemon_bin: &Path, enabled: bool) -> Result<(), String> {
            *self.autostart.borrow_mut() = enabled;
            Ok(())
        }
        fn unregister_uninstaller(&self) -> Result<(), String> {
            *self.registered.borrow_mut() = false;
            Ok(())
        }
        fn remove_shortcuts(&self, manifest: &InstallManifest) -> Vec<String> {
            manifest
                .shortcuts
                .iter()
                .filter(|s| std::fs::remove_file(s).is_ok())
                .cloned()
                .collect()
        }
        fn disconnect_harnesses(&self) -> Vec<HarnessActionResult> {
            *self.disconnected_called.borrow_mut() = true;
            Vec::new()
        }
        fn remove_ca_trust(&self, _ca_dir: &Path) -> Result<String, String> {
            Ok("mock ca removed".into())
        }
    }

    #[test]
    fn install_preserves_existing_config_and_uninstall_cleans_up() {
        let tmp = TempDir::new();
        let install_dir = tmp.path().join("app");
        let cfg_dir = tmp.path().join("cfg");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let cfg_path = cfg_dir.join("config.json");
        let custom_cfg = HideConfig {
            project_salt: "user-custom-salt-123".to_string(),
            ..HideConfig::default()
        };
        custom_cfg.save(&cfg_path).unwrap();

        let payloads = EmbeddedPayloads {
            desktop_bin: Some(b"DESKTOP_BIN"),
            daemon_bin: Some(b"DAEMON_BIN"),
            icon_ico: b"ICO",
            icon_png: b"PNG",
            version: "0.1.2",
        };
        let ops = MockOps::default();

        let outcome = perform_install_with(
            &InstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                create_shortcuts: true,
                add_to_path: true,
                autostart_daemon: true,
                language: Some(UiLanguage::En),
            },
            &payloads,
            &ops,
            Some(&cfg_path),
        );
        assert!(outcome.ok, "install failed: {:?}", outcome.error);
        assert!(install_dir.join(desktop_bin_name()).is_file());
        assert!(install_dir.join(daemon_bin_name()).is_file());
        assert!(manifest_path(&install_dir).is_file());
        assert!(*ops.registered.borrow());
        assert!(*ops.path_added.borrow());
        assert!(*ops.autostart.borrow());

        // Existing config salt must survive install/upgrade untouched while selected language is persisted
        let loaded = HideConfig::load_or_create(&cfg_path);
        assert_eq!(loaded.project_salt, "user-custom-salt-123");
        assert_eq!(loaded.language, UiLanguage::En);
        assert_eq!(configured_language(Some(&cfg_path)), UiLanguage::En);

        let uninst = perform_uninstall_with(
            &UninstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                remove_config: false,
            },
            &ops,
            Some(&cfg_path),
        );
        assert!(uninst.ok);
        assert!(*ops.disconnected_called.borrow());
        assert!(!*ops.registered.borrow());
        assert!(!*ops.path_added.borrow());
        assert!(!*ops.autostart.borrow());
        assert!(!install_dir.exists());
        assert!(cfg_path.is_file(), "config must be kept when remove_config is false");
    }

    #[test]
    fn reinstall_without_shortcuts_preserves_prior_manifest_shortcuts() {
        let tmp = TempDir::new();
        let install_dir = tmp.path().join("app");
        let cfg_path = tmp.path().join("cfg").join("config.json");
        let payloads = EmbeddedPayloads {
            desktop_bin: Some(b"DESKTOP_BIN"),
            daemon_bin: Some(b"DAEMON_BIN"),
            icon_ico: b"ICO",
            icon_png: b"PNG",
            version: "0.1.2",
        };
        let ops = MockOps::default();

        let first = perform_install_with(
            &InstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                create_shortcuts: true,
                add_to_path: true,
                autostart_daemon: false,
                language: None,
            },
            &payloads,
            &ops,
            Some(&cfg_path),
        );
        assert!(first.ok);
        assert_eq!(first.shortcuts_created.len(), 1);

        let second = perform_install_with(
            &InstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                create_shortcuts: false,
                add_to_path: false,
                autostart_daemon: false,
                language: None,
            },
            &payloads,
            &ops,
            Some(&cfg_path),
        );
        assert!(second.ok);
        let saved: InstallManifest =
            serde_json::from_str(&std::fs::read_to_string(manifest_path(&install_dir)).unwrap()).unwrap();
        assert_eq!(saved.shortcuts, first.shortcuts_created);
        assert!(saved.path_added);
    }

    #[test]
    fn uninstall_surfaces_system_errors_instead_of_swallowing() {
        struct FailingOps;
        impl SystemOps for FailingOps {
            fn stop_running_processes(&self) {}
            fn create_shortcuts(&self, _: &Path, _: &Path, _: &Path) -> Result<Vec<String>, String> {
                Ok(Vec::new())
            }
            fn register_uninstaller(&self, _: &Path, _: &Path, _: &Path, _: &str) -> Result<(), String> {
                Ok(())
            }
            fn add_to_path(&self, _: &Path) -> Result<(), String> {
                Ok(())
            }
            fn remove_from_path(&self, _: &Path) -> Result<(), String> {
                Err("path denied".into())
            }
            fn set_autostart(&self, _: &Path, _: bool) -> Result<(), String> {
                Err("autostart denied".into())
            }
            fn unregister_uninstaller(&self) -> Result<(), String> {
                Ok(())
            }
            fn remove_shortcuts(&self, _: &InstallManifest) -> Vec<String> {
                Vec::new()
            }
            fn disconnect_harnesses(&self) -> Vec<HarnessActionResult> {
                Vec::new()
            }
            fn remove_ca_trust(&self, _ca_dir: &Path) -> Result<String, String> {
                Ok("mock ca removed".into())
            }
        }

        let tmp = TempDir::new();
        let install_dir = tmp.path().join("app");
        std::fs::create_dir_all(&install_dir).unwrap();
        let res = perform_uninstall_with(
            &UninstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                remove_config: false,
            },
            &FailingOps,
            None,
        );
        assert!(!res.ok);
        let err = res.error.unwrap();
        assert!(err.contains("path denied"));
        assert!(err.contains("autostart denied"));
        assert_eq!(res.steps.iter().find(|s| s.id == "sys").unwrap().state, "error");
    }

    #[cfg(windows)]
    #[test]
    fn same_path_is_case_insensitive_on_windows() {
        let tmp = TempDir::new();
        let upper = tmp.path().to_string_lossy().to_uppercase();
        let lower = tmp.path().to_string_lossy().to_lowercase();
        assert!(same_path(Path::new(&upper), Path::new(&lower)));
    }

    #[test]
    fn validate_install_dir_rejects_unsafe_roots_and_accepts_app_subdir() {
        let tmp = TempDir::new();
        assert!(validate_install_dir(&tmp.path().join("Hide-Go")).is_ok());
        assert!(validate_install_dir(Path::new("relative/path")).is_err());
        assert!(validate_install_dir(Path::new("   ")).is_err());
        assert!(validate_install_dir(&std::env::temp_dir()).is_err());

        #[cfg(windows)]
        {
            assert!(validate_install_dir(Path::new(r"C:\")).is_err());
            assert!(validate_install_dir(Path::new(r"C:\Windows\System32\HideGo")).is_err());
        }
        #[cfg(not(windows))]
        {
            assert!(validate_install_dir(Path::new("/")).is_err());
            assert!(validate_install_dir(Path::new("/Applications")).is_err());
        }
        if let Some(home) = home_dir() {
            assert!(validate_install_dir(&home).is_err());
            assert!(validate_install_dir(&home.join("Desktop")).is_err());
            assert!(validate_install_dir(&home.join("Documents")).is_err());
        }
    }

    #[test]
    fn uninstall_requires_manifest_and_preserves_unrelated_files() {
        let tmp = TempDir::new();
        let install_dir = tmp.path().join("app");
        let cfg_path = tmp.path().join("cfg").join("config.json");
        std::fs::create_dir_all(&install_dir).unwrap();
        let unrelated = install_dir.join("user-notes.txt");
        std::fs::write(&unrelated, b"do not delete me").unwrap();

        let ops = MockOps::default();
        let without_manifest = perform_uninstall_with(
            &UninstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                remove_config: false,
            },
            &ops,
            Some(&cfg_path),
        );
        assert!(!without_manifest.ok);
        assert!(unrelated.is_file());

        let payloads = EmbeddedPayloads {
            desktop_bin: Some(b"DESKTOP"),
            daemon_bin: Some(b"DAEMON"),
            icon_ico: b"ICO",
            icon_png: b"PNG",
            version: "0.1.2",
        };
        let installed = perform_install_with(
            &InstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                create_shortcuts: false,
                add_to_path: false,
                autostart_daemon: false,
                language: None,
            },
            &payloads,
            &ops,
            Some(&cfg_path),
        );
        assert!(installed.ok);
        assert!(unrelated.is_file());

        let with_manifest = perform_uninstall_with(
            &UninstallOptions {
                install_dir: Some(install_dir.to_string_lossy().into_owned()),
                remove_config: false,
            },
            &ops,
            Some(&cfg_path),
        );
        assert!(with_manifest.ok);
        assert!(!install_dir.join(desktop_bin_name()).exists());
        assert!(!install_dir.join(daemon_bin_name()).exists());
        assert!(!manifest_path(&install_dir).exists());
        assert!(
            unrelated.is_file(),
            "unrelated files in install_dir must never be removed"
        );
    }

    #[test]
    fn escaping_and_webview_cleanup_helpers_work_safely() {
        assert_eq!(
            shell_single_quote("/tmp/a'b/hide-go").unwrap(),
            "'/tmp/a'\"'\"'b/hide-go'"
        );
        assert!(shell_single_quote("/tmp/bad\nid").is_err());
        assert_eq!(xml_escape("a&b<c>\"'").unwrap(), "a&amp;b&lt;c&gt;&quot;&apos;");
        assert_eq!(
            desktop_entry_escape("/opt/$HOME/\"app\"%f").unwrap(),
            r#"/opt/\$HOME/\"app\"%%f"#
        );

        let tmp = TempDir::new();
        let wv = tmp.path().join("Hide-Go").join("WebView2");
        std::fs::create_dir_all(&wv).unwrap();
        std::fs::write(wv.join("Cookies"), b"abc").unwrap();
        clean_webview_data_dir(&wv).unwrap();
        assert!(!wv.exists());
        assert!(!tmp.path().join("Hide-Go").exists());
    }
}
