use hide_launcher::ChromeVtable;
use ring::rand::{SecureRandom, SystemRandom};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Configuration serialized across FFI to `hide_chrome`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeWindowOptions {
    pub title: String,
    pub url: String,
    pub width: f64,
    pub height: f64,
    pub min_width: f64,
    pub min_height: f64,
    pub resizable: bool,
    pub cleanup_on_close: bool,
    pub user_data_dir: Option<PathBuf>,
}

/// Host UI abstraction implemented either via dynamically loaded `hide_chrome` or headless fallback.
pub trait ChromeHost: Send + Sync {
    fn can_open_gui(&self) -> bool;
    fn run_frameless_window(&self, opts: NativeWindowOptions) -> Result<(), String>;
    fn show_error_dialog(&self, title: &str, message: &str);
    fn pick_folder(&self, title: &str, initial_dir: Option<&Path>) -> Option<PathBuf>;
    fn detect_system_locale(&self) -> &'static str;
    fn terminate_other_processes(&self) -> usize;
}

/// `ChromeHost` backed by the C-ABI vtable loaded from `hide_chrome`.
pub struct FfiChromeHost {
    vtable: ChromeVtable,
}

impl FfiChromeHost {
    pub fn new(vtable: ChromeVtable) -> Self {
        Self { vtable }
    }
}

impl ChromeHost for FfiChromeHost {
    fn can_open_gui(&self) -> bool {
        // SAFETY: Vtable function pointer originates from loaded `hide_chrome` and takes no pointers.
        unsafe { (self.vtable.can_open_gui)() != 0 }
    }

    fn run_frameless_window(&self, opts: NativeWindowOptions) -> Result<(), String> {
        let json = serde_json::to_vec(&opts).map_err(|e| format!("failed to serialize window options: {e}"))?;
        let mut err_buf = [0u8; 4096];
        // SAFETY: Both buffers remain alive and valid for the duration of the synchronous call.
        let rc = unsafe {
            (self.vtable.run_frameless_window)(json.as_ptr(), json.len(), err_buf.as_mut_ptr(), err_buf.len())
        };
        if rc == 0 {
            Ok(())
        } else {
            let end = err_buf.iter().position(|&b| b == 0).unwrap_or(err_buf.len());
            let msg = String::from_utf8_lossy(&err_buf[..end]).trim().to_string();
            Err(if msg.is_empty() {
                "failed to open native WebView window".to_string()
            } else {
                msg
            })
        }
    }

    fn show_error_dialog(&self, title: &str, message: &str) {
        let tb = title.as_bytes();
        let mb = message.as_bytes();
        // SAFETY: `tb` and `mb` point to valid UTF-8 slices for the duration of the call.
        unsafe { (self.vtable.show_error_dialog)(tb.as_ptr(), tb.len(), mb.as_ptr(), mb.len()) };
    }

    fn pick_folder(&self, title: &str, initial_dir: Option<&Path>) -> Option<PathBuf> {
        let tb = title.as_bytes();
        let init_str = initial_dir
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ib = init_str.as_bytes();
        let mut out = [0u8; 4096];
        // SAFETY: Input slices and `out` buffer remain valid for the synchronous dialog call.
        let written = unsafe {
            (self.vtable.pick_folder)(
                tb.as_ptr(),
                tb.len(),
                ib.as_ptr(),
                ib.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        if written <= 0 {
            return None;
        }
        let len = (written as usize).min(out.len());
        let chosen = String::from_utf8_lossy(&out[..len]).trim().to_string();
        (!chosen.is_empty()).then(|| PathBuf::from(chosen))
    }

    fn detect_system_locale(&self) -> &'static str {
        let mut out = [0u8; 64];
        // SAFETY: `out` is writable for `out.len()` bytes.
        let written = unsafe { (self.vtable.detect_system_locale)(out.as_mut_ptr(), out.len()) };
        let len = written.min(out.len());
        let tag = std::str::from_utf8(&out[..len]).unwrap_or("en");
        normalize_locale_tag(tag)
    }

    fn terminate_other_processes(&self) -> usize {
        // SAFETY: `terminate_other_processes` takes no pointers and returns a count.
        unsafe { (self.vtable.terminate_other_processes)() }
    }
}

/// Non-GUI host used by unit tests and daemon-only contexts.
#[derive(Default)]
pub struct HeadlessChromeHost;

impl ChromeHost for HeadlessChromeHost {
    fn can_open_gui(&self) -> bool {
        false
    }

    fn run_frameless_window(&self, _opts: NativeWindowOptions) -> Result<(), String> {
        Err("GUI unavailable in headless context".to_string())
    }

    fn show_error_dialog(&self, title: &str, message: &str) {
        eprintln!("{title}: {message}");
    }

    fn pick_folder(&self, _title: &str, _initial_dir: Option<&Path>) -> Option<PathBuf> {
        None
    }

    fn detect_system_locale(&self) -> &'static str {
        for key in ["HIDE_GO_LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
            if let Ok(raw) = std::env::var(key) {
                if let Some(first) = raw.split(':').find(|p| !p.trim().is_empty()) {
                    let base = first.split(['.', '@']).next().unwrap_or(first).trim();
                    if !base.eq_ignore_ascii_case("C") && !base.eq_ignore_ascii_case("POSIX") {
                        return normalize_locale_tag(first);
                    }
                }
            }
        }
        "en"
    }

    fn terminate_other_processes(&self) -> usize {
        0
    }
}

pub fn normalize_locale_tag(raw: &str) -> &'static str {
    let trimmed = raw.trim();
    if trimmed.len() >= 2
        && trimmed.as_bytes()[..2].eq_ignore_ascii_case(b"zh")
        && trimmed.as_bytes().get(2).is_none_or(|b| !b.is_ascii_alphanumeric())
    {
        "zh-CN"
    } else {
        "en"
    }
}

pub fn generate_csp_nonce() -> String {
    let mut buf = [0u8; 16];
    let rng = SystemRandom::new();
    if rng.fill(&mut buf).is_err() {
        let id = uuid::Uuid::new_v4();
        buf.copy_from_slice(id.as_bytes());
    }
    hex::encode(buf)
}

pub fn is_reparse_or_symlink(path: &Path) -> bool {
    hide_launcher::is_reparse_or_symlink(path)
}

pub fn create_private_temp_dir(prefix: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", generate_csp_nonce()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(&dir)?;
    }
    Ok(dir)
}

#[cfg(windows)]
pub fn windows_system_executable(relative: &str) -> PathBuf {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(lp_buffer: *mut u16, u_size: u32) -> u32;
    }
    let mut buf = [0u16; 512];
    // SAFETY: `buf` is a writable UTF-16 buffer of length `buf.len()`.
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let sys_dir = if len > 0 && len < buf.len() {
        PathBuf::from(String::from_utf16_lossy(&buf[..len]))
    } else if let Some(root) = std::env::var_os("SystemRoot").filter(|v| !v.is_empty()) {
        PathBuf::from(root).join("System32")
    } else {
        PathBuf::from(r"C:\Windows\System32")
    };
    sys_dir.join(relative)
}

pub fn hidden_command_path(program: &Path) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut cmd = Command::new(program);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }
    #[cfg(not(windows))]
    {
        Command::new(program)
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
