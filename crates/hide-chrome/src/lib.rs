use std::path::{Path, PathBuf};
use std::process::Command;
use tao::{
    dpi::{LogicalSize, PhysicalPosition},
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::run_return::EventLoopExtRunReturn,
    window::{ResizeDirection, Theme, WindowBuilder},
};
use wry::{http::Request, WebContext, WebViewBuilder};

/// Configuration for a frameless native desktop WebView window.
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

#[derive(Debug)]
enum WindowCmd {
    Drag,
    Minimize,
    ToggleMaximize,
    Close,
    Resize(ResizeDirection),
}

const INIT_SCRIPT: &str = r#"
(() => {
  if (window.__HIDE_GO_NATIVE__) return;
  window.__HIDE_GO_NATIVE__ = true;
  const post = (msg) => {
    try {
      window.ipc?.postMessage(msg);
    } catch (_) {}
  };
  window.__hideGoWin = {
    isNative: true,
    drag: () => post('win:drag'),
    minimize: () => post('win:minimize'),
    toggleMaximize: () => post('win:maximize'),
    close: () => post('win:close'),
    resize: (dir) => post('win:resize:' + dir),
  };
})();
"#;

fn parse_resize_dir(dir: &str) -> Option<ResizeDirection> {
    match dir {
        "n" => Some(ResizeDirection::North),
        "s" => Some(ResizeDirection::South),
        "e" => Some(ResizeDirection::East),
        "w" => Some(ResizeDirection::West),
        "nw" => Some(ResizeDirection::NorthWest),
        "ne" => Some(ResizeDirection::NorthEast),
        "sw" => Some(ResizeDirection::SouthWest),
        "se" => Some(ResizeDirection::SouthEast),
        _ => None,
    }
}

/// Returns `true` when the environment has a display server capable of hosting a desktop window.
pub fn can_open_gui() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("HIDE_GO_HEADLESS").is_none()
            && (std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some())
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::var_os("HIDE_GO_HEADLESS").is_none()
    }
}

/// Launch a frameless native OS window hosting the local WebView pointing at `opts.url`.
/// Blocks on the main-thread UI event loop until the user closes the window.
/// If native WebView initialization fails (for example on stripped server VMs), logs a warning
/// and opens the URL in the system default browser as a non-blocking fallback.
pub fn run_frameless_window(opts: NativeWindowOptions) -> Result<(), String> {
    match try_run_frameless_window(&opts) {
        Ok(()) => Ok(()),
        Err(err) => {
            tracing::warn!("native WebView unavailable ({err}); falling back to system browser");
            open_browser_fallback(&opts.url);
            Err(err)
        }
    }
}

const EMBEDDED_APP_ICON_PNG: &[u8] = include_bytes!("../../../desktop/icons/128x128.png");

fn load_default_window_icon() -> Option<tao::window::Icon> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(EMBEDDED_APP_ICON_PNG));
    decoder.set_transformations(
        png::Transformations::EXPAND | png::Transformations::ALPHA | png::Transformations::STRIP_16,
    );
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let raw = &buf[..info.buffer_size()];
    let rgba = match info.color_type {
        png::ColorType::Rgba => raw.to_vec(),
        png::ColorType::Rgb => raw
            .as_chunks::<3>()
            .0
            .iter()
            .flat_map(|&[r, g, b]| [r, g, b, 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => raw.as_chunks::<2>().0.iter().flat_map(|&[g, a]| [g, g, g, a]).collect(),
        png::ColorType::Grayscale => raw.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        png::ColorType::Indexed => return None,
    };
    tao::window::Icon::from_rgba(rgba, info.width, info.height).ok()
}

fn try_run_frameless_window(opts: &NativeWindowOptions) -> Result<(), String> {
    let mut event_loop = EventLoopBuilder::<WindowCmd>::with_user_event().build();
    let app_icon = load_default_window_icon();
    #[cfg(windows)]
    let taskbar_icon = app_icon.clone();

    let window = WindowBuilder::new()
        .with_title(&opts.title)
        .with_window_icon(app_icon)
        .with_inner_size(LogicalSize::new(opts.width, opts.height))
        .with_min_inner_size(LogicalSize::new(opts.min_width, opts.min_height))
        .with_resizable(opts.resizable)
        .with_decorations(false)
        .with_visible(false)
        .build(&event_loop)
        .map_err(|e| format!("failed to create window: {e}"))?;

    #[cfg(windows)]
    {
        use tao::platform::windows::WindowExtWindows;
        window.set_undecorated_shadow(true);
        window.set_taskbar_icon(taskbar_icon);
    }

    if let Some(monitor) = window.primary_monitor().or_else(|| window.current_monitor()) {
        let mon_pos = monitor.position();
        let mon_size = monitor.size();
        let win_size = window.outer_size();
        let x = mon_pos.x + ((mon_size.width as i32 - win_size.width as i32) / 2).max(0);
        let y = mon_pos.y + ((mon_size.height as i32 - win_size.height as i32) / 2).max(0);
        window.set_outer_position(PhysicalPosition::new(x, y));
    }

    let bg_rgba: wry::RGBA = match window.theme() {
        Theme::Dark => (20, 26, 35, 255),
        _ => (253, 252, 249, 255),
    };

    let proxy = event_loop.create_proxy();
    let ipc_handler = move |req: Request<String>| {
        let body = req.body().as_str();
        let cmd = match body {
            "win:drag" => Some(WindowCmd::Drag),
            "win:minimize" => Some(WindowCmd::Minimize),
            "win:maximize" => Some(WindowCmd::ToggleMaximize),
            "win:close" => Some(WindowCmd::Close),
            _ => body
                .strip_prefix("win:resize:")
                .and_then(parse_resize_dir)
                .map(WindowCmd::Resize),
        };
        if let Some(cmd) = cmd {
            let _ = proxy.send_event(cmd);
        }
    };

    let mut web_context = opts.user_data_dir.as_ref().map(|dir| {
        let _ = std::fs::create_dir_all(dir);
        WebContext::new(Some(dir.clone()))
    });

    let allowed_origin = url_origin(&opts.url).unwrap_or_default();
    let builder = match web_context.as_mut() {
        Some(ctx) => WebViewBuilder::new_with_web_context(ctx),
        None => WebViewBuilder::new(),
    }
    .with_url(&opts.url)
    .with_background_color(bg_rgba)
    .with_initialization_script(INIT_SCRIPT)
    .with_ipc_handler(ipc_handler)
    .with_navigation_handler(move |target| !allowed_origin.is_empty() && is_same_origin_url(&allowed_origin, &target))
    .with_new_window_req_handler(|url, _| {
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("https://github.com/aflydream/hide-go/") && is_safe_external_http_url(&url) {
            open_browser_fallback(&url);
        }
        wry::NewWindowResponse::Deny
    })
    .with_drag_drop_handler(|_| true)
    .with_devtools(cfg!(debug_assertions))
    .with_accept_first_mouse(true);

    #[cfg(not(target_os = "linux"))]
    let webview = builder
        .build(&window)
        .map_err(|e| format!("failed to create WebView: {e}"))?;

    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let vbox = window
            .default_vbox()
            .ok_or_else(|| "missing default GTK container".to_string())?;
        builder
            .build_gtk(vbox)
            .map_err(|e| format!("failed to create WebKitGTK WebView: {e}"))?
    };

    window.set_visible(true);
    window.set_focus();

    let mut webview = Some(webview);
    let cleanup_on_close = opts.cleanup_on_close;
    let resizable = opts.resizable;
    let mut last_maximized = window.is_maximized();
    let mut cleanup_done = false;

    event_loop.run_return(|event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            }
            | Event::UserEvent(WindowCmd::Close) => {
                let _ = webview.take();
                if cleanup_on_close && !cleanup_done {
                    cleanup_done = true;
                    terminate_other_hide_go_processes();
                }
                *control_flow = ControlFlow::Exit;
            }
            Event::LoopDestroyed => {
                let _ = webview.take();
                if cleanup_on_close && !cleanup_done {
                    cleanup_done = true;
                    terminate_other_hide_go_processes();
                }
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(_),
                ..
            } => {
                let max = window.is_maximized();
                if max != last_maximized {
                    last_maximized = max;
                    if let Some(wv) = webview.as_ref() {
                        let _ = wv.evaluate_script(&format!(
                            "window.__hideGoMaximized = {max}; window.dispatchEvent(new CustomEvent('hidego-maximized', {{ detail: {max} }}));"
                        ));
                    }
                }
            }
            Event::UserEvent(cmd) => match cmd {
                WindowCmd::Drag => {
                    let _ = window.drag_window();
                }
                WindowCmd::Minimize => {
                    window.set_minimized(true);
                }
                WindowCmd::ToggleMaximize => {
                    if resizable {
                        let next = !window.is_maximized();
                        window.set_maximized(next);
                        last_maximized = next;
                        if let Some(wv) = webview.as_ref() {
                            let _ = wv.evaluate_script(&format!(
                                "window.__hideGoMaximized = {next}; window.dispatchEvent(new CustomEvent('hidego-maximized', {{ detail: {next} }}));"
                            ));
                        }
                    }
                }
                WindowCmd::Resize(dir) => {
                    if resizable && !window.is_maximized() {
                        let _ = window.drag_resize_window(dir);
                    }
                }
                WindowCmd::Close => {}
            },
            _ => (),
        }
    });

    drop(web_context);
    Ok(())
}

/// Extract `scheme://authority` (lowercase scheme & host) from an HTTP(S) URL.
fn url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if !matches!(scheme_lower.as_str(), "http" | "https") {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    Some(format!("{scheme_lower}://{}", authority.to_ascii_lowercase()))
}

/// Returns `true` when `target` is an HTTP(S) URL sharing the exact `scheme://host:port` origin.
pub fn is_same_origin_url(allowed_origin: &str, target: &str) -> bool {
    url_origin(target).is_some_and(|origin| origin == allowed_origin)
}

/// Validate that a URL passed to `open_browser_fallback` is a benign HTTP/HTTPS URL
/// with no whitespace, control characters, quotes, or shell metacharacters.
pub fn is_safe_external_http_url(url: &str) -> bool {
    let Some(origin) = url_origin(url) else {
        return false;
    };
    let _ = origin;
    !url.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | '\\' | '`' | '|'))
}

/// Generate a 128-bit cryptographic random hex nonce for CSP `<script nonce="...">`.
pub fn generate_csp_nonce() -> String {
    let mut buf = [0u8; 16];
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                h_algorithm: *mut core::ffi::c_void,
                pb_buffer: *mut u8,
                cb_buffer: u32,
                dw_flags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        // SAFETY: `buf` is a valid 16-byte writable buffer and flag requests the system RNG.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            fallback_entropy(&mut buf);
        }
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        let ok = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .is_ok();
        if !ok {
            fallback_entropy(&mut buf);
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        fallback_entropy(&mut buf);
    }
    let mut out = String::with_capacity(32);
    for b in buf {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn fallback_entropy(buf: &mut [u8; 16]) {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s1 = RandomState::new().build_hasher().finish().to_le_bytes();
    let s2 = RandomState::new().build_hasher().finish().to_le_bytes();
    buf[..8].copy_from_slice(&s1);
    buf[8..].copy_from_slice(&s2);
}

/// Create a private temporary directory with an unpredictable name (`0700` on Unix).
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

/// Resolve an authoritative Windows System32 executable path via `GetSystemDirectoryW`
/// to prevent binary/PATH planting from the installer's working or download directory.
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

/// Create a `Command` for a resolved executable path, suppressing console windows on Windows.
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

fn existing_initial_dir(initial_dir: Option<&Path>) -> Option<PathBuf> {
    let start = initial_dir?;
    let trimmed = start.to_string_lossy();
    if trimmed.trim().is_empty() {
        return None;
    }
    start.ancestors().find(|p| p.is_dir()).map(Path::to_path_buf)
}

/// Open the OS native folder selection dialog synchronously and return the chosen directory.
pub fn pick_folder(title: &str, initial_dir: Option<&Path>) -> Option<PathBuf> {
    let init = existing_initial_dir(initial_dir);
    #[cfg(windows)]
    {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::ERROR_CANCELLED;
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
            COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
        };
        use windows::Win32::UI::Shell::{
            FileOpenDialog, IFileOpenDialog, IShellItem, SHCreateItemFromParsingName, FOS_FORCEFILESYSTEM,
            FOS_PATHMUSTEXIST, FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
        };

        let title_owned = title.to_string();
        std::thread::spawn(move || -> Option<PathBuf> {
            struct ComGuard(bool);
            impl Drop for ComGuard {
                fn drop(&mut self) {
                    if self.0 {
                        // SAFETY: balanced with a successful `CoInitializeEx` on this dedicated STA thread.
                        unsafe { CoUninitialize() };
                    }
                }
            }

            // SAFETY: initialize single-threaded apartment COM on a dedicated worker thread.
            let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
            let _guard = ComGuard(hr.is_ok());

            // SAFETY: instantiates the native Windows Explorer folder picker dialog.
            let dialog: IFileOpenDialog =
                unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }.ok()?;
            // SAFETY: valid `IFileOpenDialog` COM pointer used strictly within this STA thread.
            unsafe {
                let mut opts = dialog.GetOptions().ok()?;
                opts |= FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
                dialog.SetOptions(opts).ok()?;

                let title_w = HSTRING::from(title_owned.as_str());
                let _ = dialog.SetTitle(&title_w);

                if let Some(ref dir) = init {
                    let hdir = HSTRING::from(dir.as_os_str());
                    if let Ok(folder_item) = SHCreateItemFromParsingName::<_, _, IShellItem>(&hdir, None) {
                        let _ = dialog.SetFolder(&folder_item);
                    }
                }

                if let Err(err) = dialog.Show(None) {
                    if err.code() != ERROR_CANCELLED.to_hresult() {
                        tracing::warn!("native folder dialog failed: {err}");
                    }
                    return None;
                }

                let item = dialog.GetResult().ok()?;
                let pwstr = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
                let path = pwstr.to_string().ok().filter(|s| !s.is_empty()).map(PathBuf::from);
                CoTaskMemFree(Some(pwstr.0 as *const _));
                path
            }
        })
        .join()
        .ok()
        .flatten()
    }
    #[cfg(target_os = "macos")]
    {
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let mut script = format!("POSIX path of (choose folder with prompt \"{}\"", esc(title));
        if let Some(ref dir) = init {
            script.push_str(&format!(
                " default location (POSIX file \"{}\")",
                esc(&dir.to_string_lossy())
            ));
        }
        script.push(')');
        let out = Command::new("/usr/bin/osascript").args(["-e", &script]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let chosen = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!chosen.is_empty()).then(|| PathBuf::from(chosen))
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        let mut zenity = Command::new("zenity");
        zenity.args(["--file-selection", "--directory", &format!("--title={title}")]);
        if let Some(ref dir) = init {
            zenity.arg(format!("--filename={}/", dir.to_string_lossy().trim_end_matches('/')));
        }
        if let Ok(out) = zenity.output() {
            if out.status.success() {
                let chosen = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !chosen.is_empty() {
                    return Some(PathBuf::from(chosen));
                }
            }
            return None;
        }
        let start = init
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        let out = Command::new("kdialog")
            .args(["--getexistingdirectory", "--", &start])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let chosen = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!chosen.is_empty()).then(|| PathBuf::from(chosen))
    }
}

/// Fallback launcher for headless/browser-only setups when a native WebView is unavailable.
pub fn open_browser_fallback(url: &str) {
    if !is_safe_external_http_url(url) {
        tracing::warn!("blocked unsafe external URL in open_browser_fallback");
        return;
    }
    #[cfg(windows)]
    {
        let rundll = windows_system_executable("rundll32.exe");
        let _ = hidden_command_path(&rundll)
            .args(["url.dll,FileProtocolHandler", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("/usr/bin/open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

/// Returns `true` when `name` is a Hide-Go runtime binary (desktop console or background daemon),
/// explicitly excluding installers/uninstallers so Setup never terminates itself.
pub fn is_hide_go_runtime_process_name(name: &str) -> bool {
    let trimmed = name.trim_end_matches(['/', '\\']);
    let base = trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    let stem = base.strip_suffix(".exe").unwrap_or(&base);
    stem == "hide-go-desktop"
        || stem.starts_with("hide-go-desktop-")
        || stem == "hide_go_desktop"
        || stem == "hide-go-daemon"
        || stem.starts_with("hide-go-daemon-")
        || stem == "hide_go_daemon"
}

/// Terminate all other running Hide-Go desktop/daemon processes (excluding the current PID)
/// and wait briefly for OS handles and sockets to close. Returns how many processes were signaled.
pub fn terminate_other_hide_go_processes() -> usize {
    let self_pid = std::process::id();
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };

        // SAFETY: `TH32CS_SNAPPROCESS` with pid 0 takes a read-only snapshot of active Win32 processes.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return 0;
        }

        let mut pids = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260],
        };

        // SAFETY: `entry.dwSize` is initialized before calling `Process32FirstW`/`Process32NextW`.
        unsafe {
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let pid = entry.th32ProcessID;
                    if pid != 0 && pid != self_pid {
                        let len = entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len());
                        let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                        if is_hide_go_runtime_process_name(&name) {
                            pids.push(pid);
                        }
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }

        // Graceful close attempt first: post WM_CLOSE to any top-level window belonging to target PIDs.
        if !pids.is_empty() {
            use windows_sys::Win32::Foundation::{HWND, LPARAM};
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
            };

            struct CloseTargets<'a> {
                pids: &'a [u32],
                signaled: bool,
            }
            unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> i32 {
                let state = &mut *(lparam as *mut CloseTargets<'_>);
                let mut pid = 0u32;
                GetWindowThreadProcessId(hwnd, &mut pid);
                if pid != 0 && state.pids.contains(&pid) {
                    let _ = PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    state.signaled = true;
                }
                1
            }
            let mut targets = CloseTargets {
                pids: &pids,
                signaled: false,
            };
            // SAFETY: `targets` outlives the synchronous `EnumWindows` callback.
            unsafe {
                EnumWindows(Some(enum_proc), (&mut targets as *mut CloseTargets<'_>) as LPARAM);
            }
            if targets.signaled {
                for &pid in &pids {
                    // SAFETY: Wait briefly for graceful WM_CLOSE exit before force termination.
                    unsafe {
                        let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
                        if !handle.is_null() {
                            WaitForSingleObject(handle, 1200);
                            CloseHandle(handle);
                        }
                    }
                }
            }
        }

        let mut killed = 0;
        for pid in pids {
            // SAFETY: Valid process handle obtained from `OpenProcess` is waited on, terminated if still alive, and closed.
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
                if !handle.is_null() {
                    let already_exited = WaitForSingleObject(handle, 0) == 0;
                    if already_exited {
                        killed += 1;
                    } else if TerminateProcess(handle, 0) != 0 {
                        WaitForSingleObject(handle, 2000);
                        killed += 1;
                    }
                    CloseHandle(handle);
                }
            }
        }
        killed
    }
    #[cfg(unix)]
    {
        let Ok(out) = Command::new("ps").args(["-eo", "pid=,comm="]).output() else {
            return 0;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut pids = Vec::new();
        for line in stdout.lines() {
            let Some((pid, comm)) = parse_ps_entry(line) else {
                continue;
            };
            if pid != self_pid && is_hide_go_runtime_process_name(comm) {
                pids.push(pid.to_string());
            }
        }
        for pid in &pids {
            let _ = Command::new("kill").args(["-TERM", pid]).status();
        }
        if !pids.is_empty() {
            for _ in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let any_alive = pids.iter().any(|pid| {
                    Command::new("kill")
                        .args(["-0", pid])
                        .status()
                        .is_ok_and(|s| s.success())
                });
                if !any_alive {
                    break;
                }
            }
            for pid in &pids {
                if Command::new("kill")
                    .args(["-0", pid])
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    let _ = Command::new("kill").args(["-KILL", pid]).status();
                }
            }
        }
        pids.len()
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = self_pid;
        0
    }
}

#[cfg(any(unix, test))]
fn parse_ps_entry(line: &str) -> Option<(u32, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (pid_str, rest) = trimmed.split_once(char::is_whitespace)?;
    let pid = pid_str.parse::<u32>().ok()?;
    let comm = rest.trim();
    (!comm.is_empty()).then_some((pid, comm))
}

/// Show a native OS error dialog so GUI apps without a console never fail silently.
pub fn show_error_dialog(title: &str, message: &str) {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, MB_TOPMOST};

        let mut wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(Some(0)).collect();
        let mut wide_msg: Vec<u16> = OsStr::new(message).encode_wide().chain(Some(0)).collect();
        // SAFETY: Both pointers reference null-terminated UTF-16 buffers valid for the duration of the synchronous call.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide_msg.as_mut_ptr(),
                wide_title.as_mut_ptr(),
                MB_OK | MB_ICONERROR | MB_TOPMOST,
            );
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("{title}: {message}");
    }
}

/// Normalize a system locale identifier (BCP-47 / POSIX) to a supported UI locale (`"zh-CN"` or `"en"`).
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

fn env_locale_candidate() -> Option<String> {
    for key in ["HIDE_GO_LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        let Ok(raw) = std::env::var(key) else {
            continue;
        };
        let parts: Vec<&str> = if key == "LANGUAGE" {
            raw.split(':').collect()
        } else {
            vec![raw.as_str()]
        };
        for part in parts {
            let cleaned = part.trim();
            if cleaned.is_empty() {
                continue;
            }
            let base = cleaned.split(['.', '@']).next().unwrap_or(cleaned).trim();
            if base.eq_ignore_ascii_case("C") || base.eq_ignore_ascii_case("POSIX") {
                continue;
            }
            return Some(cleaned.to_string());
        }
    }
    None
}

/// Detect the OS UI language (`"zh-CN"` for Chinese locales, `"en"` otherwise).
pub fn detect_system_locale() -> &'static str {
    if let Some(candidate) = env_locale_candidate() {
        return normalize_locale_tag(&candidate);
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetUserDefaultUILanguage() -> u16;
        }
        // SAFETY: `GetUserDefaultUILanguage` takes no parameters and returns a LANGID scalar.
        let lang_id = unsafe { GetUserDefaultUILanguage() };
        if (lang_id & 0x03ff) == 0x04 {
            "zh-CN"
        } else {
            "en"
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(output) = Command::new("/usr/bin/defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
            .ok()
            .filter(|o| o.status.success())
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim().trim_matches(['(', ')', ',', '"', '\'']);
                if !trimmed.is_empty() {
                    return normalize_locale_tag(trimmed);
                }
            }
        }
        "en"
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        "en"
    }
}

mod ffi {
    use super::*;

    unsafe fn str_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
        if ptr.is_null() && len > 0 {
            return None;
        }
        let slice = if len == 0 {
            &[]
        } else {
            // SAFETY: Caller guarantees `ptr` points to `len` readable bytes for this synchronous FFI call.
            std::slice::from_raw_parts(ptr, len)
        };
        std::str::from_utf8(slice).ok()
    }

    unsafe fn write_utf8(dst: *mut u8, cap: usize, text: &str) -> usize {
        if dst.is_null() || cap == 0 {
            return 0;
        }
        let mut end = text.len().min(cap);
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        // SAFETY: Caller guarantees `dst` is writable for `cap` bytes and `end <= cap`.
        std::ptr::copy_nonoverlapping(text.as_ptr(), dst, end);
        end
    }

    #[no_mangle]
    pub extern "C" fn hide_chrome_can_open_gui() -> u8 {
        match std::panic::catch_unwind(can_open_gui) {
            Ok(true) => 1,
            _ => 0,
        }
    }

    /// # Safety
    /// `opts_ptr` must be valid for `opts_len` bytes of JSON-serialized `NativeWindowOptions`.
    /// When `err_cap > 0`, `err_ptr` must be writable for `err_cap` bytes.
    #[no_mangle]
    pub unsafe extern "C" fn hide_chrome_run_frameless_window(
        opts_ptr: *const u8,
        opts_len: usize,
        err_ptr: *mut u8,
        err_cap: usize,
    ) -> i32 {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Some(json) = (unsafe { str_from_raw(opts_ptr, opts_len) }) else {
                return Err("invalid window options buffer".to_string());
            };
            let opts: NativeWindowOptions =
                serde_json::from_str(json).map_err(|e| format!("invalid window options JSON: {e}"))?;
            run_frameless_window(opts)
        }));
        match res {
            Ok(Ok(())) => 0,
            Ok(Err(msg)) => {
                write_utf8(err_ptr, err_cap, &msg);
                1
            }
            Err(_) => {
                write_utf8(err_ptr, err_cap, "hide_chrome panicked");
                1
            }
        }
    }

    /// # Safety
    /// `title_ptr` and `body_ptr` must be valid for `title_len` and `body_len` UTF-8 bytes respectively.
    #[no_mangle]
    pub unsafe extern "C" fn hide_chrome_show_error_dialog(
        title_ptr: *const u8,
        title_len: usize,
        body_ptr: *const u8,
        body_len: usize,
    ) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let title = unsafe { str_from_raw(title_ptr, title_len) }.unwrap_or("Hide-Go");
            let body = unsafe { str_from_raw(body_ptr, body_len) }.unwrap_or("Unknown error");
            show_error_dialog(title, body);
        }));
    }

    /// # Safety
    /// `title_ptr`/`title_len` and `init_ptr`/`init_len` must be readable UTF-8 buffers; when
    /// `out_cap > 0`, `out_ptr` must be writable for `out_cap` bytes.
    #[no_mangle]
    pub unsafe extern "C" fn hide_chrome_pick_folder(
        title_ptr: *const u8,
        title_len: usize,
        init_ptr: *const u8,
        init_len: usize,
        out_ptr: *mut u8,
        out_cap: usize,
    ) -> isize {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let title = unsafe { str_from_raw(title_ptr, title_len) }.unwrap_or("Select folder");
            let init = unsafe { str_from_raw(init_ptr, init_len) }
                .filter(|s| !s.is_empty())
                .map(PathBuf::from);
            pick_folder(title, init.as_deref())
        }));
        match res {
            Ok(Some(path)) => {
                let text = path.to_string_lossy();
                let written = write_utf8(out_ptr, out_cap, &text);
                if written < text.len() {
                    -1
                } else {
                    written as isize
                }
            }
            _ => -1,
        }
    }

    /// # Safety
    /// When `out_cap > 0`, `out_ptr` must be writable for `out_cap` bytes.
    #[no_mangle]
    pub unsafe extern "C" fn hide_chrome_detect_system_locale(out_ptr: *mut u8, out_cap: usize) -> usize {
        match std::panic::catch_unwind(detect_system_locale) {
            Ok(loc) => write_utf8(out_ptr, out_cap, loc),
            Err(_) => write_utf8(out_ptr, out_cap, "en"),
        }
    }

    #[no_mangle]
    pub extern "C" fn hide_chrome_terminate_other_processes() -> usize {
        std::panic::catch_unwind(terminate_other_hide_go_processes).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{existing_initial_dir, is_hide_go_runtime_process_name, normalize_locale_tag, parse_ps_entry};
    use std::path::Path;

    #[test]
    fn runtime_process_matcher_includes_desktop_and_daemon_only() {
        assert!(is_hide_go_runtime_process_name("hide-go-desktop.exe"));
        assert!(is_hide_go_runtime_process_name("Hide-Go-Desktop-Windows-x64.exe"));
        assert!(is_hide_go_runtime_process_name("hide-go-daemon.exe"));
        assert!(is_hide_go_runtime_process_name("hide-go-daemon"));
        assert!(is_hide_go_runtime_process_name(r"E:\app\hide-go-desktop.exe"));
        assert!(is_hide_go_runtime_process_name("/opt/hide-go/hide-go-desktop"));

        assert!(!is_hide_go_runtime_process_name("hide-go-setup.exe"));
        assert!(!is_hide_go_runtime_process_name("hide-go-uninstall.exe"));
        assert!(!is_hide_go_runtime_process_name("msedge.exe"));
        assert!(!is_hide_go_runtime_process_name("chrome.exe"));
    }

    #[test]
    fn parse_ps_entry_preserves_paths_with_spaces() {
        assert_eq!(
            parse_ps_entry("  4219 /Users/alice/My Apps/Hide Go/hide-go-desktop "),
            Some((4219, "/Users/alice/My Apps/Hide Go/hide-go-desktop"))
        );
        assert_eq!(parse_ps_entry("1234 hide-go-daemon"), Some((1234, "hide-go-daemon")));
        assert_eq!(parse_ps_entry("notapid hide-go-daemon"), None);
        assert_eq!(parse_ps_entry("1234   "), None);
    }

    #[test]
    fn existing_initial_dir_walks_up_to_nearest_existing_ancestor() {
        let tmp = std::env::temp_dir();
        let non_existent = tmp.join("hide-go-nonexistent-subdir-xyz").join("nested");
        assert_eq!(existing_initial_dir(Some(&non_existent)), Some(tmp));
        assert_eq!(existing_initial_dir(Some(Path::new("   "))), None);
        assert_eq!(existing_initial_dir(None), None);
    }

    #[test]
    fn webview_navigation_and_external_url_checks_enforce_strict_origin_and_scheme() {
        use super::{
            create_private_temp_dir, generate_csp_nonce, is_safe_external_http_url, is_same_origin_url, url_origin,
        };

        let allowed = url_origin("http://127.0.0.1:18787/").unwrap();
        assert!(is_same_origin_url(&allowed, "http://127.0.0.1:18787/"));
        assert!(is_same_origin_url(&allowed, "http://127.0.0.1:18787/#/traffic?id=1"));
        assert!(!is_same_origin_url(&allowed, "http://127.0.0.1:18787.evil.example/"));
        assert!(!is_same_origin_url(&allowed, "http://127.0.0.1:18788/"));
        assert!(!is_same_origin_url(&allowed, "file:///C:/Windows/win.ini"));
        assert!(!is_same_origin_url(&allowed, "javascript:alert(1)"));

        assert!(is_safe_external_http_url("http://127.0.0.1:18787/"));
        assert!(is_safe_external_http_url("https://example.com/docs?x=1"));
        assert!(!is_safe_external_http_url("file:///C:/Windows/system32/calc.exe"));
        assert!(!is_safe_external_http_url("javascript:alert(1)"));
        assert!(!is_safe_external_http_url("http://127.0.0.1:18787/ a"));
        assert!(!is_safe_external_http_url("http://user@127.0.0.1:18787/"));

        let n1 = generate_csp_nonce();
        let n2 = generate_csp_nonce();
        assert_eq!(n1.len(), 32);
        assert_ne!(n1, n2);
        assert!(n1.chars().all(|c| c.is_ascii_hexdigit()));

        let dir = create_private_temp_dir("hide-chrome-test").unwrap();
        assert!(dir.is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normalize_locale_tag_maps_chinese_variants_and_falls_back_to_en() {
        assert_eq!(normalize_locale_tag("zh-CN"), "zh-CN");
        assert_eq!(normalize_locale_tag("zh_TW.UTF-8"), "zh-CN");
        assert_eq!(normalize_locale_tag("zh-Hans"), "zh-CN");
        assert_eq!(normalize_locale_tag("ZH"), "zh-CN");
        assert_eq!(normalize_locale_tag("en-US"), "en");
        assert_eq!(normalize_locale_tag("ja-JP"), "en");
        assert_eq!(normalize_locale_tag("C"), "en");
        assert_eq!(normalize_locale_tag(""), "en");
    }

    #[test]
    fn embedded_app_icon_decodes_to_valid_window_icon() {
        assert!(super::load_default_window_icon().is_some());
    }
}
