use libloading::Library;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Function pointer table exposed by `hide_chrome` to `hide_engine`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ChromeVtable {
    pub can_open_gui: unsafe extern "C" fn() -> u8,
    pub run_frameless_window: unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> i32,
    pub show_error_dialog: unsafe extern "C" fn(*const u8, usize, *const u8, usize),
    pub pick_folder: unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8, usize) -> isize,
    pub detect_system_locale: unsafe extern "C" fn(*mut u8, usize) -> usize,
    pub terminate_other_processes: unsafe extern "C" fn() -> usize,
}

/// Platform shared library filename for a crate stem such as `hide_engine` or `hide_chrome`.
pub fn shared_lib_file_name(stem: &str) -> String {
    #[cfg(windows)]
    {
        format!("{stem}.dll")
    }
    #[cfg(target_os = "macos")]
    {
        format!("lib{stem}.dylib")
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        format!("lib{stem}.so")
    }
}

#[cfg(windows)]
fn windows_is_name_surrogate_reparse(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    const INVALID_HANDLE_VALUE: isize = -1;
    const IO_REPARSE_TAG_NAME_SURROGATE_BIT: u32 = 0x2000_0000;

    #[repr(C)]
    #[allow(dead_code)]
    struct Win32FindDataW {
        dw_file_attributes: u32,
        ft_creation_time: [u32; 2],
        ft_last_access_time: [u32; 2],
        ft_last_write_time: [u32; 2],
        n_file_size_high: u32,
        n_file_size_low: u32,
        dw_reserved0: u32,
        dw_reserved1: u32,
        c_file_name: [u16; 260],
        c_alternate_file_name: [u16; 14],
    }
    const _: () = assert!(std::mem::size_of::<Win32FindDataW>() == 592);

    #[link(name = "kernel32")]
    extern "system" {
        fn FindFirstFileW(lp_file_name: *const u16, lp_find_file_data: *mut Win32FindDataW) -> isize;
        fn FindClose(h_find_file: isize) -> i32;
    }

    // Drive roots (e.g. `C:\`) have no parent directory entry for FindFirstFileW to inspect.
    if path.parent().is_none() {
        return false;
    }

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    while wide.len() > 3 && matches!(wide.last().copied(), Some(92 | 47)) {
        wide.pop();
    }
    wide.push(0);

    let mut data = std::mem::MaybeUninit::<Win32FindDataW>::zeroed();
    // SAFETY: `wide` is null-terminated UTF-16 and `data` is valid writable storage for Win32FindDataW.
    let handle = unsafe { FindFirstFileW(wide.as_ptr(), data.as_mut_ptr()) };
    if handle == INVALID_HANDLE_VALUE {
        // Conservatively reject unreadable non-root reparse points.
        return true;
    }
    // SAFETY: `handle` is valid and `data` was initialized by FindFirstFileW.
    let data = unsafe {
        FindClose(handle);
        data.assume_init()
    };
    (data.dw_reserved0 & IO_REPARSE_TAG_NAME_SURROGATE_BIT) != 0
}

/// Returns true for POSIX symlinks and Windows symlink/junction name-surrogate reparse points,
/// while allowing benign Windows reparse points such as OneDrive Cloud Files and WOF compression.
pub fn is_reparse_or_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| {
        #[cfg(windows)]
        {
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if meta.file_type().is_symlink() {
                return true;
            }
            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
                return false;
            }
            windows_is_name_surrogate_reparse(path)
        }
        #[cfg(not(windows))]
        {
            meta.file_type().is_symlink()
        }
    })
}

fn resolve_shared_lib(exe_dir: &Path, stem: &str) -> Result<PathBuf, String> {
    let file_name = shared_lib_file_name(stem);
    let direct = exe_dir.join(&file_name);
    if direct.is_file() && !is_reparse_or_symlink(&direct) {
        return Ok(direct);
    }

    #[cfg(debug_assertions)]
    {
        let mut dev_candidates = Vec::new();
        if let Some(parent) = exe_dir.parent() {
            dev_candidates.push(parent.join(&file_name));
        }
        dev_candidates.push(PathBuf::from("target/debug").join(&file_name));
        dev_candidates.push(PathBuf::from("target/release").join(&file_name));
        for candidate in dev_candidates {
            if candidate.is_file() && !is_reparse_or_symlink(&candidate) {
                return Ok(candidate);
            }
        }
    }

    if is_reparse_or_symlink(&direct) {
        return Err(format!(
            "Refusing to load symlinked runtime library: {}",
            direct.display()
        ));
    }
    Err(format!(
        "Missing required runtime library: {}\nKeep the executable together with its DLLs and resources/ folder, or reinstall using Hide-Go-Setup.",
        direct.display()
    ))
}

/// Show a fatal startup error before `hide_chrome` / `hide_engine` can initialize.
pub fn show_fatal_launcher_error(title: &str, message: &str) {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        #[link(name = "user32")]
        extern "system" {
            fn MessageBoxW(hwnd: *mut core::ffi::c_void, text: *const u16, caption: *const u16, flags: u32) -> i32;
        }
        const MB_ICONERROR: u32 = 0x0000_0010;
        const MB_TOPMOST: u32 = 0x0004_0000;

        let mut wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(Some(0)).collect();
        let mut wide_msg: Vec<u16> = OsStr::new(message).encode_wide().chain(Some(0)).collect();
        // SAFETY: Both buffers are valid, null-terminated UTF-16 strings for the duration of MessageBoxW.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide_msg.as_mut_ptr(),
                wide_title.as_mut_ptr(),
                MB_ICONERROR | MB_TOPMOST,
            );
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("{title}: {message}");
    }
}

fn current_exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Failed to locate current executable: {e}"))?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "Current executable has no parent directory".to_string())
}

fn load_library(path: &Path) -> Result<Library, String> {
    // SAFETY: `path` was verified to be an existing regular non-symlink library owned beside the launcher.
    unsafe { Library::new(path) }.map_err(|e| format!("Failed to load runtime library {}: {e}", path.display()))
}

/// Load `hide_chrome` and `hide_engine` from the executable directory and invoke a GUI engine entry symbol.
pub fn launch_gui_entry(symbol: &[u8]) -> i32 {
    match try_launch_gui_entry(symbol) {
        Ok(code) => code,
        Err(err) => {
            show_fatal_launcher_error("Hide-Go 启动失败 / Startup Failed", &err);
            1
        }
    }
}

fn try_launch_gui_entry(symbol: &[u8]) -> Result<i32, String> {
    let exe_dir = current_exe_dir()?;
    let chrome_path = resolve_shared_lib(&exe_dir, "hide_chrome")?;
    let engine_path = resolve_shared_lib(&exe_dir, "hide_engine")?;

    let chrome_lib = load_library(&chrome_path)?;
    let engine_lib = load_library(&engine_path)?;

    let vtable = ChromeVtable {
        // SAFETY: Symbol types match the C-ABI functions exported by `crates/hide-chrome/src/lib.rs`.
        can_open_gui: unsafe {
            *chrome_lib
                .get::<unsafe extern "C" fn() -> u8>(b"hide_chrome_can_open_gui\0")
                .map_err(|e| format!("Missing hide_chrome_can_open_gui: {e}"))?
        },
        // SAFETY: Same as above.
        run_frameless_window: unsafe {
            *chrome_lib
                .get::<unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> i32>(
                    b"hide_chrome_run_frameless_window\0",
                )
                .map_err(|e| format!("Missing hide_chrome_run_frameless_window: {e}"))?
        },
        // SAFETY: Same as above.
        show_error_dialog: unsafe {
            *chrome_lib
                .get::<unsafe extern "C" fn(*const u8, usize, *const u8, usize)>(b"hide_chrome_show_error_dialog\0")
                .map_err(|e| format!("Missing hide_chrome_show_error_dialog: {e}"))?
        },
        // SAFETY: Same as above.
        pick_folder: unsafe {
            *chrome_lib
                .get::<unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8, usize) -> isize>(
                    b"hide_chrome_pick_folder\0",
                )
                .map_err(|e| format!("Missing hide_chrome_pick_folder: {e}"))?
        },
        // SAFETY: Same as above.
        detect_system_locale: unsafe {
            *chrome_lib
                .get::<unsafe extern "C" fn(*mut u8, usize) -> usize>(b"hide_chrome_detect_system_locale\0")
                .map_err(|e| format!("Missing hide_chrome_detect_system_locale: {e}"))?
        },
        // SAFETY: Same as above.
        terminate_other_processes: unsafe {
            *chrome_lib
                .get::<unsafe extern "C" fn() -> usize>(b"hide_chrome_terminate_other_processes\0")
                .map_err(|e| format!("Missing hide_chrome_terminate_other_processes: {e}"))?
        },
    };

    type GuiEntryFn = unsafe extern "C" fn(*const u8, usize, *const ChromeVtable) -> i32;
    // SAFETY: Symbol matches the `#[no_mangle] pub unsafe extern "C" fn` exported by `hide_engine`.
    let entry: GuiEntryFn = unsafe {
        *engine_lib
            .get::<GuiEntryFn>(symbol)
            .map_err(|e| format!("Missing engine entrypoint {}: {e}", String::from_utf8_lossy(symbol)))?
    };

    let exe_dir_str = exe_dir.to_string_lossy();
    let exe_dir_bytes = exe_dir_str.as_bytes();
    // SAFETY: `exe_dir_bytes` and `vtable` are valid for the duration of the synchronous entrypoint call.
    let exit_code = unsafe { entry(exe_dir_bytes.as_ptr(), exe_dir_bytes.len(), &vtable) };

    // Keep OS GUI/WebView libraries mapped through process exit to prevent teardown ordering faults.
    std::mem::forget(engine_lib);
    std::mem::forget(chrome_lib);
    Ok(exit_code)
}

/// Load `hide_engine` only (without GUI/WebView dependencies) and invoke a headless daemon entrypoint.
pub fn launch_daemon_entry(symbol: &[u8]) -> i32 {
    match try_launch_daemon_entry(symbol) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("hide-go-daemon startup failed: {err}");
            1
        }
    }
}

fn try_launch_daemon_entry(symbol: &[u8]) -> Result<i32, String> {
    let exe_dir = current_exe_dir()?;
    let engine_path = resolve_shared_lib(&exe_dir, "hide_engine")?;
    let engine_lib = load_library(&engine_path)?;

    type DaemonEntryFn = unsafe extern "C" fn() -> i32;
    // SAFETY: Symbol matches `hide_engine_run_daemon` exported by `hide_engine`.
    let entry: DaemonEntryFn = unsafe {
        *engine_lib
            .get::<DaemonEntryFn>(symbol)
            .map_err(|e| format!("Missing engine entrypoint {}: {e}", String::from_utf8_lossy(symbol)))?
    };
    // SAFETY: `entry` takes no pointers and runs synchronously.
    let exit_code = unsafe { entry() };
    std::mem::forget(engine_lib);
    Ok(exit_code)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::process::Command;

    struct TempCleanup(PathBuf);
    impl Drop for TempCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn windows_reparse_distinguishes_junctions_from_onedrive_cloud_folders() {
        let root = std::env::temp_dir().join(format!("hide-launcher-reparse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let real_dir = root.join("real");
        let junction_dir = root.join("junction");
        std::fs::create_dir_all(&real_dir).unwrap();
        let _cleanup = TempCleanup(root.clone());

        assert!(!is_reparse_or_symlink(&real_dir));
        assert!(!is_reparse_or_symlink(Path::new(r"C:\")));

        let status = Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &junction_dir.to_string_lossy(),
                &real_dir.to_string_lossy(),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
        assert!(is_reparse_or_symlink(&junction_dir), "junction must be blocked");
        let _ = std::fs::remove_dir(&junction_dir);

        if let Some(onedrive) = std::env::var_os("OneDrive").filter(|v| !v.is_empty()) {
            let p = PathBuf::from(onedrive);
            if p.is_dir() {
                assert!(
                    !is_reparse_or_symlink(&p),
                    "OneDrive folder {} must not be rejected as a symlink",
                    p.display()
                );
            }
        }
    }
}
