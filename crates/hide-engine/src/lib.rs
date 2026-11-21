pub mod chrome_bridge;
pub mod daemon;
pub mod desktop;
pub mod installer;
pub mod setup;
pub mod web_assets;

use chrome_bridge::{ChromeHost, FfiChromeHost};
use hide_launcher::ChromeVtable;
use std::path::PathBuf;
use std::sync::Arc;

unsafe fn parse_exe_dir(ptr: *const u8, len: usize) -> Option<PathBuf> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    let text = std::str::from_utf8(slice).ok()?.trim();
    (!text.is_empty()).then(|| PathBuf::from(text))
}

unsafe fn parse_chrome_host(ptr: *const ChromeVtable) -> Option<Arc<dyn ChromeHost>> {
    if ptr.is_null() {
        return None;
    }
    Some(Arc::new(FfiChromeHost::new(*ptr)))
}

#[no_mangle]
pub extern "C" fn hide_engine_run_daemon() -> i32 {
    let res = std::panic::catch_unwind(daemon::run_daemon);
    match res {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => {
            tracing::error!("Hide-Go daemon failed: {err}");
            eprintln!("Hide-Go daemon failed: {err}");
            1
        }
        Err(_) => {
            eprintln!("Hide-Go daemon panicked");
            1
        }
    }
}

/// # Safety
/// `exe_dir_ptr` must be valid for `exe_dir_len` UTF-8 bytes (or null when `exe_dir_len == 0`).
/// `chrome_ptr` must point to a valid `ChromeVtable`.
#[no_mangle]
pub unsafe extern "C" fn hide_engine_run_desktop(
    exe_dir_ptr: *const u8,
    exe_dir_len: usize,
    chrome_ptr: *const ChromeVtable,
) -> i32 {
    let exe_dir = parse_exe_dir(exe_dir_ptr, exe_dir_len);
    let Some(chrome) = parse_chrome_host(chrome_ptr) else {
        return 1;
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        desktop::run_desktop_entry(exe_dir.as_deref(), chrome)
    }))
    .unwrap_or(1)
}

/// # Safety
/// `exe_dir_ptr` must be valid for `exe_dir_len` UTF-8 bytes (or null when `exe_dir_len == 0`).
/// `chrome_ptr` must point to a valid `ChromeVtable`.
#[no_mangle]
pub unsafe extern "C" fn hide_engine_run_setup(
    exe_dir_ptr: *const u8,
    exe_dir_len: usize,
    chrome_ptr: *const ChromeVtable,
) -> i32 {
    let exe_dir = parse_exe_dir(exe_dir_ptr, exe_dir_len);
    let Some(chrome) = parse_chrome_host(chrome_ptr) else {
        return 1;
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        setup::run_setup_entry(exe_dir.as_deref(), chrome)
    }))
    .unwrap_or(1)
}
