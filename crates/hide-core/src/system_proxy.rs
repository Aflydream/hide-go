//! Reversible Windows WinInet system proxy chaining.
//!
//! When enabled for desktop clients that follow OS proxy settings rather than per-app config
//! files, Hide-Go snapshots the user's existing `Internet Settings` proxy configuration to
//! `system-proxy-backup.json` before switching `ProxyServer` to `127.0.0.1:<port>`, notifies
//! active applications via `InternetSetOptionW`, chains outbound traffic through the original
//! upstream proxy, and restores the exact previous settings on disconnect, exit, or uninstall.

use crate::config::HideConfig;
use crate::upstream_proxy::{is_self_proxy, parse_proxy_server};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type ChainedProxyCacheEntry = (Instant, Option<(String, Option<String>)>);

static SYS_PROXY_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static CHAINED_CACHE: Lazy<RwLock<Option<ChainedProxyCacheEntry>>> = Lazy::new(|| RwLock::new(None));
const CHAINED_CACHE_TTL: Duration = Duration::from_secs(2);

const DEFAULT_SYSTEM_PROXY_OVERRIDES: &[&str] = &["localhost", "127.*", "[::1]", "<local>"];
const DEFAULT_ENV_NO_PROXY: &str = "localhost,127.0.0.1,::1";
const MANAGED_USER_ENV_KEYS: &[&str] = &[
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
];

/// Snapshot of OS WinInet proxy settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WinInetSnapshot {
    pub proxy_enable: u32,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
}

/// Persisted backup of the pre-Hide-Go OS system proxy and user environment settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxyBackup {
    pub proxy_enable: u32,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    pub chained_upstream_proxy: Option<String>,
    pub active_port: u16,
    #[serde(default)]
    pub user_env_backup: BTreeMap<String, Option<String>>,
}

/// Abstract OS system-proxy adapter so tests run completely isolated from the host registry.
pub trait SystemProxyAdapter {
    fn supported(&self) -> bool;
    fn read_current(&self) -> Result<WinInetSnapshot, String>;
    fn write_snapshot(&self, snap: &WinInetSnapshot) -> Result<(), String>;
    fn read_user_env(&self, _keys: &[&str]) -> Result<BTreeMap<String, Option<String>>, String> {
        Ok(BTreeMap::new())
    }
    fn write_user_env(&self, _updates: &BTreeMap<String, Option<String>>) -> Result<(), String> {
        Ok(())
    }
}

/// Production Windows WinInet system-proxy adapter.
pub struct RealSystemProxyAdapter;

#[cfg(windows)]
mod wininet_ffi {
    use super::WinInetSnapshot;
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    type Hkey = *mut c_void;
    const HKEY_CURRENT_USER: Hkey = 0x8000_0001usize as Hkey;
    const KEY_READ: u32 = 0x0002_0019;
    const KEY_SET_VALUE: u32 = 0x0002;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_DWORD: u32 = 4;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;

    const INTERNET_SETTINGS_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const ENVIRONMENT_SUBKEY: &str = "Environment";
    const HWND_BROADCAST: *mut c_void = 0xffffusize as *mut c_void;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hkey: Hkey,
            lpsubkey: *const u16,
            uloptions: u32,
            samdesired: u32,
            phkresult: *mut Hkey,
        ) -> u32;
        fn RegQueryValueExW(
            hkey: Hkey,
            lpvaluename: *const u16,
            lpreserved: *mut u32,
            lptype: *mut u32,
            lpdata: *mut u8,
            lpcbdata: *mut u32,
        ) -> u32;
        fn RegSetValueExW(
            hkey: Hkey,
            lpvaluename: *const u16,
            reserved: u32,
            dwtype: u32,
            lpdata: *const u8,
            cbdata: u32,
        ) -> u32;
        fn RegDeleteValueW(hkey: Hkey, lpvaluename: *const u16) -> u32;
        fn RegCloseKey(hkey: Hkey) -> u32;
    }

    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(hinternet: *mut c_void, dwoption: u32, lpbuffer: *mut c_void, dwbufferlength: u32)
            -> i32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn SendMessageTimeoutW(
            hwnd: *mut c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
            fuflags: u32,
            utimeout: u32,
            lpdwresult: *mut usize,
        ) -> isize;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    static CTRL_HANDLER_INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    unsafe extern "system" fn console_ctrl_restore_handler(_ctrl_type: u32) -> i32 {
        let _ = super::restore_system_proxy();
        0
    }

    pub fn ensure_console_ctrl_restore_handler() {
        if !CTRL_HANDLER_INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            // SAFETY: `console_ctrl_restore_handler` has `extern "system"` ABI matching PHANDLER_ROUTINE.
            unsafe {
                let _ = SetConsoleCtrlHandler(Some(console_ctrl_restore_handler), 1);
            }
        }
    }

    struct KeyGuard(Hkey);
    impl Drop for KeyGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was opened by `RegOpenKeyExW`.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn read_sz(hkey: Hkey, name: &str) -> Option<String> {
        let wname = to_wide(name);
        let mut val_type: u32 = 0;
        let mut byte_len: u32 = 0;
        // SAFETY: queries buffer length for `name`.
        let q1 = unsafe {
            RegQueryValueExW(
                hkey,
                wname.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                std::ptr::null_mut(),
                &mut byte_len,
            )
        };
        if q1 != 0 || !matches!(val_type, REG_SZ | REG_EXPAND_SZ) || byte_len == 0 || byte_len > 32 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; byte_len as usize];
        // SAFETY: reads `byte_len` bytes into `buf`.
        let q2 = unsafe {
            RegQueryValueExW(
                hkey,
                wname.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr(),
                &mut byte_len,
            )
        };
        if q2 != 0 || !matches!(val_type, REG_SZ | REG_EXPAND_SZ) {
            return None;
        }
        let used = &buf[..(byte_len as usize).min(buf.len())];
        let wide: Vec<u16> = used
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[lo, hi]| u16::from_le_bytes([lo, hi]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16(&wide).ok()
    }

    fn write_sz(hkey: Hkey, name: &str, value: Option<&str>) -> Result<(), String> {
        let wname = to_wide(name);
        match value {
            Some(v) => {
                let wide = to_wide(v);
                let byte_len = (wide.len() * 2) as u32;
                // SAFETY: `wide` is NUL-terminated UTF-16LE buffer of `byte_len` bytes.
                let st =
                    unsafe { RegSetValueExW(hkey, wname.as_ptr(), 0, REG_SZ, wide.as_ptr() as *const u8, byte_len) };
                if st != 0 {
                    return Err(format!("RegSetValueExW({name}) failed with Win32 error {st}"));
                }
            }
            None => {
                // SAFETY: deletes value `name` if present.
                let st = unsafe { RegDeleteValueW(hkey, wname.as_ptr()) };
                if st != 0 && st != ERROR_FILE_NOT_FOUND {
                    return Err(format!("RegDeleteValueW({name}) failed with Win32 error {st}"));
                }
            }
        }
        Ok(())
    }

    pub fn read_wininet_snapshot() -> Result<WinInetSnapshot, String> {
        let subkey = to_wide(INTERNET_SETTINGS_SUBKEY);
        let mut hkey: Hkey = std::ptr::null_mut();
        // SAFETY: opens current user Internet Settings key for reading.
        let st = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
        if st != 0 || hkey.is_null() {
            return Err(format!("RegOpenKeyExW(read) failed with Win32 error {st}"));
        }
        let _guard = KeyGuard(hkey);

        let enable_name = to_wide("ProxyEnable");
        let mut val_type: u32 = 0;
        let mut dword_buf = [0u8; 4];
        let mut dword_len: u32 = 4;
        // SAFETY: reads DWORD into 4-byte stack buffer.
        let en_st = unsafe {
            RegQueryValueExW(
                hkey,
                enable_name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                dword_buf.as_mut_ptr(),
                &mut dword_len,
            )
        };
        let proxy_enable = if en_st == 0 && val_type == REG_DWORD && dword_len == 4 {
            u32::from_le_bytes(dword_buf)
        } else {
            0
        };
        let proxy_server = read_sz(hkey, "ProxyServer").filter(|s| !s.trim().is_empty());
        let proxy_override = read_sz(hkey, "ProxyOverride").filter(|s| !s.trim().is_empty());
        Ok(WinInetSnapshot {
            proxy_enable,
            proxy_server,
            proxy_override,
        })
    }

    pub fn write_wininet_snapshot(snap: &WinInetSnapshot) -> Result<(), String> {
        let subkey = to_wide(INTERNET_SETTINGS_SUBKEY);
        let mut hkey: Hkey = std::ptr::null_mut();
        // SAFETY: opens current user Internet Settings key for writing.
        let st = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) };
        if st != 0 || hkey.is_null() {
            return Err(format!("RegOpenKeyExW(write) failed with Win32 error {st}"));
        }
        let _guard = KeyGuard(hkey);

        let enable_name = to_wide("ProxyEnable");
        let enable_bytes = snap.proxy_enable.to_le_bytes();
        // SAFETY: writes 4-byte little-endian DWORD for `ProxyEnable`.
        let en_st = unsafe { RegSetValueExW(hkey, enable_name.as_ptr(), 0, REG_DWORD, enable_bytes.as_ptr(), 4) };
        if en_st != 0 {
            return Err(format!("RegSetValueExW(ProxyEnable) failed with Win32 error {en_st}"));
        }
        write_sz(hkey, "ProxyServer", snap.proxy_server.as_deref())?;
        write_sz(hkey, "ProxyOverride", snap.proxy_override.as_deref())?;

        // SAFETY: notifies WinInet and running applications of updated proxy settings.
        unsafe {
            let _ = InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            let _ = InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
        }
        Ok(())
    }

    pub fn read_user_env_values(keys: &[&str]) -> Result<std::collections::BTreeMap<String, Option<String>>, String> {
        let subkey = to_wide(ENVIRONMENT_SUBKEY);
        let mut hkey: Hkey = std::ptr::null_mut();
        // SAFETY: opens HKCU\Environment for reading.
        let st = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
        if st != 0 || hkey.is_null() {
            return Err(format!("RegOpenKeyExW(Environment read) failed with Win32 error {st}"));
        }
        let _guard = KeyGuard(hkey);
        let mut out = std::collections::BTreeMap::new();
        for &key in keys {
            out.insert(key.to_string(), read_sz(hkey, key));
        }
        Ok(out)
    }

    pub fn write_user_env_values(updates: &std::collections::BTreeMap<String, Option<String>>) -> Result<(), String> {
        if updates.is_empty() {
            return Ok(());
        }
        let subkey = to_wide(ENVIRONMENT_SUBKEY);
        let mut hkey: Hkey = std::ptr::null_mut();
        // SAFETY: opens HKCU\Environment for writing.
        let st = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) };
        if st != 0 || hkey.is_null() {
            return Err(format!("RegOpenKeyExW(Environment write) failed with Win32 error {st}"));
        }
        let _guard = KeyGuard(hkey);
        for (key, val) in updates {
            write_sz(hkey, key, val.as_deref())?;
        }
        let env_wide = to_wide("Environment");
        let mut result: usize = 0;
        // SAFETY: broadcasts WM_SETTINGCHANGE("Environment") so explorer and newly spawned apps pick up updated user env.
        unsafe {
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_wide.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                1000,
                &mut result,
            );
        }
        Ok(())
    }
}

impl SystemProxyAdapter for RealSystemProxyAdapter {
    fn supported(&self) -> bool {
        cfg!(windows)
    }

    fn read_current(&self) -> Result<WinInetSnapshot, String> {
        #[cfg(windows)]
        {
            wininet_ffi::read_wininet_snapshot()
        }
        #[cfg(not(windows))]
        {
            Ok(WinInetSnapshot::default())
        }
    }

    fn write_snapshot(&self, snap: &WinInetSnapshot) -> Result<(), String> {
        #[cfg(windows)]
        {
            wininet_ffi::write_wininet_snapshot(snap)
        }
        #[cfg(not(windows))]
        {
            let _ = snap;
            Ok(())
        }
    }

    fn read_user_env(&self, keys: &[&str]) -> Result<BTreeMap<String, Option<String>>, String> {
        #[cfg(windows)]
        {
            wininet_ffi::read_user_env_values(keys)
        }
        #[cfg(not(windows))]
        {
            let _ = keys;
            Ok(BTreeMap::new())
        }
    }

    fn write_user_env(&self, updates: &BTreeMap<String, Option<String>>) -> Result<(), String> {
        #[cfg(windows)]
        {
            wininet_ffi::write_user_env_values(updates)
        }
        #[cfg(not(windows))]
        {
            let _ = updates;
            Ok(())
        }
    }
}

/// Default path for the persisted system-proxy backup file (`<config_dir>/system-proxy-backup.json`).
pub fn default_backup_path() -> Option<PathBuf> {
    HideConfig::default_path().and_then(|p| p.parent().map(|d| d.join("system-proxy-backup.json")))
}

fn invalidate_chained_cache() {
    *CHAINED_CACHE.write() = None;
}

fn merge_proxy_override(existing: Option<&str>) -> String {
    let mut entries: Vec<String> = existing
        .unwrap_or_default()
        .split([';', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    for &req in DEFAULT_SYSTEM_PROXY_OVERRIDES {
        if !entries.iter().any(|e| e.eq_ignore_ascii_case(req)) {
            entries.push(req.to_string());
        }
    }
    entries.join(";")
}

fn snapshot_points_to_port(snap: &WinInetSnapshot, port: u16) -> bool {
    if snap.proxy_enable == 0 || port == 0 {
        return false;
    }
    snap.proxy_server
        .as_deref()
        .and_then(parse_proxy_server)
        .is_some_and(|u| is_self_proxy(&u, port))
}

fn load_backup(path: &Path) -> Option<SystemProxyBackup> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save_backup(path: &Path, backup: &SystemProxyBackup) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(backup).map_err(|e| format!("failed to serialize proxy backup: {e}"))?;
    crate::ca::atomic_write_private_file(path, &bytes)
}

/// Activate reversible OS system proxy chaining pointing at `127.0.0.1:<proxy_port>`.
pub fn activate_system_proxy(proxy_port: u16) -> Result<Option<String>, String> {
    let Some(path) = default_backup_path() else {
        return Ok(None);
    };
    activate_system_proxy_with(&RealSystemProxyAdapter, &path, proxy_port)
}

fn merge_env_no_proxy(existing: Option<&str>) -> String {
    let mut entries: Vec<String> = existing
        .unwrap_or_default()
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    for req in DEFAULT_ENV_NO_PROXY.split(',') {
        if !entries.iter().any(|e| e.eq_ignore_ascii_case(req)) {
            entries.push(req.to_string());
        }
    }
    entries.join(",")
}

fn value_looks_like_hidego_env(key: &str, value: &str, active_port: u16) -> bool {
    let trimmed = value.trim();
    match key {
        "HTTPS_PROXY" | "HTTP_PROXY" => parse_proxy_server(trimmed).is_some_and(|u| is_self_proxy(&u, active_port)),
        "NO_PROXY" => trimmed.eq_ignore_ascii_case(DEFAULT_ENV_NO_PROXY) || trimmed.contains("127.0.0.1"),
        "SSL_CERT_FILE" | "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH" | "NODE_EXTRA_CA_CERTS" | "REQUESTS_CA_BUNDLE" => {
            let lower = trimmed.to_ascii_lowercase();
            lower.contains("hide-go-ca.crt") || lower.contains("hide-go-ca-bundle.pem")
        }
        _ => false,
    }
}

fn build_managed_user_env_updates(proxy_port: u16, prior_no_proxy: Option<&str>) -> BTreeMap<String, Option<String>> {
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let mut updates = BTreeMap::new();
    updates.insert("HTTPS_PROXY".to_string(), Some(proxy_url.clone()));
    updates.insert("HTTP_PROXY".to_string(), Some(proxy_url));
    updates.insert("NO_PROXY".to_string(), Some(merge_env_no_proxy(prior_no_proxy)));
    if let Some(ca_dir) = crate::ca::CaManager::default_ca_dir() {
        let cert = ca_dir.join("hide-go-ca.crt");
        let bundle = ca_dir.join("hide-go-ca-bundle.pem");
        if cert.is_file() {
            updates.insert(
                "NODE_EXTRA_CA_CERTS".to_string(),
                Some(cert.to_string_lossy().into_owned()),
            );
        }
        if bundle.is_file() {
            let bstr = bundle.to_string_lossy().into_owned();
            updates.insert("SSL_CERT_FILE".to_string(), Some(bstr.clone()));
            updates.insert("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH".to_string(), Some(bstr.clone()));
            updates.insert("REQUESTS_CA_BUNDLE".to_string(), Some(bstr));
        }
    }
    updates
}

pub fn activate_system_proxy_with(
    adapter: &dyn SystemProxyAdapter,
    backup_path: &Path,
    proxy_port: u16,
) -> Result<Option<String>, String> {
    if !adapter.supported() || proxy_port == 0 {
        return Ok(None);
    }
    let _guard = SYS_PROXY_LOCK.lock();
    let cur = adapter.read_current()?;
    let cur_env = adapter.read_user_env(MANAGED_USER_ENV_KEYS).unwrap_or_default();
    let existing = load_backup(backup_path);

    let already_hidego = snapshot_points_to_port(&cur, proxy_port)
        || existing
            .as_ref()
            .is_some_and(|b| snapshot_points_to_port(&cur, b.active_port));

    let mut user_env_backup = existing.as_ref().map(|b| b.user_env_backup.clone()).unwrap_or_default();
    let prev_port = existing.as_ref().map(|b| b.active_port).unwrap_or(proxy_port);
    for &key in MANAGED_USER_ENV_KEYS {
        user_env_backup.entry(key.to_string()).or_insert_with(|| {
            let val = cur_env.get(key).cloned().flatten();
            match val {
                Some(ref v)
                    if value_looks_like_hidego_env(key, v, proxy_port)
                        || value_looks_like_hidego_env(key, v, prev_port) =>
                {
                    None
                }
                other => other,
            }
        });
    }

    let backup = if already_hidego {
        if let Some(mut prev) = existing {
            prev.active_port = proxy_port;
            prev.user_env_backup = user_env_backup;
            save_backup(backup_path, &prev)?;
            prev
        } else {
            // System proxy already points at Hide-Go with no backup (e.g. stale state); record safe direct fallback.
            let fresh = SystemProxyBackup {
                proxy_enable: 0,
                proxy_server: None,
                proxy_override: cur.proxy_override.clone(),
                chained_upstream_proxy: None,
                active_port: proxy_port,
                user_env_backup,
            };
            save_backup(backup_path, &fresh)?;
            fresh
        }
    } else {
        let chained_upstream_proxy = if cur.proxy_enable != 0 {
            cur.proxy_server
                .as_deref()
                .and_then(parse_proxy_server)
                .filter(|u| !is_self_proxy(u, proxy_port))
        } else {
            None
        };
        let fresh = SystemProxyBackup {
            proxy_enable: cur.proxy_enable,
            proxy_server: cur.proxy_server.clone(),
            proxy_override: cur.proxy_override.clone(),
            chained_upstream_proxy,
            active_port: proxy_port,
            user_env_backup,
        };
        save_backup(backup_path, &fresh)?;
        fresh
    };

    let next_snap = WinInetSnapshot {
        proxy_enable: 1,
        proxy_server: Some(format!("127.0.0.1:{proxy_port}")),
        proxy_override: Some(merge_proxy_override(backup.proxy_override.as_deref())),
    };
    adapter.write_snapshot(&next_snap)?;
    let prior_no_proxy = backup.user_env_backup.get("NO_PROXY").and_then(|v| v.as_deref());
    let env_updates = build_managed_user_env_updates(proxy_port, prior_no_proxy);
    if let Err(err) = adapter.write_user_env(&env_updates) {
        tracing::warn!("failed to write managed user proxy environment variables: {err}");
    }
    invalidate_chained_cache();
    Ok(backup.chained_upstream_proxy)
}

/// Restore the user's original OS system proxy settings if Hide-Go currently owns them.
pub fn restore_system_proxy() -> Result<bool, String> {
    let Some(path) = default_backup_path() else {
        return Ok(false);
    };
    restore_system_proxy_with(&RealSystemProxyAdapter, &path)
}

pub fn restore_system_proxy_with(adapter: &dyn SystemProxyAdapter, backup_path: &Path) -> Result<bool, String> {
    let _guard = SYS_PROXY_LOCK.lock();
    let Some(backup) = load_backup(backup_path) else {
        return Ok(false);
    };
    if adapter.supported() {
        let cur = adapter.read_current()?;
        if snapshot_points_to_port(&cur, backup.active_port) {
            adapter.write_snapshot(&WinInetSnapshot {
                proxy_enable: backup.proxy_enable,
                proxy_server: backup.proxy_server,
                proxy_override: backup.proxy_override,
            })?;
        }
        if !backup.user_env_backup.is_empty() {
            let cur_env = adapter.read_user_env(MANAGED_USER_ENV_KEYS).unwrap_or_default();
            let mut restores = BTreeMap::new();
            for (key, orig_val) in &backup.user_env_backup {
                if let Some(cur_val) = cur_env.get(key).and_then(|v| v.as_deref()) {
                    if value_looks_like_hidego_env(key, cur_val, backup.active_port) {
                        restores.insert(key.clone(), orig_val.clone());
                    }
                }
            }
            if !restores.is_empty() {
                if let Err(err) = adapter.write_user_env(&restores) {
                    tracing::warn!("failed to restore managed user environment variables: {err}");
                }
            }
        }
    }
    let _ = std::fs::remove_file(backup_path);
    invalidate_chained_cache();
    Ok(true)
}

/// Synchronize OS system proxy chaining with the live runtime configuration.
pub fn sync_system_proxy_runtime(enabled: bool, proxy_port: u16) {
    if enabled && proxy_port > 0 {
        if let Err(err) = activate_system_proxy(proxy_port) {
            tracing::warn!("failed to activate system proxy chaining on port {proxy_port}: {err}");
        }
    } else if let Err(err) = restore_system_proxy() {
        tracing::warn!("failed to restore system proxy settings: {err}");
    }
}

/// Read the pre-Hide-Go chained upstream proxy URL and bypass list from `system-proxy-backup.json`
/// (used by `upstream_proxy` whenever the active WinInet setting points at Hide-Go itself).
pub fn read_chained_upstream_proxy(own_proxy_port: u16) -> Option<(String, Option<String>)> {
    {
        let guard = CHAINED_CACHE.read();
        if let Some((captured_at, cached)) = guard.as_ref() {
            if captured_at.elapsed() < CHAINED_CACHE_TTL {
                return cached.clone();
            }
        }
    }
    let resolved = default_backup_path().as_deref().and_then(load_backup).and_then(|b| {
        let url = b.chained_upstream_proxy?;
        if is_self_proxy(&url, own_proxy_port) {
            return None;
        }
        Some((url, b.proxy_override))
    });
    *CHAINED_CACHE.write() = Some((Instant::now(), resolved.clone()));
    resolved
}

/// Returns `true` when Windows system proxy chaining is supported and currently active on `proxy_port`.
pub fn is_system_proxy_active_for_port(proxy_port: u16) -> bool {
    let adapter = RealSystemProxyAdapter;
    if !adapter.supported() || proxy_port == 0 {
        return false;
    }
    adapter
        .read_current()
        .is_ok_and(|snap| snapshot_points_to_port(&snap, proxy_port))
}

/// RAII runtime guard that activates system proxy chaining (when enabled in config) and
/// guarantees restoration when the gateway stops.
pub struct SystemProxyRuntimeGuard {
    active: bool,
}

impl SystemProxyRuntimeGuard {
    pub fn start(enabled: bool, proxy_port: u16) -> Self {
        #[cfg(windows)]
        wininet_ffi::ensure_console_ctrl_restore_handler();
        if enabled && proxy_port > 0 {
            if let Err(err) = activate_system_proxy(proxy_port) {
                tracing::warn!("system proxy activation failed on startup: {err}");
            }
        } else if let Err(err) = restore_system_proxy() {
            tracing::warn!("stale system proxy recovery failed on startup: {err}");
        }
        Self { active: true }
    }
}

impl Drop for SystemProxyRuntimeGuard {
    fn drop(&mut self) {
        if self.active {
            if let Err(err) = restore_system_proxy() {
                tracing::warn!("system proxy restore failed on shutdown: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockSystemProxy {
        snap: RefCell<WinInetSnapshot>,
        env: RefCell<BTreeMap<String, String>>,
    }

    impl MockSystemProxy {
        fn new(snap: WinInetSnapshot) -> Self {
            Self {
                snap: RefCell::new(snap),
                env: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl SystemProxyAdapter for MockSystemProxy {
        fn supported(&self) -> bool {
            true
        }
        fn read_current(&self) -> Result<WinInetSnapshot, String> {
            Ok(self.snap.borrow().clone())
        }
        fn write_snapshot(&self, snap: &WinInetSnapshot) -> Result<(), String> {
            *self.snap.borrow_mut() = snap.clone();
            Ok(())
        }
        fn read_user_env(&self, keys: &[&str]) -> Result<BTreeMap<String, Option<String>>, String> {
            let map = self.env.borrow();
            Ok(keys.iter().map(|&k| (k.to_string(), map.get(k).cloned())).collect())
        }
        fn write_user_env(&self, updates: &BTreeMap<String, Option<String>>) -> Result<(), String> {
            let mut map = self.env.borrow_mut();
            for (k, v) in updates {
                match v {
                    Some(val) => {
                        map.insert(k.clone(), val.clone());
                    }
                    None => {
                        map.remove(k);
                    }
                }
            }
            Ok(())
        }
    }

    #[test]
    fn activate_chains_existing_proxy_survives_crash_restart_and_restores_exact_settings() {
        let tmp = std::env::temp_dir().join(format!("hidego-sysproxy-{}.json", uuid::Uuid::new_v4().simple()));
        let orig = WinInetSnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:7897".to_string()),
            proxy_override: Some("localhost;192.168.*;<local>".to_string()),
        };
        let mock = MockSystemProxy::new(orig.clone());
        mock.env
            .borrow_mut()
            .insert("NO_PROXY".to_string(), "corp.internal".to_string());

        // 1. Fresh activation captures 127.0.0.1:7897 and switches WinInet + User Env to 127.0.0.1:18787
        let chained = activate_system_proxy_with(&mock, &tmp, 18787).unwrap();
        assert_eq!(chained.as_deref(), Some("http://127.0.0.1:7897/"));
        let active = mock.read_current().unwrap();
        assert_eq!(active.proxy_enable, 1);
        assert_eq!(active.proxy_server.as_deref(), Some("127.0.0.1:18787"));
        assert!(active.proxy_override.as_deref().unwrap().contains("127.*"));
        assert_eq!(
            mock.env.borrow().get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18787")
        );
        assert!(mock.env.borrow().get("NO_PROXY").unwrap().contains("corp.internal"));
        assert!(mock.env.borrow().get("NO_PROXY").unwrap().contains("127.0.0.1"));

        // 2. Simulated crash + restart on new port 18788 MUST NOT overwrite backup with 127.0.0.1:18787
        let chained2 = activate_system_proxy_with(&mock, &tmp, 18788).unwrap();
        assert_eq!(chained2.as_deref(), Some("http://127.0.0.1:7897/"));
        assert_eq!(
            mock.read_current().unwrap().proxy_server.as_deref(),
            Some("127.0.0.1:18788")
        );
        assert_eq!(
            mock.env.borrow().get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18788")
        );

        // 3. Restore returns exact pre-Hide-Go settings (WinInet + User Env)
        assert!(restore_system_proxy_with(&mock, &tmp).unwrap());
        assert_eq!(mock.read_current().unwrap(), orig);
        assert!(!mock.env.borrow().contains_key("HTTPS_PROXY"));
        assert!(!mock.env.borrow().contains_key("HTTP_PROXY"));
        assert_eq!(
            mock.env.borrow().get("NO_PROXY").map(String::as_str),
            Some("corp.internal")
        );
        assert!(!tmp.exists());
    }

    #[test]
    fn restore_does_not_clobber_manual_user_proxy_change() {
        let tmp = std::env::temp_dir().join(format!("hidego-sysproxy-{}.json", uuid::Uuid::new_v4().simple()));
        let mock = MockSystemProxy::new(WinInetSnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        });
        activate_system_proxy_with(&mock, &tmp, 18787).unwrap();
        // User manually changes system proxy to another tool while Hide-Go was active
        let user_new = WinInetSnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:9999".to_string()),
            proxy_override: Some("<local>".to_string()),
        };
        mock.write_snapshot(&user_new).unwrap();
        assert!(restore_system_proxy_with(&mock, &tmp).unwrap());
        assert_eq!(mock.read_current().unwrap(), user_new);
        assert!(!tmp.exists());
    }
}
