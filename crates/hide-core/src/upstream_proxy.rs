//! Outbound upstream proxy discovery and HTTP `CONNECT` tunnel chaining.
//!
//! Respects explicit environment proxies (`HIDE_GO_UPSTREAM_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
//! `HTTP_PROXY`) and Windows WinInet system proxy settings while:
//! - skipping Hide-Go's own listening port to prevent self-loops, and
//! - bypassing loopback and private LAN targets so local gateways stay direct.

use crate::connect::{is_loopback_host_str, is_non_public_ip};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_PROXY_RESPONSE_HEADERS: usize = 16 * 1024;

/// Parse a raw proxy setting (`127.0.0.1:7897`, `http://...`, or WinInet
/// `http=...;https=...;socks=...`) into an HTTP(S) proxy URL usable by `reqwest` and `CONNECT`.
pub fn parse_proxy_server(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if trimmed.contains('=') && !trimmed.contains("://") {
        let mut https_ep: Option<&str> = None;
        let mut http_ep: Option<&str> = None;
        for part in trimmed.split(';') {
            let Some((scheme, addr)) = part.split_once('=') else {
                continue;
            };
            let s = scheme.trim().to_ascii_lowercase();
            let a = addr.trim();
            if a.is_empty() {
                continue;
            }
            if s == "https" && https_ep.is_none() {
                https_ep = Some(a);
            } else if s == "http" && http_ep.is_none() {
                http_ep = Some(a);
            }
        }
        https_ep.or(http_ep)?.to_string()
    } else {
        trimmed.to_string()
    };

    if candidate.to_ascii_lowercase().starts_with("socks") {
        return None;
    }
    let normalized = if candidate.contains("://") {
        candidate
    } else {
        format!("http://{candidate}")
    };
    let parsed = reqwest::Url::parse(&normalized).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(parsed.to_string())
}

/// Returns `true` when `url` points back at Hide-Go's own loopback listening port.
pub fn is_self_proxy(url: &str, own_proxy_port: u16) -> bool {
    if own_proxy_port == 0 {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host_clean = host.trim_matches(['[', ']']);
    is_loopback_host_str(host_clean) && parsed.port_or_known_default() == Some(own_proxy_port)
}

/// Returns `true` for hosts that should never be routed through an external upstream proxy
/// (loopback, private/non-public IP literals, or hosts matching a `NO_PROXY`/`ProxyOverride` list).
pub fn should_bypass_proxy_for_host(target_host: &str, bypass_list: Option<&str>) -> bool {
    let clean = target_host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if clean.is_empty() || is_loopback_host_str(&clean) {
        return true;
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if is_non_public_ip(ip) {
            return true;
        }
    }
    let Some(list) = bypass_list else {
        return false;
    };
    for raw_entry in list.split([',', ';']) {
        let entry = raw_entry.trim().to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            return true;
        }
        if entry == "<local>" {
            if !clean.contains('.') {
                return true;
            }
            continue;
        }
        // Strip optional `:port` from host rules (ignoring IPv6 bracket forms without port)
        let rule_host = entry
            .strip_prefix('[')
            .and_then(|s| s.split(']').next())
            .unwrap_or_else(|| entry.split(':').next().unwrap_or(&entry))
            .trim_end_matches('.');
        if rule_host.is_empty() {
            continue;
        }
        if let Some(suffix) = rule_host.strip_prefix("*.") {
            if clean == suffix || clean.ends_with(&format!(".{suffix}")) {
                return true;
            }
        } else if let Some(suffix) = rule_host.strip_prefix('.') {
            if clean == suffix || clean.ends_with(&format!(".{suffix}")) {
                return true;
            }
        } else if clean == rule_host || clean.ends_with(&format!(".{rule_host}")) {
            return true;
        }
    }
    false
}

#[cfg(windows)]
fn read_reg_sz_value(hkey: *mut core::ffi::c_void, value_name: &str) -> Option<String> {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    type Hkey = *mut c_void;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegQueryValueExW(
            hkey: Hkey,
            lpvaluename: *const u16,
            lpreserved: *mut u32,
            lptype: *mut u32,
            lpdata: *mut u8,
            lpcbdata: *mut u32,
        ) -> u32;
    }

    let wide_name: Vec<u16> = std::ffi::OsStr::new(value_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut val_type: u32 = 0;
    let mut byte_len: u32 = 0;
    // SAFETY: first call queries required byte length for `value_name`.
    let q1 = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut byte_len,
        )
    };
    if q1 != 0 || !matches!(val_type, REG_SZ | REG_EXPAND_SZ) || byte_len == 0 || byte_len > 16 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; byte_len as usize];
    // SAFETY: `buf` is allocated with `byte_len` bytes for `RegQueryValueExW`.
    let q2 = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
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

#[cfg(windows)]
fn read_windows_system_proxy() -> Option<(String, Option<String>)> {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    type Hkey = *mut c_void;
    const HKEY_CURRENT_USER: Hkey = 0x8000_0001usize as Hkey;
    const KEY_READ: u32 = 0x0002_0019;
    const REG_DWORD: u32 = 4;

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
        fn RegCloseKey(hkey: Hkey) -> u32;
    }

    struct KeyGuard(Hkey);
    impl Drop for KeyGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was opened via `RegOpenKeyExW`.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    let to_wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };

    let subkey = to_wide(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
    let mut hkey: Hkey = std::ptr::null_mut();
    // SAFETY: queries current-user WinInet proxy configuration from the Windows Registry.
    let open_status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
    if open_status != 0 || hkey.is_null() {
        return None;
    }
    let _guard = KeyGuard(hkey);

    let enable_name = to_wide("ProxyEnable");
    let mut val_type: u32 = 0;
    let mut dword_buf = [0u8; 4];
    let mut dword_len: u32 = 4;
    // SAFETY: reads `ProxyEnable` DWORD into stack-allocated 4-byte buffer.
    let en_status = unsafe {
        RegQueryValueExW(
            hkey,
            enable_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            dword_buf.as_mut_ptr(),
            &mut dword_len,
        )
    };
    if en_status != 0 || val_type != REG_DWORD || dword_len != 4 || u32::from_le_bytes(dword_buf) == 0 {
        return None;
    }

    let raw_server = read_reg_sz_value(hkey, "ProxyServer")?;
    let proxy_url = parse_proxy_server(&raw_server)?;
    let bypass = read_reg_sz_value(hkey, "ProxyOverride");
    Some((proxy_url, bypass))
}

/// Detect the active upstream HTTP(S) proxy for `target_host`, consulting explicit env vars
/// first and Windows system proxy settings second, while guarding against self-loops and
/// bypassing local/private/NO_PROXY targets.
pub fn detect_upstream_proxy_for_host(own_proxy_port: u16, target_host: Option<&str>) -> Option<String> {
    if let Some(host) = target_host {
        if should_bypass_proxy_for_host(host, None) {
            return None;
        }
    }

    let env_no_proxy = std::env::var("NO_PROXY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("no_proxy").ok().filter(|s| !s.trim().is_empty()));

    for key in [
        "HIDE_GO_UPSTREAM_PROXY",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        if let Some(raw) = std::env::var(key).ok().filter(|s| !s.trim().is_empty()) {
            if let Some(url) = parse_proxy_server(&raw) {
                if is_self_proxy(&url, own_proxy_port) {
                    continue;
                }
                if key != "HIDE_GO_UPSTREAM_PROXY" {
                    if let Some(host) = target_host {
                        if should_bypass_proxy_for_host(host, env_no_proxy.as_deref()) {
                            return None;
                        }
                    }
                }
                return Some(url);
            }
        }
    }

    #[cfg(windows)]
    if let Some((url, bypass)) = read_windows_system_proxy() {
        if !is_self_proxy(&url, own_proxy_port) {
            if let Some(host) = target_host {
                if should_bypass_proxy_for_host(host, bypass.as_deref())
                    || should_bypass_proxy_for_host(host, env_no_proxy.as_deref())
                {
                    return None;
                }
            }
            return Some(url);
        }
        // WinInet currently points at Hide-Go itself via reversible system-proxy chaining:
        // forward out through the snapshotted pre-Hide-Go upstream proxy (if any).
        if let Some((chained_url, chained_bypass)) = crate::system_proxy::read_chained_upstream_proxy(own_proxy_port) {
            if let Some(host) = target_host {
                if should_bypass_proxy_for_host(host, chained_bypass.as_deref())
                    || should_bypass_proxy_for_host(host, env_no_proxy.as_deref())
                {
                    return None;
                }
            }
            return Some(chained_url);
        }
    }

    None
}

/// Open a raw TCP tunnel to `target_host:target_port` via an upstream HTTP `CONNECT` proxy.
pub async fn connect_via_http_proxy(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let parsed = reqwest::Url::parse(proxy_url).map_err(|e| format!("invalid upstream proxy URL: {e}"))?;
    if parsed.scheme() != "http" {
        return Err(format!(
            "unsupported upstream CONNECT proxy scheme: {}",
            parsed.scheme()
        ));
    }
    let proxy_host = parsed
        .host_str()
        .ok_or_else(|| "upstream proxy URL missing host".to_string())?
        .trim_matches(['[', ']'])
        .to_string();
    let proxy_port = parsed.port_or_known_default().unwrap_or(80);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect((proxy_host.as_str(), proxy_port)))
        .await
        .map_err(|_| format!("timed out connecting to upstream proxy {proxy_host}:{proxy_port}"))?
        .map_err(|e| format!("failed to connect to upstream proxy {proxy_host}:{proxy_port}: {e}"))?;

    let authority = if target_host.contains(':') {
        format!("[{target_host}]:{target_port}")
    } else {
        format!("{target_host}:{target_port}")
    };
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n");
    if !parsed.username().is_empty() || parsed.password().is_some() {
        let creds = format!("{}:{}", parsed.username(), parsed.password().unwrap_or_default());
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            BASE64.encode(creds.as_bytes())
        ));
    }
    req.push_str("\r\n");

    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "timed out writing CONNECT request to upstream proxy".to_string())?
        .map_err(|e| format!("failed writing CONNECT request to upstream proxy: {e}"))?;

    // Read response header byte-by-byte so no tunneled payload bytes past `\r\n\r\n` are consumed.
    let mut header_buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    tokio::time::timeout(timeout, async {
        loop {
            let n = stream
                .read(&mut byte)
                .await
                .map_err(|e| format!("failed reading upstream proxy CONNECT response: {e}"))?;
            if n == 0 {
                return Err("upstream proxy closed connection during CONNECT".to_string());
            }
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                return Ok(());
            }
            if header_buf.len() >= MAX_PROXY_RESPONSE_HEADERS {
                return Err("upstream proxy CONNECT response headers exceeded limit".to_string());
            }
        }
    })
    .await
    .map_err(|_| "timed out reading upstream proxy CONNECT response".to_string())??;

    let header_str = String::from_utf8_lossy(&header_buf);
    let status_line = header_str.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status_code != 200 {
        return Err(format!("upstream proxy rejected CONNECT to {authority}: {status_line}"));
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn proxy_parser_self_loop_and_bypass_behave_safely() {
        assert_eq!(
            parse_proxy_server("127.0.0.1:7897").as_deref(),
            Some("http://127.0.0.1:7897/")
        );
        assert_eq!(
            parse_proxy_server("http=127.0.0.1:7890;https=127.0.0.1:7891;socks=127.0.0.1:7892").as_deref(),
            Some("http://127.0.0.1:7891/")
        );
        assert_eq!(
            parse_proxy_server("http=127.0.0.1:7890").as_deref(),
            Some("http://127.0.0.1:7890/")
        );
        assert!(parse_proxy_server("socks5://127.0.0.1:7897").is_none());
        assert!(parse_proxy_server("   ").is_none());

        assert!(is_self_proxy("http://127.0.0.1:18787/", 18787));
        assert!(is_self_proxy("http://localhost:18787/", 18787));
        assert!(!is_self_proxy("http://127.0.0.1:7897/", 18787));
        assert!(!is_self_proxy("http://proxy.corp.local:8080/", 18787));

        assert!(should_bypass_proxy_for_host("127.0.0.1", None));
        assert!(should_bypass_proxy_for_host("localhost", None));
        assert!(should_bypass_proxy_for_host("192.168.1.10", None));
        assert!(!should_bypass_proxy_for_host("api.openai.com", None));
        assert!(should_bypass_proxy_for_host(
            "api.openai.com",
            Some("localhost,*.openai.com")
        ));
        assert!(should_bypass_proxy_for_host("intranet", Some("<local>")));
        assert!(!should_bypass_proxy_for_host("api.anthropic.com", Some("<local>")));
    }

    #[tokio::test]
    async fn connect_via_http_proxy_tunnels_payload_cleanly() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = proxy_listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            while !req.ends_with(b"\r\n\r\n") {
                sock.read_exact(&mut b).await.unwrap();
                req.push(b[0]);
            }
            let text = String::from_utf8_lossy(&req);
            assert!(text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"), "{text}");
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();

            let mut echo = [0u8; 4];
            sock.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"PING");
            sock.write_all(b"PONG").await.unwrap();
        });

        let mut tunnel = connect_via_http_proxy(
            &format!("http://{proxy_addr}"),
            "example.com",
            443,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        tunnel.write_all(b"PING").await.unwrap();
        let mut resp = [0u8; 4];
        tunnel.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"PONG");
        server.await.unwrap();
    }
}
