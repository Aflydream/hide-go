//! Single-port HTTP/HTTPS forward proxy (`HTTP CONNECT` + selective AI-host TLS MITM).
//!
//! - Plain origin-form HTTP requests (`/api/*`, `/v1/*`, `/qoder/*`, desktop UI) go
//!   directly to the existing Axum `Router`.
//! - Absolute-form HTTP proxy requests (`HTTP_PROXY`) are inspected for AI hosts or
//!   forwarded transparently for non-AI hosts.
//! - `CONNECT host:port` tunnels selectively terminate TLS with an on-demand leaf cert
//!   signed by `CaManager` **only** for known/configured AI API hosts; every other
//!   host is bridged at raw TCP level via `tokio::io::copy_bidirectional` with zero
//!   decryption or key visibility.

use crate::ca::validate_leaf_host;
use crate::config::HideConfig;
use crate::protobuf::detect_protobuf_framing;
use crate::proxy::{
    build_router, handle_forward_http_request, handle_mitm_http_request, handle_mitm_streaming_rpc_request,
    GatewayState, MAX_REQUEST_BODY,
};
use crate::upstream_proxy::{connect_via_http_proxy, detect_upstream_proxy_for_host};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tower_service::Service;

const CONNECT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(20);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MITM_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MITM_MAX_BUF_SIZE: usize = 64 * 1024;

const EXACT_AI_MITM_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "autopush-cloudcode-pa.googleapis.com",
    "staging-cloudcode-pa.googleapis.com",
    "cloudaicompanion.googleapis.com",
    "daily-cloudcode-pa.sandbox.googleapis.com",
    "autopush-cloudcode-pa.sandbox.googleapis.com",
    "antigravity-pa.googleapis.com",
    "jetski-webchannel.googleapis.com",
    "aiplatform.googleapis.com",
    "api2.cursor.sh",
    "api3.cursor.sh",
    "repo42.cursor.sh",
    "api1.qoder.sh",
    "repo1.qoder.sh",
    "gateway.qoder.com.cn",
    "repo.qoder.com.cn",
    "openapi.qoder.com.cn",
    "qts.qoder.com.cn",
    "dashscope.aliyuncs.com",
    "dashscope-intl.aliyuncs.com",
    "open.bigmodel.cn",
    "api.z.ai",
    "api.x.ai",
    "cli-chat-proxy.grok.com",
    "api.deepseek.com",
    "openrouter.ai",
    "api.groq.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.perplexity.ai",
    "api.zcode.ai",
];

/// Auth/login/OAuth/general hosts that must NEVER be implicitly matched by wildcards.
const NEVER_MITM_EXACT_HOSTS: &[&str] = &[
    "oauth2.googleapis.com",
    "accounts.google.com",
    "www.googleapis.com",
    "storage.googleapis.com",
    "auth.qoder.sh",
    "login.qoder.sh",
    "auth.qoder.com",
    "login.qoder.com",
    "auth.qoder.com.cn",
    "login.qoder.com.cn",
    "auth.cursor.sh",
    "login.cursor.sh",
    "chatgpt.com",
];

fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed.trim_end_matches('.').to_ascii_lowercase()
}

fn match_host_pattern(host: &str, pattern: &str) -> bool {
    let pat = normalize_host(pattern);
    if pat.is_empty() {
        return false;
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        !suffix.is_empty()
            && host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        host == pat
    }
}

fn is_builtin_ai_wildcard(host: &str) -> bool {
    // `*-aiplatform.googleapis.com` (single region label before `-aiplatform`)
    if let Some(region) = host.strip_suffix("-aiplatform.googleapis.com") {
        if !region.is_empty() && !region.contains('.') {
            return true;
        }
    }
    // `*-cloudcode-pa.googleapis.com`, `*-cloudcode-pa.sandbox.googleapis.com`,
    // `*-antigravity-pa.googleapis.com`, `*-antigravity-pa.sandbox.googleapis.com`
    for suffix in [
        "-generativelanguage.googleapis.com",
        "-cloudaicompanion.googleapis.com",
        "-cloudcode-pa.googleapis.com",
        "-cloudcode-pa.sandbox.googleapis.com",
        "-antigravity-pa.googleapis.com",
        "-antigravity-pa.sandbox.googleapis.com",
    ] {
        if let Some(prefix) = host.strip_suffix(suffix) {
            if !prefix.is_empty() && !prefix.contains('.') {
                return true;
            }
        }
    }
    if match_host_pattern(host, "*.cloudcode-pa.googleapis.com") {
        return true;
    }
    // `*.cursorapi.com` / `*.cursor.sh` (auth/login guarded out by NEVER_MITM_EXACT_HOSTS)
    if match_host_pattern(host, "*.cursorapi.com") || match_host_pattern(host, "*.cursor.sh") {
        return true;
    }
    // `*.qoder.sh` / `*.qoder.com` / `*.qoder.com.cn` (auth/login guarded out by NEVER_MITM_EXACT_HOSTS)
    if match_host_pattern(host, "*.qoder.sh")
        || match_host_pattern(host, "*.qoder.com")
        || match_host_pattern(host, "*.qoder.com.cn")
    {
        return true;
    }
    // `*.openai.azure.com`
    if match_host_pattern(host, "*.openai.azure.com") {
        return true;
    }
    // `bedrock-runtime.<region>.amazonaws.com`
    if let Some(rest) = host.strip_prefix("bedrock-runtime.") {
        if let Some(region) = rest.strip_suffix(".amazonaws.com") {
            if !region.is_empty() && !region.contains('.') {
                return true;
            }
        }
    }
    false
}

/// Returns `true` if `host` matches Hide-Go's built-in AI API MITM host list.
pub fn is_builtin_ai_mitm_host(host: &str) -> bool {
    let norm = normalize_host(host);
    if norm.is_empty() || norm.contains('*') || NEVER_MITM_EXACT_HOSTS.contains(&norm.as_str()) {
        return false;
    }
    EXACT_AI_MITM_HOSTS.contains(&norm.as_str()) || is_builtin_ai_wildcard(&norm)
}

/// Decide whether a destination hostname should undergo selective TLS MITM.
/// Non-AI hosts (GitHub, npm, OAuth, banking, etc.) return `false` and get raw TCP passthrough.
pub fn should_mitm_host(host: &str, cfg: &HideConfig) -> bool {
    let norm = normalize_host(host);
    if norm.is_empty() || norm.contains('*') {
        return false;
    }
    if cfg.mitm_bypass_hosts.iter().any(|p| match_host_pattern(&norm, p)) {
        return false;
    }
    if cfg.mitm_extra_hosts.iter().any(|p| match_host_pattern(&norm, p)) {
        return true;
    }
    if NEVER_MITM_EXACT_HOSTS.contains(&norm.as_str()) {
        return false;
    }
    EXACT_AI_MITM_HOSTS.contains(&norm.as_str()) || is_builtin_ai_wildcard(&norm)
}

fn connect_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message.into(),
            }
        })),
    )
        .into_response()
}

fn split_authority_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let raw = authority.trim();
    if raw.is_empty() || raw.chars().any(char::is_whitespace) || raw.contains(['/', '@', '?', '#']) {
        return None;
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = rest[..close].trim();
        if host.is_empty() {
            return None;
        }
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            default_port
        } else {
            let port_str = after.strip_prefix(':')?;
            let parsed: u16 = port_str.parse().ok()?;
            if parsed == 0 {
                return None;
            }
            parsed
        };
        return Some((host.to_ascii_lowercase(), port));
    }

    if let Some((host_part, port_part)) = raw.rsplit_once(':') {
        if host_part.contains(':') {
            // Unbracketed multi-colon string (e.g. bare IPv6 without port) is ambiguous with port
            return None;
        }
        let host = host_part.trim().trim_end_matches('.');
        if host.is_empty() {
            return None;
        }
        let parsed: u16 = port_part.parse().ok()?;
        if parsed == 0 {
            return None;
        }
        Some((host.to_ascii_lowercase(), parsed))
    } else {
        let host = raw.trim_end_matches('.');
        if host.is_empty() {
            return None;
        }
        Some((host.to_ascii_lowercase(), default_port))
    }
}

fn parse_connect_authority(uri: &Uri, headers: &HeaderMap) -> Option<(String, u16)> {
    if let Some(auth) = uri.authority() {
        return split_authority_host_port(auth.as_str(), 443);
    }
    let raw_uri = uri.to_string();
    if !raw_uri.is_empty() && raw_uri != "/" && !raw_uri.starts_with('/') {
        if let Some(parsed) = split_authority_host_port(&raw_uri, 443) {
            return Some(parsed);
        }
    }
    headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| split_authority_host_port(h, 443))
}

pub(crate) fn is_non_public_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _d] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (b & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
                || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 IETF protocol assignments
                || (a == 198 && (b & 0b1111_1110) == 18) // 198.18.0.0/15 benchmarking
                || a >= 240 // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique Local
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-local
                || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 documentation
                || (seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0) // ::/96 IPv4-compatible
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0) // 64:ff9b::/96 NAT64
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001) // 64:ff9b:1::/48 local NAT64
        }
    }
}

pub(crate) fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.is_loopback(), |v4| v4.is_loopback()),
        IpAddr::V4(v4) => v4.is_loopback(),
    }
}

pub(crate) fn is_loopback_host_str(host: &str) -> bool {
    let norm = normalize_host(host);
    if matches!(
        norm.as_str(),
        "localhost" | "localhost.localdomain" | "ip6-localhost" | "ip6-loopback"
    ) || norm.ends_with(".localhost")
    {
        return true;
    }
    norm.parse::<IpAddr>().is_ok_and(is_loopback_ip)
}

/// True only when `(host, port)` explicitly matches an entry in `cfg.allowed_loopback_proxy_targets`,
/// both host strings are loopback, and `port` is non-zero and never `cfg.proxy_port`.
pub(crate) fn is_allowed_loopback_proxy_target(host: &str, port: u16, cfg: &HideConfig) -> bool {
    if port == 0 || (cfg.proxy_port != 0 && port == cfg.proxy_port) {
        return false;
    }
    let norm = normalize_host(host);
    if !is_loopback_host_str(&norm) {
        return false;
    }
    cfg.allowed_loopback_proxy_targets.iter().any(|entry| {
        let Some((entry_host, entry_port)) = split_authority_host_port(entry, 0) else {
            return false;
        };
        if entry_port == 0 || entry_port != port {
            return false;
        }
        let norm_entry = normalize_host(&entry_host);
        norm_entry == norm && is_loopback_host_str(&norm_entry)
    })
}

pub(crate) fn is_cloud_metadata_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (a == 100 && b == 100 && c == 100 && d == 200) // Alibaba Cloud metadata
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (seg[0] == 0xfd00 && seg[1] == 0x0ec2 && seg[7] == 0x0254) // AWS IMDSv2 IPv6
        }
    }
}

pub(crate) fn is_cloud_metadata_hostname(host: &str) -> bool {
    let norm = normalize_host(host);
    if norm.is_empty()
        || norm.chars().any(|c| c.is_control() || c.is_whitespace())
        || norm.contains(['/', '@', '?', '#', '\\', '*'])
    {
        return true;
    }
    matches!(
        norm.as_str(),
        "metadata.google.internal"
            | "metadata.goog"
            | "metadata"
            | "instance-data"
            | "169.254.169.254"
            | "100.100.100.200"
            | "fd00:ec2::254"
    )
}

/// Guard for explicitly operator-configured upstreams (`HideConfig.harness_upstreams` / `HIDE_GO_UPSTREAM_URL`).
/// Allows loopback and private LAN gateways (e.g. corporate LiteLLM, Ollama, vLLM) while still
/// strictly blocking cloud metadata endpoints and self-loop connections back into Hide-Go.
pub(crate) fn is_forbidden_operator_upstream(host: &str, port: u16, listen_port: u16) -> bool {
    if port == 0 {
        return true;
    }
    let norm = normalize_host(host);
    if norm.is_empty() || is_cloud_metadata_hostname(&norm) {
        return true;
    }
    if listen_port != 0 && port == listen_port && is_loopback_host_str(&norm) {
        return true;
    }
    if let Ok(ip) = norm.parse::<IpAddr>() {
        return is_cloud_metadata_ip(ip);
    }
    false
}

pub(crate) fn is_forbidden_hostname(host: &str) -> bool {
    let norm = normalize_host(host);
    if norm.is_empty()
        || norm.chars().any(|c| c.is_control() || c.is_whitespace())
        || norm.contains(['/', '@', '?', '#', '\\', '*'])
    {
        return true;
    }
    matches!(
        norm.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "ip6-localhost"
            | "ip6-loopback"
            | "metadata.google.internal"
            | "metadata.goog"
            | "metadata"
            | "instance-data"
            | "169.254.169.254"
            | "100.100.100.200"
            | "fd00:ec2::254"
    ) || norm.ends_with(".localhost")
        || norm.ends_with(".localdomain")
        || norm.ends_with(".internal")
}

pub(crate) fn is_allowed_resolved_ip(ip: IpAddr, port: u16, listen_port: u16, allow_loopback: bool) -> bool {
    if is_loopback_ip(ip) {
        return allow_loopback && port != 0 && (listen_port == 0 || port != listen_port);
    }
    !is_non_public_ip(ip)
}

fn is_proxy_target_allowed(
    host: &str,
    port: u16,
    cfg: &HideConfig,
    allow_loopback_for_tests: bool,
    base_ports: &[u16],
) -> bool {
    let explicit_loopback = is_allowed_loopback_proxy_target(host, port, cfg);
    let allow_loopback = allow_loopback_for_tests || explicit_loopback;
    let port_allowed = (port != 0 && (base_ports.contains(&port) || cfg.allowed_connect_ports.contains(&port)))
        || explicit_loopback
        || (allow_loopback_for_tests && port != 0 && port != cfg.proxy_port);
    port_allowed && !is_forbidden_target_host_port(host, port, cfg.proxy_port, allow_loopback)
}

pub(crate) fn is_forbidden_target_host_port(host: &str, port: u16, listen_port: u16, allow_loopback: bool) -> bool {
    if port == 0 {
        return true;
    }
    let norm = normalize_host(host);
    if norm.is_empty() {
        return true;
    }
    if listen_port != 0 && port == listen_port && is_loopback_host_str(&norm) {
        return true;
    }
    if let Ok(ip) = norm.parse::<IpAddr>() {
        return !is_allowed_resolved_ip(ip, port, listen_port, allow_loopback);
    }
    if is_forbidden_hostname(&norm) {
        if allow_loopback && is_loopback_host_str(&norm) && (listen_port == 0 || port != listen_port) {
            return false;
        }
        return true;
    }
    false
}

#[cfg(test)]
fn is_forbidden_connect_target(host: &str, port: u16, listen_port: u16) -> bool {
    is_forbidden_target_host_port(host, port, listen_port, false)
}

fn is_browser_cross_site_proxy_trigger(headers: &HeaderMap) -> bool {
    if headers.contains_key(header::ORIGIN) {
        return true;
    }
    if let Some(site) = headers.get("sec-fetch-site") {
        if !matches!(site.to_str(), Ok("none" | "same-origin")) {
            return true;
        }
    }
    false
}

async fn read_limited_body<B>(body: B) -> Result<Bytes, Box<Response>>
where
    B: hyper::body::Body + Send,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    match Limited::new(body, MAX_REQUEST_BODY).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                Err(Box::new(connect_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    "request body exceeds gateway limit",
                )))
            } else {
                Err(Box::new(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    format!("failed to read request body: {err}"),
                )))
            }
        }
    }
}

async fn dial_upstream_tcp(
    host: &str,
    port: u16,
    cfg: &HideConfig,
    allow_loopback_for_tests: bool,
    err_prefix: &str,
) -> Result<TcpStream, Box<Response>> {
    let explicit_loopback = is_allowed_loopback_proxy_target(host, port, cfg);
    let allow_loopback = allow_loopback_for_tests || explicit_loopback;

    if !allow_loopback_for_tests && !explicit_loopback && !is_loopback_host_str(host) {
        if let Some(proxy_url) = detect_upstream_proxy_for_host(cfg.proxy_port, Some(host)) {
            match connect_via_http_proxy(&proxy_url, host, port, CONNECT_UPSTREAM_TIMEOUT).await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    tracing::debug!(
                        "upstream HTTP proxy CONNECT failed for {host}:{port} via {proxy_url} ({err}); falling back to direct"
                    );
                }
            }
        }
    }

    let resolved = match tokio::time::timeout(CONNECT_UPSTREAM_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => addrs.collect::<Vec<SocketAddr>>(),
        Ok(Err(err)) => {
            return Err(Box::new(connect_error(
                StatusCode::BAD_GATEWAY,
                &format!("{err_prefix}_dns_failed"),
                format!("failed to resolve {host}:{port}: {err}"),
            )));
        }
        Err(_) => {
            return Err(Box::new(connect_error(
                StatusCode::GATEWAY_TIMEOUT,
                &format!("{err_prefix}_dns_timeout"),
                format!("timed out resolving {host}:{port}"),
            )));
        }
    };

    let filtered: Vec<SocketAddr> = if err_prefix == "websocket" {
        resolved
            .into_iter()
            .filter(|sa| is_allowed_resolved_ip(sa.ip(), port, cfg.proxy_port, allow_loopback))
            .collect()
    } else {
        if resolved.is_empty()
            || resolved.iter().any(|addr| {
                if explicit_loopback && !allow_loopback_for_tests {
                    !is_loopback_ip(addr.ip()) || port == 0 || (cfg.proxy_port != 0 && port == cfg.proxy_port)
                } else {
                    !is_allowed_resolved_ip(addr.ip(), port, cfg.proxy_port, allow_loopback)
                }
            })
        {
            return Err(Box::new(connect_error(
                StatusCode::FORBIDDEN,
                "forbidden_connect_target",
                "CONNECT target resolved to a non-public IP blocked by gateway policy",
            )));
        }
        resolved
    };

    if filtered.is_empty() {
        return Err(Box::new(connect_error(
            StatusCode::FORBIDDEN,
            "forbidden_target",
            "target resolved solely to non-public addresses",
        )));
    }

    match tokio::time::timeout(CONNECT_UPSTREAM_TIMEOUT, TcpStream::connect(filtered.as_slice())).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(Box::new(connect_error(
            StatusCode::BAD_GATEWAY,
            &format!("{err_prefix}_upstream_failed"),
            format!("failed to connect to {host}:{port}: {err}"),
        ))),
        Err(_) => Err(Box::new(connect_error(
            StatusCode::GATEWAY_TIMEOUT,
            &format!("{err_prefix}_upstream_timeout"),
            format!("timed out connecting to {host}:{port}"),
        ))),
    }
}

async fn handle_connect_tunnel(state: GatewayState, req: Request<Body>) -> Response {
    if is_browser_cross_site_proxy_trigger(req.headers()) {
        return connect_error(
            StatusCode::FORBIDDEN,
            "forbidden_proxy_origin",
            "cross-origin CONNECT requests are forbidden",
        );
    }
    let Some((host, port)) = parse_connect_authority(req.uri(), req.headers()) else {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_connect_authority",
            "CONNECT target must be a valid host:port authority",
        );
    };
    let cfg = state.get_config();
    if !is_proxy_target_allowed(&host, port, &cfg, state.allow_loopback_for_tests, &[443]) {
        return connect_error(
            StatusCode::FORBIDDEN,
            "forbidden_connect_target",
            "CONNECT target is blocked by gateway security policy",
        );
    }

    let Ok(permit) = state.connect_semaphore.clone().try_acquire_owned() else {
        return connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "too_many_tunnels",
            "gateway concurrent tunnel capacity reached",
        );
    };

    if !should_mitm_host(&host, &cfg) {
        state.record_connect_host(&host, port, false, false);
        let mut upstream = match dial_upstream_tcp(&host, port, &cfg, state.allow_loopback_for_tests, "connect").await {
            Ok(stream) => stream,
            Err(err_resp) => return *err_resp,
        };

        let on_upgrade = hyper::upgrade::on(req);
        let audit_state = state.clone();
        let audit_host = host.clone();
        let started_at = std::time::Instant::now();
        tokio::spawn(async move {
            let _permit = permit;
            match on_upgrade.await {
                Ok(upgraded) => {
                    let mut client_io = TokioIo::new(upgraded);
                    match tokio::io::copy_bidirectional(&mut client_io, &mut upstream).await {
                        Ok((to_upstream, to_client)) => {
                            let signals = crate::audit::inspect_connect_tunnel_audit(&audit_host, to_upstream);
                            if !signals.is_empty() {
                                audit_state.record_passthrough_tunnel_audit(
                                    &audit_host,
                                    port,
                                    to_upstream,
                                    to_client,
                                    started_at.elapsed().as_millis() as u64,
                                    signals,
                                );
                            }
                        }
                        Err(err) => {
                            tracing::debug!("TCP passthrough closed for {audit_host}:{port}: {err}");
                            if crate::audit::classify_host_risk(&audit_host) == crate::audit::HostRiskKind::Telemetry {
                                let signals = crate::audit::inspect_connect_tunnel_audit(&audit_host, 0);
                                if !signals.is_empty() {
                                    audit_state.record_passthrough_tunnel_audit(
                                        &audit_host,
                                        port,
                                        0,
                                        0,
                                        started_at.elapsed().as_millis() as u64,
                                        signals,
                                    );
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::debug!("CONNECT upgrade failed for {audit_host}:{port}: {err}");
                }
            }
        });
        return Response::new(Body::empty());
    }

    state.record_connect_host(&host, port, true, false);
    if let Err(err) = validate_leaf_host(&host) {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_connect_host",
            format!("invalid MITM target host: {err}"),
        );
    }

    let server_config = match state.ca.server_config_for_host_async(&host).await {
        Ok(cfg) => cfg,
        Err(err) => {
            return connect_error(
                StatusCode::BAD_GATEWAY,
                "mitm_cert_failed",
                format!("failed to mint TLS certificate for {host}: {err}"),
            );
        }
    };

    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let _permit = permit;
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(err) => {
                tracing::debug!("MITM CONNECT upgrade failed for {host}:{port}: {err}");
                return;
            }
        };
        let tls_acceptor = TlsAcceptor::from(server_config);
        let tls_stream =
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls_acceptor.accept(TokioIo::new(upgraded))).await {
                Ok(Ok(s)) => s,
                Ok(Err(err)) => {
                    tracing::debug!("TLS handshake failed inside MITM tunnel for {host}:{port}: {err}");
                    state.record_mitm_tls_failure(&host, port, &err.to_string());
                    return;
                }
                Err(_) => {
                    tracing::debug!("TLS handshake timed out inside MITM tunnel for {host}:{port}");
                    state.record_mitm_tls_failure(&host, port, "TLS handshake timed out");
                    return;
                }
            };

        let host_clone = host.clone();
        let state_clone = state.clone();
        let service = service_fn(move |inner_req: hyper::Request<hyper::body::Incoming>| {
            let state = state_clone.clone();
            let host = host_clone.clone();
            async move {
                if is_websocket_upgrade_request(inner_req.method(), inner_req.headers()) {
                    return Ok::<_, Infallible>(handle_mitm_websocket_upgrade(state, host, port, inner_req).await);
                }
                let (parts, incoming) = inner_req.into_parts();
                let req_ct = parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
                if let Some(framing) = detect_protobuf_framing(req_ct).filter(|f| f.is_enveloped()) {
                    let resp = handle_mitm_streaming_rpc_request(
                        state,
                        "https",
                        &host,
                        port,
                        framing,
                        parts.method,
                        parts.uri,
                        parts.headers,
                        incoming,
                    )
                    .await;
                    return Ok::<_, Infallible>(resp);
                }
                let body_bytes = match read_limited_body(incoming).await {
                    Ok(bytes) => bytes,
                    Err(err_resp) => return Ok::<_, Infallible>(*err_resp),
                };
                let resp = handle_mitm_http_request(
                    state,
                    "https",
                    &host,
                    port,
                    parts.method,
                    parts.uri,
                    parts.headers,
                    body_bytes,
                )
                .await;
                Ok::<_, Infallible>(resp)
            }
        });

        let mut builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .preserve_header_case(true)
            .header_read_timeout(MITM_HEADER_READ_TIMEOUT)
            .max_buf_size(MITM_MAX_BUF_SIZE);
        builder.http2().timer(hyper_util::rt::TokioTimer::new());
        if let Err(err) = builder
            .serve_connection_with_upgrades(TokioIo::new(tls_stream), service)
            .await
        {
            tracing::debug!("MITM HTTP tunnel closed for {host}:{port}: {err}");
        }
    });

    Response::new(Body::empty())
}

fn is_websocket_upgrade_request(method: &Method, headers: &HeaderMap) -> bool {
    *method == Method::GET
        && headers
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

fn build_upstream_tls_client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> = once_cell::sync::Lazy::new(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("valid TLS protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    });
    CONFIG.clone()
}

/// Transparently bridge WebSocket (`Upgrade: websocket`) connections inside a MITM tunnel
/// directly to the upstream TLS server so Realtime / IDE WebSockets never break.
async fn handle_mitm_websocket_upgrade(
    state: GatewayState,
    host: String,
    port: u16,
    req: hyper::Request<hyper::body::Incoming>,
) -> Response {
    let cfg = state.get_config();
    let explicit_loopback = is_allowed_loopback_proxy_target(&host, port, &cfg);
    let allow_loopback = state.allow_loopback_for_tests || explicit_loopback;
    if is_forbidden_target_host_port(&host, port, cfg.proxy_port, allow_loopback) {
        return connect_error(
            StatusCode::FORBIDDEN,
            "forbidden_target",
            "WebSocket target is blocked by gateway security policy",
        );
    }

    let tcp = match dial_upstream_tcp(&host, port, &cfg, state.allow_loopback_for_tests, "websocket").await {
        Ok(s) => s,
        Err(err_resp) => return *err_resp,
    };

    let Ok(server_name) = rustls::pki_types::ServerName::try_from(host.clone()) else {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_host", "invalid TLS server name");
    };
    let connector = tokio_rustls::TlsConnector::from(build_upstream_tls_client_config());
    let mut upstream_tls = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp)).await
    {
        Ok(Ok(s)) => s,
        _ => {
            return connect_error(
                StatusCode::BAD_GATEWAY,
                "websocket_tls_failed",
                format!("TLS handshake failed with WebSocket upstream {host}:{port}"),
            );
        }
    };

    let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let mut raw_req = format!("GET {path_and_query} HTTP/1.1\r\nHost: {host_header}\r\n");
    for (name, value) in req.headers() {
        let lower = name.as_str();
        if matches!(
            lower,
            "host" | "x-hide-go-token" | "x-hide-go-upstream" | "x-upstream-url" | "x-target-upstream"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            if !v.contains(['\r', '\n']) {
                raw_req.push_str(name.as_str());
                raw_req.push_str(": ");
                raw_req.push_str(v);
                raw_req.push_str("\r\n");
            }
        }
    }
    raw_req.push_str("\r\n");

    if upstream_tls.write_all(raw_req.as_bytes()).await.is_err() {
        return connect_error(
            StatusCode::BAD_GATEWAY,
            "websocket_handshake_failed",
            "failed to send WebSocket upgrade request to upstream",
        );
    }

    let mut reader = BufReader::new(upstream_tls);
    let mut status_line = String::new();
    let Ok(Ok(n)) = tokio::time::timeout(MITM_HEADER_READ_TIMEOUT, reader.read_line(&mut status_line)).await else {
        return connect_error(
            StatusCode::BAD_GATEWAY,
            "websocket_handshake_timeout",
            "timed out waiting for upstream WebSocket upgrade response",
        );
    };
    if n == 0 {
        return connect_error(
            StatusCode::BAD_GATEWAY,
            "websocket_handshake_eof",
            "upstream closed connection during WebSocket upgrade",
        );
    }
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);

    let mut resp_builder = Response::builder().status(status_code);
    for _ in 0..128 {
        let mut line = String::new();
        let Ok(Ok(len)) = tokio::time::timeout(MITM_HEADER_READ_TIMEOUT, reader.read_line(&mut line)).await else {
            return connect_error(
                StatusCode::BAD_GATEWAY,
                "websocket_handshake_timeout",
                "timed out reading upstream WebSocket headers",
            );
        };
        if len == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k_trim = k.trim();
            let v_trim = v.trim();
            if !k_trim.is_empty() && !k_trim.eq_ignore_ascii_case("set-cookie") {
                resp_builder = resp_builder.header(k_trim, v_trim);
            }
        }
    }

    if status_code != StatusCode::SWITCHING_PROTOCOLS {
        return resp_builder.body(Body::empty()).unwrap_or_else(|_| {
            connect_error(
                StatusCode::BAD_GATEWAY,
                "websocket_rejected",
                "upstream rejected upgrade",
            )
        });
    }

    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            let mut client_io = TokioIo::new(upgraded);
            // Forward any buffered WebSocket frames already read by BufReader before bidirectional copy.
            let buffered = reader.buffer().to_vec();
            let mut upstream_io = reader.into_inner();
            if !buffered.is_empty() && client_io.write_all(&buffered).await.is_err() {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
        }
    });

    resp_builder
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::SWITCHING_PROTOCOLS.into_response())
}

async fn handle_absolute_proxy_request(state: GatewayState, req: Request<Body>) -> Response {
    if is_browser_cross_site_proxy_trigger(req.headers()) {
        return connect_error(
            StatusCode::FORBIDDEN,
            "forbidden_proxy_origin",
            "cross-origin proxy requests are forbidden",
        );
    }
    let scheme = req.uri().scheme_str().unwrap_or("http").to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "unsupported_proxy_scheme",
            "unsupported proxy URI scheme",
        );
    }
    let default_port = if scheme == "https" { 443 } else { 80 };
    let Some((host, port)) = req
        .uri()
        .authority()
        .and_then(|auth| split_authority_host_port(auth.as_str(), default_port))
    else {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_authority",
            "absolute proxy URI must include a valid host",
        );
    };

    let cfg = state.get_config();
    if !is_proxy_target_allowed(&host, port, &cfg, state.allow_loopback_for_tests, &[80, 443]) {
        return connect_error(
            StatusCode::FORBIDDEN,
            "forbidden_proxy_target",
            "proxy target is blocked by gateway security policy",
        );
    }

    let mitm_inspect = should_mitm_host(&host, &cfg);
    let (parts, body) = req.into_parts();
    let body_bytes = match read_limited_body(body).await {
        Ok(bytes) => bytes,
        Err(err_resp) => return *err_resp,
    };
    handle_forward_http_request(state, parts.method, parts.uri, parts.headers, body_bytes, mitm_inspect).await
}

/// Per-connection Tower service dispatching `CONNECT`, absolute-form proxy URLs, and normal Axum routes.
#[derive(Clone)]
pub struct GatewayProxyService {
    state: GatewayState,
    router: Router,
    peer_addr: Option<SocketAddr>,
}

impl GatewayProxyService {
    pub fn new(state: GatewayState, router: Router, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            state,
            router,
            peer_addr,
        }
    }
}

impl Service<Request<Body>> for GatewayProxyService {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        let router = self.router.clone();
        let peer_addr = self.peer_addr;
        Box::pin(async move {
            let is_proxy_method = *req.method() == Method::CONNECT || req.uri().scheme().is_some();
            if is_proxy_method && peer_addr.is_some_and(|addr| !addr.ip().is_loopback()) {
                return Ok(connect_error(
                    StatusCode::FORBIDDEN,
                    "forbidden_proxy_client",
                    "proxy requests are restricted to loopback clients",
                ));
            }
            if *req.method() == Method::CONNECT {
                return Ok(handle_connect_tunnel(state, req).await);
            }
            if req.uri().scheme().is_some() {
                return Ok(handle_absolute_proxy_request(state, req).await);
            }
            router.oneshot(req).await
        })
    }
}

/// Top-level `MakeService` compatible with `axum::serve(listener, ...)`.
#[derive(Clone)]
pub struct GatewayMakeService {
    state: GatewayState,
    router: Router,
}

impl<'a> Service<axum::serve::IncomingStream<'a>> for GatewayMakeService {
    type Response = GatewayProxyService;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: axum::serve::IncomingStream<'a>) -> Self::Future {
        let peer_addr = Some(target.remote_addr());
        std::future::ready(Ok(GatewayProxyService::new(
            self.state.clone(),
            self.router.clone(),
            peer_addr,
        )))
    }
}

/// Build the single-port gateway service used by `hide-go-daemon` and `hide-go-desktop`.
pub fn build_gateway_service(state: GatewayState, extra_router: Option<Router>) -> GatewayMakeService {
    let core_router = build_router(state.clone());
    let router = match extra_router {
        Some(extra) => extra.merge(core_router),
        None => core_router,
    };
    GatewayMakeService { state, router }
}

/// Build a `GatewayProxyService` factory for direct hyper serving (e.g. `hide-go-daemon` with timeouts).
pub fn build_gateway_proxy_service(
    state: GatewayState,
    extra_router: Option<Router>,
    peer_addr: Option<SocketAddr>,
) -> GatewayProxyService {
    let core_router = build_router(state.clone());
    let router = match extra_router {
        Some(extra) => extra.merge(core_router),
        None => core_router,
    };
    GatewayProxyService::new(state, router, peer_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{CaManager, MockCaTrustAdapter};
    use crate::config::{CustomRule, PrivacyMode};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as TokioMutex;

    #[test]
    fn selective_mitm_policy_allows_ai_hosts_and_skips_auth_and_general_hosts() {
        let mut cfg = HideConfig::default();

        for host in [
            "api.anthropic.com",
            "API.OPENAI.COM",
            "generativelanguage.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.sandbox.googleapis.com",
            "jetski-webchannel.googleapis.com",
            "us-central1-aiplatform.googleapis.com",
            "api2.cursor.sh",
            "api3.cursorapi.com",
            "api1.qoder.sh",
            "gateway.qoder.com.cn",
            "dashscope.aliyuncs.com",
            "myresource.openai.azure.com",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "cli-chat-proxy.grok.com",
        ] {
            assert!(should_mitm_host(host, &cfg), "expected MITM for {host}");
        }

        for host in [
            "github.com",
            "registry.npmjs.org",
            "oauth2.googleapis.com",
            "accounts.google.com",
            "www.googleapis.com",
            "storage.googleapis.com",
            "auth.qoder.sh",
            "login.qoder.sh",
            "chatgpt.com",
            "example.com",
            "",
        ] {
            assert!(!should_mitm_host(host, &cfg), "expected bypass for {host}");
        }

        cfg.mitm_extra_hosts.push("chatgpt.com".into());
        cfg.mitm_extra_hosts.push("*.internal-ai.local".into());
        assert!(should_mitm_host("chatgpt.com", &cfg));
        assert!(should_mitm_host("llm.internal-ai.local", &cfg));

        cfg.mitm_bypass_hosts.push("api.anthropic.com".into());
        cfg.mitm_bypass_hosts.push("*.internal-ai.local".into());
        assert!(!should_mitm_host("api.anthropic.com", &cfg));
        assert!(!should_mitm_host("llm.internal-ai.local", &cfg));
    }

    #[test]
    fn connect_authority_and_ssrf_guards_behave_safely() {
        let headers = HeaderMap::new();
        let uri: Uri = "api.openai.com:443".parse().unwrap();
        assert_eq!(
            parse_connect_authority(&uri, &headers),
            Some(("api.openai.com".into(), 443))
        );

        let v6_uri: Uri = "[::1]:8443".parse().unwrap();
        assert_eq!(parse_connect_authority(&v6_uri, &headers), Some(("::1".into(), 8443)));

        assert!(is_forbidden_connect_target("169.254.169.254", 80, 18787));
        assert!(is_forbidden_connect_target("metadata.google.internal", 443, 18787));
        assert!(is_forbidden_connect_target("127.0.0.1", 18787, 18787));
        assert!(is_forbidden_connect_target("localhost", 18787, 18787));
        assert!(is_forbidden_connect_target("::1", 18787, 18787));
        assert!(is_forbidden_connect_target("127.0.0.1", 19999, 18787));
        assert!(is_forbidden_connect_target("10.0.0.1", 443, 18787));
        assert!(is_forbidden_connect_target("172.16.0.1", 443, 18787));
        assert!(is_forbidden_connect_target("192.168.1.1", 443, 18787));
        assert!(is_forbidden_connect_target("100.64.0.1", 443, 18787));
        assert!(is_forbidden_connect_target("::ffff:127.0.0.1", 443, 18787));
        assert!(is_forbidden_connect_target("::ffff:10.0.0.1", 443, 18787));
        assert!(is_forbidden_connect_target("fc00::1", 443, 18787));
        assert!(is_forbidden_connect_target("fe80::1", 443, 18787));
        assert!(!is_forbidden_connect_target("api.openai.com", 443, 18787));
        assert!(!should_mitm_host("*.qoder.sh", &HideConfig::default()));
        assert!(!should_mitm_host("*.openai.com", &HideConfig::default()));
    }

    /// Generate an independent self-signed CA + leaf cert for mock upstream HTTPS servers
    /// (intentionally separate from Hide-Go's own CA to prove MITM vs passthrough).
    fn make_independent_upstream_tls(host_ip: &str) -> (Vec<u8>, Arc<rustls::ServerConfig>) {
        let mock_ca = CaManager::ephemeral(Arc::new(MockCaTrustAdapter::default())).unwrap();
        let ca_der = mock_ca.ca_cert_der().to_vec();
        let server_cfg = mock_ca.server_config_for_host(host_ip).unwrap();
        (ca_der, server_cfg)
    }

    type CapturedBodies = Arc<TokioMutex<Vec<(String, Vec<u8>)>>>;

    async fn spawn_mock_https_upstream(
        server_cfg: Arc<rustls::ServerConfig>,
        captured_bodies: CapturedBodies,
        response_content_type: &'static str,
        response_body: Vec<u8>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_cfg);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let captured = captured_bodies.clone();
                let resp_bytes = response_body.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let captured = captured.clone();
                        let resp_bytes = resp_bytes.clone();
                        async move {
                            let uri = req.uri().to_string();
                            let bytes = req
                                .into_body()
                                .collect()
                                .await
                                .map(|c| c.to_bytes().to_vec())
                                .unwrap_or_default();
                            captured.lock().await.push((uri, bytes.clone()));
                            let body_out = if resp_bytes.is_empty() && response_content_type == "application/json" {
                                let echoed = serde_json::from_slice::<serde_json::Value>(&bytes)
                                    .ok()
                                    .and_then(|v| v["messages"][0]["content"].as_str().map(str::to_owned))
                                    .unwrap_or_default();
                                serde_json::json!({
                                    "id": "msg_1",
                                    "content": [{"type": "text", "text": echoed}]
                                })
                                .to_string()
                                .into_bytes()
                            } else {
                                resp_bytes.clone()
                            };
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", response_content_type)
                                    .body(http_body_util::Full::new(Bytes::from(body_out)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        addr
    }

    async fn spawn_gateway_with_state(state: GatewayState) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        state.config.write().proxy_port = addr.port();
        let svc = build_gateway_service(state, None);
        tokio::spawn(async move {
            let _ = axum::serve(listener, svc).await;
        });
        addr
    }

    #[tokio::test]
    async fn connect_mitm_desensitizes_and_restores_json_while_preserving_binary_rpc() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (upstream_ca_der, upstream_server_cfg) = make_independent_upstream_tls("127.0.0.1");
        let captured = Arc::new(TokioMutex::new(Vec::<(String, Vec<u8>)>::new()));
        let upstream_addr =
            spawn_mock_https_upstream(upstream_server_cfg, captured.clone(), "application/json", Vec::new()).await;

        let hide_ca = Arc::new(CaManager::ephemeral(Arc::new(MockCaTrustAdapter::default())).unwrap());
        let hide_ca_der = hide_ca.ca_cert_der().to_vec();

        let cfg = HideConfig {
            mode: PrivacyMode::AutoDesensitize,
            mitm_extra_hosts: vec!["127.0.0.1".into()],
            protect_secrets_and_keys: true,
            protect_project_paths: true,
            custom_rules: vec![CustomRule {
                id: "rule-proj".into(),
                name: "Secret Project".into(),
                pattern: "SecretRepo".into(),
                replacement_hint: "PROJ".into(),
                enabled: true,
            }],
            proxy_port: 0,
            ..HideConfig::default()
        };

        let mut state = GatewayState::new(cfg).with_ca(hide_ca).with_loopback_for_tests(true);
        // Gateway's outbound HTTP client trusts the mock upstream CA (not Hide-Go's own CA)
        let upstream_client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_der(&upstream_ca_der).unwrap())
            .build()
            .unwrap();
        state.use_system_upstream_proxy = false;
        state.http_client = upstream_client.clone();
        state.local_http_client = upstream_client;

        let gw_addr = spawn_gateway_with_state(state.clone()).await;

        // Client trusts ONLY Hide-Go's CA (NOT upstream's independent CA), proving TLS MITM works
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{gw_addr}")).unwrap())
            .add_root_certificate(reqwest::Certificate::from_der(&hide_ca_der).unwrap())
            .build()
            .unwrap();

        let resp = client
            .post(format!("https://{upstream_addr}/v1/messages"))
            .header("content-type", "application/json")
            .body(r#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"Check E:\\Projects\\SecretRepo\\src\\main.rs with sk-ant-api03-secretvalue1234567890"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let restored_text = resp.text().await.unwrap();

        // Upstream received sanitized payload without real secret key or project path
        let logs = captured.lock().await;
        assert_eq!(logs.len(), 1);
        let sent_to_upstream = String::from_utf8(logs[0].1.clone()).unwrap();
        assert!(!sent_to_upstream.contains("SecretRepo"));
        assert!(!sent_to_upstream.contains("sk-ant-api03-secretvalue1234567890"));
        drop(logs);

        // Client received restored secret/project path from vault
        assert!(
            restored_text.contains("SecretRepo"),
            "expected restored project path, got: {restored_text}"
        );
        assert!(
            restored_text.contains("sk-ant-api03-secretvalue1234567890"),
            "expected restored API key, got: {restored_text}"
        );

        // Invalid/opaque Connect+Proto payload fails safe and passes through byte-for-byte
        let bin_payload = vec![0x00, 0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let bin_resp = client
            .post(format!(
                "https://{upstream_addr}/aiserver.v1.ChatService/StreamUnifiedChatWithTools"
            ))
            .header("content-type", "application/connect+proto")
            .body(bin_payload.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(bin_resp.status(), StatusCode::OK);

        let logs = captured.lock().await;
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[1].1, bin_payload);
        drop(logs);

        // Valid Connect+Proto Protobuf message carrying a secret key MUST be desensitized before upstream!
        let secret_text = "sk-wbefwubfbsrfrsuf baseurl:linuu.do/v1";
        let mut pb_msg = vec![0x0A, secret_text.len() as u8];
        pb_msg.extend_from_slice(secret_text.as_bytes());
        let mut connect_proto_req = vec![0x00];
        connect_proto_req.extend_from_slice(&(pb_msg.len() as u32).to_be_bytes());
        connect_proto_req.extend_from_slice(&pb_msg);

        let pb_resp = client
            .post(format!(
                "https://{upstream_addr}/google.internal.cloud.code.v1internal.CodeAssist/StreamGenerateContent"
            ))
            .header("content-type", "application/connect+proto")
            .body(connect_proto_req)
            .send()
            .await
            .unwrap();
        assert_eq!(pb_resp.status(), StatusCode::OK);

        let logs = captured.lock().await;
        assert_eq!(logs.len(), 3);
        let upstream_wire = &logs[2].1;
        assert!(
            !String::from_utf8_lossy(upstream_wire).contains("sk-wbefwubfbsrfrsuf"),
            "upstream must never see raw secret key inside Connect+Proto payload"
        );
        assert!(
            String::from_utf8_lossy(upstream_wire).contains("baseurl:linuu.do/v1"),
            "non-sensitive text must remain intact inside Connect+Proto payload"
        );
        drop(logs);

        let audits = state.audit_logs.read();
        assert!(audits.iter().any(|r| r.action_taken == "protobuf-passed"));
        assert!(audits.iter().any(|r| r.action_taken == "protobuf-desensitized"));
    }

    #[tokio::test]
    async fn connect_non_ai_host_uses_raw_tcp_passthrough_without_mitm() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Non-AI upstream uses its OWN independent CA on `localhost`
        let (upstream_ca_der, upstream_server_cfg) = make_independent_upstream_tls("127.0.0.1");
        let captured = Arc::new(TokioMutex::new(Vec::<(String, Vec<u8>)>::new()));
        let upstream_addr = spawn_mock_https_upstream(
            upstream_server_cfg,
            captured,
            "application/json",
            br#"{"ok":true}"#.to_vec(),
        )
        .await;

        let hide_ca = Arc::new(CaManager::ephemeral(Arc::new(MockCaTrustAdapter::default())).unwrap());
        let hide_ca_der = hide_ca.ca_cert_der().to_vec();

        // Notice `127.0.0.1` is NOT in `mitm_extra_hosts`, so it must get raw TCP passthrough!
        let state = GatewayState::new(HideConfig::default())
            .with_ca(hide_ca)
            .with_loopback_for_tests(true);
        let gw_addr = spawn_gateway_with_state(state.clone()).await;

        // Client trusting Hide-Go's CA ONLY must FAIL TLS verification because Hide-Go did NOT MITM!
        let hide_ca_only_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{gw_addr}")).unwrap())
            .add_root_certificate(reqwest::Certificate::from_der(&hide_ca_der).unwrap())
            .build()
            .unwrap();
        let err = hide_ca_only_client
            .get(format!("https://{upstream_addr}/user"))
            .send()
            .await
            .expect_err("raw TCP passthrough should NOT present Hide-Go CA cert");
        assert!(err.is_connect() || err.is_request());

        // Client trusting upstream's independent CA succeeds end-to-end with zero audit log!
        let upstream_trusted_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{gw_addr}")).unwrap())
            .add_root_certificate(reqwest::Certificate::from_der(&upstream_ca_der).unwrap())
            .build()
            .unwrap();
        let ok = upstream_trusted_client
            .get(format!("https://{upstream_addr}/user"))
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(ok.text().await.unwrap(), r#"{"ok":true}"#);
        assert!(
            state.audit_logs.read().is_empty(),
            "passthrough host must produce zero decrypted audit records"
        );
    }

    #[tokio::test]
    async fn connect_blocks_self_loop_ssrf_non443_and_cross_site_triggers() {
        let state = GatewayState::new(HideConfig::default());
        let gw_addr = spawn_gateway_with_state(state.clone()).await;

        for (target, extra_hdr) in [
            (format!("127.0.0.1:{}", gw_addr.port()), ""),
            ("169.254.169.254:80".to_string(), ""),
            ("10.0.0.1:443".to_string(), ""),
            ("api.openai.com:22".to_string(), ""),
            ("api.openai.com:443".to_string(), "Origin: https://evil.example\r\n"),
        ] {
            let mut stream = TcpStream::connect(gw_addr).await.unwrap();
            let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{extra_hdr}\r\n");
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf[..n]);
            assert!(
                resp.starts_with("HTTP/1.1 403"),
                "expected 403 for {target} ({extra_hdr}), got: {resp}"
            );
        }

        // Non-loopback peer IP must also be rejected even if the destination is valid.
        let svc = build_gateway_proxy_service(state, None, Some("203.0.113.10:54321".parse::<SocketAddr>().unwrap()));
        let req = axum::http::Request::builder()
            .method(Method::CONNECT)
            .uri("api.openai.com:443")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn port_allowlist_permits_8443_public_and_rejects_unlisted_ports_and_private_ips() {
        let mut cfg = HideConfig::default();
        cfg.proxy_port = 18787;
        cfg.allowed_loopback_proxy_targets = vec![
            "127.0.0.1:8888".into(),
            "localhost:3000".into(),
            "127.0.0.1:18787".into(), // self-port must NEVER be allowed
            "10.0.0.1:8888".into(),   // non-loopback private IP must NEVER be allowed
        ];

        assert!(is_proxy_target_allowed("mcp.example.com", 443, &cfg, false, &[443]));
        assert!(is_proxy_target_allowed("mcp.example.com", 8443, &cfg, false, &[443]));
        assert!(is_proxy_target_allowed(
            "mcp.example.com",
            8443,
            &cfg,
            false,
            &[80, 443]
        ));

        // Unlisted ports rejected on both CONNECT and forward HTTP
        assert!(!is_proxy_target_allowed("api.openai.com", 22, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("api.openai.com", 6379, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("api.openai.com", 22, &cfg, false, &[80, 443]));
        assert!(!is_proxy_target_allowed(
            "api.openai.com",
            6379,
            &cfg,
            false,
            &[80, 443]
        ));

        // Private / link-local / CGNAT / unlisted loopback stay blocked even on :8443
        assert!(!is_proxy_target_allowed("10.0.0.1", 8443, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("172.16.0.1", 8443, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("192.168.1.1", 8443, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("100.64.0.1", 8443, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("169.254.169.254", 8443, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("127.0.0.1", 8443, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("10.0.0.1", 8888, &cfg, false, &[443]));

        // Explicit loopback targets allowed, except self-port
        assert!(is_proxy_target_allowed("127.0.0.1", 8888, &cfg, false, &[443]));
        assert!(is_proxy_target_allowed("localhost", 3000, &cfg, false, &[80, 443]));
        assert!(!is_proxy_target_allowed("127.0.0.1", 18787, &cfg, false, &[443]));
        assert!(!is_proxy_target_allowed("127.0.0.1", 6379, &cfg, false, &[443]));
    }

    #[tokio::test]
    async fn connect_and_forward_honor_allowed_loopback_targets_while_blocking_self_and_unlisted_ports() {
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = mock_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}")
                        .await;
                });
            }
        });

        let mut cfg = HideConfig::default();
        cfg.allowed_loopback_proxy_targets = vec![format!("127.0.0.1:{}", mock_addr.port())];
        let state = GatewayState::new(cfg);
        let gw_addr = spawn_gateway_with_state(state.clone()).await;
        // Also try adding self-port dynamically to prove self-port remains blocked
        state
            .config
            .write()
            .allowed_loopback_proxy_targets
            .push(format!("127.0.0.1:{}", gw_addr.port()));

        // 1. Explicit loopback target succeeds via CONNECT tunnel
        let mut tunnel = TcpStream::connect(gw_addr).await.unwrap();
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            mock_addr.port(),
            mock_addr.port()
        );
        tunnel.write_all(connect_req.as_bytes()).await.unwrap();
        let mut head = [0u8; 256];
        let n = tunnel.read(&mut head).await.unwrap();
        let head_str = String::from_utf8_lossy(&head[..n]);
        assert!(head_str.starts_with("HTTP/1.1 200"), "got: {head_str}");
        tunnel
            .write_all(b"GET /search HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut body = Vec::new();
        tunnel.read_to_end(&mut body).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains(r#"{"ok":true}"#));

        // 2. Explicit loopback target succeeds via forward HTTP
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(format!("http://{gw_addr}")).unwrap())
            .build()
            .unwrap();
        let ok_resp = client
            .get(format!("http://127.0.0.1:{}/search", mock_addr.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(ok_resp.status(), StatusCode::OK);
        assert_eq!(ok_resp.text().await.unwrap(), r#"{"ok":true}"#);

        // 3. Self-port (even though added to allowed_loopback_proxy_targets) and unlisted ports (22, 6379) remain 403
        for target in [
            format!("127.0.0.1:{}", gw_addr.port()),
            "127.0.0.1:6379".to_string(),
            "api.openai.com:22".to_string(),
            "api.openai.com:6379".to_string(),
        ] {
            let mut s = TcpStream::connect(gw_addr).await.unwrap();
            let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
            s.write_all(req.as_bytes()).await.unwrap();
            let mut buf = [0u8; 512];
            let n = s.read(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf[..n]);
            assert!(
                resp.starts_with("HTTP/1.1 403"),
                "expected 403 for {target}, got: {resp}"
            );
        }

        for url in [
            format!("http://127.0.0.1:{}/api/status", gw_addr.port()),
            "http://127.0.0.1:6379/".to_string(),
            "http://api.openai.com:22/".to_string(),
            "http://api.openai.com:6379/".to_string(),
        ] {
            let resp = client.get(&url).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "expected 403 for {url}");
        }
    }

    #[test]
    fn operator_upstream_allows_private_lan_and_blocks_metadata_and_self_loop() {
        assert!(!is_forbidden_operator_upstream("192.168.1.50", 11434, 18787));
        assert!(!is_forbidden_operator_upstream("10.0.0.5", 8080, 18787));
        assert!(!is_forbidden_operator_upstream("llm.corp.internal", 443, 18787));
        assert!(!is_forbidden_operator_upstream("127.0.0.1", 15721, 18787));

        assert!(is_forbidden_operator_upstream("127.0.0.1", 18787, 18787));
        assert!(is_forbidden_operator_upstream("localhost", 18787, 18787));
        assert!(is_forbidden_operator_upstream("169.254.169.254", 80, 18787));
        assert!(is_forbidden_operator_upstream("100.100.100.200", 80, 18787));
        assert!(is_forbidden_operator_upstream("metadata.google.internal", 80, 18787));
        assert!(is_forbidden_operator_upstream("fd00:ec2::254", 80, 18787));
    }

    #[tokio::test]
    async fn mitm_full_duplex_bidirectional_grpc_streams_without_deadlock_and_restores_each_turn() {
        use http_body_util::StreamBody;
        use hyper::body::Frame;
        use tokio::sync::mpsc;

        let _ = rustls::crypto::ring::default_provider().install_default();

        // Spawn an HTTPS HTTP/2 upstream that echoes each incoming gRPC data frame immediately
        // BEFORE the client closes its request stream (true full-duplex bidirectional streaming),
        // then sends `grpc-status: 0` trailer once client ends its stream.
        let (upstream_ca_der, upstream_server_cfg) = make_independent_upstream_tls("127.0.0.1");
        let upstream_seen = Arc::new(TokioMutex::new(Vec::<Vec<u8>>::new()));
        let seen_clone = upstream_seen.clone();

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(upstream_server_cfg);
            loop {
                let Ok((tcp, _)) = upstream_listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let seen = seen_clone.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let mut req_body = req.into_body();
                            let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(8);
                            tokio::spawn(async move {
                                while let Some(Ok(frame)) = req_body.frame().await {
                                    if let Ok(data) = frame.into_data() {
                                        if data.is_empty() {
                                            continue;
                                        }
                                        seen.lock().await.push(data.to_vec());
                                        let _ = tx.send(Ok(Frame::data(data))).await;
                                    }
                                }
                                let mut trailers = HeaderMap::new();
                                trailers.insert("grpc-status", "0".parse().unwrap());
                                let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                            });
                            let stream = futures_util::stream::unfold(rx, |mut rx| async move {
                                rx.recv().await.map(|item| (item, rx))
                            });
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/grpc+proto")
                                    .body(Body::new(StreamBody::new(stream)))
                                    .unwrap(),
                            )
                        }
                    });
                    let mut builder =
                        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                    builder.http2().timer(hyper_util::rt::TokioTimer::new());
                    let _ = builder.serve_connection(TokioIo::new(tls), svc).await;
                });
            }
        });

        let gateway_ca = Arc::new(CaManager::ephemeral(Arc::new(MockCaTrustAdapter::new())).unwrap());
        let hide_ca_der = gateway_ca.ca_cert_der().to_vec();
        let mut cfg = HideConfig::default();
        cfg.mitm_extra_hosts.push("127.0.0.1".to_string());
        let mut state = GatewayState::new(cfg).with_ca(gateway_ca).with_loopback_for_tests(true);
        state.local_http_client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_der(&upstream_ca_der).unwrap())
            .build()
            .unwrap();
        let gw_addr = spawn_gateway_with_state(state.clone()).await;

        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{gw_addr}")).unwrap())
            .add_root_certificate(reqwest::Certificate::from_der(&hide_ca_der).unwrap())
            .build()
            .unwrap();

        let make_grpc_frame = |text: &str| -> Bytes {
            let mut pb = vec![0x0A, text.len() as u8];
            pb.extend_from_slice(text.as_bytes());
            let mut env = vec![0x00];
            env.extend_from_slice(&(pb.len() as u32).to_be_bytes());
            env.extend_from_slice(&pb);
            Bytes::from(env)
        };

        let (req_tx, req_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        let req_stream =
            futures_util::stream::unfold(req_rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) });

        // Send Turn 1 BEFORE closing request stream!
        let turn1 = "Turn1 secret sk-wbefwubfbsrfrsuf";
        let turn2 = "Turn2 secret sk-proj-SecondBidiKey1234567890";
        req_tx.send(Ok(make_grpc_frame(turn1))).await.unwrap();

        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .post(format!(
                    "https://{upstream_addr}/google.internal.cloud.code.v1internal.CodeAssist/BidiStream"
                ))
                .header("content-type", "application/grpc+proto")
                .body(reqwest::Body::wrap_stream(req_stream))
                .send(),
        )
        .await
        .expect("bidirectional gRPC must receive response headers while request stream is still open")
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let http_resp: axum::http::Response<reqwest::Body> = resp.into();
        let mut resp_body = http_resp.into_body();

        // Receive Turn 1 echo BEFORE sending Turn 2 (proves zero buffering deadlock!).
        let frame1 = tokio::time::timeout(Duration::from_secs(5), resp_body.frame())
            .await
            .expect("must receive Turn 1 response frame before client sends Turn 2")
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&frame1[5..]).contains(turn1),
            "Turn 1 must restore original secret: {:?}",
            String::from_utf8_lossy(&frame1)
        );

        // Now send Turn 2 with a brand-new secret on the SAME open bidirectional stream, then close!
        req_tx.send(Ok(make_grpc_frame(turn2))).await.unwrap();
        drop(req_tx);

        let mut rest_data = Vec::new();
        let mut trailers = HeaderMap::new();
        while let Some(frame_res) = tokio::time::timeout(Duration::from_secs(5), resp_body.frame())
            .await
            .expect("timed out reading Turn 2 / trailers")
        {
            let frame = frame_res.unwrap();
            match frame.into_data() {
                Ok(d) => rest_data.extend_from_slice(&d),
                Err(frame) => {
                    if let Ok(t) = frame.into_trailers() {
                        trailers.extend(t);
                    }
                }
            }
        }
        assert!(
            String::from_utf8_lossy(&rest_data).contains(turn2),
            "Turn 2 new secret must be restored dynamically by live vault matcher"
        );
        assert_eq!(
            trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
            Some("0"),
            "HTTP/2 grpc-status trailer must survive full-duplex bidirectional stream"
        );

        let seen = upstream_seen.lock().await;
        let combined_seen: Vec<u8> = seen.iter().flatten().copied().collect();
        let seen_str = String::from_utf8_lossy(&combined_seen);
        assert!(!seen_str.contains("sk-wbefwubfbsrfrsuf"));
        assert!(!seen_str.contains("sk-proj-SecondBidiKey1234567890"));
    }
}
