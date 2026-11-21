use crate::{
    chrome_bridge::{create_private_temp_dir, generate_csp_nonce, ChromeHost, NativeWindowOptions},
    web_assets::{build_nonce_csp, resolve_resources_dir, UiBundle},
};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hide_core::{
    build_gateway_service, build_router, harness::HarnessProfile, proxy::is_local_browser_request, vault::VaultEntry,
    GatewayMakeService, GatewayState, HarnessKind, HideConfig, TrafficAuditRecord, TrafficCategory,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// Desktop bridge combining `hide-core` gateway state with disk-loaded Desktop UI assets.
pub struct DesktopBridge {
    pub state: GatewayState,
    ui: Arc<UiBundle>,
    chrome: Arc<dyn ChromeHost>,
}

#[derive(Clone)]
struct UiRouterState {
    gateway: GatewayState,
    ui: Arc<UiBundle>,
    chrome: Arc<dyn ChromeHost>,
    shutdown: Option<Arc<Notify>>,
    ui_seen: Option<Arc<AtomicBool>>,
}

fn load_desktop_ui_bundle(exe_dir: Option<&Path>) -> Result<UiBundle, String> {
    if let Some(resources_dir) = resolve_resources_dir(exe_dir) {
        let ui_dir = resources_dir.join("ui");
        if ui_dir.is_dir() {
            return UiBundle::load_from_dir(&ui_dir, "index.html");
        }
    }

    #[cfg(debug_assertions)]
    {
        let dev_dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist");
        if dev_dist.join("index.html").is_file() {
            return UiBundle::load_from_dir(&dev_dist, "index.html");
        }
        let cwd_dist = PathBuf::from("dist");
        if cwd_dist.join("index.html").is_file() {
            return UiBundle::load_from_dir(&cwd_dist, "index.html");
        }
    }

    Err(
        "缺少前端资源目录 resources/ui/，请保持安装目录完整或通过 Hide-Go-Setup 重新安装。\nMissing resources/ui/ directory; keep installation files together or reinstall using Hide-Go-Setup."
            .to_string(),
    )
}

impl DesktopBridge {
    pub fn new(exe_dir: Option<&Path>, chrome: Arc<dyn ChromeHost>) -> Result<Self, String> {
        let ui = Arc::new(load_desktop_ui_bundle(exe_dir)?);
        let state = match HideConfig::default_path() {
            Some(path) => GatewayState::with_persisted_config(path),
            None => GatewayState::default(),
        };
        Ok(Self { state, ui, chrome })
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        let ui_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist");
        let ui = Arc::new(
            UiBundle::load_from_dir(&ui_dir, "index.html")
                .expect("repo dist/index.html must be built before running desktop tests"),
        );
        Self {
            state: GatewayState::default(),
            ui,
            chrome: Arc::new(crate::chrome_bridge::HeadlessChromeHost),
        }
    }

    pub fn get_config(&self) -> HideConfig {
        self.state.get_config()
    }

    pub fn update_config(&self, next: HideConfig) -> HideConfig {
        self.state.update_config(next)
    }

    pub fn get_logs(&self) -> Vec<TrafficAuditRecord> {
        self.state.get_records()
    }

    pub fn clear_logs(&self) {
        self.state.clear_records();
    }

    pub fn get_harnesses(&self) -> Vec<HarnessProfile> {
        self.state.get_harness_profiles()
    }

    pub fn get_vault(&self) -> Vec<VaultEntry> {
        self.state.get_vault_entries()
    }

    pub fn clear_vault(&self) {
        self.state.clear_vault();
    }

    pub fn simulate_harness(
        &self,
        harness: HarnessKind,
        category: TrafficCategory,
        custom_payload: Option<String>,
    ) -> TrafficAuditRecord {
        self.state.simulate_traffic(harness, category, custom_payload)
    }

    fn ui_router_with_control(&self, shutdown: Option<Arc<Notify>>, ui_seen: Option<Arc<AtomicBool>>) -> Router {
        let ui_state = UiRouterState {
            gateway: self.state.clone(),
            ui: self.ui.clone(),
            chrome: self.chrome.clone(),
            shutdown,
            ui_seen,
        };
        Router::new()
            .route("/", get(serve_index))
            .route("/index.html", get(serve_index))
            .route("/assets/*file", get(serve_ui_asset))
            .route("/api/quit", post(api_desktop_quit))
            .with_state(ui_state)
    }

    fn ui_router(&self) -> Router {
        self.ui_router_with_control(None, None)
    }

    pub fn build_desktop_router(&self) -> Router {
        let core_router = build_router(self.state.clone());
        self.ui_router().merge(core_router)
    }

    pub fn build_desktop_gateway_service(&self) -> GatewayMakeService {
        build_gateway_service(self.state.clone(), Some(self.ui_router()))
    }

    fn build_desktop_gateway_service_with_control(
        &self,
        shutdown: Arc<Notify>,
        ui_seen: Arc<AtomicBool>,
    ) -> GatewayMakeService {
        build_gateway_service(
            self.state.clone(),
            Some(self.ui_router_with_control(Some(shutdown), Some(ui_seen))),
        )
    }

    pub async fn run_desktop_app(&self) -> Result<(), Box<dyn std::error::Error>> {
        let stopped = terminate_existing_if_enabled(self.chrome.as_ref());
        let port = std::env::var("HIDE_GO_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or_else(|| self.state.get_config().proxy_port);

        let listener = bind_loopback_with_retry(port, stopped > 0)
            .await
            .map_err(std::io::Error::other)?;
        let addr = listener.local_addr()?;
        self.state.config.write().proxy_port = addr.port();
        let shutdown = Arc::new(Notify::new());
        let ui_seen = Arc::new(AtomicBool::new(false));
        let app = self.build_desktop_gateway_service_with_control(shutdown.clone(), ui_seen);

        let ui_url = format!("http://{}", addr);
        tracing::info!("Hide-Go Standalone Desktop App running at {}", ui_url);
        if !self.chrome.can_open_gui() && std::env::var_os("HIDE_GO_ADMIN_TOKEN").is_none() {
            tracing::info!("Hide-Go headless desktop console started (set HIDE_GO_ADMIN_TOKEN to pin API auth)");
        }

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                tokio::select! {
                    _ = shutdown.notified() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            })
            .await?;
        Ok(())
    }

    pub fn run_desktop_app_blocking(self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.chrome.can_open_gui() {
            let rt = tokio::runtime::Runtime::new()?;
            return rt.block_on(self.run_desktop_app());
        }

        let keep_existing = std::env::var_os("HIDE_GO_KEEP_EXISTING").is_some();
        let stopped = terminate_existing_if_enabled(self.chrome.as_ref());
        let port = std::env::var("HIDE_GO_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or_else(|| self.state.get_config().proxy_port);
        let shutdown = Arc::new(Notify::new());
        let ui_seen = Arc::new(AtomicBool::new(false));
        let app = self.build_desktop_gateway_service_with_control(shutdown.clone(), ui_seen.clone());
        let state = self.state.clone();
        let shutdown_server = shutdown.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<String, String>>(1);

        let server_thread = std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match bind_loopback_with_retry(port, stopped > 0).await {
                    Ok(l) => l,
                    Err(msg) => {
                        let _ = tx.send(Err(msg));
                        return;
                    }
                };
                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = tx.send(Err(format!("local_addr failed: {e}")));
                        return;
                    }
                };
                state.config.write().proxy_port = addr.port();
                let ui_url = format!("http://{addr}/");
                tracing::info!("Hide-Go Standalone Desktop App running at {}", ui_url);
                let _ = tx.send(Ok(ui_url));
                if let Err(e) = axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        tokio::select! {
                            _ = shutdown_server.notified() => {}
                            _ = tokio::signal::ctrl_c() => {}
                        }
                    })
                    .await
                {
                    tracing::error!("desktop gateway server error: {e}");
                }
            });
        });

        let ui_url = rx
            .recv()
            .map_err(|e| format!("desktop server startup channel closed: {e}"))?
            .map_err(|e| format!("failed to start desktop server: {e}"))?;

        let (webview_dir, temp_webview_dir) = desktop_webview_data_dir();
        let window_res = self.chrome.run_frameless_window(NativeWindowOptions {
            title: "Hide-Go".into(),
            url: ui_url.clone(),
            width: 1380.0,
            height: 880.0,
            min_width: 960.0,
            min_height: 640.0,
            resizable: true,
            cleanup_on_close: !keep_existing,
            user_data_dir: Some(webview_dir),
        });
        if window_res.is_err() {
            tracing::warn!(
                "Desktop UI opened in system browser at {ui_url}; use POST /api/quit or Ctrl+C to stop gateway"
            );
            let watchdog_shutdown = shutdown.clone();
            let watchdog_seen = ui_seen.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(45));
                if !watchdog_seen.load(Ordering::Relaxed) {
                    tracing::warn!("no browser UI connected within 45s after WebView fallback; shutting down cleanly");
                    watchdog_shutdown.notify_one();
                }
            });
            let _ = server_thread.join();
        } else {
            shutdown.notify_one();
            let _ = server_thread.join();
        }
        if let Some(tmp_dir) = temp_webview_dir {
            let _ = std::fs::remove_dir_all(tmp_dir);
        }
        if !keep_existing {
            self.chrome.terminate_other_processes();
        }
        Ok(())
    }
}

pub fn run_desktop_entry(exe_dir: Option<&Path>, chrome: Arc<dyn ChromeHost>) -> i32 {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let bridge = match DesktopBridge::new(exe_dir, chrome.clone()) {
        Ok(bridge) => bridge,
        Err(err) => {
            tracing::error!("Hide-Go Desktop failed to initialize: {err}");
            chrome.show_error_dialog("Hide-Go 启动失败", &err);
            return 1;
        }
    };
    if let Err(err) = bridge.run_desktop_app_blocking() {
        tracing::error!("Hide-Go Desktop failed to start: {err}");
        chrome.show_error_dialog("Hide-Go 启动失败", &err.to_string());
        return 1;
    }
    0
}

fn desktop_webview_data_dir() -> (PathBuf, Option<PathBuf>) {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    #[cfg(windows)]
    let persisted = env("LOCALAPPDATA")
        .or_else(|| env("USERPROFILE"))
        .map(|p| p.join("Hide-Go").join("WebView2"));
    #[cfg(target_os = "macos")]
    let persisted = env("HOME").map(|h| h.join("Library/Application Support/hide-go/webview"));
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let persisted = env("XDG_DATA_HOME")
        .or_else(|| env("HOME").map(|h| h.join(".local/share")))
        .map(|p| p.join("hide-go").join("webview"));

    if let Some(dir) = persisted {
        return (dir, None);
    }
    match create_private_temp_dir("hide-go-webview") {
        Ok(dir) => (dir.clone(), Some(dir)),
        Err(_) => (std::env::temp_dir().join("Hide-Go-WebView2"), None),
    }
}

fn terminate_existing_if_enabled(chrome: &dyn ChromeHost) -> usize {
    if std::env::var_os("HIDE_GO_KEEP_EXISTING").is_some() {
        return 0;
    }
    let stopped = chrome.terminate_other_processes();
    if stopped > 0 {
        tracing::info!("terminated {stopped} existing Hide-Go background process(es)");
    }
    stopped
}

async fn bind_loopback_with_retry(port: u16, had_existing: bool) -> Result<TcpListener, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let attempts = if had_existing { 12 } else { 1 };
    for attempt in 0..attempts {
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if attempt + 1 < attempts {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                return Err(format!(
                    "本地端口 {port} 已被占用。\n\n请先关闭占用该端口的程序后重试，或设置环境变量 HIDE_GO_PORT 指定其他端口。\n({e})"
                ));
            }
            Err(e) => return Err(format!("bind failed: {e}")),
        }
    }
    unreachable!()
}

fn render_index_html(ui: &UiBundle, chrome: &dyn ChromeHost, token: &str, nonce: &str) -> String {
    let sys_locale = chrome.detect_system_locale();
    ui.render_html(sys_locale, nonce, "__HIDE_GO_TOKEN__", token)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut diff = ab.len() ^ bb.len();
    for i in 0..ab.len().min(bb.len()) {
        diff |= (ab[i] ^ bb[i]) as usize;
    }
    diff == 0
}

async fn api_desktop_quit(State(state): State<UiRouterState>, headers: HeaderMap) -> Response {
    if !is_local_browser_request(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let expected = state.gateway.admin_token();
    let supplied = headers
        .get("x-hide-go-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|a| a.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                .map(|(_, t)| t.trim())
        });
    if !supplied.is_some_and(|t| constant_time_eq(t, expected)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Some(shutdown) = state.shutdown {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            shutdown.notify_one();
        });
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn serve_index(State(state): State<UiRouterState>, headers: HeaderMap) -> Response {
    if !is_local_browser_request(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(seen) = &state.ui_seen {
        seen.store(true, Ordering::Relaxed);
    }

    let nonce = generate_csp_nonce();
    let csp = build_nonce_csp(&nonce);
    let html = render_index_html(&state.ui, state.chrome.as_ref(), state.gateway.admin_token(), &nonce);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::REFERRER_POLICY, "no-referrer".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::X_FRAME_OPTIONS, "DENY".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        Html(html),
    )
        .into_response()
}

async fn serve_ui_asset(State(state): State<UiRouterState>, uri: Uri) -> Response {
    state.ui.serve_asset(uri.path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chrome_bridge::HeadlessChromeHost;
    use axum::{body::to_bytes, extract::State};

    #[tokio::test]
    async fn embedded_assets_match_index_links_and_contents() {
        let bridge = DesktopBridge::for_tests();
        let state = UiRouterState {
            gateway: bridge.state.clone(),
            ui: bridge.ui.clone(),
            chrome: bridge.chrome.clone(),
            shutdown: None,
            ui_seen: None,
        };
        assert!(!bridge.ui.assets.is_empty());
        let linked = |path: &str| bridge.ui.html.contains(path.trim_start_matches('/'));
        let bundled = |path: &str| {
            bridge.ui.assets.iter().any(|(owner, (_, bytes))| {
                linked(owner) && String::from_utf8_lossy(bytes).contains(path.trim_start_matches('/'))
            })
        };
        for (path, (content_type, bytes)) in &bridge.ui.assets {
            assert!(path.starts_with("/assets/"));
            assert!(linked(path) || bundled(path), "{path} is loaded but never referenced");
            assert!(!bytes.is_empty());
            for url in [path.to_string(), format!("{path}?v=test")] {
                let response = serve_ui_asset(State(state.clone()), url.parse().unwrap()).await;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()[header::CONTENT_TYPE], *content_type);
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                assert_eq!(body.as_ref(), bytes.as_slice());
            }
        }
    }

    #[tokio::test]
    async fn embedded_assets_reject_unlisted_paths() {
        let bridge = DesktopBridge::for_tests();
        let state = UiRouterState {
            gateway: bridge.state.clone(),
            ui: bridge.ui.clone(),
            chrome: bridge.chrome.clone(),
            shutdown: None,
            ui_seen: None,
        };
        let mut paths = vec![
            "/assets/not-embedded.js".to_string(),
            "/assets/not-embedded.css".to_string(),
            "/assets/index.js.map".to_string(),
            "/assets/index.html".to_string(),
        ];
        for path in bridge.ui.assets.keys() {
            paths.push(format!("/unlisted{path}"));
            paths.push(format!("{path}.js"));
            paths.push(format!("{path}.css"));
        }
        for path in paths {
            let response = serve_ui_asset(State(state.clone()), path.parse().unwrap()).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[test]
    fn index_token_is_json_and_cannot_close_the_script() {
        let bridge = DesktopBridge::for_tests();
        let token = "</script><script>alert(\"x\")</script>&'\\\n\r\t\0\u{001b}\u{2028}\u{2029}";
        let nonce = "0123456789abcdef0123456789abcdef";
        let html = render_index_html(&bridge.ui, bridge.chrome.as_ref(), token, nonce);
        let (_, script) = html
            .split_once(&format!("<script nonce=\"{nonce}\">window.__HIDE_GO_TOKEN__="))
            .unwrap();
        let (json, _) = script.split_once(";</script>").unwrap();
        assert!(!json.contains(['<', '>', '&', '\u{2028}', '\u{2029}']));
        assert_eq!(serde_json::from_str::<String>(json).unwrap(), token);
        assert!(!html.contains("__HIDE_GO_NONCE__"));
        assert_eq!(
            html.matches("</script>").count(),
            bridge.ui.html.matches("</script>").count() + 1
        );
    }

    #[tokio::test]
    async fn local_index_is_not_cached_and_sets_no_cookie() {
        let bridge = DesktopBridge::for_tests();
        let state = UiRouterState {
            gateway: bridge.state.clone(),
            ui: bridge.ui.clone(),
            chrome: bridge.chrome.clone(),
            shutdown: None,
            ui_seen: None,
        };
        for host in ["127.0.0.1:18787", "localhost:1420", "[::1]:43210"] {
            for origin in [None, Some(format!("http://{host}"))] {
                let mut headers = HeaderMap::new();
                headers.insert(header::HOST, host.parse().unwrap());
                if let Some(origin) = origin {
                    headers.insert(header::ORIGIN, origin.parse().unwrap());
                    headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
                }
                let response = serve_index(State(state.clone()), headers).await;
                assert_eq!(response.status(), StatusCode::OK, "{host}");
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
                assert!(!response.headers().contains_key(header::SET_COOKIE));
                let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .to_string();
                let script_src = csp
                    .split(';')
                    .find(|d| d.trim_start().starts_with("script-src"))
                    .unwrap();
                assert!(!script_src.contains("'unsafe-inline'"));
                let nonce = script_src.split("'nonce-").nth(1).unwrap().split('\'').next().unwrap();
                assert_eq!(nonce.len(), 32);
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                assert_eq!(
                    body.as_ref(),
                    render_index_html(&bridge.ui, state.chrome.as_ref(), state.gateway.admin_token(), nonce).as_bytes()
                );
            }
        }
    }

    #[tokio::test]
    async fn index_rejects_rebinding_and_cross_origin_requests() {
        let bridge = DesktopBridge::for_tests();
        let state = UiRouterState {
            gateway: bridge.state.clone(),
            ui: bridge.ui.clone(),
            chrome: Arc::new(HeadlessChromeHost),
            shutdown: None,
            ui_seen: None,
        };
        let cases = [
            (None, None),
            (Some("attacker.example:18787"), None),
            (Some("127.0.0.1.attacker.example:18787"), None),
            (Some("localhost.attacker.example:18787"), None),
            (Some("0.0.0.0:18787"), None),
            (Some("127.0.0.1:18787"), Some("http://attacker.example:18787")),
            (Some("127.0.0.1:18787"), Some("http://127.0.0.1:1420")),
            (Some("127.0.0.1:18787"), Some("http://localhost:18787")),
            (Some("127.0.0.1:18787"), Some("null")),
        ];
        for (host, origin) in cases {
            for fetch_site in [None, Some("same-site")] {
                let mut headers = HeaderMap::new();
                if let Some(host) = host {
                    headers.insert(header::HOST, host.parse().unwrap());
                }
                if let Some(origin) = origin {
                    headers.insert(header::ORIGIN, origin.parse().unwrap());
                }
                if let Some(fetch_site) = fetch_site {
                    headers.insert("sec-fetch-site", fetch_site.parse().unwrap());
                }
                let response = serve_index(State(state.clone()), headers).await;
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{host:?} {origin:?} {fetch_site:?}"
                );
                assert!(!response.headers().contains_key(header::SET_COOKIE));
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                assert!(!String::from_utf8_lossy(&body).contains("__HIDE_GO_TOKEN__"));
            }
        }
    }

    #[tokio::test]
    async fn desktop_quit_requires_local_origin_and_admin_token() {
        let bridge = DesktopBridge::for_tests();
        let state = UiRouterState {
            gateway: bridge.state.clone(),
            ui: bridge.ui.clone(),
            chrome: bridge.chrome.clone(),
            shutdown: Some(Arc::new(Notify::new())),
            ui_seen: None,
        };
        let mut no_tok = HeaderMap::new();
        no_tok.insert(header::HOST, "127.0.0.1:18787".parse().unwrap());
        assert_eq!(
            api_desktop_quit(State(state.clone()), no_tok).await.status(),
            StatusCode::UNAUTHORIZED
        );

        let mut evil = HeaderMap::new();
        evil.insert(header::HOST, "127.0.0.1:18787".parse().unwrap());
        evil.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        evil.insert("x-hide-go-token", state.gateway.admin_token().parse().unwrap());
        assert_eq!(
            api_desktop_quit(State(state.clone()), evil).await.status(),
            StatusCode::FORBIDDEN
        );

        let mut ok = HeaderMap::new();
        ok.insert(header::HOST, "127.0.0.1:18787".parse().unwrap());
        ok.insert("x-hide-go-token", state.gateway.admin_token().parse().unwrap());
        assert_eq!(api_desktop_quit(State(state), ok).await.status(), StatusCode::OK);
    }
}
