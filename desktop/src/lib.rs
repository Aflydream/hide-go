use axum::{
    http::{header, HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use hide_core::{
    build_router, harness::HarnessProfile, proxy::is_local_browser_request, vault::VaultEntry, GatewayState,
    HarnessKind, HideConfig, TrafficAuditRecord, TrafficCategory,
};
use std::net::SocketAddr;
use std::process::Command;
use tokio::net::TcpListener;

include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));

/// Desktop bridge embedding both the `hide-core` Rust privacy gateway and the compiled Desktop UI
pub struct DesktopBridge {
    pub state: GatewayState,
}

impl Default for DesktopBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl DesktopBridge {
    /// Desktop state with configuration persisted to the platform config directory.
    pub fn new() -> Self {
        let state = match HideConfig::default_path() {
            Some(path) => GatewayState::with_persisted_config(path),
            None => GatewayState::default(),
        };
        Self { state }
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

    /// Build the self-contained desktop router serving both embedded UI and all proxy/API routes
    pub fn build_desktop_router(&self) -> Router {
        let core_router = build_router(self.state.clone());
        let ui_router = Router::new()
            .route("/", get(serve_index))
            .route("/index.html", get(serve_index))
            .route("/assets/*file", get(serve_embedded_asset))
            .with_state(self.state.clone());
        ui_router.merge(core_router)
    }

    /// Open the console in a chromeless browser window (Edge/Chrome `--app`), falling back to
    /// the default browser. Each candidate is checked for real success, not just a spawn.
    pub fn launch_native_desktop_window(url: &str) {
        if std::env::var("HIDE_GO_HEADLESS").is_ok() {
            return;
        }
        let app = format!("--app={url}");
        let size = "--window-size=1440,920".to_string();
        let mut candidates: Vec<(String, Vec<String>)> = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let env = |k: &str| std::env::var(k).unwrap_or_default();
            for base in [env("ProgramFiles(x86)"), env("ProgramFiles"), env("LOCALAPPDATA")] {
                if base.is_empty() {
                    continue;
                }
                for rel in [
                    r"Microsoft\Edge\Application\msedge.exe",
                    r"Google\Chrome\Application\chrome.exe",
                ] {
                    let path = std::path::Path::new(&base).join(rel);
                    if path.is_file() {
                        candidates.push((path.display().to_string(), vec![app.clone(), size.clone()]));
                    }
                }
            }
            candidates.push((
                "rundll32".into(),
                vec!["url.dll,FileProtocolHandler".into(), url.to_string()],
            ));
        }

        #[cfg(target_os = "macos")]
        {
            for bundle in [
                "/Applications/Google Chrome.app",
                "/Applications/Microsoft Edge.app",
                "/Applications/Chromium.app",
            ] {
                if std::path::Path::new(bundle).exists() {
                    candidates.push((
                        "open".into(),
                        vec!["-na".into(), bundle.into(), "--args".into(), app.clone(), size.clone()],
                    ));
                }
            }
            candidates.push(("open".into(), vec![url.to_string()]));
        }

        #[cfg(target_os = "linux")]
        {
            if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
                return;
            }
            for bin in [
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
                "microsoft-edge",
            ] {
                candidates.push((bin.into(), vec![app.clone(), size.clone()]));
            }
            candidates.push(("xdg-open".into(), vec![url.to_string()]));
        }

        for (bin, args) in candidates {
            match Command::new(&bin).args(&args).spawn() {
                // `open` / `xdg-open` exit immediately; a non-zero status means "no such app".
                Ok(mut child) if bin == "open" || bin == "xdg-open" || bin == "rundll32" => {
                    if child.wait().is_ok_and(|s| s.success()) {
                        return;
                    }
                }
                Ok(_) => return,
                Err(_) => continue,
            }
        }
        tracing::warn!("could not open a browser window; open {url} manually");
    }

    pub async fn run_desktop_app(&self) -> Result<(), Box<dyn std::error::Error>> {
        let port = std::env::var("HIDE_GO_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or_else(|| self.state.get_config().proxy_port);

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
        let addr = listener.local_addr()?;
        // Update only the live runtime port so an ephemeral HIDE_GO_PORT or port 0
        // does not overwrite the user's persisted config.json.
        self.state.config.write().proxy_port = addr.port();
        let app = self.build_desktop_router();

        let ui_url = format!("http://{}", addr);
        tracing::info!("Hide-Go Standalone Desktop App running at {}", ui_url);
        Self::launch_native_desktop_window(&ui_url);

        axum::serve(listener, app).await?;
        Ok(())
    }
}

fn render_index_html(token: &str) -> String {
    let token_json = serde_json::to_string(token)
        .expect("admin token must serialize as a JSON string")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    let token_script = format!("<script>window.__HIDE_GO_TOKEN__={token_json};</script></head>");
    EMBEDDED_INDEX_HTML.replacen("</head>", &token_script, 1)
}

async fn serve_index(axum::extract::State(state): axum::extract::State<GatewayState>, headers: HeaderMap) -> Response {
    if !is_local_browser_request(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }

    // No cookie: browsers send 127.0.0.1 cookies to every local port. The token only lives in
    // this no-store page and is sent as a header by the console.
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        ],
        Html(render_index_html(state.admin_token())),
    )
        .into_response()
}

async fn serve_embedded_asset(uri: Uri) -> Response {
    if let Some(&(_, content_type, bytes)) = EMBEDDED_ASSETS.iter().find(|(path, _, _)| *path == uri.path()) {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            bytes,
        )
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, extract::State};

    #[tokio::test]
    async fn embedded_assets_match_index_links_and_contents() {
        assert!(!EMBEDDED_ASSETS.is_empty());
        let linked = |path: &str| EMBEDDED_INDEX_HTML.contains(path.trim_start_matches('/'));
        // Fonts and images are not linked from the page itself but from inside the CSS/JS bundle.
        let bundled = |path: &str| {
            EMBEDDED_ASSETS.iter().any(|&(owner, _, bytes)| {
                linked(owner) && String::from_utf8_lossy(bytes).contains(path.trim_start_matches('/'))
            })
        };
        for &(path, content_type, bytes) in EMBEDDED_ASSETS {
            assert!(path.starts_with("/assets/"));
            assert!(linked(path) || bundled(path), "{path} is embedded but never referenced");
            assert!(!bytes.is_empty());
            for url in [path.to_string(), format!("{path}?v=test")] {
                let response = serve_embedded_asset(url.parse().unwrap()).await;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                assert_eq!(body.as_ref(), bytes);
            }
        }
    }

    #[tokio::test]
    async fn embedded_assets_reject_unlisted_paths() {
        let mut paths = vec![
            "/assets/not-embedded.js".to_string(),
            "/assets/not-embedded.css".to_string(),
            "/assets/index.js.map".to_string(),
            "/assets/index.html".to_string(),
        ];
        for &(path, _, _) in EMBEDDED_ASSETS {
            paths.push(format!("/unlisted{path}"));
            paths.push(format!("{path}.js"));
            paths.push(format!("{path}.css"));
        }
        for path in paths {
            let response = serve_embedded_asset(path.parse().unwrap()).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[test]
    fn index_token_is_json_and_cannot_close_the_script() {
        let token = "</script><script>alert(\"x\")</script>&'\\\n\r\t\0\u{001b}\u{2028}\u{2029}";
        let html = render_index_html(token);
        let (_, script) = html.split_once("<script>window.__HIDE_GO_TOKEN__=").unwrap();
        let (json, _) = script.split_once(";</script>").unwrap();
        assert!(!json.contains(['<', '>', '&', '\u{2028}', '\u{2029}']));
        assert_eq!(serde_json::from_str::<String>(json).unwrap(), token);
        assert_eq!(
            html.matches("</script>").count(),
            EMBEDDED_INDEX_HTML.matches("</script>").count() + 1
        );
    }

    #[tokio::test]
    async fn local_index_is_not_cached_and_sets_no_cookie() {
        let state = GatewayState::default();
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
                assert!(response.headers().contains_key(header::CONTENT_SECURITY_POLICY));
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                assert_eq!(body.as_ref(), render_index_html(state.admin_token()).as_bytes());
            }
        }
    }

    #[tokio::test]
    async fn index_rejects_rebinding_and_cross_origin_requests() {
        let state = GatewayState::default();
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
}
