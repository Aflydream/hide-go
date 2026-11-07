use axum::{
    http::{header, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use hide_core::{
    build_router,
    harness::HarnessProfile,
    vault::VaultEntry,
    GatewayState, HarnessKind, HideConfig, TrafficAuditRecord, TrafficCategory,
};
use std::net::SocketAddr;
use std::process::Command;
use tokio::net::TcpListener;

/// Embedded Desktop UI assets compiled into the single Rust binary
const EMBEDDED_INDEX_HTML: &str = include_str!("../../dist/index.html");
const EMBEDDED_CSS: &[u8] = include_bytes!("../../dist/assets/index-D0EjfAtG.css");
const EMBEDDED_JS: &[u8] = include_bytes!("../../dist/assets/index-BtEHzYbi.js");

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
    pub fn new() -> Self {
        Self {
            state: GatewayState::default(),
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

    /// Launch native OS desktop window (Windows Edge/Chrome App mode, macOS WebKit/App window, Linux WebView/App window)
    pub fn launch_native_desktop_window(url: &str) {
        if std::env::var("HIDE_GO_HEADLESS").is_ok() {
            return;
        }

        #[cfg(target_os = "windows")]
        {
            let edge_status = Command::new("cmd")
                .args([
                    "/C",
                    "start",
                    "",
                    "msedge",
                    &format!("--app={}", url),
                    "--window-size=1420,920",
                ])
                .spawn();
            if edge_status.is_err() {
                let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
            }
        }

        #[cfg(target_os = "macos")]
        {
            let chrome_app = Command::new("open")
                .args([
                    "-na",
                    "Google Chrome",
                    "--args",
                    &format!("--app={}", url),
                    "--window-size=1420,920",
                ])
                .spawn();
            if chrome_app.is_err() {
                let _ = Command::new("open").arg(url).spawn();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok() {
                let candidates = [
                    (
                        "google-chrome",
                        vec![
                            format!("--app={}", url),
                            "--window-size=1420,920".to_string(),
                        ],
                    ),
                    (
                        "chromium",
                        vec![
                            format!("--app={}", url),
                            "--window-size=1420,920".to_string(),
                        ],
                    ),
                    ("xdg-open", vec![url.to_string()]),
                ];
                for (bin, args) in candidates {
                    if Command::new(bin).args(&args).spawn().is_ok() {
                        break;
                    }
                }
            }
        }
    }

    pub async fn run_desktop_app(&self) -> Result<(), Box<dyn std::error::Error>> {
        let port = std::env::var("HIDE_GO_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or_else(|| self.state.get_config().proxy_port);

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let app = self.build_desktop_router();
        let listener = TcpListener::bind(addr).await?;

        let ui_url = format!("http://{}", addr);
        tracing::info!("🛡️ Hide-Go Standalone Desktop App running at {}", ui_url);
        Self::launch_native_desktop_window(&ui_url);

        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn serve_index(
    axum::extract::State(state): axum::extract::State<GatewayState>,
) -> Response {
    let token = state.admin_token();
    let token_script = format!(
        "<script>window.__HIDE_GO_TOKEN__={:?};</script></head>",
        token
    );
    let html_with_token = EMBEDDED_INDEX_HTML.replacen("</head>", &token_script, 1);
    let cookie = format!(
        "hide_go_session={}; HttpOnly; SameSite=Strict; Path=/",
        token
    );

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::SET_COOKIE, cookie),
        ],
        Html(html_with_token),
    )
        .into_response()
}

async fn serve_embedded_asset(uri: Uri) -> Response {
    let path = uri.path();
    if path.ends_with(".css") {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
            EMBEDDED_CSS,
        )
            .into_response()
    } else if path.ends_with(".js") {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
            EMBEDDED_JS,
        )
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

