#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod installer;

use axum::{
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hide_core::config::{HarnessKind, HideConfig};
use hide_core::harness_detect::{connect_harness, detect_all_harness_profiles};
use hide_core::proxy::is_local_browser_request;
use installer::{
    configured_proxy_port, current_platform, default_install_dir, desktop_bin_name, detect_existing_install,
    is_reparse_or_symlink, manifest_path, perform_install, perform_uninstall, schedule_self_cleanup,
    validate_install_dir, EmbeddedPayloads, InstallManifest, InstallOptions, UninstallOptions,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/embedded_setup_assets.rs"));

fn payloads() -> EmbeddedPayloads<'static> {
    EmbeddedPayloads {
        desktop_bin: EMBEDDED_DESKTOP_BIN,
        daemon_bin: EMBEDDED_DAEMON_BIN,
        icon_ico: EMBEDDED_ICON_ICO,
        icon_png: EMBEDDED_ICON_PNG,
        version: env!("CARGO_PKG_VERSION"),
    }
}

#[derive(Clone)]
struct SetupState {
    mode: &'static str,
    token: Arc<String>,
    shutdown: Arc<Notify>,
    pending_cleanup: Arc<Mutex<Option<PathBuf>>>,
    ui_seen: Arc<AtomicBool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupInfoResponse {
    mode: &'static str,
    version: &'static str,
    platform: &'static str,
    has_embedded_binaries: bool,
    default_install_dir: String,
    already_installed: bool,
    existing_install_dir: Option<String>,
    default_proxy_port: u16,
    config_path: Option<String>,
    harnesses: Vec<hide_core::harness::HarnessProfile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectHarnessesReq {
    kinds: Vec<HarnessKind>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LaunchReq {
    install_dir: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PickDirReq {
    initial_dir: Option<String>,
}

struct CliArgs {
    mode: &'static str,
    silent: bool,
    install_dir: Option<String>,
    create_shortcuts: bool,
    add_to_path: bool,
    autostart_daemon: bool,
    auto_connect: bool,
    remove_config: bool,
}

fn exe_looks_like_uninstaller() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase()))
        .is_some_and(|stem| stem.contains("uninstall"))
}

fn parse_args() -> CliArgs {
    parse_args_from(std::env::args().skip(1), exe_looks_like_uninstaller())
}

fn parse_args_from<I: Iterator<Item = String>>(mut it: I, exe_is_uninstall: bool) -> CliArgs {
    let mut args = CliArgs {
        mode: if exe_is_uninstall { "uninstall" } else { "install" },
        silent: false,
        install_dir: None,
        create_shortcuts: true,
        add_to_path: true,
        autostart_daemon: false,
        auto_connect: false,
        remove_config: false,
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--uninstall" => args.mode = "uninstall",
            "--install" => args.mode = "install",
            "--silent" => args.silent = true,
            "--no-shortcuts" => args.create_shortcuts = false,
            "--no-path" => args.add_to_path = false,
            "--autostart" => args.autostart_daemon = true,
            "--auto-connect" => args.auto_connect = true,
            "--remove-config" => args.remove_config = true,
            "--dir" => {
                if let Some(d) = it.next() {
                    args.install_dir = Some(d);
                }
            }
            _ => {}
        }
    }
    args
}

fn render_setup_html(token: &str, nonce: &str) -> String {
    let token_json = serde_json::to_string(token)
        .expect("setup token must serialize as JSON string")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    let token_script =
        format!("<script nonce=\"{nonce}\">window.__HIDE_GO_SETUP_TOKEN__={token_json};</script></head>");
    EMBEDDED_SETUP_HTML
        .replace("nonce=\"__HIDE_GO_NONCE__\"", &format!("nonce=\"{nonce}\""))
        .replacen("</head>", &token_script, 1)
}

async fn require_setup_auth(State(state): State<SetupState>, req: axum::extract::Request, next: Next) -> Response {
    let headers = req.headers();
    if !is_local_browser_request(headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "cross_origin_forbidden"})),
        )
            .into_response();
    }
    let supplied = headers
        .get("x-hide-go-setup-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if supplied != Some(state.token.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_setup_token"})),
        )
            .into_response();
    }
    next.run(req).await
}

async fn serve_setup_index(State(state): State<SetupState>, headers: HeaderMap) -> Response {
    if !is_local_browser_request(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    state.ui_seen.store(true, Ordering::Relaxed);
    let nonce = hide_chrome::generate_csp_nonce();
    let csp = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
    let csp_header = HeaderValue::from_str(&csp).unwrap_or_else(|_| {
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
    });
    let mut resp = Html(render_setup_html(&state.token, &nonce)).into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, csp_header);
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

async fn serve_asset(AxumPath(path): AxumPath<String>) -> Response {
    let req_path = format!("/assets/{}", path.trim_start_matches('/'));
    if let Some((_, content_type, bytes)) = EMBEDDED_ASSETS.iter().find(|(p, _, _)| *p == req_path) {
        (
            [
                (header::CONTENT_TYPE, *content_type),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            *bytes,
        )
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn api_setup_info(State(state): State<SetupState>) -> Response {
    match tokio::task::spawn_blocking(move || {
        let existing = detect_existing_install();
        let cfg_path = HideConfig::default_path();
        let port = configured_proxy_port(cfg_path.as_deref());
        let harnesses = detect_all_harness_profiles(port, &HashMap::new());
        SetupInfoResponse {
            mode: state.mode,
            version: env!("CARGO_PKG_VERSION"),
            platform: current_platform(),
            has_embedded_binaries: EMBEDDED_DESKTOP_BIN.is_some() && EMBEDDED_DAEMON_BIN.is_some(),
            default_install_dir: default_install_dir().to_string_lossy().into_owned(),
            already_installed: existing.is_some(),
            existing_install_dir: existing.map(|m| m.install_dir),
            default_proxy_port: port,
            config_path: cfg_path.map(|p| p.to_string_lossy().into_owned()),
            harnesses,
        }
    })
    .await
    {
        Ok(info) => Json(info).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn api_setup_pick_dir(body: Option<Json<PickDirReq>>) -> Response {
    let initial = body
        .and_then(|Json(req)| req.initial_dir)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    match tokio::task::spawn_blocking(move || hide_chrome::pick_folder("选择 Hide-Go 安装目录", initial.as_deref()))
        .await
    {
        Ok(chosen) => Json(serde_json::json!({
            "path": chosen.map(|p| p.to_string_lossy().into_owned())
        }))
        .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn api_setup_install(Json(opts): Json<InstallOptions>) -> Response {
    match tokio::task::spawn_blocking(move || {
        hide_chrome::terminate_other_hide_go_processes();
        perform_install(&opts, &payloads())
    })
    .await
    {
        Ok(out) => Json(out).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn api_setup_connect_harnesses(Json(req): Json<ConnectHarnessesReq>) -> Response {
    match tokio::task::spawn_blocking(move || {
        let port = configured_proxy_port(HideConfig::default_path().as_deref());
        req.kinds
            .into_iter()
            .map(|k| connect_harness(k, port))
            .collect::<Vec<_>>()
    })
    .await
    {
        Ok(res) => Json(res).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn api_setup_uninstall(State(state): State<SetupState>, Json(opts): Json<UninstallOptions>) -> Response {
    match tokio::task::spawn_blocking(move || {
        hide_chrome::terminate_other_hide_go_processes();
        perform_uninstall(&opts)
    })
    .await
    {
        Ok(out) => {
            if let Some(dir) = out.pending_cleanup_dir.clone() {
                if let Ok(mut slot) = state.pending_cleanup.lock() {
                    *slot = Some(dir);
                }
            }
            Json(out).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn validate_launch_target(dir: &std::path::Path) -> Result<PathBuf, (StatusCode, String)> {
    validate_install_dir(dir).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mp = manifest_path(dir);
    if is_reparse_or_symlink(&mp) {
        return Err((StatusCode::FORBIDDEN, "安装清单路径是符号链接，拒绝启动".into()));
    }
    let raw = std::fs::read_to_string(&mp).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "未检测到有效 install-manifest.json，拒绝从未经验证目录启动程序".into(),
        )
    })?;
    let manifest: InstallManifest = serde_json::from_str(&raw).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "install-manifest.json 格式无效，拒绝启动程序".into(),
        )
    })?;
    let manifest_dir = PathBuf::from(manifest.install_dir.trim());
    let norm = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let same = {
        let a = norm(&manifest_dir);
        let b = norm(dir);
        #[cfg(windows)]
        {
            a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
        }
        #[cfg(not(windows))]
        {
            a == b
        }
    };
    if !same {
        return Err((StatusCode::FORBIDDEN, "安装目录与安装清单不匹配，拒绝启动".into()));
    }
    let exe = dir.join(desktop_bin_name());
    if is_reparse_or_symlink(&exe) {
        return Err((StatusCode::FORBIDDEN, "目标程序是符号链接，拒绝启动".into()));
    }
    if !exe.is_file() {
        return Err((StatusCode::NOT_FOUND, format!("未找到已安装的程序: {}", exe.display())));
    }
    Ok(exe)
}

async fn api_setup_launch(State(state): State<SetupState>, Json(req): Json<LaunchReq>) -> Response {
    let dir = req
        .install_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_install_dir);
    let exe = match validate_launch_target(&dir) {
        Ok(exe) => exe,
        Err((status, msg)) => {
            return (status, Json(serde_json::json!({"message": msg}))).into_response();
        }
    };
    match Command::new(&exe).spawn() {
        Ok(_) => {
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                shutdown.notify_one();
            });
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": format!("启动失败: {e}")})),
        )
            .into_response(),
    }
}

async fn api_setup_quit(State(state): State<SetupState>) -> Response {
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        shutdown.notify_one();
    });
    Json(serde_json::json!({"ok": true})).into_response()
}

fn build_setup_router(state: SetupState) -> Router {
    let api = Router::new()
        .route("/info", get(api_setup_info))
        .route("/pick-dir", post(api_setup_pick_dir))
        .route("/install", post(api_setup_install))
        .route("/connect-harnesses", post(api_setup_connect_harnesses))
        .route("/uninstall", post(api_setup_uninstall))
        .route("/launch", post(api_setup_launch))
        .route("/quit", post(api_setup_quit))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_setup_auth));

    Router::new()
        .route("/", get(serve_setup_index))
        .route("/assets/*path", get(serve_asset))
        .nest("/api/setup", api)
        .with_state(state)
}

fn setup_webview_data_dir() -> (PathBuf, Option<PathBuf>) {
    match hide_chrome::create_private_temp_dir("hide-go-setup-webview") {
        Ok(dir) => (dir.clone(), Some(dir)),
        Err(_) => (std::env::temp_dir().join("Hide-Go-Setup-WebView2"), None),
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = parse_args();
    let silent = cli.silent;
    if let Err(err) = run(cli) {
        tracing::error!("Hide-Go Setup failed: {err}");
        if silent {
            eprintln!("Hide-Go Setup failed: {err}");
        } else {
            hide_chrome::show_error_dialog("Hide-Go Setup 启动失败", &err.to_string());
        }
        std::process::exit(1);
    }
}

fn run(cli: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    if cli.silent {
        hide_chrome::terminate_other_hide_go_processes();
        if cli.mode == "uninstall" {
            let out = perform_uninstall(&UninstallOptions {
                install_dir: cli.install_dir,
                remove_config: cli.remove_config,
            });
            if let Some(dir) = out.pending_cleanup_dir {
                schedule_self_cleanup(&dir);
            }
            if !out.ok {
                let msg = out.error.unwrap_or_else(|| "silent uninstall failed".to_string());
                return Err(msg.into());
            }
            return Ok(());
        } else {
            let out = perform_install(
                &InstallOptions {
                    install_dir: cli.install_dir,
                    create_shortcuts: cli.create_shortcuts,
                    add_to_path: cli.add_to_path,
                    autostart_daemon: cli.autostart_daemon,
                },
                &payloads(),
            );
            if !out.ok {
                let msg = out.error.unwrap_or_else(|| "silent install failed".to_string());
                return Err(msg.into());
            }
            if cli.auto_connect {
                let port = configured_proxy_port(HideConfig::default_path().as_deref());
                let results = hide_core::harness_detect::connect_all_detected(port);
                for res in results.into_iter().filter(|r| !r.ok) {
                    tracing::warn!("auto-connect {:?} failed: {}", res.kind, res.message);
                }
            }
            return Ok(());
        }
    }

    let shutdown = Arc::new(Notify::new());
    let pending_cleanup = Arc::new(Mutex::new(None));
    let ui_seen = Arc::new(AtomicBool::new(false));
    let token = Arc::new(format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()));
    let state = SetupState {
        mode: cli.mode,
        token,
        shutdown: shutdown.clone(),
        pending_cleanup: pending_cleanup.clone(),
        ui_seen: ui_seen.clone(),
    };
    let app = build_setup_router(state);
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
            let listener = match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await {
                Ok(l) => l,
                Err(e) => {
                    let _ = tx.send(Err(format!("bind failed: {e}")));
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
            let url = format!("http://{addr}/");
            tracing::info!("Hide-Go Setup listening on {url}");
            let _ = tx.send(Ok(url));
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    tokio::select! {
                        _ = shutdown_server.notified() => {}
                        _ = tokio::signal::ctrl_c() => {}
                    }
                })
                .await
            {
                tracing::error!("setup server error: {e}");
            }
        });
    });

    let url = rx
        .recv()
        .map_err(|e| format!("setup startup channel closed: {e}"))?
        .map_err(|e| format!("failed to start setup server: {e}"))?;

    let title = if cli.mode == "uninstall" {
        "Hide-Go 卸载向导"
    } else {
        "Hide-Go 安装向导"
    };

    if hide_chrome::can_open_gui() {
        let (webview_dir, temp_webview_dir) = setup_webview_data_dir();
        let win_res = hide_chrome::run_frameless_window(hide_chrome::NativeWindowOptions {
            title: title.into(),
            url: url.clone(),
            width: 840.0,
            height: 580.0,
            min_width: 780.0,
            min_height: 540.0,
            resizable: false,
            cleanup_on_close: false,
            user_data_dir: Some(webview_dir),
        });
        if win_res.is_ok() {
            shutdown.notify_one();
        } else {
            tracing::warn!("Hide-Go Setup opened in system browser at {url}");
            let watchdog_shutdown = shutdown.clone();
            let watchdog_seen = ui_seen.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(45));
                if !watchdog_seen.load(Ordering::Relaxed) {
                    tracing::warn!("no browser UI connected within 45s after WebView fallback; shutting down cleanly");
                    watchdog_shutdown.notify_one();
                }
            });
        }
        let _ = server_thread.join();
        if let Some(tmp_dir) = temp_webview_dir {
            let _ = std::fs::remove_dir_all(tmp_dir);
        }
    } else {
        tracing::info!("Hide-Go Setup headless URL: {url}");
        eprintln!("Hide-Go Setup listening on {url}");
        let _ = server_thread.join();
    }
    if let Some(dir) = pending_cleanup.lock().ok().and_then(|mut g| g.take()) {
        schedule_self_cleanup(&dir);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request};
    use tower::util::ServiceExt;

    #[test]
    fn embedded_setup_assets_match_html_links() {
        for attr in ["src=\"", "href=\""] {
            let mut rest = EMBEDDED_SETUP_HTML;
            while let Some(i) = rest.find(attr) {
                rest = &rest[i + attr.len()..];
                let end = rest.find('"').unwrap();
                let url = &rest[..end];
                if url.starts_with("/assets/") {
                    assert!(
                        EMBEDDED_ASSETS
                            .iter()
                            .any(|(path, _, bytes)| *path == url && !bytes.is_empty()),
                        "missing embedded setup asset {url}"
                    );
                }
            }
        }
    }

    #[test]
    fn setup_token_escaping_blocks_script_breakout() {
        let html = render_setup_html("</script><script>alert(1)</script>", "testnonce123");
        assert!(!html.contains("</script><script>alert(1)</script>"));
        assert!(html.contains("\\u003c/script\\u003e"));
        assert!(html.contains("<script nonce=\"testnonce123\">window.__HIDE_GO_SETUP_TOKEN__="));
    }

    #[tokio::test]
    async fn setup_api_requires_token_and_local_origin() {
        let state = SetupState {
            mode: "install",
            token: Arc::new("secret".into()),
            shutdown: Arc::new(Notify::new()),
            pending_cleanup: Arc::new(Mutex::new(None)),
            ui_seen: Arc::new(AtomicBool::new(false)),
        };
        let app = build_setup_router(state);

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/setup/info")
                    .header("host", "127.0.0.1:49999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let evil = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/setup/info")
                    .header("host", "127.0.0.1:49999")
                    .header("origin", "https://evil.example")
                    .header("x-hide-go-setup-token", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(evil.status(), StatusCode::FORBIDDEN);

        let pick_unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/setup/pick-dir")
                    .header("host", "127.0.0.1:49999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pick_unauth.status(), StatusCode::UNAUTHORIZED);

        let ok = app
            .oneshot(
                Request::builder()
                    .uri("/api/setup/info")
                    .header("host", "127.0.0.1:49999")
                    .header("x-hide-go-setup-token", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[test]
    fn uninstall_binary_name_defaults_to_uninstall_mode() {
        assert_eq!(parse_args_from(std::iter::empty(), true).mode, "uninstall");
        assert_eq!(
            parse_args_from(["--install".to_string()].into_iter(), true).mode,
            "install"
        );
        assert_eq!(parse_args_from(std::iter::empty(), false).mode, "install");
        assert_eq!(
            parse_args_from(["--uninstall".to_string()].into_iter(), false).mode,
            "uninstall"
        );
    }

    #[tokio::test]
    async fn setup_index_sets_nonce_csp_and_rejects_unvalidated_launch() {
        let state = SetupState {
            mode: "install",
            token: Arc::new("secret".into()),
            shutdown: Arc::new(Notify::new()),
            pending_cleanup: Arc::new(Mutex::new(None)),
            ui_seen: Arc::new(AtomicBool::new(false)),
        };
        let app = build_setup_router(state);
        let index_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "127.0.0.1:49999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(index_resp.status(), StatusCode::OK);
        let csp = index_resp.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("script-src 'self' 'nonce-"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));

        let bad_launch = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/setup/launch")
                    .header("host", "127.0.0.1:49999")
                    .header("content-type", "application/json")
                    .header("x-hide-go-setup-token", "secret")
                    .body(Body::from(r#"{"installDir":"relative/path"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_launch.status(), StatusCode::BAD_REQUEST);
    }
}
