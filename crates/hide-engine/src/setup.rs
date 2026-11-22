use crate::chrome_bridge::is_reparse_or_symlink;
use crate::{
    chrome_bridge::{
        create_private_temp_dir, desktop_bin_name, generate_csp_nonce, normalize_locale_tag, ChromeHost,
        NativeWindowOptions,
    },
    installer::{
        configured_language, configured_proxy_port, current_platform, default_install_dir, detect_existing_install,
        discover_package_root, has_install_payload, manifest_path, perform_install, perform_uninstall, same_path,
        schedule_self_cleanup, validate_install_dir, EmbeddedPayloadArchive, InstallManifest, InstallOptions,
        PayloadSource, UninstallOptions,
    },
    web_assets::{build_nonce_csp, resolve_resources_dir, UiBundle},
};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hide_core::config::{HarnessKind, HideConfig, UiLanguage};
use hide_core::harness_detect::{connect_harness, detect_all_harness_profiles};
use hide_core::proxy::is_local_browser_request;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone, Default)]
struct LocaleMessages {
    zh_cn: Arc<HashMap<String, String>>,
    en: Arc<HashMap<String, String>>,
}

impl LocaleMessages {
    fn from_embedded(zh_cn_json: &str, en_json: &str) -> Self {
        let parse = |raw: &str| -> HashMap<String, String> {
            serde_json::from_str::<HashMap<String, String>>(raw.trim_start_matches('\u{feff}')).unwrap_or_default()
        };
        Self {
            zh_cn: Arc::new(parse(zh_cn_json)),
            en: Arc::new(parse(en_json)),
        }
    }

    fn load_from_dir(dir: &Path) -> Self {
        let load_file = |name: &str| -> HashMap<String, String> {
            let p = dir.join(name);
            if is_reparse_or_symlink(&p) || !p.is_file() {
                return HashMap::new();
            }
            std::fs::read_to_string(&p)
                .ok()
                .and_then(|s| serde_json::from_str::<HashMap<String, String>>(&s).ok())
                .unwrap_or_default()
        };
        Self {
            zh_cn: Arc::new(load_file("zh-CN.json")),
            en: Arc::new(load_file("en.json")),
        }
    }

    fn get(&self, locale: &str, key: &str) -> String {
        let primary = if locale == "zh-CN" { &self.zh_cn } else { &self.en };
        primary
            .get(key)
            .or_else(|| self.en.get(key))
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }
}

fn load_setup_locales(exe_dir: Option<&Path>) -> LocaleMessages {
    if let Some(res_dir) = resolve_resources_dir(exe_dir) {
        let loc_dir = res_dir.join("locales");
        if loc_dir.is_dir() && !is_reparse_or_symlink(&loc_dir) {
            return LocaleMessages::load_from_dir(&loc_dir);
        }
    }
    #[cfg(debug_assertions)]
    {
        let dev_loc = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/locales");
        if dev_loc.is_dir() {
            return LocaleMessages::load_from_dir(&dev_loc);
        }
    }
    LocaleMessages::default()
}

fn load_setup_ui_bundle(exe_dir: Option<&Path>) -> Result<UiBundle, String> {
    if let Some(res_dir) = resolve_resources_dir(exe_dir) {
        let setup_dir = res_dir.join("setup");
        if setup_dir.is_dir() {
            return UiBundle::load_from_dir(&setup_dir, "setup.html");
        }
    }
    #[cfg(debug_assertions)]
    {
        let dev_dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist");
        if dev_dist.join("setup.html").is_file() {
            return UiBundle::load_from_dir(&dev_dist, "setup.html");
        }
        let cwd_dist = PathBuf::from("dist");
        if cwd_dist.join("setup.html").is_file() {
            return UiBundle::load_from_dir(&cwd_dist, "setup.html");
        }
    }
    let checked = exe_dir
        .map(|d| d.join("resources/setup"))
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("resources/setup")))
        })
        .map(|p| format!(" ({})", p.display()))
        .unwrap_or_default();
    Err(format!(
        "缺少安装向导界面资源 resources/setup/{checked}，请保持安装压缩包目录完整解压后运行。\nMissing resources/setup/ directory{checked}; extract the full Setup archive before launching."
    ))
}

pub struct EmbeddedSetupAssets {
    pub ui: UiBundle,
    pub zh_cn_json: &'static str,
    pub en_json: &'static str,
    pub payload_archive: Option<EmbeddedPayloadArchive>,
}

fn payloads_for_exe(exe_dir: Option<&Path>, embedded_archive: Option<EmbeddedPayloadArchive>) -> PayloadSource {
    PayloadSource {
        package_root: discover_package_root(exe_dir),
        embedded_archive,
        require_manifest: !cfg!(debug_assertions),
        version: env!("CARGO_PKG_VERSION"),
    }
}

#[derive(Clone)]
struct SetupState {
    mode: &'static str,
    token: Arc<String>,
    exe_dir: Option<Arc<PathBuf>>,
    embedded_archive: Option<EmbeddedPayloadArchive>,
    ui: Arc<UiBundle>,
    chrome: Arc<dyn ChromeHost>,
    locales: LocaleMessages,
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
    system_locale: &'static str,
    language: UiLanguage,
    has_install_payload: bool,
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
    #[serde(default)]
    locale: Option<String>,
}

struct CliArgs {
    mode: &'static str,
    silent: bool,
    install_dir: Option<String>,
    create_desktop_shortcut: bool,
    create_start_menu_shortcut: bool,
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
        create_desktop_shortcut: true,
        create_start_menu_shortcut: true,
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
            "--no-shortcuts" => {
                args.create_desktop_shortcut = false;
                args.create_start_menu_shortcut = false;
            }
            "--no-desktop-shortcut" => args.create_desktop_shortcut = false,
            "--no-start-menu" => args.create_start_menu_shortcut = false,
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

fn render_setup_html(ui: &UiBundle, chrome: &dyn ChromeHost, token: &str, nonce: &str) -> String {
    let sys_locale = chrome.detect_system_locale();
    ui.render_html(sys_locale, nonce, "__HIDE_GO_SETUP_TOKEN__", token)
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
    let nonce = generate_csp_nonce();
    let csp = build_nonce_csp(&nonce);
    let csp_header = HeaderValue::from_str(&csp).unwrap_or_else(|_| {
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
    });
    let mut resp = Html(render_setup_html(
        &state.ui,
        state.chrome.as_ref(),
        &state.token,
        &nonce,
    ))
    .into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, csp_header);
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

async fn serve_asset(State(state): State<SetupState>, uri: Uri) -> Response {
    state.ui.serve_asset(uri.path())
}

async fn api_setup_info(State(state): State<SetupState>) -> Response {
    let exe_dir = state.exe_dir.as_deref().cloned();
    let embedded_archive = state.embedded_archive;
    let chrome = state.chrome.clone();
    match tokio::task::spawn_blocking(move || {
        let existing = detect_existing_install();
        let cfg_path = HideConfig::default_path();
        let port = configured_proxy_port(cfg_path.as_deref());
        let language = configured_language(cfg_path.as_deref());
        let harnesses = detect_all_harness_profiles(port, &HashMap::new());
        let payload_source = payloads_for_exe(exe_dir.as_deref(), embedded_archive);
        SetupInfoResponse {
            mode: state.mode,
            version: env!("CARGO_PKG_VERSION"),
            platform: current_platform(),
            system_locale: chrome.detect_system_locale(),
            language,
            has_install_payload: has_install_payload(&payload_source),
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

async fn api_setup_pick_dir(State(state): State<SetupState>, body: Option<Json<PickDirReq>>) -> Response {
    let req = body.map(|Json(r)| r).unwrap_or_default();
    let initial = req
        .initial_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let locale = req
        .locale
        .as_deref()
        .map(normalize_locale_tag)
        .unwrap_or_else(|| state.chrome.detect_system_locale());
    let title = state.locales.get(locale, "setup.pickDirTitle");
    let chrome = state.chrome.clone();
    match tokio::task::spawn_blocking(move || chrome.pick_folder(&title, initial.as_deref())).await {
        Ok(chosen) => Json(serde_json::json!({
            "path": chosen.map(|p| p.to_string_lossy().into_owned())
        }))
        .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn api_setup_install(State(state): State<SetupState>, Json(opts): Json<InstallOptions>) -> Response {
    let exe_dir = state.exe_dir.as_deref().cloned();
    let embedded_archive = state.embedded_archive;
    let chrome = state.chrome.clone();
    match tokio::task::spawn_blocking(move || {
        let src = payloads_for_exe(exe_dir.as_deref(), embedded_archive);
        perform_install(&opts, &src, chrome)
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
    let chrome = state.chrome.clone();
    match tokio::task::spawn_blocking(move || perform_uninstall(&opts, chrome)).await {
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

fn validate_launch_target(dir: &Path) -> Result<PathBuf, (StatusCode, String)> {
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
    if !same_path(&manifest_dir, dir) {
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
    match Command::new(&exe).current_dir(&dir).spawn() {
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
    match create_private_temp_dir("hide-go-setup-webview") {
        Ok(dir) => (dir.clone(), Some(dir)),
        Err(_) => (std::env::temp_dir().join("Hide-Go-Setup-WebView2"), None),
    }
}

pub fn localized_setup_message(locale: &str, zh_cn_json: &str, en_json: &str, key: &str) -> String {
    let locales = LocaleMessages::from_embedded(zh_cn_json, en_json);
    locales.get(locale, key).to_string()
}

pub fn run_setup_entry(exe_dir: Option<&Path>, chrome: Arc<dyn ChromeHost>) -> i32 {
    run_setup_impl(exe_dir, chrome, None)
}

pub fn run_setup_standalone(exe_dir: Option<&Path>, chrome: Arc<dyn ChromeHost>, embedded: EmbeddedSetupAssets) -> i32 {
    run_setup_impl(exe_dir, chrome, Some(embedded))
}

fn run_setup_impl(exe_dir: Option<&Path>, chrome: Arc<dyn ChromeHost>, embedded: Option<EmbeddedSetupAssets>) -> i32 {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let cli = parse_args();
    let silent = cli.silent;
    let fallback_locales = match &embedded {
        Some(emb) => LocaleMessages::from_embedded(emb.zh_cn_json, emb.en_json),
        None => load_setup_locales(exe_dir),
    };
    if let Err(err) = run(cli, exe_dir, chrome.clone(), embedded) {
        tracing::error!("Hide-Go Setup failed: {err}");
        if silent {
            eprintln!("Hide-Go Setup failed: {err}");
        } else {
            let sys_locale = chrome.detect_system_locale();
            let title = fallback_locales.get(sys_locale, "setup.launchErrorTitle");
            let title = if title.is_empty() { "Hide-Go Setup" } else { &title };
            chrome.show_error_dialog(title, &err.to_string());
        }
        return 1;
    }
    0
}

fn run(
    cli: CliArgs,
    exe_dir: Option<&Path>,
    chrome: Arc<dyn ChromeHost>,
    embedded: Option<EmbeddedSetupAssets>,
) -> Result<(), Box<dyn std::error::Error>> {
    let embedded_archive = embedded.as_ref().and_then(|e| e.payload_archive);
    if cli.silent {
        if cli.mode == "uninstall" {
            let out = perform_uninstall(
                &UninstallOptions {
                    install_dir: cli.install_dir,
                    remove_config: cli.remove_config,
                },
                chrome,
            );
            if let Some(dir) = out.pending_cleanup_dir {
                schedule_self_cleanup(&dir);
            }
            if !out.ok {
                let msg = out.error.unwrap_or_else(|| "silent uninstall failed".to_string());
                return Err(msg.into());
            }
            return Ok(());
        } else {
            let payloads = payloads_for_exe(exe_dir, embedded_archive);
            let out = perform_install(
                &InstallOptions {
                    install_dir: cli.install_dir,
                    create_shortcuts: cli.create_desktop_shortcut || cli.create_start_menu_shortcut,
                    create_desktop_shortcut: Some(cli.create_desktop_shortcut),
                    create_start_menu_shortcut: Some(cli.create_start_menu_shortcut),
                    add_to_path: cli.add_to_path,
                    autostart_daemon: cli.autostart_daemon,
                    language: None,
                },
                &payloads,
                chrome,
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

    let (ui, locales) = match embedded {
        Some(emb) => (
            Arc::new(emb.ui),
            LocaleMessages::from_embedded(emb.zh_cn_json, emb.en_json),
        ),
        None => (Arc::new(load_setup_ui_bundle(exe_dir)?), load_setup_locales(exe_dir)),
    };
    let shutdown = Arc::new(Notify::new());
    let pending_cleanup = Arc::new(Mutex::new(None));
    let ui_seen = Arc::new(AtomicBool::new(false));
    let token = Arc::new(format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()));
    let state = SetupState {
        mode: cli.mode,
        token,
        exe_dir: exe_dir.map(|p| Arc::new(p.to_path_buf())),
        embedded_archive,
        ui,
        chrome: chrome.clone(),
        locales: locales.clone(),
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

    let resolved_locale =
        configured_language(HideConfig::default_path().as_deref()).resolve(chrome.detect_system_locale());
    let title_key = if cli.mode == "uninstall" {
        "setup.windowTitle.uninstall"
    } else {
        "setup.windowTitle.install"
    };
    let title = locales.get(resolved_locale, title_key);

    if chrome.can_open_gui() {
        let (webview_dir, temp_webview_dir) = setup_webview_data_dir();
        let win_res = chrome.run_frameless_window(NativeWindowOptions {
            title,
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
    use crate::chrome_bridge::HeadlessChromeHost;
    use axum::{body::Body, extract::Request};
    use tower::util::ServiceExt;

    fn test_setup_state() -> SetupState {
        let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist");
        let ui = Arc::new(UiBundle::load_from_dir(&dist, "setup.html").expect("dist/setup.html must be built"));
        let loc_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/locales");
        let locales = LocaleMessages::load_from_dir(&loc_dir);
        SetupState {
            mode: "install",
            token: Arc::new("secret".into()),
            exe_dir: None,
            embedded_archive: None,
            ui,
            chrome: Arc::new(HeadlessChromeHost),
            locales,
            shutdown: Arc::new(Notify::new()),
            pending_cleanup: Arc::new(Mutex::new(None)),
            ui_seen: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn embedded_setup_assets_match_html_links() {
        let state = test_setup_state();
        for attr in ["src=\"", "href=\""] {
            let mut rest = state.ui.html.as_str();
            while let Some(i) = rest.find(attr) {
                rest = &rest[i + attr.len()..];
                let end = rest.find('"').unwrap();
                let url = &rest[..end];
                if url.starts_with("/assets/") {
                    assert!(
                        state.ui.assets.get(url).is_some_and(|(_, b)| !b.is_empty()),
                        "missing setup asset {url}"
                    );
                }
            }
        }
    }

    #[test]
    fn setup_token_escaping_blocks_script_breakout() {
        let state = test_setup_state();
        let html = render_setup_html(
            &state.ui,
            state.chrome.as_ref(),
            "</script><script>alert(1)</script>",
            "testnonce123",
        );
        assert!(!html.contains("</script><script>alert(1)</script>"));
        assert!(html.contains("\\u003c/script\\u003e"));
        assert!(html.contains("<script nonce=\"testnonce123\">window.__HIDE_GO_SETUP_TOKEN__="));
    }

    #[tokio::test]
    async fn setup_api_requires_token_and_local_origin() {
        let app = build_setup_router(test_setup_state());

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
    fn cli_shortcut_and_uninstall_flags_parse_correctly() {
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

        let desk_only = parse_args_from(["--no-start-menu".to_string()].into_iter(), false);
        assert!(desk_only.create_desktop_shortcut);
        assert!(!desk_only.create_start_menu_shortcut);

        let menu_only = parse_args_from(["--no-desktop-shortcut".to_string()].into_iter(), false);
        assert!(!menu_only.create_desktop_shortcut);
        assert!(menu_only.create_start_menu_shortcut);

        let none = parse_args_from(["--no-shortcuts".to_string()].into_iter(), false);
        assert!(!none.create_desktop_shortcut);
        assert!(!none.create_start_menu_shortcut);
    }

    #[tokio::test]
    async fn setup_index_sets_nonce_csp_and_rejects_unvalidated_launch() {
        let app = build_setup_router(test_setup_state());
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

    #[test]
    fn locale_resource_files_have_exact_key_parity_and_setup_titles() {
        use std::collections::BTreeSet;

        let loc_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/locales");
        let locales = LocaleMessages::load_from_dir(&loc_dir);
        let zh_keys: BTreeSet<&String> = locales.zh_cn.keys().collect();
        let en_keys: BTreeSet<&String> = locales.en.keys().collect();
        assert!(!zh_keys.is_empty());
        assert_eq!(zh_keys, en_keys, "zh-CN.json and en.json keys diverged");

        for key in [
            "setup.windowTitle.install",
            "setup.windowTitle.uninstall",
            "setup.pickDirTitle",
        ] {
            let zh_val = locales.get("zh-CN", key);
            let en_val = locales.get("en", key);
            assert_ne!(zh_val, key, "missing zh-CN key {key}");
            assert_ne!(en_val, key, "missing en key {key}");
            assert!(!zh_val.trim().is_empty());
            assert!(!en_val.trim().is_empty());
        }
    }

    #[test]
    fn embedded_setup_ui_and_locales_parse_cleanly() {
        let html = "<!doctype html><html><head><link rel=\"stylesheet\" href=\"/assets/app.css\"><script src=\"/assets/app.js\"></script></head><body></body></html>";
        let assets: [(&str, &str, &[u8]); 2] = [
            (
                "/assets/app.js",
                "application/javascript; charset=utf-8",
                b"console.log(1);",
            ),
            ("/assets/app.css", "text/css; charset=utf-8", b"body{}"),
        ];
        let bundle = UiBundle::from_embedded(html, &assets).expect("valid embedded UI bundle");
        assert_eq!(bundle.assets.len(), 2);
        assert!(UiBundle::from_embedded(html, &assets[..1]).is_err());

        let locales = LocaleMessages::from_embedded(
            r#"{"setup.windowTitle.install":"安装"}"#,
            r#"{"setup.windowTitle.install":"Setup"}"#,
        );
        assert_eq!(locales.get("zh-CN", "setup.windowTitle.install"), "安装");
        assert_eq!(locales.get("en", "setup.windowTitle.install"), "Setup");
    }
}
