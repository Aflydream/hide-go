#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use hide_go_desktop_lib::DesktopBridge;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bridge = DesktopBridge::new();
    if let Err(err) = bridge.run_desktop_app_blocking() {
        tracing::error!("Hide-Go Desktop failed to start: {err}");
        hide_chrome::show_error_dialog("Hide-Go 启动失败", &err.to_string());
        std::process::exit(1);
    }
}
