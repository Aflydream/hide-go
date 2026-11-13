#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use hide_go_desktop_lib::DesktopBridge;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bridge = DesktopBridge::new();
    bridge.run_desktop_app().await
}
