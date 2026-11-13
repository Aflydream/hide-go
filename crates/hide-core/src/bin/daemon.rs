use hide_core::{build_router, GatewayState, HideConfig};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config_path = HideConfig::default_path();
    let mut config = config_path
        .as_deref()
        .map(HideConfig::load_or_create)
        .unwrap_or_default();
    let port = std::env::var("HIDE_GO_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(config.proxy_port);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    let addr = listener.local_addr()?;
    config.proxy_port = addr.port();
    let mut state = GatewayState::new(config);
    state.config_path = config_path.map(std::sync::Arc::new);
    let app = build_router(state.clone());

    tracing::info!("Hide-Go gateway listening on http://{addr}");
    if std::env::var("HIDE_GO_ADMIN_TOKEN").is_err() {
        tracing::info!(
            "management API token (set HIDE_GO_ADMIN_TOKEN to pin it): {}",
            state.admin_token()
        );
    }

    axum::serve(listener, app).await?;
    Ok(())
}
