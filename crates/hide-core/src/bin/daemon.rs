use hide_core::{build_router, GatewayState, HideConfig};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = HideConfig::default();
    let port = std::env::var("HIDE_GO_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(config.proxy_port);

    let state = GatewayState::new(config);
    let app = build_router(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("🛡️ Hide-Go Privacy Firewall & All-Hide Gateway listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
