use axum::body::Body;
use hide_core::{build_gateway_proxy_service, GatewayState, HideConfig, MIN_ADMIN_TOKEN_LEN};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower_service::Service;

const MAX_CONCURRENT_CONNECTIONS: usize = 512;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HTTP_BUF_SIZE: usize = 64 * 1024;

pub fn run_daemon() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_daemon_async())
}

async fn run_daemon_async() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(raw_token) = std::env::var("HIDE_GO_ADMIN_TOKEN") {
        let trimmed = raw_token.trim();
        if !trimmed.is_empty() && trimmed.len() < MIN_ADMIN_TOKEN_LEN {
            return Err(format!(
                "HIDE_GO_ADMIN_TOKEN is too short ({} chars); minimum required is {MIN_ADMIN_TOKEN_LEN} characters",
                trimmed.len()
            )
            .into());
        }
    }

    let config_path = HideConfig::default_path();
    let mut config = config_path
        .as_deref()
        .map(HideConfig::load_or_create)
        .unwrap_or_default();
    let port = std::env::var("HIDE_GO_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(config.proxy_port);

    config.proxy_port = port;
    let mut state = GatewayState::new(config);
    state.config_path = config_path.map(Arc::new);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    let addr = listener.local_addr()?;
    state.config.write().proxy_port = addr.port();
    let _sys_proxy_guard =
        hide_core::system_proxy::SystemProxyRuntimeGuard::start(state.get_config().system_proxy_chain, addr.port());

    tracing::info!("Hide-Go gateway listening on http://{addr}");
    if std::env::var("HIDE_GO_ADMIN_TOKEN").is_err() {
        tracing::info!(
            "management API authentication enabled with ephemeral random token (set HIDE_GO_ADMIN_TOKEN >= {MIN_ADMIN_TOKEN_LEN} chars to pin it)"
        );
    }

    let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        #[cfg(unix)]
        let shutdown_sig = async {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        };
        #[cfg(not(unix))]
        let shutdown_sig = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        tokio::select! {
            _ = shutdown_sig => {
                tracing::info!("shutdown signal received; stopping Hide-Go daemon");
                break;
            }
            accept_res = listener.accept() => {
                let (stream, peer_addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!("accept error: {err}");
                        continue;
                    }
                };
                if !peer_addr.ip().is_loopback() {
                    tracing::warn!("rejected non-loopback peer connection from {peer_addr}");
                    drop(stream);
                    continue;
                }
                let Ok(permit) = conn_semaphore.clone().try_acquire_owned() else {
                    tracing::warn!("connection limit ({MAX_CONCURRENT_CONNECTIONS}) reached; dropping {peer_addr}");
                    drop(stream);
                    continue;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let proxy_svc = build_gateway_proxy_service(state, None, Some(peer_addr));
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let mut proxy_svc = proxy_svc.clone();
                        async move { proxy_svc.call(req.map(Body::new)).await }
                    });
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .max_buf_size(MAX_HTTP_BUF_SIZE)
                        .serve_connection(TokioIo::new(stream), svc)
                        .with_upgrades()
                        .await
                    {
                        tracing::debug!("daemon connection closed ({peer_addr}): {err}");
                    }
                });
            }
        }
    }
    Ok(())
}
