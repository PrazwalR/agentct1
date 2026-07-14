use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("AGENTCTL_ENGINE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8088);
    // Default to loopback-only, matching the Node control plane's default. Set
    // AGENTCTL_ENGINE_HOST=0.0.0.0 explicitly to accept non-local connections.
    let host: std::net::IpAddr = std::env::var("AGENTCTL_ENGINE_HOST")
        .ok()
        .and_then(|h| h.parse().ok())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let addr = SocketAddr::from((host, port));

    let token = std::env::var("AGENTCTL_ENGINE_TOKEN").ok();
    if token.is_none() {
        eprintln!(
            "warning: AGENTCTL_ENGINE_TOKEN not set — /score and /inspect/* are unauthenticated"
        );
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    println!("agentctl-engine listening on http://{addr}");
    axum::serve(listener, agentctl_engine::api::app(token))
        .await
        .expect("server error");
}
