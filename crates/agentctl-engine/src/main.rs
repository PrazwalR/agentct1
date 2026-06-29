use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("AGENTCTL_ENGINE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8088);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    println!("agentctl-engine listening on http://{addr}");
    axum::serve(listener, agentctl_engine::api::app())
        .await
        .expect("server error");
}
