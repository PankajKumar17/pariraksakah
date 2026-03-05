// CyberShield-X Self-Healing Code DNA — Main Entry Point
use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "self-healing",
        "version": "1.0.0"
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/health", get(health_check));

    let port: u16 = std::env::var("SELF_HEALING_PORT")
        .unwrap_or_else(|_| "8008".to_string())
        .parse()
        .unwrap_or(8008);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Self-Healing service starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
