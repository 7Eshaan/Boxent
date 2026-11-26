//! MCP over Streamable HTTP, for daemon and multi-agent use.
//!
//! Off unless configured. When on, it listens on loopback only and every request needs
//! `Authorization: Bearer <token>`. The MCP SDK also checks `Host` (loopback names only, which
//! defeats DNS rebinding) and refuses any request that carries an `Origin` header, so a web page
//! in a browser cannot drive it. `/metrics` serves Prometheus metrics behind the same token.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use boxent_core::{Engine, EngineError};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio_util::sync::CancellationToken;

use super::server::{BoxentServer, Session};

#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Must be a loopback address.
    pub listen: SocketAddr,
    pub token: String,
}

/// Serves until `stop` is cancelled.
pub async fn serve_http(
    engine: Engine,
    opts: HttpOptions,
    stop: CancellationToken,
) -> Result<(), EngineError> {
    let listener = tokio::net::TcpListener::bind(opts.listen)
        .await
        .map_err(EngineError::internal)?;
    serve_http_on(engine, listener, opts.token, stop).await
}

/// Serves on a listener the caller bound (tests use an ephemeral port).
pub async fn serve_http_on(
    engine: Engine,
    listener: tokio::net::TcpListener,
    token: String,
    stop: CancellationToken,
) -> Result<(), EngineError> {
    let addr = listener.local_addr().map_err(EngineError::internal)?;
    if !addr.ip().is_loopback() {
        return Err(EngineError::internal(
            "the HTTP listener must be on a loopback address",
        ));
    }
    if token.len() < 32 {
        return Err(EngineError::internal(
            "the HTTP token must be at least 32 characters",
        ));
    }
    let shared = Arc::new(Session::default());
    let mcp_engine = engine.clone();
    let config = StreamableHttpServerConfig::default()
        .enforce_origin_validation()
        .with_cancellation_token(stop.child_token());
    let mcp = StreamableHttpService::new(
        move || {
            Ok(BoxentServer::new_http(
                mcp_engine.clone(),
                Arc::clone(&shared),
            ))
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let app = Router::new()
        .nest_service("/mcp", mcp)
        .route("/metrics", get(metrics))
        .with_state(engine)
        .layer(middleware::from_fn_with_state(
            Arc::new(token),
            require_token,
        ));
    tracing::info!(event = "http_listening", addr = %addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { stop.cancelled().await })
        .await
        .map_err(EngineError::internal)
}

async fn metrics(State(engine): State<Engine>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        engine.metrics_text(),
    )
}

async fn require_token(
    State(token): State<Arc<String>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(p) if constant_time_eq(p.as_bytes(), token.as_bytes()) => next.run(req).await,
        _ => {
            tracing::warn!(event = "http_unauthorized", path = %req.uri().path());
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                "missing or wrong bearer token\n",
            )
                .into_response()
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
