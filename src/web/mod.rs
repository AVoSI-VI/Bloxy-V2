//! The administration interface: a small JSON API plus the static assets that
//! drive it.

mod api;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const PANELS_JS: &str = include_str!("assets/panels.js");
const STYLE_CSS: &str = include_str!("assets/style.css");

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let listen = state.config().admin.listen;
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding admin interface on {listen}"))?;

    tracing::info!(address = %listen, "admin interface listening at http://{listen}");

    axum::serve(listener, app)
        .await
        .context("serving the admin interface")?;
    Ok(())
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/panels.js", get(panels_js))
        .route("/style.css", get(style_css))
        .route("/ca.crt", get(ca_certificate))
        .route("/api/status", get(api::status))
        .route("/api/config", get(api::get_config).put(api::put_config))
        .route("/api/reload", post(api::reload))
        .route("/api/lists/refresh", post(api::refresh_lists))
        .route("/api/events", get(api::events).delete(api::clear_events))
        .route("/api/domains", post(api::edit_domain))
        .with_state(state)
}

// ------------------------------------------------------------ static assets

async fn index() -> impl IntoResponse {
    asset("text/html; charset=utf-8", INDEX_HTML)
}

async fn app_js() -> impl IntoResponse {
    asset("application/javascript; charset=utf-8", APP_JS)
}

async fn panels_js() -> impl IntoResponse {
    asset("application/javascript; charset=utf-8", PANELS_JS)
}

async fn style_css() -> impl IntoResponse {
    asset("text/css; charset=utf-8", STYLE_CSS)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn ca_certificate(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"bloxy-ca.crt\"",
            ),
        ],
        state.ca.ca_pem().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::config::Paths;
    use crate::state::AppState;

    #[tokio::test]
    async fn get_status_is_ok() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(Paths::new(dir.path().to_path_buf())).unwrap();

        let response = super::router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
