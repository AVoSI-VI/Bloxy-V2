//! The administration interface: a small JSON API plus the static assets that
//! drive it.

mod api;
mod auth_api;
mod guard;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::header;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const PANELS_JS: &str = include_str!("assets/panels.js");
const AUTH_JS: &str = include_str!("assets/auth.js");
const STYLE_CSS: &str = include_str!("assets/style.css");

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let listen = state.config().admin.listen;
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding admin interface on {listen}"))?;

    tracing::info!(address = %listen, "admin interface listening at http://{listen}");

    // `ConnectInfo` is how the gate reads the client address. Serving with
    // plain `into_make_service` makes that extractor fail, and every protected
    // request comes back 500.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("serving the admin interface")?;
    Ok(())
}

/// Assets, the CA certificate, and login stay outside the gate. `route_layer`
/// (not `layer`) leaves an unknown path as 404 instead of 401.
fn router(state: Arc<AppState>) -> Router {
    let session_only = Router::new()
        .route("/api/auth/logout", post(auth_api::logout))
        .route("/api/auth/password", post(auth_api::change_password))
        .route(
            "/api/auth/token",
            post(auth_api::create_token).delete(auth_api::revoke_token),
        )
        .route_layer(middleware::from_fn(guard::require_session));

    let protected = Router::new()
        .route("/api/status", get(api::status))
        .route("/api/config", get(api::get_config).put(api::put_config))
        .route("/api/reload", post(api::reload))
        .route("/api/lists/refresh", post(api::refresh_lists))
        .route("/api/events", get(api::events).delete(api::clear_events))
        .route("/api/domains", post(api::edit_domain))
        .merge(session_only)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            guard::require_auth,
        ));

    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/panels.js", get(panels_js))
        .route("/auth.js", get(auth_js))
        .route("/style.css", get(style_css))
        .route("/ca.crt", get(ca_certificate))
        .route("/api/auth/state", get(auth_api::auth_state))
        .route("/api/auth/login", post(auth_api::login))
        .merge(protected)
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

async fn auth_js() -> impl IntoResponse {
    asset("application/javascript; charset=utf-8", AUTH_JS)
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
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    use crate::config::{Config, Paths};
    use crate::state::AppState;

    const PASSWORD: &str = "long-enough";

    fn router_with(setup: impl FnOnce(&Paths)) -> (tempfile::TempDir, axum::Router) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        setup(&paths);
        let state = AppState::for_tests(paths).unwrap();
        (dir, super::router(state))
    }

    fn with_peer(request: Request<Body>) -> Request<Body> {
        let mut request = request;
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 10], 40000))));
        request
    }

    fn get(uri: &str) -> Request<Body> {
        with_peer(Request::builder().uri(uri).body(Body::empty()).unwrap())
    }

    fn post_json(uri: &str, body: &str) -> Request<Body> {
        with_peer(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
    }

    fn with_header(
        mut request: Request<Body>,
        name: header::HeaderName,
        value: &str,
    ) -> Request<Body> {
        request.headers_mut().insert(name, value.parse().unwrap());
        request
    }

    async fn text(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn session_and_bearer_token_pass_the_gate() {
        let mut api_token = String::new();
        let (_dir, app) = router_with(|paths| {
            crate::auth::cli::store_password(paths, PASSWORD).unwrap();
            api_token = crate::auth::cli::store_new_token(paths).unwrap();
        });

        let page = app.clone().oneshot(get("/")).await.unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let ca = app.clone().oneshot(get("/ca.crt")).await.unwrap();
        assert_eq!(ca.status(), StatusCode::OK);

        let status = app.clone().oneshot(get("/api/status")).await.unwrap();
        assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
        assert!(text(status).await.contains("authentication required"));

        let missing = app
            .clone()
            .oneshot(get("/api/does-not-exist"))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let state = app.clone().oneshot(get("/api/auth/state")).await.unwrap();
        assert_eq!(state.status(), StatusCode::OK);
        let state_body = text(state).await;
        assert!(state_body.contains("\"password_set\":true"));
        assert!(state_body.contains("\"authenticated\":false"));

        let wrong = app
            .clone()
            .oneshot(post_json(
                "/api/auth/login",
                r#"{"password":"not-the-password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let login = app
            .clone()
            .oneshot(post_json(
                "/api/auth/login",
                &format!(r#"{{"password":"{PASSWORD}"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::NO_CONTENT);
        let set_cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("bloxy_session="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));
        assert!(!set_cookie.contains("Secure"));
        let cookie = set_cookie.split(';').next().unwrap().to_string();

        let authed = app
            .clone()
            .oneshot(with_header(get("/api/status"), header::COOKIE, &cookie))
            .await
            .unwrap();
        assert_eq!(authed.status(), StatusCode::OK);

        let bearer_logout = app
            .clone()
            .oneshot(with_header(
                post_json("/api/auth/logout", ""),
                header::AUTHORIZATION,
                &format!("Bearer {api_token}"),
            ))
            .await
            .unwrap();
        assert_eq!(bearer_logout.status(), StatusCode::FORBIDDEN);

        let bearer = app
            .clone()
            .oneshot(with_header(
                get("/api/status"),
                header::AUTHORIZATION,
                &format!("Bearer {api_token}"),
            ))
            .await
            .unwrap();
        assert_eq!(bearer.status(), StatusCode::OK);

        let wrong_token = app
            .clone()
            .oneshot(with_header(
                get("/api/status"),
                header::AUTHORIZATION,
                "Bearer bloxy_wrong",
            ))
            .await
            .unwrap();
        assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);

        let logout = app
            .clone()
            .oneshot(with_header(
                post_json("/api/auth/logout", ""),
                header::COOKIE,
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
        let cleared = logout
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cleared.contains("Max-Age=0"));

        let after = app
            .clone()
            .oneshot(with_header(get("/api/status"), header::COOKIE, &cookie))
            .await
            .unwrap();
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_required_off_lets_status_through() {
        let (_dir, app) = router_with(|paths| {
            paths.ensure().unwrap();
            let mut config = Config::default();
            config.admin.auth_required = false;
            config.save(&paths.config()).unwrap();
        });

        let status = app.oneshot(get("/api/status")).await.unwrap();
        assert_eq!(status.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_without_a_password_is_forbidden() {
        let (_dir, app) = router_with(|_| {});

        let login = app
            .oneshot(post_json(
                "/api/auth/login",
                r#"{"password":"long-enough"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::FORBIDDEN);
        assert!(text(login).await.contains("no admin password is set"));
    }
}
