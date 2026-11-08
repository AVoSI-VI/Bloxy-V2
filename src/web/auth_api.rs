//! Login, logout, and the public snapshot of whether the interface is locked.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{hash_password, new_api_token, session, verify_password, MIN_PASSWORD_CHARS};
use crate::state::AppState;

use super::api::ApiError;
use super::guard;

#[derive(Debug, Serialize)]
pub(super) struct AuthStateResponse {
    auth_required: bool,
    password_set: bool,
    authenticated: bool,
    tls: bool,
}

pub(super) async fn auth_state(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<AuthStateResponse> {
    let admin = state.config().admin;
    let credentials = state.auth.credentials();
    Json(AuthStateResponse {
        auth_required: admin.auth_required,
        password_set: credentials.password_hash.is_some(),
        authenticated: authenticated(&state, &headers),
        tls: admin.tls_enabled,
    })
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    if session::cookie_value(headers).is_some_and(|token| state.auth.sessions.touch(token)) {
        return true;
    }
    guard::bearer_token(headers).is_some_and(|token| state.auth.credentials().accepts_token(token))
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginBody {
    password: String,
}

pub(super) async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> Response {
    let ip = addr.ip();
    if let Err(retry_after) = state.auth.lockout.check(ip) {
        tracing::warn!(%ip, "admin login locked out");
        return guard::locked_out(retry_after);
    }

    let Some(hash) = state.auth.credentials().password_hash else {
        return ApiError::new(StatusCode::FORBIDDEN, "no admin password is set").into_response();
    };

    let password = body.password;
    let accepted =
        match tokio::task::spawn_blocking(move || verify_password(&hash, &password)).await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::error!(%error, "password verification task failed");
                false
            }
        };

    if !accepted {
        state.auth.lockout.record_failure(ip);
        tracing::warn!(%ip, "admin login failed");
        return guard::invalid_credentials().await;
    }

    state.auth.lockout.clear(ip);
    let token = state.auth.sessions.create();
    let secure = state.config().admin.tls_enabled;
    tracing::info!(%ip, "admin login succeeded");
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session::set_cookie(&token, secure))],
    )
        .into_response()
}

pub(super) async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = session::cookie_value(&headers) {
        state.auth.sessions.remove(token);
    }
    let secure = state.config().admin.tls_enabled;
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session::clear_cookie(secure))],
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct PasswordBody {
    current: String,
    new: String,
}

pub(super) async fn change_password(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> Response {
    let ip = addr.ip();
    // Copied before the slow checks so a missing cookie cannot fall through
    // into `clear_except` and drop every session.
    let Some(session_token) = session::cookie_value(&headers).map(str::to_owned) else {
        return ApiError::new(StatusCode::FORBIDDEN, "this endpoint requires a session")
            .into_response();
    };

    if let Err(retry_after) = state.auth.lockout.check(ip) {
        tracing::warn!(%ip, "admin password change locked out");
        return guard::locked_out(retry_after);
    }

    let Some(hash) = state.auth.credentials().password_hash else {
        return ApiError::new(StatusCode::FORBIDDEN, "no admin password is set").into_response();
    };

    let current = body.current;
    let accepted = match tokio::task::spawn_blocking(move || verify_password(&hash, &current)).await
    {
        Ok(accepted) => accepted,
        Err(error) => {
            tracing::error!(%error, "password verification task failed");
            false
        }
    };
    if !accepted {
        state.auth.lockout.record_failure(ip);
        tracing::warn!(%ip, "admin password change rejected");
        return guard::invalid_credentials().await;
    }

    if body.new.chars().count() < MIN_PASSWORD_CHARS {
        return ApiError::bad_request(&format!(
            "password must be at least {MIN_PASSWORD_CHARS} characters"
        ))
        .into_response();
    }

    let new_password = body.new;
    let new_hash = match tokio::task::spawn_blocking(move || hash_password(&new_password)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(error)) => return ApiError::from(error).into_response(),
        Err(error) => {
            tracing::error!(%error, "password hashing task failed");
            return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "password change failed")
                .into_response();
        }
    };

    let mut credentials = state.auth.credentials();
    credentials.password_hash = Some(new_hash);
    if let Err(error) = state.auth.set_credentials(credentials) {
        return ApiError::from(error).into_response();
    }
    state.auth.sessions.clear_except(&session_token);
    state.auth.lockout.clear(ip);
    tracing::info!(%ip, "admin password changed");
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Debug, Serialize)]
pub(super) struct IssuedToken {
    token: String,
}

pub(super) async fn create_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<IssuedToken>, ApiError> {
    let (token, hash) = new_api_token();
    let mut credentials = state.auth.credentials();
    credentials.api_token_hash = Some(hash);
    state.auth.set_credentials(credentials)?;
    tracing::info!(ip = %addr.ip(), "admin API token generated");
    Ok(Json(IssuedToken { token }))
}

pub(super) async fn revoke_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<StatusCode, ApiError> {
    let mut credentials = state.auth.credentials();
    credentials.api_token_hash = None;
    state.auth.set_credentials(credentials)?;
    tracing::info!(ip = %addr.ip(), "admin API token revoked");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    use crate::config::Paths;
    use crate::state::AppState;

    const PASSWORD: &str = "long-enough";
    const REPLACEMENT: &str = "replacement-password";

    fn router_with(setup: impl FnOnce(&Paths)) -> (tempfile::TempDir, axum::Router) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        setup(&paths);
        let state = AppState::for_tests(paths).unwrap();
        (dir, super::super::router(state))
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

    fn delete(uri: &str) -> Request<Body> {
        with_peer(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .body(Body::empty())
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

    async fn login(app: &axum::Router, password: &str) -> String {
        let response = app
            .clone()
            .oneshot(post_json(
                "/api/auth/login",
                &format!(r#"{{"password":"{password}"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn credential_routes_keep_the_callers_session_and_reject_a_bearer() {
        let mut api_token = String::new();
        let (dir, app) = router_with(|paths| {
            crate::auth::cli::store_password(paths, PASSWORD).unwrap();
            api_token = crate::auth::cli::store_new_token(paths).unwrap();
        });

        let page = text(app.clone().oneshot(get("/")).await.unwrap()).await;
        assert!(page.contains("/auth.js"));
        assert!(page.contains("id=\"login\""));
        assert!(page.contains("data-panel=\"admin\""));
        let script = app.clone().oneshot(get("/auth.js")).await.unwrap();
        assert_eq!(script.status(), StatusCode::OK);

        let anonymous = app
            .clone()
            .oneshot(post_json(
                "/api/auth/password",
                r#"{"current":"long-enough","new":"replacement-password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        for request in [
            post_json(
                "/api/auth/password",
                r#"{"current":"long-enough","new":"replacement-password"}"#,
            ),
            post_json("/api/auth/token", ""),
            delete("/api/auth/token"),
        ] {
            let response = app
                .clone()
                .oneshot(with_header(
                    request,
                    header::AUTHORIZATION,
                    &format!("Bearer {api_token}"),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        let first = login(&app, PASSWORD).await;
        let second = login(&app, PASSWORD).await;

        let started = Instant::now();
        let wrong = app
            .clone()
            .oneshot(with_header(
                post_json(
                    "/api/auth/password",
                    r#"{"current":"not-the-password","new":"replacement-password"}"#,
                ),
                header::COOKIE,
                &first,
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert!(text(wrong).await.contains("invalid credentials"));
        assert!(started.elapsed() >= Duration::from_millis(400));

        let short = app
            .clone()
            .oneshot(with_header(
                post_json(
                    "/api/auth/password",
                    r#"{"current":"long-enough","new":"short"}"#,
                ),
                header::COOKIE,
                &first,
            ))
            .await
            .unwrap();
        assert_eq!(short.status(), StatusCode::BAD_REQUEST);
        assert!(text(short).await.contains("at least 8"));

        let changed = app
            .clone()
            .oneshot(with_header(
                post_json(
                    "/api/auth/password",
                    &format!(r#"{{"current":"{PASSWORD}","new":"{REPLACEMENT}"}}"#),
                ),
                header::COOKIE,
                &first,
            ))
            .await
            .unwrap();
        assert_eq!(changed.status(), StatusCode::NO_CONTENT);

        let dropped = app
            .clone()
            .oneshot(with_header(get("/api/status"), header::COOKIE, &second))
            .await
            .unwrap();
        assert_eq!(dropped.status(), StatusCode::UNAUTHORIZED);
        let kept = app
            .clone()
            .oneshot(with_header(get("/api/status"), header::COOKIE, &first))
            .await
            .unwrap();
        assert_eq!(kept.status(), StatusCode::OK);

        let stored = std::fs::read_to_string(dir.path().join("admin-auth.json")).unwrap();
        assert!(!stored.contains(PASSWORD));
        assert!(!stored.contains(REPLACEMENT));

        let issued = app
            .clone()
            .oneshot(with_header(
                post_json("/api/auth/token", ""),
                header::COOKIE,
                &first,
            ))
            .await
            .unwrap();
        assert_eq!(issued.status(), StatusCode::OK);
        let issued_body = text(issued).await;
        let token = issued_body
            .split('"')
            .find(|part| part.starts_with("bloxy_"))
            .unwrap()
            .to_string();
        let stored = std::fs::read_to_string(dir.path().join("admin-auth.json")).unwrap();
        assert!(!stored.contains(&token));
        assert!(!stored.contains(&api_token));

        let old_bearer = app
            .clone()
            .oneshot(with_header(
                get("/api/status"),
                header::AUTHORIZATION,
                &format!("Bearer {api_token}"),
            ))
            .await
            .unwrap();
        assert_eq!(old_bearer.status(), StatusCode::UNAUTHORIZED);

        let new_bearer = app
            .clone()
            .oneshot(with_header(
                get("/api/status"),
                header::AUTHORIZATION,
                &format!("Bearer {token}"),
            ))
            .await
            .unwrap();
        assert_eq!(new_bearer.status(), StatusCode::OK);

        let revoked = app
            .clone()
            .oneshot(with_header(
                delete("/api/auth/token"),
                header::COOKIE,
                &first,
            ))
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        let after_revoke = app
            .clone()
            .oneshot(with_header(
                get("/api/status"),
                header::AUTHORIZATION,
                &format!("Bearer {token}"),
            ))
            .await
            .unwrap();
        assert_eq!(after_revoke.status(), StatusCode::UNAUTHORIZED);
    }
}
