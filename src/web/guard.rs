//! Decides whether a request may call the admin API.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::auth::lockout::LOGIN_FAILURE_DELAY;
use crate::auth::session;
use crate::state::AppState;

use super::api::ApiError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity {
    Session,
    Token,
    /// `admin.auth_required` is off, so the gate is not checking credentials.
    Open,
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    if !state.config().admin.auth_required {
        request.extensions_mut().insert(Identity::Open);
        return next.run(request).await;
    }

    if let Some(token) = session::cookie_value(request.headers()) {
        if state.auth.sessions.touch(token) {
            request.extensions_mut().insert(Identity::Session);
            return next.run(request).await;
        }
    }

    if let Some(token) = bearer_token(request.headers()) {
        let ip = addr.ip();
        if let Err(retry_after) = state.auth.lockout.check(ip) {
            tracing::warn!(%ip, "admin API token check locked out");
            return locked_out(retry_after);
        }
        if state.auth.credentials().accepts_token(token) {
            state.auth.lockout.clear(ip);
            request.extensions_mut().insert(Identity::Token);
            return next.run(request).await;
        }
        state.auth.lockout.record_failure(ip);
        tracing::warn!(%ip, "rejected admin API token");
        return invalid_credentials().await;
    }

    ApiError::new(StatusCode::UNAUTHORIZED, "authentication required").into_response()
}

/// Credential management and logout accept a session cookie and nothing else.
pub async fn require_session(request: Request, next: Next) -> Response {
    if request.extensions().get::<Identity>() == Some(&Identity::Session) {
        next.run(request).await
    } else {
        ApiError::new(StatusCode::FORBIDDEN, "this endpoint requires a session").into_response()
    }
}

pub(super) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() || token.contains(char::is_whitespace) {
        return None;
    }
    Some(token)
}

pub(super) fn locked_out(retry_after: Duration) -> Response {
    let seconds = retry_after.as_secs().max(1);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": format!("too many attempts; try again in {seconds} seconds"),
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&seconds.to_string()).expect("retry-after is digits"),
    );
    response
}

pub(super) async fn invalid_credentials() -> Response {
    tokio::time::sleep(LOGIN_FAILURE_DELAY).await;
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
}
