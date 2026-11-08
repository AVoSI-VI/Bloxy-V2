//! Login, logout, and the public snapshot of whether the interface is locked.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{session, verify_password};
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
