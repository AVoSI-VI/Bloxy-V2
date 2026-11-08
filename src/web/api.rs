//! JSON handlers for the admin interface.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::Config;
use crate::lists::ListStatus;
use crate::state::AppState;

// ---------------------------------------------------------------- API types

#[derive(Debug, Serialize)]
pub(super) struct Status {
    version: &'static str,
    uptime_seconds: i64,
    counters: crate::stats::Counters,
    blocked_domains: usize,
    allowed_domains: usize,
    filter_sources: Vec<String>,
    dns_lists: Vec<ListStatus>,
    filter_lists: Vec<ListStatus>,
    ca_fingerprint: String,
    ca_cached_hosts: u64,
    config: Config,
}

pub(super) async fn status(State(state): State<Arc<AppState>>) -> Json<Status> {
    let domains = state.domains();
    let filter = state.filter();
    let lists = state.list_status();

    Json(Status {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: (time::OffsetDateTime::now_utc() - state.started).whole_seconds(),
        counters: state.stats.snapshot(),
        blocked_domains: domains.blocked_count(),
        allowed_domains: domains.allowed_count(),
        filter_sources: filter.sources.clone(),
        dns_lists: lists.dns,
        filter_lists: lists.filters,
        ca_fingerprint: state.ca.fingerprint(),
        ca_cached_hosts: state.ca.cached_hosts(),
        config: state.config(),
    })
}

pub(super) async fn get_config(State(state): State<Arc<AppState>>) -> Json<Config> {
    Json(state.config())
}

#[derive(Debug, Serialize)]
pub(super) struct ConfigSaved {
    ok: bool,
    /// Listener addresses are bound at startup, so changing one needs a
    /// restart before it takes effect.
    restart_required: bool,
}

pub(super) async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(config): Json<Config>,
) -> Result<Json<ConfigSaved>, ApiError> {
    let previous = state.config();
    let restart_required = previous.proxy.listen != config.proxy.listen
        || previous.dns.listen != config.dns.listen
        || previous.admin.listen != config.admin.listen
        || previous.proxy.enabled != config.proxy.enabled
        || previous.dns.enabled != config.dns.enabled;

    state.set_config(config).await?;

    Ok(Json(ConfigSaved {
        ok: true,
        restart_required,
    }))
}

pub(super) async fn reload(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.reload().await;
    Json(json!({ "ok": true }))
}

pub(super) async fn refresh_lists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.refresh_lists().await;
    let lists = state.list_status();
    Json(json!({
        "ok": true,
        "dns_lists": lists.dns,
        "filter_lists": lists.filters,
    }))
}

#[derive(Debug, Deserialize)]
pub(super) struct EventQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    200
}

pub(super) async fn events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventQuery>,
) -> impl IntoResponse {
    Json(state.stats.recent(query.limit.min(2000)))
}

pub(super) async fn clear_events(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.stats.clear();
    Json(json!({ "ok": true }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DomainList {
    Blocked,
    Allowed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DomainAction {
    Add,
    Remove,
}

#[derive(Debug, Deserialize)]
pub(super) struct DomainEdit {
    list: DomainList,
    action: DomainAction,
    domain: String,
}

/// Adds or removes a single domain. Kept separate from the whole-config PUT so
/// the common case does not have to round-trip every setting.
pub(super) async fn edit_domain(
    State(state): State<Arc<AppState>>,
    Json(edit): Json<DomainEdit>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let domain = edit
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() {
        return Err(ApiError::bad_request("domain must not be empty"));
    }

    let mut config = state.config();
    let target = match edit.list {
        DomainList::Blocked => &mut config.dns.blocked_domains,
        DomainList::Allowed => &mut config.dns.allowed_domains,
    };

    match edit.action {
        DomainAction::Add => {
            if !target.contains(&domain) {
                target.push(domain.clone());
                target.sort();
            }
        }
        DomainAction::Remove => target.retain(|existing| existing != &domain),
    }

    state.set_config(config).await?;
    Ok(Json(json!({ "ok": true, "domain": domain })))
}

// --------------------------------------------------------------- error type

pub(super) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(super) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(super) fn bad_request(message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::warn!(%error, "admin request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}
