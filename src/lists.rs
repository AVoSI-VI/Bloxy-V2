//! Downloading and caching of remote block/filter lists.
//!
//! Lists are cached on disk so a restart (or an offline start) does not need
//! the network. A failed refresh never discards a good cached copy.

use std::path::Path;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::Serialize;

use crate::config::{ListSource, Paths};

/// How many lists to download at once.
const CONCURRENCY: usize = 6;
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// Guards against a mis-typed URL pulling down something enormous.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct ListStatus {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    /// Size of the cached copy, if there is one.
    pub bytes: u64,
    /// RFC 3339 timestamp of the cached copy.
    pub updated: Option<String>,
    /// Populated when the most recent refresh failed. The cached copy, if any,
    /// is still in use.
    pub error: Option<String>,
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("bloxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("static reqwest client configuration is valid")
}

/// Downloads every enabled source into the cache. Disabled sources are left
/// alone but still reported.
pub async fn refresh(
    http: &reqwest::Client,
    paths: &Paths,
    sources: &[ListSource],
) -> Vec<ListStatus> {
    // Built as a plain loop rather than `.map()`: a closure returning a
    // borrowing future cannot be inferred as higher-ranked here.
    let mut pending = Vec::with_capacity(sources.len());
    for source in sources {
        pending.push(refresh_one(http, paths, source));
    }

    let results = stream::iter(pending)
        .buffer_unordered(CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    // `buffer_unordered` yields out of order; restore the configured order so
    // the UI is stable.
    let mut by_url: std::collections::HashMap<&str, ListStatus> = results
        .iter()
        .map(|entry| (entry.url.as_str(), entry.clone()))
        .collect();
    sources
        .iter()
        .filter_map(|source| by_url.remove(source.url.as_str()))
        .collect()
}

async fn refresh_one(http: &reqwest::Client, paths: &Paths, source: &ListSource) -> ListStatus {
    if !source.enabled {
        return status(paths, source, None);
    }

    match fetch_one(http, paths, source).await {
        Ok(()) => status(paths, source, None),
        Err(error) => {
            tracing::warn!(url = %source.url, %error, "list refresh failed");
            status(paths, source, Some(error.to_string()))
        }
    }
}

async fn fetch_one(
    http: &reqwest::Client,
    paths: &Paths,
    source: &ListSource,
) -> anyhow::Result<()> {
    let response = http.get(&source.url).send().await?.error_for_status()?;

    if let Some(length) = response.content_length() {
        anyhow::ensure!(
            length <= MAX_LIST_BYTES,
            "list is {length} bytes, over the {MAX_LIST_BYTES} byte limit"
        );
    }

    let body = response.text().await?;
    anyhow::ensure!(
        body.len() as u64 <= MAX_LIST_BYTES,
        "list is over the {MAX_LIST_BYTES} byte limit"
    );

    let path = paths.cached_list(&source.url);
    std::fs::create_dir_all(paths.cache_dir())?;

    // Write via a sibling temp file so readers never see a partial list.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, &path)?;

    tracing::info!(name = %source.name, bytes = body.len(), "list updated");
    Ok(())
}

/// Reads the cached text of every enabled source, skipping any that have never
/// been downloaded.
pub fn load_cached(paths: &Paths, sources: &[ListSource]) -> Vec<(String, String)> {
    sources
        .iter()
        .filter(|source| source.enabled)
        .filter_map(|source| {
            let path = paths.cached_list(&source.url);
            match std::fs::read_to_string(&path) {
                Ok(text) => Some((source.name.clone(), text)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!(name = %source.name, "no cached copy yet");
                    None
                }
                Err(error) => {
                    tracing::warn!(name = %source.name, %error, "could not read cached list");
                    None
                }
            }
        })
        .collect()
}

pub fn statuses(paths: &Paths, sources: &[ListSource]) -> Vec<ListStatus> {
    sources
        .iter()
        .map(|source| status(paths, source, None))
        .collect()
}

fn status(paths: &Paths, source: &ListSource, error: Option<String>) -> ListStatus {
    let path = paths.cached_list(&source.url);
    let (bytes, updated) = match std::fs::metadata(&path) {
        Ok(meta) => (meta.len(), modified_at(&meta)),
        Err(_) => (0, None),
    };

    ListStatus {
        name: source.name.clone(),
        url: source.url.clone(),
        enabled: source.enabled,
        bytes,
        updated,
        error,
    }
}

fn modified_at(meta: &std::fs::Metadata) -> Option<String> {
    let modified = meta.modified().ok()?;
    time::OffsetDateTime::from(modified)
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Removes cache files that no longer belong to any configured source.
pub fn prune_cache(paths: &Paths, sources: &[ListSource]) {
    let keep: std::collections::HashSet<std::path::PathBuf> = sources
        .iter()
        .map(|source| paths.cached_list(&source.url))
        .collect();

    let Ok(entries) = std::fs::read_dir(paths.cache_dir()) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("txt") && !keep.contains(&path) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// True when the cache directory holds a copy of this URL.
pub fn is_cached(paths: &Paths, url: &str) -> bool {
    Path::new(&paths.cached_list(url)).exists()
}
