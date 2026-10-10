//! Shared runtime state.
//!
//! The compiled engines are held behind `RwLock<Arc<..>>` and swapped
//! wholesale on reload, so request handling never blocks on a rebuild and
//! in-flight requests finish against the engine they started with.

use std::sync::Arc;

use anyhow::Result;
use parking_lot::RwLock;
use time::OffsetDateTime;

use crate::ca::CertAuthority;
use crate::config::{Config, Paths};
use crate::domains::{self, DomainSet};
use crate::filter::FilterEngine;
use crate::lists::{self, ListStatus};
use crate::stats::Stats;

pub struct AppState {
    pub paths: Paths,
    pub ca: Arc<CertAuthority>,
    pub stats: Stats,
    pub http: reqwest::Client,
    pub started: OffsetDateTime,

    config: RwLock<Config>,
    filter: RwLock<Arc<FilterEngine>>,
    domains: RwLock<Arc<DomainSet>>,
    list_status: RwLock<ListStatuses>,
}

#[derive(Debug, Clone, Default)]
pub struct ListStatuses {
    pub dns: Vec<ListStatus>,
    pub filters: Vec<ListStatus>,
}

impl AppState {
    pub async fn new(paths: Paths) -> Result<Arc<Self>> {
        paths.ensure()?;

        let config = Config::load_or_create(&paths.config())?;
        let ca = Arc::new(CertAuthority::load_or_create(
            &paths.ca_cert(),
            &paths.ca_key(),
        )?);

        let state = Arc::new(Self {
            list_status: RwLock::new(ListStatuses {
                dns: lists::statuses(&paths, &config.dns.blocklists),
                filters: lists::statuses(&paths, &config.filtering.lists),
            }),
            config: RwLock::new(config),
            filter: RwLock::new(Arc::new(FilterEngine::empty())),
            domains: RwLock::new(Arc::new(DomainSet::new())),
            paths,
            ca,
            stats: Stats::new(),
            http: lists::client(),
            started: OffsetDateTime::now_utc(),
        });

        state.reload().await;
        Ok(state)
    }

    pub fn config(&self) -> Config {
        self.config.read().clone()
    }

    pub fn filter(&self) -> Arc<FilterEngine> {
        self.filter.read().clone()
    }

    pub fn domains(&self) -> Arc<DomainSet> {
        self.domains.read().clone()
    }

    pub fn list_status(&self) -> ListStatuses {
        self.list_status.read().clone()
    }

    /// Replaces the configuration, persists it, and rebuilds the engines.
    ///
    /// Listener addresses are not re-bound; changing those needs a restart.
    pub async fn set_config(&self, config: Config) -> Result<()> {
        config.save(&self.paths.config())?;
        let sources: Vec<_> = config
            .dns
            .blocklists
            .iter()
            .chain(config.filtering.lists.iter())
            .cloned()
            .collect();
        *self.config.write() = config;

        lists::prune_cache(&self.paths, &sources);
        self.reload().await;
        Ok(())
    }

    /// Rebuilds the domain set and filter engine from the on-disk cache.
    pub async fn reload(&self) {
        let config = self.config();
        let paths = self.paths.clone();

        let dns_lists = lists::load_cached(&paths, &config.dns.blocklists);
        let filter_lists = lists::load_cached(&paths, &config.filtering.lists);

        // Parsing full filter lists takes seconds of CPU, so keep it off the
        // async runtime's worker threads.
        let built = tokio::task::spawn_blocking(move || {
            let mut set = DomainSet::new();
            for (name, text) in &dns_lists {
                let parsed = domains::parse_domain_list(text);
                tracing::info!(list = %name, domains = parsed.len(), "loaded DNS blocklist");
                for domain in parsed {
                    set.block(&domain);
                }
            }
            for domain in &config.dns.blocked_domains {
                set.block(domain);
            }
            for domain in &config.dns.allowed_domains {
                set.allow(domain);
            }

            let filter = if config.filtering.enabled {
                FilterEngine::build(filter_lists, &config.filtering.custom_rules)
            } else {
                FilterEngine::empty()
            };

            (set, filter)
        })
        .await;

        match built {
            Ok((set, filter)) => {
                tracing::info!(
                    blocked_domains = set.blocked_count(),
                    allowed_domains = set.allowed_count(),
                    filter_lists = filter.sources.len(),
                    "engines reloaded"
                );
                *self.domains.write() = Arc::new(set);
                *self.filter.write() = Arc::new(filter);
            }
            Err(error) => {
                tracing::error!(%error, "engine rebuild panicked; keeping previous engines");
            }
        }

        self.refresh_statuses(None, None);
    }

    /// Downloads every enabled list, then rebuilds.
    pub async fn refresh_lists(&self) {
        let config = self.config();
        let dns = lists::refresh(&self.http, &self.paths, &config.dns.blocklists).await;
        let filters = lists::refresh(&self.http, &self.paths, &config.filtering.lists).await;
        self.reload().await;
        self.refresh_statuses(Some(dns), Some(filters));
    }

    /// Recomputes cache metadata, preserving any errors passed in from a
    /// refresh that just ran.
    fn refresh_statuses(&self, dns: Option<Vec<ListStatus>>, filters: Option<Vec<ListStatus>>) {
        let config = self.config();
        let mut status = self.list_status.write();
        status.dns = dns.unwrap_or_else(|| lists::statuses(&self.paths, &config.dns.blocklists));
        status.filters =
            filters.unwrap_or_else(|| lists::statuses(&self.paths, &config.filtering.lists));
    }
}
