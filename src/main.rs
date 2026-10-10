//! bloxy: a filtering proxy with a DNS blackhole and a small admin interface.

mod ca;
mod config;
mod dns;
mod domains;
mod filter;
mod lists;
mod proxy;
mod state;
mod stats;
mod web;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use crate::config::Paths;
use crate::state::AppState;

#[derive(Debug, Parser)]
#[command(name = "bloxy", version, about, long_about = None)]
struct Args {
    /// Directory holding the config, the CA, and the list cache.
    #[arg(long, value_name = "DIR", default_value = "data")]
    data_dir: PathBuf,

    /// Download every enabled list on startup instead of using the cache.
    #[arg(long)]
    update_lists: bool,

    /// Log filter, in `tracing` syntax.
    #[arg(long, value_name = "FILTER", default_value = "info")]
    log: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log)),
        )
        .init();

    // Every TLS user in the process shares this provider, including reqwest,
    // which is built with `rustls-no-provider` for exactly this reason.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider was already installed"))?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the async runtime")?
        .block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let paths = Paths::new(args.data_dir);
    let state = AppState::new(paths).await?;
    let config = state.config();

    tracing::info!(
        data_dir = %state.paths.root.display(),
        "CA fingerprint SHA-256 {}",
        state.ca.fingerprint()
    );

    if args.update_lists {
        tracing::info!("downloading filter lists");
        state.refresh_lists().await;
    } else if !has_any_cached_list(&state) {
        tracing::warn!(
            "no lists are cached yet; start with --update-lists or use \
             \"Update all lists now\" in the admin interface"
        );
    }

    let mut tasks = tokio::task::JoinSet::new();

    if config.proxy.enabled {
        let state = state.clone();
        tasks.spawn(async move { labelled("proxy", proxy::serve(state).await) });
    }

    if config.dns.enabled {
        let state = state.clone();
        tasks.spawn(async move { labelled("dns", dns::serve(state).await) });
    }

    {
        let state = state.clone();
        tasks.spawn(async move { labelled("admin", web::serve(state).await) });
    }

    tracing::info!("bloxy is running; press Ctrl-C to stop");

    // Any service exiting is a fatal condition: they are all supposed to run
    // until shutdown.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
        Some(result) = tasks.join_next() => {
            match result {
                Ok(Err(error)) => Err(error),
                Ok(Ok(())) => Ok(()),
                Err(error) => Err(anyhow::anyhow!("a service task panicked: {error}")),
            }
        }
    }
}

fn labelled(service: &'static str, result: Result<()>) -> Result<()> {
    result.with_context(|| format!("the {service} service failed"))
}

fn has_any_cached_list(state: &Arc<AppState>) -> bool {
    let config = state.config();
    config
        .dns
        .blocklists
        .iter()
        .chain(config.filtering.lists.iter())
        .filter(|source| source.enabled)
        .any(|source| lists::is_cached(&state.paths, &source.url))
}
