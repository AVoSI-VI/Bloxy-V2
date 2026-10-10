//! Counters and a bounded event log for the admin UI.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::Serialize;
use time::OffsetDateTime;

const MAX_EVENTS: usize = 2000;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    Dns,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Allowed,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// RFC 3339 UTC timestamp.
    pub time: String,
    pub source: Source,
    pub action: Action,
    pub client: String,
    pub target: String,
    /// Which rule or list caused the decision, when known.
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub dns_queries: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub http_requests: AtomicU64,
    pub http_blocked: AtomicU64,
    events: Mutex<VecDeque<Event>>,
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an event, dropping the oldest once the log is full. Allowed
    /// events are counted but not logged: at proxy volumes the log would be
    /// nothing but noise.
    pub fn record(&self, source: Source, action: Action, client: &str, target: &str, reason: &str) {
        match (source, action) {
            (Source::Dns, Action::Allowed) => {
                self.dns_queries.fetch_add(1, Ordering::Relaxed);
            }
            (Source::Dns, Action::Blocked) => {
                self.dns_queries.fetch_add(1, Ordering::Relaxed);
                self.dns_blocked.fetch_add(1, Ordering::Relaxed);
            }
            (Source::Proxy, Action::Allowed) => {
                self.http_requests.fetch_add(1, Ordering::Relaxed);
            }
            (Source::Proxy, Action::Blocked) => {
                self.http_requests.fetch_add(1, Ordering::Relaxed);
                self.http_blocked.fetch_add(1, Ordering::Relaxed);
            }
        }

        if action != Action::Blocked {
            return;
        }

        let event = Event {
            time: format_now(),
            source,
            action,
            client: client.to_string(),
            target: truncate(target, 512),
            reason: truncate(reason, 256),
        };

        let mut events = self.events.lock();
        if events.len() == MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let events = self.events.lock();
        events.iter().rev().take(limit).cloned().collect()
    }

    pub fn clear(&self) {
        self.events.lock().clear();
    }

    pub fn snapshot(&self) -> Counters {
        Counters {
            dns_queries: self.dns_queries.load(Ordering::Relaxed),
            dns_blocked: self.dns_blocked.load(Ordering::Relaxed),
            http_requests: self.http_requests.load(Ordering::Relaxed),
            http_blocked: self.http_blocked.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Counters {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub http_requests: u64,
    pub http_blocked: u64,
}

fn format_now() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::from("unknown"))
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}
