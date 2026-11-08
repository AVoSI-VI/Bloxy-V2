//! In-memory admin sessions. A restart drops every one of them.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::http::{header, HeaderMap, HeaderValue};
use parking_lot::Mutex;

use crate::ca;

pub const COOKIE_NAME: &str = "bloxy_session";
pub const SESSION_IDLE: Duration = Duration::from_secs(60 * 60 * 24);
pub const MAX_SESSIONS: usize = 64;

pub struct Store {
    inner: Mutex<HashMap<String, Session>>,
}

pub struct Session {
    created: Instant,
    last_seen: Instant,
}

impl Store {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Evicts idle sessions, then the oldest if the cap is still full.
    pub fn create(&self) -> String {
        self.create_at(Instant::now())
    }

    fn create_at(&self, now: Instant) -> String {
        let mut sessions = self.inner.lock();
        sessions
            .retain(|_, session| now.saturating_duration_since(session.last_seen) < SESSION_IDLE);
        if sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.created)
                .map(|(token, _)| token.clone())
            {
                sessions.remove(&oldest);
            }
        }

        let token = ca::hex(&rand::random::<[u8; 32]>());
        sessions.insert(
            token.clone(),
            Session {
                created: now,
                last_seen: now,
            },
        );
        token
    }

    /// Slides the idle window. An unknown or idle session is removed.
    pub fn touch(&self, token: &str) -> bool {
        self.touch_at(token, Instant::now())
    }

    fn touch_at(&self, token: &str, now: Instant) -> bool {
        let mut sessions = self.inner.lock();
        let expired = match sessions.get(token) {
            Some(session) => now.saturating_duration_since(session.last_seen) >= SESSION_IDLE,
            None => return false,
        };
        if expired {
            sessions.remove(token);
            return false;
        }
        sessions
            .get_mut(token)
            .expect("session still present")
            .last_seen = now;
        true
    }

    pub fn remove(&self, token: &str) {
        self.inner.lock().remove(token);
    }

    /// Password changes keep the caller's session and drop the rest.
    pub fn clear_except(&self, keep: &str) {
        self.inner.lock().retain(|token, _| token == keep);
    }
}

/// The session token from a `Cookie` header, if the client sent one.
pub fn cookie_value(headers: &HeaderMap) -> Option<&str> {
    let header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in header.split(';') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if name.trim() == COOKIE_NAME {
            return Some(value.trim());
        }
    }
    None
}

pub fn set_cookie(token: &str, secure: bool) -> HeaderValue {
    cookie(token, secure, false)
}

pub fn clear_cookie(secure: bool) -> HeaderValue {
    cookie("", secure, true)
}

fn cookie(token: &str, secure: bool, clear: bool) -> HeaderValue {
    let mut value = format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict");
    if clear {
        value.push_str("; Max-Age=0");
    }
    if secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).expect("session cookie is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_fails_once_the_session_has_been_idle() {
        let store = Store::new();
        let created = Instant::now();
        let token = store.create_at(created);

        assert!(store.touch_at(&token, created + SESSION_IDLE - Duration::from_nanos(1)));

        let token = store.create_at(created);
        assert!(!store.touch_at(&token, created + SESSION_IDLE));
        assert!(!store.touch_at(&token, created + SESSION_IDLE));
    }

    #[test]
    fn creating_past_the_cap_evicts_the_oldest() {
        let store = Store::new();
        let start = Instant::now();
        let mut tokens = Vec::new();
        for index in 0..=MAX_SESSIONS {
            tokens.push(store.create_at(start + Duration::from_millis(index as u64)));
        }

        let now = start + Duration::from_secs(1);
        assert!(!store.touch_at(&tokens[0], now));
        assert!(store.touch_at(&tokens[1], now));
        assert!(store.touch_at(tokens.last().unwrap(), now));
    }

    #[test]
    fn clear_except_keeps_exactly_one() {
        let store = Store::new();
        let start = Instant::now();
        let first = store.create_at(start);
        let kept = store.create_at(start + Duration::from_secs(1));
        let third = store.create_at(start + Duration::from_secs(2));

        store.clear_except(&kept);

        let now = start + Duration::from_secs(3);
        assert!(!store.touch_at(&first, now));
        assert!(store.touch_at(&kept, now));
        assert!(!store.touch_at(&third, now));
    }

    #[test]
    fn cookie_value_finds_the_session_among_other_cookies() {
        let mut headers = HeaderMap::new();
        assert!(cookie_value(&headers).is_none());

        headers.insert(
            header::COOKIE,
            "theme=dark; bloxy_session=abc".parse().unwrap(),
        );
        assert_eq!(cookie_value(&headers), Some("abc"));

        headers.insert(
            header::COOKIE,
            "  bloxy_session=abc  ; other=1".parse().unwrap(),
        );
        assert_eq!(cookie_value(&headers), Some("abc"));

        headers.insert(header::COOKIE, "theme=dark".parse().unwrap());
        assert!(cookie_value(&headers).is_none());
    }

    #[test]
    fn secure_is_only_set_when_asked() {
        assert_eq!(
            set_cookie("abc", false).to_str().unwrap(),
            "bloxy_session=abc; Path=/; HttpOnly; SameSite=Strict"
        );
        assert!(set_cookie("abc", true)
            .to_str()
            .unwrap()
            .ends_with("; Secure"));
        assert_eq!(
            clear_cookie(true).to_str().unwrap(),
            "bloxy_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure"
        );
    }
}
