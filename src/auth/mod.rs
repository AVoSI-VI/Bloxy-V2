//! Admin credentials. The password and the API token live in their own file,
//! never in `config.json`, which the admin API returns and the UI edits whole.

pub(crate) mod cli;
pub(crate) mod lockout;
pub(crate) mod session;

use anyhow::{Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::ca;
use crate::config::{write_json_atomic, Paths};

/// Same minimum the password-change API will enforce.
pub(crate) const MIN_PASSWORD_CHARS: usize = 8;

/// Compared when no API token is stored, so that case does the same SHA-256
/// work as a wrong token. 64 hex characters, the length of a real hash.
const DUMMY_TOKEN_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Credentials {
    pub password_hash: Option<String>,
    pub api_token_hash: Option<String>,
}

impl Credentials {
    /// A missing file is a fresh install: no password and no token.
    pub fn load_or_default(paths: &Paths) -> Result<Self> {
        let path = paths.admin_auth();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_json_atomic(&paths.admin_auth(), self)
    }

    /// Constant-time token check. A missing token is compared with a dummy
    /// hash of the same length, so the two answers take the same path.
    pub fn accepts_token(&self, presented: &str) -> bool {
        let stored = self.api_token_hash.as_deref().unwrap_or(DUMMY_TOKEN_HASH);
        let matches = token_matches(stored, presented);
        self.api_token_hash.is_some() && matches
    }
}

/// Password hash, API token hash, and the in-memory session and lockout state.
pub struct AuthState {
    paths: Paths,
    credentials: RwLock<Credentials>,
    pub sessions: session::Store,
    pub lockout: lockout::Tracker,
}

impl AuthState {
    pub fn load(paths: &Paths) -> Result<Self> {
        Ok(Self {
            credentials: RwLock::new(Credentials::load_or_default(paths)?),
            sessions: session::Store::new(),
            lockout: lockout::Tracker::new(),
            paths: paths.clone(),
        })
    }

    pub fn credentials(&self) -> Credentials {
        self.credentials.read().clone()
    }

    /// Writes the file, then swaps the in-memory copy. A failed write leaves
    /// the previous credentials in place.
    pub fn set_credentials(&self, credentials: Credentials) -> Result<()> {
        credentials.save(&self.paths)?;
        *self.credentials.write() = credentials;
        Ok(())
    }
}

/// Argon2id PHC string, using `Argon2::default()` parameters.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("hashing the password: {error}"))?;
    Ok(hash.to_string())
}

/// `false` for a wrong password and for a hash this build cannot parse.
///
/// Callers must run this through `spawn_blocking`. Argon2id takes tens of
/// milliseconds and would stall every other admin request on a worker thread.
pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// `(token text, sha256 hex)`. The text is `bloxy_` plus 32 random bytes.
pub fn new_api_token() -> (String, String) {
    let bytes: [u8; 32] = rand::random();
    let token = format!("bloxy_{}", ca::hex(&bytes));
    let hash = ca::hex(&ca::sha256(token.as_bytes()));
    (token, hash)
}

/// Constant-time compare of a stored SHA-256 hex against `presented`.
pub fn token_matches(hash_hex: &str, presented: &str) -> bool {
    let actual = ca::hex(&ca::sha256(presented.as_bytes()));
    bool::from(hash_hex.as_bytes().ct_eq(actual.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_verifies_and_rejects_a_wrong_password() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(verify_password(&hash, "correct-horse"));
        assert!(!verify_password(&hash, "wrong-horse"));
    }

    #[test]
    fn malformed_password_hash_is_a_rejection() {
        assert!(!verify_password("not-a-phc-string", "correct-horse"));
        assert!(!verify_password("", "correct-horse"));
    }

    #[test]
    fn token_hash_matches_only_the_issued_token() {
        let (token, hash) = new_api_token();
        assert!(token.starts_with("bloxy_"));
        assert_eq!(token.len(), "bloxy_".len() + 64);
        assert_eq!(hash, ca::hex(&ca::sha256(token.as_bytes())));
        assert!(token_matches(&hash, &token));
        assert_eq!(DUMMY_TOKEN_HASH.len(), hash.len());

        let mut changed = token.clone();
        let last = changed.pop().unwrap();
        changed.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!token_matches(&hash, &changed));
    }

    #[test]
    fn a_missing_token_does_not_match_an_empty_or_dummy_presentation() {
        let credentials = Credentials::default();
        assert!(!credentials.accepts_token(""));
        assert!(!credentials.accepts_token(DUMMY_TOKEN_HASH));
        assert!(!credentials.accepts_token("bloxy_not-a-real-token"));
    }

    #[test]
    fn credentials_round_trip_and_a_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());

        let loaded = Credentials::load_or_default(&paths).unwrap();
        assert!(loaded.password_hash.is_none());
        assert!(loaded.api_token_hash.is_none());

        let credentials = Credentials {
            password_hash: Some("$argon2id$example".into()),
            api_token_hash: Some("ab".repeat(32)),
        };
        credentials.save(&paths).unwrap();
        let loaded = Credentials::load_or_default(&paths).unwrap();
        assert_eq!(loaded.password_hash, credentials.password_hash);
        assert_eq!(loaded.api_token_hash, credentials.api_token_hash);
    }

    #[test]
    fn set_credentials_saves_before_it_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        let auth = AuthState::load(&paths).unwrap();
        assert!(auth.credentials().password_hash.is_none());

        auth.set_credentials(Credentials {
            password_hash: Some("stored-hash".into()),
            api_token_hash: None,
        })
        .unwrap();

        assert_eq!(
            auth.credentials().password_hash.as_deref(),
            Some("stored-hash")
        );
        let reloaded = AuthState::load(&paths).unwrap();
        assert_eq!(
            reloaded.credentials().password_hash.as_deref(),
            Some("stored-hash")
        );
    }
}
