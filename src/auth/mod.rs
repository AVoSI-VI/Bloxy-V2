//! Admin credentials. The password and the API token live in their own file,
//! never in `config.json`, which the admin API returns and the UI edits whole.

use std::io::IsTerminal;

use anyhow::{Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::ca;
use crate::config::{write_json_atomic, Paths};

/// Same minimum the password-change API will enforce.
pub(crate) const MIN_PASSWORD_CHARS: usize = 8;

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
/// The login handler is the caller. Until that lands, only the tests use it.
#[allow(dead_code)]
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
///
/// The request gate is the caller. Until that lands, only the tests use it.
#[allow(dead_code)]
pub fn token_matches(hash_hex: &str, presented: &str) -> bool {
    let actual = ca::hex(&ca::sha256(presented.as_bytes()));
    bool::from(hash_hex.as_bytes().ct_eq(actual.as_bytes()))
}

/// Prompts (or reads one stdin line), stores the password, and leaves any
/// existing API token in place.
pub fn set_password(paths: &Paths) -> Result<()> {
    let password = read_new_password()?;
    store_password(paths, &password)?;
    eprintln!("admin password saved");
    Ok(())
}

pub(crate) fn store_password(paths: &Paths, password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        anyhow::bail!("password must be at least {MIN_PASSWORD_CHARS} characters");
    }
    let mut credentials = Credentials::load_or_default(paths)?;
    credentials.password_hash = Some(hash_password(password)?);
    credentials.save(paths)
}

/// Prints a fresh token on stdout. The previous token stops working.
pub fn new_token(paths: &Paths) -> Result<()> {
    let token = store_new_token(paths)?;
    println!("{token}");
    eprintln!("this token will not be shown again");
    Ok(())
}

pub(crate) fn store_new_token(paths: &Paths) -> Result<String> {
    let (token, hash) = new_api_token();
    let mut credentials = Credentials::load_or_default(paths)?;
    credentials.api_token_hash = Some(hash);
    credentials.save(paths)?;
    Ok(token)
}

fn read_new_password() -> Result<String> {
    let password = if std::io::stdin().is_terminal() {
        let first =
            rpassword::prompt_password("New admin password: ").context("reading the password")?;
        let second = rpassword::prompt_password("Confirm admin password: ")
            .context("reading the password confirmation")?;
        if first != second {
            anyhow::bail!("passwords do not match");
        }
        first
    } else {
        // `echo pw | bloxy --set-admin-password` has no second line to confirm.
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading the password from stdin")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    Ok(password)
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

        let mut changed = token.clone();
        let last = changed.pop().unwrap();
        changed.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!token_matches(&hash, &changed));
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
    fn storing_a_password_keeps_the_existing_token() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        let token = store_new_token(&paths).unwrap();

        store_password(&paths, "long-enough").unwrap();

        let loaded = Credentials::load_or_default(&paths).unwrap();
        assert!(verify_password(
            loaded.password_hash.as_deref().unwrap(),
            "long-enough"
        ));
        assert!(token_matches(
            loaded.api_token_hash.as_deref().unwrap(),
            &token
        ));
    }

    #[test]
    fn a_short_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        let error = store_password(&paths, "short").unwrap_err();
        assert!(error.to_string().contains("at least 8"));
        assert!(!paths.admin_auth().exists());
    }

    #[test]
    fn a_new_token_replaces_the_previous_one() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        let first = store_new_token(&paths).unwrap();
        let second = store_new_token(&paths).unwrap();

        let loaded = Credentials::load_or_default(&paths).unwrap();
        let hash = loaded.api_token_hash.unwrap();
        assert!(!token_matches(&hash, &first));
        assert!(token_matches(&hash, &second));
    }
}
