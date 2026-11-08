//! `--set-admin-password` and `--new-api-token`. These never build `AppState`.

use std::io::IsTerminal;

use anyhow::{Context, Result};

use crate::config::Paths;

use super::{hash_password, new_api_token, Credentials, MIN_PASSWORD_CHARS};

#[cfg(test)]
use super::{token_matches, verify_password};

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
