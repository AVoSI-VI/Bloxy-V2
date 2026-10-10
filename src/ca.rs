//! The local certificate authority used for TLS interception.
//!
//! A single CA key pair is generated on first run and persisted. Leaf
//! certificates are minted on demand per hostname and cached, so a repeat visit
//! to a host costs nothing.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use moka::sync::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration as TimeDuration, OffsetDateTime};

/// How long minted leaf certificates stay valid.
const LEAF_VALIDITY_DAYS: i64 = 365;
/// How long the CA itself stays valid.
const CA_VALIDITY_DAYS: i64 = 3650;
/// Backdated slightly to tolerate clock skew between the proxy and clients.
const LEAF_BACKDATE_HOURS: i64 = 24;

const MAX_CACHED_HOSTS: u64 = 4096;
const CACHE_TTL: Duration = Duration::from_secs(60 * 60 * 24);

pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    /// Sent alongside every leaf so clients that want the full chain get it.
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    /// One key pair reused by every leaf. Minting a fresh key per host would
    /// dominate handshake cost and buys nothing here.
    leaf_key: KeyPair,
    leaf_key_der: PrivateKeyDer<'static>,
    cache: Cache<String, Arc<ServerConfig>>,
}

impl CertAuthority {
    /// Loads the CA from disk, generating and persisting a new one if either
    /// file is missing.
    pub fn load_or_create(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let (ca_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            (
                std::fs::read_to_string(cert_path)
                    .with_context(|| format!("reading CA certificate {}", cert_path.display()))?,
                std::fs::read_to_string(key_path)
                    .with_context(|| format!("reading CA key {}", key_path.display()))?,
            )
        } else {
            let (cert_pem, key_pem) = generate_ca()?;
            if let Some(parent) = cert_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(cert_path, &cert_pem)
                .with_context(|| format!("writing CA certificate {}", cert_path.display()))?;
            write_private_key(key_path, &key_pem)
                .with_context(|| format!("writing CA key {}", key_path.display()))?;
            tracing::info!(path = %cert_path.display(), "generated a new certificate authority");
            (cert_pem, key_pem)
        };

        let ca_key = KeyPair::from_pem(&key_pem).context("parsing CA private key")?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).context("loading CA certificate")?;

        let ca_der = pem_to_der(&ca_pem).context("decoding CA certificate")?;

        let leaf_key = KeyPair::generate().context("generating leaf key pair")?;
        let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        Ok(Self {
            issuer,
            ca_der,
            ca_pem,
            leaf_key,
            leaf_key_der,
            cache: Cache::builder()
                .max_capacity(MAX_CACHED_HOSTS)
                .time_to_live(CACHE_TTL)
                .build(),
        })
    }

    /// The CA certificate in PEM form, for the client to install as a trust
    /// anchor.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Lowercase hex SHA-256 of the CA certificate, so the user can verify what
    /// they installed.
    pub fn fingerprint(&self) -> String {
        sha256(self.ca_der.as_ref())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn cached_hosts(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Returns a ready-to-use rustls config presenting a certificate for
    /// `host`, minting and caching one if needed.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = host.to_ascii_lowercase();
        if let Some(config) = self.cache.get(&host) {
            return Ok(config);
        }

        let config = Arc::new(self.build_server_config(&host)?);
        self.cache.insert(host, config.clone());
        Ok(config)
    }

    fn build_server_config(&self, host: &str) -> Result<ServerConfig> {
        let leaf = self.mint_leaf(host)?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf, self.ca_der.clone()],
                self.leaf_key_der.clone_key(),
            )
            .context("building rustls server config")?;

        // The interception path speaks HTTP/1.1 only, so never negotiate h2.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    fn mint_leaf(&self, host: &str) -> Result<CertificateDer<'static>> {
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                host.to_string()
                    .try_into()
                    .with_context(|| format!("{host} is not a usable DNS name"))?,
            ),
        };

        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san];
        params.not_before = OffsetDateTime::now_utc() - TimeDuration::hours(LEAF_BACKDATE_HOURS);
        params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(LEAF_VALIDITY_DAYS);
        params.serial_number = Some(SerialNumber::from(rand::random::<u64>()));
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;

        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .with_context(|| format!("signing certificate for {host}"))?;
        Ok(cert.der().clone())
    }
}

fn generate_ca() -> Result<(String, String)> {
    let key = KeyPair::generate().context("generating CA key pair")?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::hours(LEAF_BACKDATE_HOURS);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(CA_VALIDITY_DAYS);
    params.serial_number = Some(SerialNumber::from(rand::random::<u64>()));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "bloxy Root CA");
    name.push(DnType::OrganizationName, "bloxy");
    params.distinguished_name = name;

    let cert = params.self_signed(&key).context("self-signing CA")?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Writes a private key with owner-only permissions where the platform
/// supports it.
fn write_private_key(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn pem_to_der(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .context("PEM contained no certificate")?
        .context("malformed PEM certificate")?;
    Ok(first)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca(dir: &Path) -> CertAuthority {
        CertAuthority::load_or_create(&dir.join("ca.crt"), &dir.join("ca.key")).unwrap()
    }

    #[test]
    fn generates_then_reloads_the_same_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();

        let first = test_ca(dir.path());
        let second = test_ca(dir.path());
        assert_eq!(first.ca_pem(), second.ca_pem());
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn mints_certificates_for_hosts_and_ip_literals() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca = test_ca(dir.path());

        assert!(ca.server_config_for("example.com").is_ok());
        assert!(ca.server_config_for("127.0.0.1").is_ok());
    }

    #[test]
    fn caches_by_host() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca = test_ca(dir.path());

        let first = ca.server_config_for("example.com").unwrap();
        let second = ca.server_config_for("EXAMPLE.com").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }
}
