//! On-disk configuration. Serialised as JSON so the admin UI can round-trip it
//! without a second schema.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub dns: DnsConfig,
    pub filtering: FilteringConfig,
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// When false, CONNECT requests are tunnelled opaquely and only the
    /// hostname can be filtered.
    pub mitm_enabled: bool,
    /// Hosts that are always tunnelled without interception. Entries match the
    /// host itself and any subdomain of it. Useful for certificate-pinned apps.
    pub mitm_bypass: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:8080".parse().unwrap(),
            mitm_enabled: true,
            mitm_bypass: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockResponse {
    /// Answer with NXDOMAIN. Cheapest for the client, but some stacks retry.
    NxDomain,
    /// Answer with 0.0.0.0 / :: so the connection fails fast locally.
    NullAddress,
    /// Answer with REFUSED.
    Refused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Tried in order; the first to answer within `upstream_timeout_ms` wins.
    pub upstreams: Vec<SocketAddr>,
    pub upstream_timeout_ms: u64,
    pub block_response: BlockResponse,
    /// TTL handed out on blackholed answers.
    pub block_ttl: u32,
    pub blocklists: Vec<ListSource>,
    /// Individually blocked domains. Each also blocks its subdomains.
    pub blocked_domains: Vec<String>,
    /// Takes precedence over both blocklists and `blocked_domains`.
    pub allowed_domains: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:5353".parse().unwrap(),
            upstreams: vec!["1.1.1.1:53".parse().unwrap(), "9.9.9.9:53".parse().unwrap()],
            upstream_timeout_ms: 3000,
            block_response: BlockResponse::NullAddress,
            block_ttl: 60,
            blocklists: vec![ListSource {
                name: "StevenBlack unified hosts".into(),
                url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
                enabled: true,
            }],
            blocked_domains: Vec::new(),
            allowed_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilteringConfig {
    pub enabled: bool,
    /// Inject element-hiding CSS and scriptlets into HTML responses. Requires
    /// MITM, and forces `Accept-Encoding` down to gzip/deflate so bodies can be
    /// rewritten.
    pub cosmetic_filtering: bool,
    pub lists: Vec<ListSource>,
    /// Extra rules in uBlock Origin / Adblock Plus syntax.
    pub custom_rules: Vec<String>,
}

impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cosmetic_filtering: true,
            lists: vec![
                ListSource {
                    name: "uBO filters".into(),
                    url: "https://ublockorigin.github.io/uAssets/filters/filters.txt".into(),
                    enabled: true,
                },
                ListSource {
                    name: "uBO badware".into(),
                    url: "https://ublockorigin.github.io/uAssets/filters/badware.txt".into(),
                    enabled: true,
                },
                ListSource {
                    name: "uBO privacy".into(),
                    url: "https://ublockorigin.github.io/uAssets/filters/privacy.txt".into(),
                    enabled: true,
                },
                ListSource {
                    name: "EasyList".into(),
                    url: "https://easylist.to/easylist/easylist.txt".into(),
                    enabled: true,
                },
                ListSource {
                    name: "EasyPrivacy".into(),
                    url: "https://easylist.to/easylist/easyprivacy.txt".into(),
                    enabled: true,
                },
            ],
            custom_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub listen: SocketAddr,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8081".parse().unwrap(),
        }
    }
}

/// A remote filter list or hosts list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSource {
    pub name: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        // Windows editors commonly save UTF-8 with a byte order mark, which
        // JSON does not permit.
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        serde_json::from_str(text).with_context(|| format!("parsing config {}", path.display()))
    }

    /// Writes via a temporary file so a crash mid-write cannot truncate the
    /// existing config.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("writing config {}", path.display()))?;
        Ok(())
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Config::load(path)
        } else {
            let config = Config::default();
            config.save(path)?;
            Ok(config)
        }
    }
}

/// Filesystem layout for everything the server persists.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn ca_cert(&self) -> PathBuf {
        self.root.join("ca").join("bloxy-ca.crt")
    }

    pub fn ca_key(&self) -> PathBuf {
        self.root.join("ca").join("bloxy-ca.key")
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// Cache filename for a list URL. Hashed because URLs contain characters
    /// that are not portable in filenames.
    pub fn cached_list(&self, url: &str) -> PathBuf {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in url.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.cache_dir().join(format!("{hash:016x}.txt"))
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.root.join("ca"))?;
        std::fs::create_dir_all(self.cache_dir())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let mut config = Config::default();
        config.dns.blocked_domains = vec!["example.com".into()];
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.dns.blocked_domains, vec!["example.com".to_string()]);
        assert_eq!(loaded.proxy.listen, config.proxy.listen);
    }

    #[test]
    fn accepts_a_utf8_byte_order_mark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "\u{feff}{\"admin\":{\"listen\":\"127.0.0.1:9999\"}}").unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.admin.listen.port(), 9999);
    }

    #[test]
    fn missing_sections_fall_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.proxy.listen, Config::default().proxy.listen);
        assert!(loaded.filtering.enabled);
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_silently_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "{\"proxy\":{\"lissten\":\"127.0.0.1:1\"}}").unwrap();

        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn cached_list_paths_are_stable_and_distinct() {
        let paths = Paths::new(PathBuf::from("data"));
        assert_eq!(
            paths.cached_list("https://a.example/list.txt"),
            paths.cached_list("https://a.example/list.txt")
        );
        assert_ne!(
            paths.cached_list("https://a.example/list.txt"),
            paths.cached_list("https://b.example/list.txt")
        );
    }
}
