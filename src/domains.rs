//! Domain blocklist matching, shared by the DNS blackhole and the proxy.

use std::collections::HashSet;

/// A set of domains where membership also covers every subdomain, plus an
/// allowlist that wins over the block set.
#[derive(Debug, Default)]
pub struct DomainSet {
    blocked: HashSet<String>,
    allowed: HashSet<String>,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block(&mut self, domain: &str) {
        if let Some(normalised) = normalise(domain) {
            self.blocked.insert(normalised);
        }
    }

    pub fn allow(&mut self, domain: &str) {
        if let Some(normalised) = normalise(domain) {
            self.allowed.insert(normalised);
        }
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    pub fn allowed_count(&self) -> usize {
        self.allowed.len()
    }

    /// True when `host` or any of its parent domains is blocked and no parent
    /// is allowlisted. The allowlist is checked at each level so that
    /// allowing `cdn.example.com` still leaves `example.com` blocked.
    pub fn is_blocked(&self, host: &str) -> bool {
        let Some(host) = normalise(host) else {
            return false;
        };
        for candidate in suffixes(&host) {
            if self.allowed.contains(candidate) {
                return false;
            }
            if self.blocked.contains(candidate) {
                return true;
            }
        }
        false
    }
}

/// Yields `a.b.c`, `b.c`, `c` in that order.
fn suffixes(host: &str) -> impl Iterator<Item = &str> {
    std::iter::once(host).chain(
        host.match_indices('.')
            .map(move |(index, _)| &host[index + 1..]),
    )
}

/// Lowercases, strips a trailing root dot, and rejects anything that is not a
/// plausible hostname (blocklists are full of junk lines).
fn normalise(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return None;
    }
    if domain.starts_with('.') || domain.contains("..") {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

/// Parses a hosts file, an `AdGuard`-style domain list, or a plain list of
/// domains. Lines that are not recognisable domains are skipped.
///
/// Returns the domains found, so callers can report list sizes.
pub fn parse_domain_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        // `#` and `!` are both used as comment markers across list formats.
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }

        // AdGuard/uBO syntax: `||example.com^`. Anything with extra options
        // after the `^` is a network filter, not a plain domain block, so it is
        // left for the filter engine.
        if let Some(rest) = line.strip_prefix("||") {
            let rest = rest.trim_end_matches('^');
            if !rest.contains(['/', '$', '*', '^']) {
                if let Some(domain) = normalise(rest) {
                    out.push(domain);
                }
            }
            continue;
        }

        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else { continue };

        match fields.next() {
            // `0.0.0.0 example.com` / `127.0.0.1 example.com foo.example.com`
            Some(second) if is_ip_literal(first) => {
                for host in std::iter::once(second).chain(fields) {
                    if host.eq_ignore_ascii_case("localhost")
                        || host.eq_ignore_ascii_case("localhost.localdomain")
                        || host.eq_ignore_ascii_case("broadcasthost")
                    {
                        continue;
                    }
                    if let Some(domain) = normalise(host) {
                        out.push(domain);
                    }
                }
            }
            // Multiple fields but no leading IP: not a format we understand.
            Some(_) => continue,
            // A bare domain per line.
            None => {
                if let Some(domain) = normalise(first) {
                    out.push(domain);
                }
            }
        }
    }
    out
}

fn is_ip_literal(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_subdomains() {
        let mut set = DomainSet::new();
        set.block("example.com");
        assert!(set.is_blocked("example.com"));
        assert!(set.is_blocked("ads.example.com"));
        assert!(set.is_blocked("a.b.example.com"));
        assert!(!set.is_blocked("notexample.com"));
        assert!(!set.is_blocked("com"));
    }

    #[test]
    fn allowlist_wins_at_its_own_level() {
        let mut set = DomainSet::new();
        set.block("example.com");
        set.allow("cdn.example.com");
        assert!(set.is_blocked("example.com"));
        assert!(!set.is_blocked("cdn.example.com"));
        assert!(!set.is_blocked("img.cdn.example.com"));
    }

    #[test]
    fn matching_is_case_and_dot_insensitive() {
        let mut set = DomainSet::new();
        set.block("Example.COM.");
        assert!(set.is_blocked("ADS.example.com."));
    }

    #[test]
    fn parses_hosts_format() {
        let text = "\
# comment
0.0.0.0 ads.example.com
127.0.0.1 localhost
127.0.0.1 tracker.test another.test
||adguard.example^
plain.example.com
! banner comment
||has.options^$third-party
192.168.1.1 router.lan # trailing comment
";
        let domains = parse_domain_list(text);
        assert_eq!(
            domains,
            vec![
                "ads.example.com",
                "tracker.test",
                "another.test",
                "adguard.example",
                "plain.example.com",
                "router.lan",
            ]
        );
    }

    #[test]
    fn rejects_junk_lines() {
        assert!(parse_domain_list("not a domain at all\n..\n \n").is_empty());
    }
}
