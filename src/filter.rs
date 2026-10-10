//! uBlock Origin / Adblock Plus filter list matching, backed by Brave's
//! `adblock` engine.

use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use adblock::Engine;

/// What the proxy should do with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Blocked, with the matching rule for the event log.
    Block {
        rule: String,
    },
    /// Allowed, but a `removeparam` rule stripped query parameters.
    Rewrite {
        url: String,
    },
}

pub struct FilterEngine {
    engine: Engine,
    /// Names of the lists compiled into this engine, for the admin UI.
    pub sources: Vec<String>,
}

impl FilterEngine {
    /// Compiles `lists` (raw filter list text, paired with a display name) plus
    /// any freeform `custom_rules` into a matching engine.
    pub fn build(lists: Vec<(String, String)>, custom_rules: &[String]) -> Self {
        // Debug mode keeps the original rule text so the UI can explain why a
        // request was blocked.
        let mut set = FilterSet::new(true);
        let mut sources = Vec::with_capacity(lists.len());

        for (name, text) in lists {
            set.add_filter_list(text, ParseOptions::default());
            sources.push(name);
        }

        if !custom_rules.is_empty() {
            set.add_filter_list(custom_rules.join("\n"), ParseOptions::default());
            sources.push(format!("custom ({} rules)", custom_rules.len()));
        }

        Self {
            engine: Engine::new_with_filter_set(set),
            sources,
        }
    }

    pub fn empty() -> Self {
        Self {
            engine: Engine::new_with_filter_set(FilterSet::new(true)),
            sources: Vec::new(),
        }
    }

    /// `source_url` is the page the request originated from, used for
    /// first/third-party and domain-scoped rules. Pass the request URL itself
    /// for top-level navigations.
    pub fn check(&self, url: &str, source_url: &str, request_type: &str, method: &str) -> Decision {
        let Ok(request) = Request::new(url, source_url, request_type, method) else {
            // An unparseable URL is not something the filter lists can express
            // an opinion about.
            return Decision::Allow;
        };

        let result = self.engine.check_network_request(&request);

        if result.should_block() {
            let rule = result
                .filter
                .as_ref()
                .and_then(|info| info.raw_line.clone())
                .unwrap_or_else(|| String::from("network filter"));
            return Decision::Block { rule };
        }

        match result.rewritten_url {
            Some(rewritten) if rewritten != url => Decision::Rewrite { url: rewritten },
            _ => Decision::Allow,
        }
    }

    /// Element-hiding CSS and scriptlets for a page URL. Returns `None` when
    /// there is nothing to inject.
    pub fn cosmetic_payload(&self, url: &str) -> Option<CosmeticPayload> {
        let resources = self.engine.url_cosmetic_resources(url);

        let mut selectors: Vec<&str> = resources
            .hide_selectors
            .iter()
            .map(String::as_str)
            .collect();

        if selectors.is_empty() && resources.injected_script.trim().is_empty() {
            return None;
        }

        // Stable output keeps injected HTML byte-identical across requests,
        // which makes debugging far easier.
        selectors.sort_unstable();

        Some(CosmeticPayload {
            css: if selectors.is_empty() {
                String::new()
            } else {
                format!("{}{{display:none !important;}}", selectors.join(","))
            },
            script: resources.injected_script,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CosmeticPayload {
    pub css: String,
    pub script: String,
}

/// Maps an HTTP request to the resource type vocabulary the filter lists use.
///
/// `Sec-Fetch-Dest` is authoritative when present (all current browsers send
/// it); otherwise this falls back to `Accept` and the URL's file extension.
pub fn request_type_for(
    sec_fetch_dest: Option<&str>,
    accept: Option<&str>,
    is_websocket: bool,
    path: &str,
) -> &'static str {
    if is_websocket {
        return "websocket";
    }

    if let Some(dest) = sec_fetch_dest {
        let mapped = match dest {
            "document" => "document",
            "iframe" | "frame" => "sub_frame",
            "image" => "image",
            "script" | "serviceworker" | "sharedworker" | "worker" => "script",
            "style" => "stylesheet",
            "font" => "font",
            "audio" | "video" | "track" | "audioworklet" | "paintworklet" => "media",
            "object" | "embed" => "object",
            "manifest" | "report" => "other",
            "empty" => "xmlhttprequest",
            _ => "",
        };
        if !mapped.is_empty() {
            return mapped;
        }
    }

    if let Some(accept) = accept {
        if accept.starts_with("text/html") || accept.contains("application/xhtml+xml") {
            return "document";
        }
        if accept.starts_with("text/css") {
            return "stylesheet";
        }
        if accept.starts_with("image/") {
            return "image";
        }
        if accept.starts_with("font/") || accept.contains("font/woff") {
            return "font";
        }
        if accept.starts_with("audio/") || accept.starts_with("video/") {
            return "media";
        }
    }

    let extension = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .and_then(|segment| segment.rsplit_once('.'))
        .map(|(_, ext)| ext)
        .unwrap_or("");

    match extension.to_ascii_lowercase().as_str() {
        "js" | "mjs" => "script",
        "css" => "stylesheet",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico" | "avif" | "bmp" => "image",
        "woff" | "woff2" | "ttf" | "otf" | "eot" => "font",
        "mp4" | "webm" | "mp3" | "ogg" | "m4a" | "m4s" | "ts" | "m3u8" => "media",
        "html" | "htm" => "document",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_a_matching_network_rule() {
        let engine = FilterEngine::build(vec![("test".into(), "||ads.example.com^\n".into())], &[]);

        let decision = engine.check(
            "https://ads.example.com/banner.png",
            "https://news.example/",
            "image",
            "GET",
        );
        assert!(matches!(decision, Decision::Block { .. }));

        let allowed = engine.check(
            "https://cdn.example.com/banner.png",
            "https://news.example/",
            "image",
            "GET",
        );
        assert_eq!(allowed, Decision::Allow);
    }

    #[test]
    fn exception_rules_win() {
        let engine = FilterEngine::build(
            vec![(
                "test".into(),
                "||ads.example.com^\n@@||ads.example.com/allowed.png\n".into(),
            )],
            &[],
        );

        assert!(matches!(
            engine.check(
                "https://ads.example.com/blocked.png",
                "https://news.example/",
                "image",
                "GET"
            ),
            Decision::Block { .. }
        ));
        assert_eq!(
            engine.check(
                "https://ads.example.com/allowed.png",
                "https://news.example/",
                "image",
                "GET"
            ),
            Decision::Allow
        );
    }

    #[test]
    fn custom_rules_are_applied() {
        let engine = FilterEngine::build(Vec::new(), &["||tracker.test^".to_string()]);
        assert!(matches!(
            engine.check(
                "https://tracker.test/pixel.gif",
                "https://news.example/",
                "image",
                "GET"
            ),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn cosmetic_rules_produce_css() {
        let engine = FilterEngine::build(
            vec![("test".into(), "example.com##.ad-banner\n".into())],
            &[],
        );
        let payload = engine.cosmetic_payload("https://example.com/page").unwrap();
        assert!(payload.css.contains(".ad-banner"));
        assert!(payload.css.contains("display:none !important"));
    }

    #[test]
    fn unparseable_urls_are_allowed() {
        let engine = FilterEngine::build(vec![("test".into(), "||ads.example.com^\n".into())], &[]);
        assert_eq!(
            engine.check("not a url", "https://news.example/", "image", "GET"),
            Decision::Allow
        );
    }

    #[test]
    fn request_type_prefers_sec_fetch_dest() {
        assert_eq!(
            request_type_for(Some("image"), Some("text/html"), false, "/a.js"),
            "image"
        );
        assert_eq!(
            request_type_for(None, Some("text/html,application/xhtml+xml"), false, "/"),
            "document"
        );
        assert_eq!(request_type_for(None, None, false, "/app.js"), "script");
        assert_eq!(
            request_type_for(None, None, false, "/style.css?v=2"),
            "stylesheet"
        );
        assert_eq!(request_type_for(None, None, true, "/socket"), "websocket");
        assert_eq!(request_type_for(None, None, false, "/api/data"), "other");
    }
}
