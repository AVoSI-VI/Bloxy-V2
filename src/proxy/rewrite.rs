//! Injection of element-hiding CSS and scriptlets into HTML responses.
//!
//! Everything here works on bytes rather than `String`. HTML is not guaranteed
//! to be UTF-8, and the markup we insert is pure ASCII, so it splices safely
//! into any ASCII-compatible encoding without needing to decode the page.

use std::io::Read;

use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING,
};
use hyper::Response;

use crate::filter::CosmeticPayload;

use super::{full_body, ProxyBody};

/// Pages larger than this are streamed through untouched rather than buffered.
const MAX_BUFFERED_HTML: usize = 16 * 1024 * 1024;

/// Read buffer for the brotli decoder.
const BROTLI_BUFFER: usize = 32 * 1024;

/// The content codings [`decode`] understands, as an `Accept-Encoding` value.
///
/// The proxy sends this on requests whose response it intends to rewrite, so an
/// origin cannot pick a coding that would force the page through unfiltered.
pub const ACCEPTED_ENCODINGS: &str = "gzip, deflate, br, zstd, identity";

/// A `Content-Encoding` this module can undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl Coding {
    /// Returns `None` for anything that cannot be decoded, which includes
    /// multi-coding values such as `gzip, br`: those would have to be unwrapped
    /// in sequence, and no real origin sends them.
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => Some(Self::Identity),
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }

    /// Reads the coding of a response, treating an absent header as identity
    /// and an unreadable one as undecodable.
    fn of(headers: &hyper::HeaderMap) -> Option<Self> {
        match headers.get(CONTENT_ENCODING) {
            None => Some(Self::Identity),
            Some(value) => Self::parse(value.to_str().ok()?),
        }
    }
}

/// True when the response looks like HTML we can safely rewrite.
pub fn is_rewritable_html(response: &Response<Incoming>) -> bool {
    let is_html = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.starts_with("text/html") || value.starts_with("application/xhtml+xml")
        });

    if !is_html {
        return false;
    }

    // The proxy narrows the request's Accept-Encoding for HTML, so this should
    // already hold; it is checked here because an origin may ignore that.
    let encoding_ok = Coding::of(response.headers()).is_some();

    let small_enough = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|length| length <= MAX_BUFFERED_HTML);

    encoding_ok && small_enough
}

/// Buffers an HTML response, injects `payload`, and returns it decompressed.
///
/// The body is consumed, so this can only be called once `is_rewritable_html`
/// has confirmed the response is a candidate. On any decoding failure the
/// original bytes are passed through unmodified.
pub async fn inject(
    response: Response<Incoming>,
    payload: &CosmeticPayload,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let (mut parts, body) = response.into_parts();

    let collected = match Limited::new(body, MAX_BUFFERED_HTML).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            tracing::debug!(%error, "could not buffer HTML response; serving an error");
            let mut error_response = Response::new(full_body(Bytes::from_static(
                b"bloxy could not buffer this response for filtering",
            )));
            *error_response.status_mut() = hyper::StatusCode::BAD_GATEWAY;
            return Ok(error_response);
        }
    };

    let decoded = match Coding::of(&parts.headers).and_then(|coding| decode(&collected, coding)) {
        Some(decoded) => decoded,
        None => {
            tracing::debug!(
                encoding = ?parts.headers.get(CONTENT_ENCODING),
                "could not decode HTML body; leaving it untouched"
            );
            // Re-emit exactly what arrived, encoding header included.
            return Ok(Response::from_parts(parts, full_body(collected)));
        }
    };

    let injected = splice(&decoded, &build_snippet(payload));

    // The body is now plain bytes of a known length.
    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&injected.len().to_string())
            .expect("a decimal length is a valid header value"),
    );

    Ok(Response::from_parts(
        parts,
        full_body(Bytes::from(injected)),
    ))
}

fn decode(body: &[u8], coding: Coding) -> Option<Vec<u8>> {
    match coding {
        Coding::Identity => Some(body.to_vec()),
        Coding::Gzip => read_all(flate2::read::GzDecoder::new(body)),
        // Servers disagree on whether "deflate" means zlib or raw; try zlib
        // first since that is what the specification requires.
        Coding::Deflate => read_all(flate2::read::ZlibDecoder::new(body))
            .or_else(|| read_all(flate2::read::DeflateDecoder::new(body))),
        Coding::Brotli => read_all(brotli::Decompressor::new(body, BROTLI_BUFFER)),
        Coding::Zstd => read_all(ruzstd::decoding::StreamingDecoder::new(body).ok()?),
    }
}

/// Decompresses a reader fully, giving up if the result would exceed the
/// buffering cap.
///
/// Reading one byte past the cap is what distinguishes "this page is too big"
/// from "this page is exactly at the limit"; without it an oversized page would
/// be silently truncated and served as broken HTML. Bailing out instead sends
/// the original bytes through unmodified. The cap also bounds the damage a
/// compression bomb can do, which matters more for brotli and zstd than it did
/// for gzip.
fn read_all(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(MAX_BUFFERED_HTML as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;

    if out.len() > MAX_BUFFERED_HTML {
        return None;
    }
    Some(out)
}

fn build_snippet(payload: &CosmeticPayload) -> Vec<u8> {
    let mut snippet = Vec::new();

    if !payload.css.is_empty() {
        snippet.extend_from_slice(b"<style id=\"bloxy-cosmetic\">");
        // A selector list cannot legally contain `<`, but a malformed rule
        // could; dropping it is cheaper than escaping and cannot break markup.
        if !payload.css.contains('<') {
            snippet.extend_from_slice(payload.css.as_bytes());
        }
        snippet.extend_from_slice(b"</style>");
    }

    let script = payload.script.trim();
    // A scriptlet containing a closing script tag would terminate the block
    // early and inject arbitrary markup into the page.
    if !script.is_empty() && !script.to_ascii_lowercase().contains("</script") {
        snippet.extend_from_slice(b"<script id=\"bloxy-scriptlets\">");
        snippet.extend_from_slice(script.as_bytes());
        snippet.extend_from_slice(b"</script>");
    }

    snippet
}

/// Inserts `snippet` as early in the document as is valid: immediately after
/// the opening `<head>` tag, else after `<html>`, else at the very start.
fn splice(html: &[u8], snippet: &[u8]) -> Vec<u8> {
    if snippet.is_empty() {
        return html.to_vec();
    }

    let at = insertion_point(html);
    let mut out = Vec::with_capacity(html.len() + snippet.len());
    out.extend_from_slice(&html[..at]);
    out.extend_from_slice(snippet);
    out.extend_from_slice(&html[at..]);
    out
}

fn insertion_point(html: &[u8]) -> usize {
    for tag in [b"<head".as_slice(), b"<html".as_slice()] {
        if let Some(start) = find_ascii_ci(html, tag) {
            // Skip past the end of the opening tag itself.
            if let Some(offset) = html[start..].iter().position(|byte| *byte == b'>') {
                return start + offset + 1;
            }
        }
    }
    0
}

/// Case-insensitive subsequence search over ASCII bytes.
fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> CosmeticPayload {
        CosmeticPayload {
            css: ".ad{display:none !important;}".into(),
            script: "console.log(1)".into(),
        }
    }

    #[test]
    fn inserts_after_the_head_tag() {
        let html = b"<!doctype html><html><head><title>x</title></head><body></body></html>";
        let out = splice(html, &build_snippet(&payload()));
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("<head><style id=\"bloxy-cosmetic\">"));
        assert!(text.contains("console.log(1)"));
        assert!(text.starts_with("<!doctype html>"));
    }

    #[test]
    fn falls_back_to_the_html_tag() {
        let html = b"<html><body>no head</body></html>";
        let text = String::from_utf8(splice(html, &build_snippet(&payload()))).unwrap();
        assert!(text.starts_with("<html><style"));
    }

    #[test]
    fn falls_back_to_the_start_of_the_document() {
        let html = b"just a fragment";
        let text = String::from_utf8(splice(html, &build_snippet(&payload()))).unwrap();
        assert!(text.starts_with("<style"));
        assert!(text.ends_with("just a fragment"));
    }

    #[test]
    fn tag_matching_is_case_insensitive() {
        let html = b"<HTML><HEAD></HEAD></HTML>";
        let text = String::from_utf8(splice(html, &build_snippet(&payload()))).unwrap();
        assert!(text.starts_with("<HTML><HEAD><style"));
    }

    #[test]
    fn drops_scriptlets_that_would_escape_the_script_block() {
        let hostile = CosmeticPayload {
            css: String::new(),
            script: "</script><img src=x onerror=alert(1)>".into(),
        };
        let snippet = String::from_utf8(build_snippet(&hostile)).unwrap();
        assert!(snippet.is_empty());
    }

    #[test]
    fn drops_css_that_would_escape_the_style_block() {
        let hostile = CosmeticPayload {
            css: "</style><script>alert(1)</script>".into(),
            script: String::new(),
        };
        let snippet = String::from_utf8(build_snippet(&hostile)).unwrap();
        assert_eq!(snippet, "<style id=\"bloxy-cosmetic\"></style>");
    }

    #[test]
    fn non_utf8_bytes_survive_injection() {
        // A windows-1252 page with a 0x93 smart quote.
        let html = b"<html><head></head><body>\x93hi\x94</body></html>";
        let out = splice(html, &build_snippet(&payload()));
        assert!(out.windows(2).any(|w| w == [0x93, b'h']));
    }

    const PAGE: &[u8] = b"<html><head></head><body>hello</body></html>";

    #[test]
    fn round_trips_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(PAGE).unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(decode(&compressed, Coding::Gzip).unwrap(), PAGE);
    }

    #[test]
    fn round_trips_zlib_and_raw_deflate() {
        use flate2::write::{DeflateEncoder, ZlibEncoder};
        use std::io::Write;

        let mut zlib = ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        zlib.write_all(PAGE).unwrap();
        assert_eq!(
            decode(&zlib.finish().unwrap(), Coding::Deflate).unwrap(),
            PAGE
        );

        let mut raw = DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        raw.write_all(PAGE).unwrap();
        assert_eq!(
            decode(&raw.finish().unwrap(), Coding::Deflate).unwrap(),
            PAGE
        );
    }

    #[test]
    fn round_trips_brotli() {
        use std::io::Write;

        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
        encoder.write_all(PAGE).unwrap();
        let compressed = encoder.into_inner();

        assert_eq!(decode(&compressed, Coding::Brotli).unwrap(), PAGE);
    }

    #[test]
    fn round_trips_zstd() {
        let compressed =
            ruzstd::encoding::compress_to_vec(PAGE, ruzstd::encoding::CompressionLevel::Fastest);

        assert_eq!(decode(&compressed, Coding::Zstd).unwrap(), PAGE);
    }

    #[test]
    fn identity_passes_bytes_straight_through() {
        assert_eq!(decode(b"plain", Coding::Identity).unwrap(), b"plain");
    }

    #[test]
    fn corrupt_bodies_are_rejected_rather_than_panicking() {
        for coding in [Coding::Gzip, Coding::Deflate, Coding::Brotli, Coding::Zstd] {
            assert!(
                decode(b"not actually compressed", coding).is_none(),
                "{coding:?} accepted garbage"
            );
        }
    }

    #[test]
    fn recognises_every_supported_coding() {
        assert_eq!(Coding::parse(""), Some(Coding::Identity));
        assert_eq!(Coding::parse("identity"), Some(Coding::Identity));
        assert_eq!(Coding::parse("gzip"), Some(Coding::Gzip));
        assert_eq!(Coding::parse("x-gzip"), Some(Coding::Gzip));
        assert_eq!(Coding::parse("deflate"), Some(Coding::Deflate));
        assert_eq!(Coding::parse("br"), Some(Coding::Brotli));
        assert_eq!(Coding::parse("zstd"), Some(Coding::Zstd));
        assert_eq!(Coding::parse("  BR  "), Some(Coding::Brotli));
    }

    #[test]
    fn rejects_unknown_and_stacked_codings() {
        assert_eq!(Coding::parse("compress"), None);
        assert_eq!(Coding::parse("gzip, br"), None);
    }

    /// Every coding advertised to origins must be one the decoder can undo,
    /// otherwise the proxy would invite responses it cannot rewrite.
    #[test]
    fn advertised_encodings_are_all_decodable() {
        for coding in ACCEPTED_ENCODINGS.split(',') {
            assert!(
                Coding::parse(coding).is_some(),
                "advertised {coding:?} but cannot decode it"
            );
        }
    }

    #[test]
    fn oversized_output_is_rejected_instead_of_truncated() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        // Compresses to a few kilobytes but expands past the buffering cap.
        let bomb = vec![b'a'; MAX_BUFFERED_HTML + 1024];
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&bomb).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 100 * 1024);

        assert!(decode(&compressed, Coding::Gzip).is_none());
    }

    #[test]
    fn output_exactly_at_the_cap_is_still_accepted() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let exact = vec![b'a'; MAX_BUFFERED_HTML];
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&exact).unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(
            decode(&compressed, Coding::Gzip).unwrap().len(),
            MAX_BUFFERED_HTML
        );
    }
}
