//! The filtering HTTP/HTTPS proxy.
//!
//! Plain HTTP arrives as absolute-form requests and is filtered directly.
//! HTTPS arrives as `CONNECT`; when interception is enabled the proxy answers
//! the tunnel itself with a certificate minted by the local CA, then filters
//! the requests inside it. When interception is off, or the host is on the
//! bypass list, the bytes are relayed opaquely and only the hostname can be
//! filtered.

mod rewrite;
mod upstream;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, ACCEPT, ACCEPT_ENCODING, ALT_SVC, CONNECTION, HOST, REFERER, UPGRADE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::filter::{request_type_for, Decision};
use crate::state::AppState;
use crate::stats::{Action, Source};

use upstream::Upstream;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Headers that apply to a single hop and must not be forwarded.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

struct Proxy {
    state: Arc<AppState>,
    tls: tokio_rustls::TlsConnector,
}

/// One client connection. An intercepted CONNECT creates a nested session for
/// the requests inside the tunnel.
struct Session {
    proxy: Arc<Proxy>,
    client: SocketAddr,
    upstream: Arc<Upstream>,
    /// `Some` when this session is the inside of an intercepted TLS tunnel.
    intercepted: Option<Origin>,
}

#[derive(Debug, Clone)]
struct Origin {
    host: String,
    port: u16,
}

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let listen = state.config().proxy.listen;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding proxy listener on {listen}"))?;

    tracing::info!(address = %listen, "proxy listening");

    let proxy = Arc::new(Proxy {
        state,
        tls: upstream::tls_connector(),
    });

    loop {
        let (stream, client) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "proxy accept failed");
                continue;
            }
        };
        stream.set_nodelay(true).ok();

        let session = Arc::new(Session {
            upstream: Arc::new(Upstream::new(proxy.tls.clone())),
            proxy: proxy.clone(),
            client,
            intercepted: None,
        });

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let session = session.clone();
                async move { Ok::<_, Infallible>(handle(req, session).await) }
            });

            let result = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(stream), service)
                // Required for CONNECT and WebSocket upgrades.
                .with_upgrades()
                .await;

            if let Err(error) = result {
                tracing::debug!(%client, %error, "proxy connection ended");
            }
        });
    }
}

async fn handle(req: Request<Incoming>, session: Arc<Session>) -> Response<ProxyBody> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, session).await;
    }
    forward(req, session).await
}

// ---------------------------------------------------------------- CONNECT

async fn handle_connect(req: Request<Incoming>, session: Arc<Session>) -> Response<ProxyBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return simple(StatusCode::BAD_REQUEST, "CONNECT requires an authority");
    };

    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);
    let state = &session.proxy.state;

    if state.domains().is_blocked(&host) {
        state.stats.record(
            Source::Proxy,
            Action::Blocked,
            &session.client.ip().to_string(),
            &format!("CONNECT {host}:{port}"),
            "domain blocklist",
        );
        return simple(StatusCode::FORBIDDEN, "blocked by bloxy (domain blocklist)");
    }

    let config = state.config();
    let intercept = config.proxy.mitm_enabled
        && port == 443
        && !host_matches_any(&host, &config.proxy.mitm_bypass);

    // The tunnel only exists after this response is written, so the rest runs
    // on the upgraded connection.
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(upgraded) => upgraded,
            Err(error) => {
                tracing::debug!(%host, %error, "CONNECT upgrade failed");
                return;
            }
        };
        let io = TokioIo::new(upgraded);

        let result = if intercept {
            intercept_tls(
                io,
                Origin {
                    host: host.clone(),
                    port,
                },
                session,
            )
            .await
        } else {
            tunnel(io, &host, port).await
        };

        if let Err(error) = result {
            tracing::debug!(%host, %error, "tunnel ended");
        }
    });

    Response::new(empty_body())
}

/// Relays bytes between the client and the origin without inspecting them.
async fn tunnel<I>(mut io: I, host: &str, port: u16) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut origin = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;
    origin.set_nodelay(true).ok();

    tokio::io::copy_bidirectional(&mut io, &mut origin)
        .await
        .context("relaying tunnel bytes")?;
    Ok(())
}

/// Terminates TLS with a minted certificate and serves the requests inside.
async fn intercept_tls<I>(io: I, origin: Origin, session: Arc<Session>) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let server_config = session.proxy.state.ca.server_config_for(&origin.host)?;
    let stream = TlsAcceptor::from(server_config)
        .accept(io)
        .await
        .with_context(|| format!("TLS handshake with client for {}", origin.host))?;

    // A fresh upstream so the tunnel's origin connection is not shared with
    // the outer plain-HTTP session.
    let inner = Arc::new(Session {
        upstream: Arc::new(Upstream::new(session.proxy.tls.clone())),
        proxy: session.proxy.clone(),
        client: session.client,
        intercepted: Some(origin),
    });

    // Calls `forward` rather than `handle`: a CONNECT inside an established
    // tunnel is meaningless, and avoiding the recursion keeps the handler
    // future a plain `impl Future`.
    let service = service_fn(move |req| {
        let inner = inner.clone();
        async move { Ok::<_, Infallible>(forward(req, inner).await) }
    });

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .context("serving intercepted connection")?;
    Ok(())
}

// ---------------------------------------------------------------- forwarding

async fn forward(mut req: Request<Incoming>, session: Arc<Session>) -> Response<ProxyBody> {
    let state = session.proxy.state.clone();
    let client_ip = session.client.ip().to_string();

    let Some(target) = resolve_target(&req, session.intercepted.as_ref()) else {
        return simple(
            StatusCode::BAD_REQUEST,
            "could not determine the request target",
        );
    };

    if state.domains().is_blocked(&target.host) {
        state.stats.record(
            Source::Proxy,
            Action::Blocked,
            &client_ip,
            &target.url,
            "domain blocklist",
        );
        return simple(StatusCode::FORBIDDEN, "blocked by bloxy (domain blocklist)");
    }

    let is_websocket = header_contains(&req, UPGRADE, "websocket");
    let request_type = request_type_for(
        header_str(&req, "sec-fetch-dest").as_deref(),
        header_str(&req, ACCEPT.as_str()).as_deref(),
        is_websocket,
        req.uri().path(),
    );

    // Without a Referer the request is treated as first-party, which is the
    // conservative choice: `$third-party` rules will not fire on it.
    let source_url = header_str(&req, REFERER.as_str()).unwrap_or_else(|| target.url.clone());

    let config = state.config();
    let mut url = target.url.clone();

    if config.filtering.enabled {
        let match_url = if is_websocket {
            websocket_url(&target)
        } else {
            target.url.clone()
        };

        match state
            .filter()
            .check(&match_url, &source_url, request_type, req.method().as_str())
        {
            Decision::Block { rule } => {
                state
                    .stats
                    .record(Source::Proxy, Action::Blocked, &client_ip, &url, &rule);
                return simple(StatusCode::FORBIDDEN, "blocked by bloxy (filter list)");
            }
            Decision::Rewrite { url: rewritten } => {
                tracing::debug!(from = %url, to = %rewritten, "removeparam rewrote a URL");
                url = rewritten;
            }
            Decision::Allow => {}
        }
    }

    state
        .stats
        .record(Source::Proxy, Action::Allowed, &client_ip, &url, "");

    // Cosmetic filtering needs a body it can decompress and splice.
    let wants_cosmetics = config.filtering.enabled
        && config.filtering.cosmetic_filtering
        && matches!(request_type, "document" | "sub_frame");

    let client_upgrade = if is_websocket {
        req.extensions_mut().remove::<OnUpgrade>()
    } else {
        None
    };

    let outbound = match build_outbound(req, &url, wants_cosmetics, is_websocket) {
        Ok(outbound) => outbound,
        Err(error) => {
            tracing::debug!(%error, "could not build the upstream request");
            return simple(StatusCode::BAD_REQUEST, "malformed request");
        }
    };

    let response = match session
        .upstream
        .send(target.tls, &target.host, target.port, outbound)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(url = %url, %error, "upstream request failed");
            return simple(StatusCode::BAD_GATEWAY, "bloxy could not reach the origin");
        }
    };

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return relay_upgrade(response, client_upgrade);
    }

    if wants_cosmetics && rewrite::is_rewritable_html(&response) {
        if let Some(payload) = state.filter().cosmetic_payload(&url) {
            match rewrite::inject(response, &payload).await {
                Ok(rewritten) => return sanitise_response(rewritten),
                Err(error) => {
                    tracing::debug!(%error, "cosmetic injection failed");
                    return simple(
                        StatusCode::BAD_GATEWAY,
                        "bloxy could not filter the response",
                    );
                }
            }
        } else {
            return sanitise_response(response.map(|body| body.boxed()));
        }
    }

    sanitise_response(response.map(|body| body.boxed()))
}

/// Where a request is actually going, in the several forms needed downstream.
struct Target {
    tls: bool,
    host: String,
    port: u16,
    /// Absolute URL, used for filter matching and logging.
    url: String,
}

fn resolve_target(req: &Request<Incoming>, intercepted: Option<&Origin>) -> Option<Target> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Inside an intercepted tunnel the scheme and authority come from CONNECT,
    // not from the request line.
    if let Some(origin) = intercepted {
        return Some(Target {
            tls: true,
            host: origin.host.clone(),
            port: origin.port,
            url: build_url(true, &origin.host, origin.port, path),
        });
    }

    // Absolute-form, which is what a well-behaved client sends to a proxy.
    if let Some(authority) = req.uri().authority() {
        let tls = req.uri().scheme_str() == Some("https");
        let port = authority.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let host = authority.host().to_ascii_lowercase();
        return Some(Target {
            url: build_url(tls, &host, port, path),
            tls,
            host,
            port,
        });
    }

    // Origin-form with a Host header, as seen from transparently redirected
    // clients. Only plain HTTP can reach here.
    let host_header = req.headers().get(HOST)?.to_str().ok()?;
    let authority: hyper::http::uri::Authority = host_header.parse().ok()?;
    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(80);
    Some(Target {
        url: build_url(false, &host, port, path),
        tls: false,
        host,
        port,
    })
}

fn build_url(tls: bool, host: &str, port: u16, path: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    let default_port = if tls { 443 } else { 80 };
    if port == default_port {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}")
    }
}

/// Filter lists match WebSocket requests on `ws://` / `wss://` URLs.
fn websocket_url(target: &Target) -> String {
    let http_url = &target.url;
    if target.tls {
        http_url.replacen("https://", "wss://", 1)
    } else {
        http_url.replacen("http://", "ws://", 1)
    }
}

/// Rebuilds the request for the origin: origin-form URI, hop-by-hop headers
/// removed, and `Accept-Encoding` narrowed when the body must be rewritten.
fn build_outbound(
    req: Request<Incoming>,
    url: &str,
    wants_cosmetics: bool,
    is_websocket: bool,
) -> Result<Request<ProxyBody>> {
    let (mut parts, body) = req.into_parts();

    let parsed: Uri = url.parse().context("re-parsing the target URL")?;
    let path = parsed
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| String::from("/"));
    parts.uri = path.parse().context("building the origin-form URI")?;

    // Upgrade requests need Connection and Upgrade to survive the hop.
    strip_hop_by_hop(&mut parts.headers, is_websocket);

    if wants_cosmetics {
        // Pin the response to a coding the rewriter can undo, so an origin
        // cannot pick something exotic and push the page through unfiltered.
        parts.headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static(rewrite::ACCEPTED_ENCODINGS),
        );
    }

    Ok(Request::from_parts(parts, body.boxed()))
}

/// Wires a 101 response's upgraded stream to the client's, so WebSocket
/// traffic flows through the tunnel unchanged.
fn relay_upgrade(
    mut response: Response<Incoming>,
    client_upgrade: Option<OnUpgrade>,
) -> Response<ProxyBody> {
    let Some(client_upgrade) = client_upgrade else {
        return simple(
            StatusCode::BAD_GATEWAY,
            "origin switched protocols unexpectedly",
        );
    };
    let Some(origin_upgrade) = response.extensions_mut().remove::<OnUpgrade>() else {
        return simple(
            StatusCode::BAD_GATEWAY,
            "origin did not provide an upgradable stream",
        );
    };

    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, origin_upgrade) {
            Ok((client, origin)) => {
                let mut client = TokioIo::new(client);
                let mut origin = TokioIo::new(origin);
                if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut origin).await {
                    tracing::debug!(%error, "upgraded stream ended");
                }
            }
            Err(error) => tracing::debug!(%error, "protocol upgrade failed"),
        }
    });

    let (parts, _) = response.into_parts();
    Response::from_parts(parts, empty_body())
}

/// Cleans up an origin response before it is handed back to the client.
///
/// As well as the per-hop headers, this drops `Alt-Svc`. That header is how an
/// origin advertises an HTTP/3 endpoint, and a client that took the offer would
/// reach the origin over QUIC on UDP/443 — a path this proxy cannot see, let
/// alone filter. A response that arrived through the proxy should not carry
/// directions for going around it.
fn sanitise_response(mut response: Response<ProxyBody>) -> Response<ProxyBody> {
    strip_hop_by_hop(response.headers_mut(), false);
    response.headers_mut().remove(ALT_SVC);
    response
}

/// Removes headers that apply only to the current hop, including any named by
/// the `Connection` header itself. `keep_upgrade` preserves the handshake
/// headers for protocol upgrades, which must be forwarded.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap, keep_upgrade: bool) {
    let tokens = connection_tokens(headers);

    let doomed: Vec<hyper::header::HeaderName> = headers
        .keys()
        .filter(|name| {
            let lower = name.as_str().to_ascii_lowercase();
            if keep_upgrade && (lower == "connection" || lower == "upgrade") {
                return false;
            }
            HOP_BY_HOP.contains(&lower.as_str()) || tokens.contains(&lower)
        })
        .cloned()
        .collect();

    for name in doomed {
        headers.remove(&name);
    }
}

/// Header names listed in `Connection:`, which are hop-by-hop by definition.
fn connection_tokens(headers: &hyper::HeaderMap) -> Vec<String> {
    headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|token| token.trim().to_ascii_lowercase())
                .filter(|token| !token.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn host_matches_any(host: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim().trim_start_matches('.').to_ascii_lowercase();
        !pattern.is_empty() && (host == pattern || host.ends_with(&format!(".{pattern}")))
    })
}

fn header_str<T>(req: &Request<T>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn header_contains<T>(req: &Request<T>, name: hyper::header::HeaderName, needle: &str) -> bool {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
}

fn simple(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = format!("{message}\n");
    let mut response = Response::new(full_body(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

pub fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_urls_without_default_ports() {
        assert_eq!(
            build_url(true, "example.com", 443, "/a?b=1"),
            "https://example.com/a?b=1"
        );
        assert_eq!(
            build_url(false, "example.com", 80, "/"),
            "http://example.com/"
        );
        assert_eq!(
            build_url(true, "example.com", 8443, "/"),
            "https://example.com:8443/"
        );
    }

    #[test]
    fn bypass_patterns_cover_subdomains_only() {
        let patterns = vec!["example.com".to_string(), ".pinned.test".to_string()];
        assert!(host_matches_any("example.com", &patterns));
        assert!(host_matches_any("api.example.com", &patterns));
        assert!(host_matches_any("pinned.test", &patterns));
        assert!(!host_matches_any("notexample.com", &patterns));
        assert!(!host_matches_any("example.com.evil.test", &patterns));
    }

    #[test]
    fn empty_bypass_patterns_match_nothing() {
        assert!(!host_matches_any("example.com", &[String::new()]));
        assert!(!host_matches_any("example.com", &[]));
    }

    #[test]
    fn connection_tokens_are_parsed() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, X-Custom"));
        let tokens = connection_tokens(&headers);
        assert_eq!(tokens, vec!["keep-alive", "x-custom"]);
    }

    #[test]
    fn responses_cannot_advertise_a_route_around_the_proxy() {
        let mut response = Response::new(empty_body());
        response.headers_mut().insert(
            ALT_SVC,
            HeaderValue::from_static("h3=\":443\"; ma=86400, h3-29=\":443\""),
        );
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        response.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );

        let sanitised = sanitise_response(response);

        assert!(!sanitised.headers().contains_key(ALT_SVC));
        assert!(!sanitised.headers().contains_key(CONNECTION));
        // Unrelated headers must survive the cleanup.
        assert_eq!(
            sanitised
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .unwrap(),
            "text/html"
        );
    }

    #[test]
    fn websocket_urls_use_the_ws_scheme() {
        let target = Target {
            tls: true,
            host: "example.com".into(),
            port: 443,
            url: "https://example.com/socket".into(),
        };
        assert_eq!(websocket_url(&target), "wss://example.com/socket");
    }
}
