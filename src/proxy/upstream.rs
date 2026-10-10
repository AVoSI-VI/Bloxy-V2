//! Outbound connections to origin servers.
//!
//! Each client connection owns one `Upstream`, which keeps a single origin
//! connection alive and reuses it. Because HTTP/1.1 exchanges on a connection
//! are ordered anyway, serialising through one mutex costs nothing and saves a
//! TCP and TLS handshake per request.

use std::sync::Arc;

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::ProxyBody;

/// Identifies an origin connection: scheme plus authority.
type ConnectionKey = (bool, String, u16);

pub struct Upstream {
    tls: TlsConnector,
    active: tokio::sync::Mutex<Option<Active>>,
}

struct Active {
    key: ConnectionKey,
    sender: SendRequest<ProxyBody>,
}

impl Upstream {
    pub fn new(tls: TlsConnector) -> Self {
        Self {
            tls,
            active: tokio::sync::Mutex::new(None),
        }
    }

    /// Sends `request` to `host:port`, reusing the pooled connection when it
    /// targets the same origin and is still usable.
    pub async fn send(
        &self,
        use_tls: bool,
        host: &str,
        port: u16,
        request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>> {
        let key: ConnectionKey = (use_tls, host.to_ascii_lowercase(), port);
        let mut active = self.active.lock().await;

        let reusable = active
            .as_ref()
            .is_some_and(|conn| conn.key == key && !conn.sender.is_closed());

        if !reusable {
            let sender = self.connect(use_tls, host, port).await?;
            *active = Some(Active {
                key: key.clone(),
                sender,
            });
        }

        let conn = active.as_mut().expect("connection was just established");
        conn.sender
            .ready()
            .await
            .with_context(|| format!("upstream {host}:{port} closed before the request"))?;

        let response = conn
            .sender
            .send_request(request)
            .await
            .with_context(|| format!("sending request to {host}:{port}"))?;

        // The response head has arrived; the body streams via the connection
        // task, so the next request need not wait on it here.
        drop(active);
        Ok(response)
    }

    async fn connect(
        &self,
        use_tls: bool,
        host: &str,
        port: u16,
    ) -> Result<SendRequest<ProxyBody>> {
        let tcp = TcpStream::connect((host, port))
            .await
            .with_context(|| format!("connecting to {host}:{port}"))?;
        tcp.set_nodelay(true).ok();

        if use_tls {
            let name = ServerName::try_from(host.to_string())
                .with_context(|| format!("{host} is not a valid TLS server name"))?;
            let stream = self
                .tls
                .connect(name, tcp)
                .await
                .with_context(|| format!("TLS handshake with {host}:{port}"))?;
            handshake(TokioIo::new(stream)).await
        } else {
            handshake(TokioIo::new(tcp)).await
        }
    }
}

async fn handshake<I>(io: I) -> Result<SendRequest<ProxyBody>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::Builder::new()
        // Some origins are sensitive to header casing; round-tripping it
        // verbatim keeps the proxy as transparent as possible.
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await
        .context("HTTP handshake with upstream")?;

    // `with_upgrades` is required for WebSocket responses to be relayable.
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            tracing::debug!(%error, "upstream connection ended");
        }
    });

    Ok(sender)
}

/// A TLS client configuration that validates origin certificates against the
/// webpki root store. Interception must not weaken upstream verification.
pub fn tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    TlsConnector::from(Arc::new(config))
}
