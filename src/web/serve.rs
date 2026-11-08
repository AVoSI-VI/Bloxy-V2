//! Accept loop for the admin interface, plain HTTP or TLS.
//!
//! One loop covers both modes. TLS uses a certificate minted once at startup
//! from the local CA. Each request gets `ConnectInfo` inserted by hand,
//! because this path does not go through `axum::serve`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::state::AppState;

pub async fn run(state: Arc<AppState>, app: Router) -> Result<()> {
    let admin = state.config().admin;
    let listen = admin.listen;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding admin interface on {listen}"))?;
    let bound = listener
        .local_addr()
        .context("reading the admin listen address")?;

    let acceptor = if admin.tls_enabled {
        let hostname = certificate_host(admin.tls_hostname.as_deref(), listen);
        let config = state
            .ca
            .server_config_for(&hostname)
            .with_context(|| format!("minting the admin certificate for {hostname}"))?;
        Some(TlsAcceptor::from(config))
    } else {
        None
    };

    let scheme = if acceptor.is_some() { "https" } else { "http" };
    tracing::info!("admin interface listening at {scheme}://{bound}");

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "admin accept failed");
                continue;
            }
        };
        stream.set_nodelay(true).ok();

        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_socket(stream, addr, acceptor, app).await {
                tracing::debug!(%addr, %error, "admin connection ended");
            }
        });
    }
}

/// `tls_hostname` when it is set, otherwise the listen address's IP. A blank
/// name means the same as unset: `mint_leaf` already treats an IP string as
/// an IP SAN.
fn certificate_host(hostname: Option<&str>, listen: SocketAddr) -> String {
    match hostname.map(str::trim).filter(|host| !host.is_empty()) {
        Some(host) => host.to_string(),
        None => listen.ip().to_string(),
    }
}

async fn serve_socket(
    stream: TcpStream,
    addr: SocketAddr,
    acceptor: Option<TlsAcceptor>,
    app: Router,
) -> Result<()> {
    if let Some(acceptor) = acceptor {
        let stream = acceptor
            .accept(stream)
            .await
            .context("TLS handshake with admin client")?;
        serve_http(stream, addr, app).await
    } else {
        serve_http(stream, addr, app).await
    }
}

async fn serve_http<I>(io: I, addr: SocketAddr, app: Router) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    // The gate reads the client IP from `ConnectInfo`. Without this, every
    // protected request is a 500 rather than a 401.
    let service =
        TowerToHyperService::new(app.map_request(move |mut request: Request<Incoming>| {
            request.extensions_mut().insert(ConnectInfo(addr));
            request.map(axum::body::Body::new)
        }));

    http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .await
        .context("serving admin connection")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use rustls::RootCertStore;
    use rustls_pki_types::ServerName;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    use crate::config::{Config, Paths};
    use crate::state::AppState;

    struct Server {
        task: tokio::task::JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn boot(tls: bool) -> (SocketAddr, Arc<AppState>, Server) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        paths.ensure().unwrap();
        let mut config = Config::default();
        config.admin.listen = addr;
        config.admin.tls_enabled = tls;
        config.save(&paths.config()).unwrap();
        let state = AppState::for_tests(paths).unwrap();

        let app = super::super::router(state.clone());
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            super::run(task_state, app).await.expect("admin listener");
        });
        (addr, state, Server { task, _dir: dir })
    }

    async fn connect(addr: SocketAddr) -> TcpStream {
        let start = Instant::now();
        loop {
            if let Ok(stream) = TcpStream::connect(addr).await {
                return stream;
            }
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "listener did not start"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn status_of(mut io: impl AsyncRead + AsyncWrite + Unpin, path: &str) -> String {
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        io.write_all(request.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = io.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn plain_listener_reaches_the_gate() {
        let (addr, _state, _server) = boot(false);
        assert_eq!(status_of(connect(addr).await, "/").await, "200");
        assert_eq!(status_of(connect(addr).await, "/api/status").await, "401");
    }

    #[tokio::test]
    async fn tls_listener_accepts_a_client_that_trusts_the_ca() {
        let (addr, state, _server) = boot(true);
        let mut roots = RootCertStore::empty();
        let mut reader = std::io::BufReader::new(state.ca.ca_pem().as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            roots.add(cert.unwrap()).unwrap();
        }
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let tcp = connect(addr).await;
        let tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(status_of(tls, "/").await, "200");

        let tcp = connect(addr).await;
        let tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(status_of(tls, "/api/status").await, "401");
    }
}
