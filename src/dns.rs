//! A forwarding DNS server that blackholes blocked domains.
//!
//! Queries for blocked names are answered locally; everything else is relayed
//! verbatim to an upstream resolver, which keeps every record type and every
//! EDNS option intact without this server having to understand them.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::config::BlockResponse;
use crate::state::AppState;
use crate::stats::{Action, Source};

/// The largest DNS message accepted over UDP. Beyond this, clients are
/// expected to retry over TCP.
const UDP_BUFFER: usize = 4096;
/// A TCP DNS message is length-prefixed with a u16, so this is the hard cap.
const TCP_BUFFER: usize = u16::MAX as usize;

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let listen = state.config().dns.listen;

    let udp = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("binding DNS UDP socket on {listen}"))?;
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding DNS TCP socket on {listen}"))?;

    tracing::info!(address = %listen, "DNS server listening");

    let udp_state = state.clone();
    let udp_task = tokio::spawn(async move { serve_udp(udp_state, udp).await });
    let tcp_task = tokio::spawn(async move { serve_tcp(state, tcp).await });

    tokio::select! {
        result = udp_task => result.context("DNS UDP task panicked")?,
        result = tcp_task => result.context("DNS TCP task panicked")?,
    }
}

async fn serve_udp(state: Arc<AppState>, socket: UdpSocket) -> Result<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; UDP_BUFFER];

    loop {
        let (len, client) = match socket.recv_from(&mut buffer).await {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(%error, "DNS UDP receive failed");
                continue;
            }
        };

        let query = buffer[..len].to_vec();
        let state = state.clone();
        let socket = socket.clone();

        tokio::spawn(async move {
            if let Some(response) = handle_query(&state, &query, client).await {
                if let Err(error) = socket.send_to(&response, client).await {
                    tracing::debug!(%client, %error, "DNS UDP reply failed");
                }
            }
        });
    }
}

async fn serve_tcp(state: Arc<AppState>, listener: TcpListener) -> Result<()> {
    loop {
        let (stream, client) = match listener.accept().await {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(%error, "DNS TCP accept failed");
                continue;
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_tcp_connection(&state, stream, client).await {
                tracing::debug!(%client, %error, "DNS TCP connection ended");
            }
        });
    }
}

async fn handle_tcp_connection(
    state: &AppState,
    mut stream: TcpStream,
    client: SocketAddr,
) -> Result<()> {
    let mut buffer = vec![0u8; TCP_BUFFER];

    // A single TCP connection may carry many queries back to back.
    loop {
        let mut length = [0u8; 2];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            // A clean close between messages is normal.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }

        let length = u16::from_be_bytes(length) as usize;
        stream.read_exact(&mut buffer[..length]).await?;

        let Some(response) = handle_query(state, &buffer[..length], client).await else {
            return Ok(());
        };

        let response_length = u16::try_from(response.len())
            .context("DNS response too large for a TCP length prefix")?;
        stream.write_all(&response_length.to_be_bytes()).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

/// Returns the bytes to send back, or `None` if the query should be dropped.
async fn handle_query(state: &AppState, query: &[u8], client: SocketAddr) -> Option<Vec<u8>> {
    let request = match Message::from_bytes(query) {
        Ok(message) => message,
        Err(error) => {
            tracing::debug!(%client, %error, "dropping malformed DNS query");
            return None;
        }
    };

    // Anything other than a single-question query is relayed untouched; the
    // blocklist has nothing meaningful to say about it.
    let Some(question) = request.queries.first() else {
        return forward(state, query).await;
    };

    let name = question.name().to_string();
    let host = name.trim_end_matches('.');

    if state.domains().is_blocked(host) {
        let config = state.config();
        state.stats.record(
            Source::Dns,
            Action::Blocked,
            &client.ip().to_string(),
            host,
            "DNS blocklist",
        );

        let response = blocked_response(
            &request,
            question.query_type(),
            config.dns.block_response,
            config.dns.block_ttl,
        );

        return match response.to_vec() {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                tracing::warn!(%error, "encoding blocked DNS response failed");
                None
            }
        };
    }

    state.stats.record(
        Source::Dns,
        Action::Allowed,
        &client.ip().to_string(),
        host,
        "",
    );

    forward(state, query).await
}

fn blocked_response(
    request: &Message,
    query_type: RecordType,
    mode: BlockResponse,
    ttl: u32,
) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.message_type = MessageType::Response;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();

    // Echo EDNS so clients that required it do not treat the answer as broken.
    if let Some(edns) = request.edns.clone() {
        response.set_edns(edns);
    }

    match mode {
        BlockResponse::NxDomain => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockResponse::Refused => {
            response.metadata.response_code = ResponseCode::Refused;
        }
        BlockResponse::NullAddress => {
            let name = request.queries[0].name().clone();
            // Any other record type gets NOERROR with no answers, which is the
            // correct way to say "this name exists but not for that type".
            match query_type {
                RecordType::A => {
                    response.add_answer(Record::from_rdata(
                        name,
                        ttl,
                        RData::A(A(Ipv4Addr::UNSPECIFIED)),
                    ));
                }
                RecordType::AAAA => {
                    response.add_answer(Record::from_rdata(
                        name,
                        ttl,
                        RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                    ));
                }
                _ => {}
            }
        }
    }

    response
}

/// Relays the original query bytes to each upstream in turn, returning the
/// first answer. Returns SERVFAIL if every upstream fails.
async fn forward(state: &AppState, query: &[u8]) -> Option<Vec<u8>> {
    let config = state.config();
    let timeout = Duration::from_millis(config.dns.upstream_timeout_ms);

    for upstream in &config.dns.upstreams {
        match tokio::time::timeout(timeout, forward_once(*upstream, query)).await {
            Ok(Ok(response)) => return Some(response),
            Ok(Err(error)) => {
                tracing::debug!(%upstream, %error, "upstream DNS query failed");
            }
            Err(_) => {
                tracing::debug!(%upstream, "upstream DNS query timed out");
            }
        }
    }

    tracing::warn!("all upstream DNS servers failed");
    servfail(query)
}

async fn forward_once(upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;

    let mut buffer = vec![0u8; TCP_BUFFER];
    loop {
        let len = socket.recv(&mut buffer).await?;
        anyhow::ensure!(len >= 2, "upstream returned a runt DNS response");

        // The socket is connected, but still ignore replies whose transaction
        // ID does not match the query we sent.
        if buffer[..2] == query[..2] {
            buffer.truncate(len);
            return Ok(buffer);
        }
    }
}

/// Builds a SERVFAIL for a query we could not resolve, reusing its header.
fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_bytes(query).ok()?;
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::ServFail;
    response.queries = request.queries.clone();
    response.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn query_for(record_type: RecordType) -> Message {
        let mut message = Message::new(1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str("ads.example.com.").unwrap(),
            record_type,
        ));
        message
    }

    #[test]
    fn null_address_answers_a_with_zeroes() {
        let request = query_for(RecordType::A);
        let response = blocked_response(&request, RecordType::A, BlockResponse::NullAddress, 60);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn null_address_gives_nodata_for_other_types() {
        let request = query_for(RecordType::MX);
        let response = blocked_response(&request, RecordType::MX, BlockResponse::NullAddress, 60);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn nxdomain_mode_sets_the_response_code() {
        let request = query_for(RecordType::A);
        let response = blocked_response(&request, RecordType::A, BlockResponse::NxDomain, 60);

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn responses_echo_the_question_and_id() {
        let request = query_for(RecordType::A);
        let response = blocked_response(&request, RecordType::A, BlockResponse::NxDomain, 60);

        assert_eq!(response.metadata.id, 1234);
        assert_eq!(response.queries, request.queries);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert!(response.to_vec().is_ok());
    }
}
