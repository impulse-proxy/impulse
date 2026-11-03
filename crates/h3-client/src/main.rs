use std::{
    collections::{HashMap, VecDeque},
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use clap::Parser;
use quiche::h3::NameValue;
use rand::RngCore;

const MAX_DATAGRAM_SIZE_BYTES: usize = 65_535;
const MAX_UDP_PAYLOAD_BYTES: usize = 1_350;
const UDP_READ_TIMEOUT_MS: u64 = 50;
const REQUEST_TIMEOUT_SECS: u64 = 5;
const QUIC_IDLE_TIMEOUT_MS: u64 = 5_000;
const QUIC_INITIAL_MAX_DATA: u64 = 10_000_000;
const QUIC_INITIAL_STREAM_DATA: u64 = 1_000_000;
const QUIC_INITIAL_MAX_STREAMS_BIDI: u64 = 100;
const QUIC_INITIAL_MAX_STREAMS_UNI: u64 = 100;

#[derive(Parser)]
#[command(version, about = "Minimal HTTP/3 client using quiche")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:9889")]
    connect: String,

    #[arg(long, default_value = "/")]
    path: String,

    #[arg(long, default_value = "GET")]
    method: String,

    #[arg(long, default_value = "localhost")]
    host: String,

    /// Additional request headers as `name=value`. Repeat to add more headers.
    /// Pseudo-headers such as `:protocol=websocket` are supported.
    #[arg(long = "header")]
    headers: Vec<String>,

    #[arg(long)]
    insecure: bool,

    /// Number of requests to execute in this process.
    #[arg(long, default_value_t = 1)]
    requests: usize,

    /// Maximum number of in-flight HTTP/3 request streams on a single QUIC connection.
    #[arg(long, default_value_t = 1)]
    parallel_streams: usize,

    /// Emit one line per request as: "<ok:0|1> <latency_ns>".
    /// Intended for load scripts that aggregate per-request latency.
    #[arg(long)]
    report_latency: bool,

    /// Suppress response headers/body output.
    #[arg(long)]
    quiet: bool,

    /// Per-attempt timeout in milliseconds for in-flight requests.
    #[arg(long, default_value_t = REQUEST_TIMEOUT_SECS * 1000)]
    request_timeout_ms: u64,

    /// Additional retries for transport-level request failures.
    #[arg(long, default_value_t = 0)]
    max_request_retries: usize,

    /// Additional connection re-establishment attempts.
    #[arg(long, default_value_t = 0)]
    max_connection_retries: usize,
}

struct InflightRequest {
    request_id: usize,
    first_start: Instant,
    attempt_start: Instant,
    body: Vec<u8>,
}

fn emit_request_result(ok: bool, latency_ns: u128, report_latency: bool) {
    if report_latency {
        println!("{} {}", if ok { 1 } else { 0 }, latency_ns);
    }
}

fn should_retry_request(attempts_started: usize, max_request_retries: usize) -> bool {
    attempts_started <= max_request_retries
}

fn parse_header_arg(header: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (name, value) = header
        .split_once('=')
        .ok_or_else(|| format!("invalid --header '{header}': expected name=value"))?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() {
        return Err(format!("invalid --header '{header}': header name is empty"));
    }
    Ok((name.as_bytes().to_vec(), value.as_bytes().to_vec()))
}

fn open_connection(
    config: &mut quiche::Config,
    host: &str,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<quiche::Connection, Box<dyn std::error::Error>> {
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    Ok(quiche::connect(
        Some(host),
        &scid,
        local_addr,
        peer_addr,
        config,
    )?)
}

fn flush_egress(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    out: &mut [u8],
) -> Result<(), quiche::Error> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => {
                let _ = socket.send_to(&out[..write], send_info.to);
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn retry_or_fail_request(
    request_id: usize,
    request_attempts: &[usize],
    request_started: &[Option<Instant>],
    pending: &mut VecDeque<usize>,
    max_request_retries: usize,
    failures: &mut usize,
    completed: &mut usize,
    report_latency: bool,
) {
    if should_retry_request(request_attempts[request_id], max_request_retries) {
        pending.push_back(request_id);
        return;
    }

    *failures = failures.saturating_add(1);
    *completed = completed.saturating_add(1);
    let latency_ns = request_started[request_id]
        .map(|start| start.elapsed().as_nanos())
        .unwrap_or(0);
    emit_request_result(false, latency_ns, report_latency);
}

fn run_client(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr: SocketAddr = cli.connect.parse()?;
    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;

    let socket = UdpSocket::bind(bind_addr)?;
    let local_addr = socket.local_addr()?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    config.enable_early_data();
    config.verify_peer(!cli.insecure);

    let mut conn = open_connection(&mut config, &cli.host, local_addr, peer_addr)?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    let mut reconnect_attempts = 0usize;
    let mut pending: VecDeque<usize> = (0..cli.requests).collect();
    let mut request_attempts = vec![0usize; cli.requests];
    let mut request_started: Vec<Option<Instant>> = vec![None; cli.requests];
    let mut completed = 0usize;
    let mut failures = 0usize;
    let mut last_error: Option<String> = None;
    let mut inflight: HashMap<u64, InflightRequest> = HashMap::new();
    let per_request_timeout = Duration::from_millis(cli.request_timeout_ms);
    let extra_headers = cli
        .headers
        .iter()
        .map(|header| parse_header_arg(header))
        .collect::<Result<Vec<_>, _>>()?;

    // Kick off handshake packet(s).
    let _ = flush_egress(&mut conn, &socket, &mut out);

    while completed < cli.requests {
        let mut reconnect_requested = false;

        // Flush pending egress packets.
        if let Err(e) = flush_egress(&mut conn, &socket, &mut out) {
            last_error = Some(format!("send failed: {e:?}"));
            reconnect_requested = true;
        }

        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(UDP_READ_TIMEOUT_MS));
        socket.set_read_timeout(Some(timeout))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    last_error = Some(format!("recv failed: {e:?}"));
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => {
                last_error = Some(e.to_string());
            }
        }

        if h3_conn.is_none() && (conn.is_established() || conn.is_in_early_data()) {
            let h3_config = quiche::h3::Config::new()?;
            h3_conn = Some(quiche::h3::Connection::with_transport(
                &mut conn, &h3_config,
            )?);
        }

        if let Some(h3) = h3_conn.as_mut() {
            // Submit more requests on the same connection up to stream concurrency cap.
            while inflight.len() < cli.parallel_streams {
                let Some(request_id) = pending.pop_front() else {
                    break;
                };
                let first_start_ref = request_started[request_id].get_or_insert_with(Instant::now);
                let first_start = *first_start_ref;

                let mut req = vec![
                    quiche::h3::Header::new(b":method", cli.method.as_bytes()),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", cli.host.as_bytes()),
                    quiche::h3::Header::new(b":path", cli.path.as_bytes()),
                    quiche::h3::Header::new(b"user-agent", b"impulse-h3-client"),
                ];
                req.extend(
                    extra_headers
                        .iter()
                        .map(|(name, value)| quiche::h3::Header::new(name, value)),
                );

                match h3.send_request(&mut conn, &req, true) {
                    Ok(stream_id) => {
                        request_attempts[request_id] =
                            request_attempts[request_id].saturating_add(1);
                        inflight.insert(
                            stream_id,
                            InflightRequest {
                                request_id,
                                first_start,
                                attempt_start: Instant::now(),
                                body: Vec::new(),
                            },
                        );
                    }
                    Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                        pending.push_front(request_id);
                        break;
                    }
                    Err(e) => {
                        request_attempts[request_id] =
                            request_attempts[request_id].saturating_add(1);
                        last_error = Some(format!("send_request failed: {e:?}"));
                        retry_or_fail_request(
                            request_id,
                            &request_attempts,
                            &request_started,
                            &mut pending,
                            cli.max_request_retries,
                            &mut failures,
                            &mut completed,
                            cli.report_latency,
                        );
                    }
                }
            }

            loop {
                match h3.poll(&mut conn) {
                    Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        if !cli.quiet && !cli.report_latency && cli.requests == 1 {
                            for header in list {
                                let name = String::from_utf8_lossy(header.name());
                                let value = String::from_utf8_lossy(header.value());
                                println!("{name}: {value}");
                            }
                            println!();
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => loop {
                        match h3.recv_body(&mut conn, stream_id, &mut buf) {
                            Ok(read) => {
                                if let Some(state) = inflight.get_mut(&stream_id) {
                                    state.body.extend_from_slice(&buf[..read]);
                                }
                            }
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => {
                                if let Some(state) = inflight.remove(&stream_id) {
                                    last_error = Some(format!("recv_body failed: {e:?}"));
                                    retry_or_fail_request(
                                        state.request_id,
                                        &request_attempts,
                                        &request_started,
                                        &mut pending,
                                        cli.max_request_retries,
                                        &mut failures,
                                        &mut completed,
                                        cli.report_latency,
                                    );
                                }
                                break;
                            }
                        }
                    },
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        if let Some(state) = inflight.remove(&stream_id) {
                            let latency_ns = state.first_start.elapsed().as_nanos();
                            completed = completed.saturating_add(1);
                            emit_request_result(true, latency_ns, cli.report_latency);

                            if !cli.quiet
                                && !cli.report_latency
                                && cli.requests == 1
                                && !state.body.is_empty()
                            {
                                let body = String::from_utf8_lossy(&state.body);
                                println!("{body}");
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Reset(_))) => {
                        if let Some(state) = inflight.remove(&stream_id) {
                            retry_or_fail_request(
                                state.request_id,
                                &request_attempts,
                                &request_started,
                                &mut pending,
                                cli.max_request_retries,
                                &mut failures,
                                &mut completed,
                                cli.report_latency,
                            );
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        last_error = Some(format!("h3 poll failed: {e:?}"));
                        reconnect_requested = true;
                        break;
                    }
                }
            }
        }

        // Per-request timeout enforcement for in-flight streams.
        let mut timed_out = Vec::new();
        for (stream_id, state) in &inflight {
            if state.attempt_start.elapsed() > per_request_timeout {
                timed_out.push(*stream_id);
            }
        }
        for stream_id in timed_out {
            if let Some(state) = inflight.remove(&stream_id) {
                retry_or_fail_request(
                    state.request_id,
                    &request_attempts,
                    &request_started,
                    &mut pending,
                    cli.max_request_retries,
                    &mut failures,
                    &mut completed,
                    cli.report_latency,
                );
            }
        }

        if conn.is_closed() {
            reconnect_requested = true;
        }

        if reconnect_requested && completed < cli.requests {
            for (_stream_id, state) in inflight.drain() {
                retry_or_fail_request(
                    state.request_id,
                    &request_attempts,
                    &request_started,
                    &mut pending,
                    cli.max_request_retries,
                    &mut failures,
                    &mut completed,
                    cli.report_latency,
                );
            }

            if completed >= cli.requests {
                break;
            }

            if reconnect_attempts >= cli.max_connection_retries {
                while let Some(request_id) = pending.pop_front() {
                    failures = failures.saturating_add(1);
                    completed = completed.saturating_add(1);
                    let latency_ns = request_started[request_id]
                        .map(|start| start.elapsed().as_nanos())
                        .unwrap_or(0);
                    emit_request_result(false, latency_ns, cli.report_latency);
                }
                break;
            }

            reconnect_attempts = reconnect_attempts.saturating_add(1);
            conn = open_connection(&mut config, &cli.host, local_addr, peer_addr)?;
            h3_conn = None;
            let _ = flush_egress(&mut conn, &socket, &mut out);
        }
    }

    if !cli.report_latency && failures > 0 {
        let suffix = last_error
            .as_deref()
            .map(|msg| format!(": {msg}"))
            .unwrap_or_default();
        return Err(format!(
            "{} of {} request(s) failed{}",
            failures, cli.requests, suffix
        )
        .into());
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.requests == 0 {
        return Err("--requests must be >= 1".into());
    }

    if cli.parallel_streams == 0 {
        return Err("--parallel-streams must be >= 1".into());
    }

    if cli.request_timeout_ms == 0 {
        return Err("--request-timeout-ms must be >= 1".into());
    }

    if cli.method.trim().is_empty() {
        return Err("--method must not be empty".into());
    }

    run_client(&cli)
}

#[cfg(test)]
mod tests {
    use super::should_retry_request;

    #[test]
    fn retry_budget_interpretation_is_stable() {
        assert!(!should_retry_request(1, 0));
        assert!(should_retry_request(1, 1));
        assert!(!should_retry_request(2, 1));
        assert!(should_retry_request(3, 3));
    }
}
