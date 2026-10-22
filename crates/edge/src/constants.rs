// ─── Memory envelope ──────────────────────────────────────────────────────────
//
// Per-stream worst-case memory (defaults; operator can tune via `performance.*`):
//
//   Request path
//   ├─ body channel:    REQUEST_CHUNK_CHANNEL_CAPACITY * REQUEST_CHUNK_BYTES_LIMIT
//   │                   = 64 * 16 KiB = 1 MiB
//   └─ hard request cap: MAX_REQUEST_BODY_BYTES = 1 MiB → 413 on breach
//
//   Response path
//   ├─ response channel: RESPONSE_CHUNK_CHANNEL_CAPACITY * RESPONSE_CHUNK_BYTES_LIMIT
//   │                   = 16 * 16 KiB = 256 KiB
//   └─ hard response cap: max_response_body_bytes (default 100 MiB)
//      - declared content-length over cap -> 503 before streaming
//      - unknown-length responses are cap-validated before headers are emitted
//        and return 503 on breach (no reset fallback)
//
// Per-connection worst-case:
//   MAX_STREAMS_PER_CONNECTION (= QUIC_INITIAL_MAX_STREAMS_BIDI = 100) streams
//   × per-stream worst case above → ~200 MiB request + ~100 MiB response ≈ 300 MiB
//   (all caps enforced; no path causes unbounded growth)
//
// ─────────────────────────────────────────────────────────────────────────────

pub const MAX_DATAGRAM_SIZE_BYTES: usize = 65_535;
pub const MAX_UDP_PAYLOAD_BYTES: usize = 1_350;

pub const UDP_READ_TIMEOUT_MS: u64 = 50;
pub const BACKEND_TIMEOUT_SECS: u64 = 2;
pub const REQUEST_TIMEOUT_SECS: u64 = 5;

pub const QUIC_IDLE_TIMEOUT_MS: u64 = 5_000;
pub const QUIC_INITIAL_MAX_DATA: u64 = 10_000_000;
pub const QUIC_INITIAL_STREAM_DATA: u64 = 1_000_000;

/// Hard application-level cap on request body size per stream.
/// Requests exceeding this are rejected with 413 before forwarding to upstream.
/// Must be ≤ QUIC_INITIAL_STREAM_DATA (flow-control limit).
pub const MAX_REQUEST_BODY_BYTES: usize = 1_000_000;
pub const QUIC_INITIAL_MAX_STREAMS_BIDI: u64 = 100;
pub const QUIC_INITIAL_MAX_STREAMS_UNI: u64 = 100;

/// Application-level cap on concurrent open streams per QUIC connection.
/// Mirrors QUIC_INITIAL_MAX_STREAMS_BIDI so the app map never grows beyond
/// what the transport layer permits.  Must be kept in sync.
pub const MAX_STREAMS_PER_CONNECTION: usize = QUIC_INITIAL_MAX_STREAMS_BIDI as usize;

pub(crate) const DEFAULT_SCID_LEN_BYTES: usize = 16;
pub(crate) const RESET_TOKEN_LEN_BYTES: usize = 16;
pub(crate) const MIN_SCID_LEN_BYTES: usize = 8;

// Queue/backpressure controls for streaming request/response bodies.
pub(crate) const REQUEST_CHUNK_CHANNEL_CAPACITY: usize = 64;
pub(crate) const REQUEST_CHUNK_BYTES_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_CHUNK_CHANNEL_CAPACITY: usize = 16;
pub(crate) const RESPONSE_CHUNK_BYTES_LIMIT: usize = 16 * 1024;

pub(crate) const SCID_ROTATION_INTERVAL_SECS: u64 = 60;
pub(crate) const SCID_ROTATION_PACKET_THRESHOLD: u64 = 8;

pub(crate) fn scid_rotation_interval() -> std::time::Duration {
    std::time::Duration::from_secs(SCID_ROTATION_INTERVAL_SECS)
}
