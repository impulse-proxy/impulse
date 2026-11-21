//! Taskless response body source for HTTP/3 responses that need no per-chunk
//! processing (no compression, no cache fill, headers already sent).
//!
//! The general path spawns a pump task that converts upstream frames into
//! [`ResponseChunk`]s and sends them through a second channel to the worker. For
//! a plain pass-through response that task and channel add nothing: the worker
//! already polls once per progress pass. [`DirectResponseBody`] lets the worker
//! convert upstream frames itself, with the same guardrails and chunking.
//!
//! Backpressure stays native and bounded. The worker reads one upstream frame per
//! poll and only while it can still write downstream. When it stops reading, the
//! transport's bounded body channel fills and the transport stops reading from
//! the backend socket. Nothing else buffers: at most one frame's worth of split
//! chunks is carried between polls.

use std::{collections::VecDeque, time::Instant};

use impulse_errors::{PoolError, ProxyError};
use impulse_transport::http3::{UpstreamBody, UpstreamBodyFrame};
use tokio::sync::mpsc::{self, error::TryRecvError};

use crate::{
    edge_core::body_guardrails::{
        BodyLimitKind, BodyTimeoutKind, ProgressiveEmissionPolicy, ResponseBodyGuardrailConfig,
        ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput,
        checked_response_body_guardrails, response_body_limit_reason, response_chunk_ranges,
    },
    quic_listener::collect_h3_trailers,
    runtime::connection::{response::ResponseChunk, stream::TimeoutReason},
};

/// Translate a failed guardrail decision into the chunk that ends the response.
pub(crate) fn response_body_guardrail_chunk(
    decision: ResponseBodyGuardrailDecision,
) -> Option<ResponseChunk> {
    match decision {
        ResponseBodyGuardrailDecision::Continue { .. } => None,
        ResponseBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Idle,
        } => Some(ResponseChunk::Timeout(TimeoutReason::ResponseBodyIdle)),
        ResponseBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Total,
        } => Some(ResponseChunk::Timeout(TimeoutReason::ResponseBodyTotal)),
        ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySize,
        } => Some(ResponseChunk::Error(ProxyError::Pool(
            PoolError::BackendOverloaded(
                response_body_limit_reason(BodyLimitKind::BodySize).into(),
            ),
        ))),
        ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::UnknownLengthPrebuffer,
        } => Some(ResponseChunk::Error(ProxyError::Pool(
            PoolError::BackendOverloaded(
                response_body_limit_reason(BodyLimitKind::UnknownLengthPrebuffer).into(),
            ),
        ))),
        ResponseBodyGuardrailDecision::Reject { .. } => Some(ResponseChunk::Error(
            ProxyError::Pool(PoolError::BackendOverloaded(
                response_body_limit_reason(BodyLimitKind::BufferedBody).into(),
            )),
        )),
    }
}

/// Where the worker reads response chunks from.
pub(crate) enum ResponseSource {
    /// Chunks produced by a pump task: compression, cache fill, deferred headers,
    /// and prebuilt channels such as tunnels.
    Pump(mpsc::Receiver<ResponseChunk>),
    /// Upstream frames converted inline by the worker.
    Direct(Box<DirectResponseBody>),
}

impl From<mpsc::Receiver<ResponseChunk>> for ResponseSource {
    fn from(receiver: mpsc::Receiver<ResponseChunk>) -> Self {
        Self::Pump(receiver)
    }
}

/// Result of asking a [`ResponseSource`] for its next chunk.
pub(crate) enum ChunkPoll {
    Chunk(ResponseChunk),
    /// Nothing is ready yet; ask again on the next progress pass.
    Empty,
    /// The source ended without delivering a terminal chunk.
    Disconnected,
}

impl ResponseSource {
    pub(crate) fn try_next(&mut self) -> ChunkPoll {
        match self {
            Self::Pump(receiver) => match receiver.try_recv() {
                Ok(chunk) => ChunkPoll::Chunk(chunk),
                Err(TryRecvError::Empty) => ChunkPoll::Empty,
                Err(TryRecvError::Disconnected) => ChunkPoll::Disconnected,
            },
            Self::Direct(body) => body.poll_chunk(),
        }
    }
}

/// Inputs the direct source needs from the response-start plan.
pub(crate) struct DirectResponseConfig {
    pub(crate) guardrails: ResponseBodyGuardrailConfig,
    pub(crate) declared_content_length: Option<usize>,
    pub(crate) progressive_emission_allowed: bool,
    pub(crate) exempt_from_body_size_cap: bool,
}

pub(crate) struct DirectResponseBody {
    body: UpstreamBody,
    config: DirectResponseConfig,
    started_at: Instant,
    last_progress_at: Instant,
    bytes_received: usize,
    /// Chunks split from one upstream frame that were not returned yet.
    carry: VecDeque<ResponseChunk>,
    finished: bool,
}

impl DirectResponseBody {
    pub(crate) fn new(body: UpstreamBody, config: DirectResponseConfig) -> Self {
        let now = Instant::now();
        Self {
            body,
            config,
            started_at: now,
            last_progress_at: now,
            bytes_received: 0,
            carry: VecDeque::new(),
            finished: false,
        }
    }

    fn guardrail_input(&self, next_chunk_bytes: usize) -> ResponseBodyGuardrailInput {
        ResponseBodyGuardrailInput {
            elapsed: self.started_at.elapsed(),
            idle_for: self.last_progress_at.elapsed(),
            bytes_received: self.bytes_received,
            prebuffered_bytes: 0,
            next_chunk_bytes,
            declared_content_length: self.config.declared_content_length,
            headers_emitted: true,
            progressive_emission_allowed: self.config.progressive_emission_allowed,
            body_forwarding_enabled: true,
            exempt_from_body_size_cap: self.config.exempt_from_body_size_cap,
        }
    }

    fn finish_with(&mut self, chunk: ResponseChunk) -> ChunkPoll {
        self.finished = true;
        self.carry.clear();
        ChunkPoll::Chunk(chunk)
    }

    /// Return the next chunk, reading at most as many upstream frames as needed to
    /// produce one. Never waits: an empty upstream channel is [`ChunkPoll::Empty`].
    pub(crate) fn poll_chunk(&mut self) -> ChunkPoll {
        if let Some(chunk) = self.carry.pop_front() {
            return ChunkPoll::Chunk(chunk);
        }
        if self.finished {
            return ChunkPoll::Disconnected;
        }

        loop {
            // Time-based guardrails are evaluated on every poll, so an idle or
            // overlong response ends even when no frame arrives.
            if let Err(decision) =
                checked_response_body_guardrails(self.config.guardrails, self.guardrail_input(0))
            {
                return match response_body_guardrail_chunk(decision) {
                    Some(chunk) => self.finish_with(chunk),
                    None => ChunkPoll::Empty,
                };
            }

            match self.body.try_recv() {
                Ok(Ok(UpstreamBodyFrame::Data(data))) => {
                    if !data.is_empty() {
                        self.last_progress_at = Instant::now();
                    }
                    let evaluated = match checked_response_body_guardrails(
                        self.config.guardrails,
                        self.guardrail_input(data.len()),
                    ) {
                        Ok(evaluated) => evaluated,
                        Err(decision) => {
                            return match response_body_guardrail_chunk(decision) {
                                Some(chunk) => self.finish_with(chunk),
                                None => ChunkPoll::Empty,
                            };
                        }
                    };
                    self.bytes_received = evaluated.next_state.bytes_received;
                    let streaming = evaluated.streaming;
                    if matches!(streaming.emission, ProgressiveEmissionPolicy::SuppressBody) {
                        continue;
                    }
                    for (start, end) in response_chunk_ranges(data.len(), streaming.chunk_emission)
                    {
                        if start < end {
                            self.carry
                                .push_back(ResponseChunk::Data(data.slice(start..end)));
                        }
                    }
                    if let Some(chunk) = self.carry.pop_front() {
                        return ChunkPoll::Chunk(chunk);
                    }
                }
                Ok(Ok(UpstreamBodyFrame::Trailers(trailers))) => {
                    let headers = collect_h3_trailers(&trailers);
                    if !headers.is_empty() {
                        return ChunkPoll::Chunk(ResponseChunk::Trailers { headers });
                    }
                }
                Ok(Err(error)) => return self.finish_with(ResponseChunk::Error(error)),
                Err(TryRecvError::Empty) => return ChunkPoll::Empty,
                // The transport closing the channel is the normal end of the body.
                Err(TryRecvError::Disconnected) => return self.finish_with(ResponseChunk::End),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;

    type FrameTx = mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>;

    fn config(
        max_body_bytes: usize,
        chunk_bytes: usize,
        idle: Duration,
        total: Duration,
    ) -> DirectResponseConfig {
        DirectResponseConfig {
            guardrails: ResponseBodyGuardrailConfig {
                idle_timeout: idle,
                total_timeout: total,
                max_body_bytes,
                unknown_length_prebuffer_bytes: max_body_bytes,
                chunk_bytes,
            },
            declared_content_length: None,
            progressive_emission_allowed: true,
            exempt_from_body_size_cap: false,
        }
    }

    fn default_config() -> DirectResponseConfig {
        config(
            1 << 20,
            usize::MAX,
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
    }

    fn channel(cfg: DirectResponseConfig) -> (FrameTx, DirectResponseBody) {
        let (tx, rx) = mpsc::channel(16);
        (tx, DirectResponseBody::new(rx, cfg))
    }

    fn data(bytes: &'static [u8]) -> Result<UpstreamBodyFrame, ProxyError> {
        Ok(UpstreamBodyFrame::Data(Bytes::from_static(bytes)))
    }

    fn expect_data(poll: ChunkPoll) -> Vec<u8> {
        match poll {
            ChunkPoll::Chunk(ResponseChunk::Data(bytes)) => bytes.to_vec(),
            ChunkPoll::Chunk(other) => panic!("expected data, got {other:?}"),
            ChunkPoll::Empty => panic!("expected data, got Empty"),
            ChunkPoll::Disconnected => panic!("expected data, got Disconnected"),
        }
    }

    #[test]
    fn data_frames_are_forwarded_in_order_one_frame_per_poll() {
        let (tx, mut body) = channel(default_config());
        for frame in [&b"one"[..], b"two", b"three"] {
            tx.try_send(Ok(UpstreamBodyFrame::Data(Bytes::copy_from_slice(frame))))
                .expect("queue frame");
        }
        assert_eq!(tx.capacity(), 16 - 3);

        assert_eq!(expect_data(body.poll_chunk()), b"one");
        // Demand-driven: only one frame was taken, the rest stay in the bounded
        // transport channel, which is what keeps backpressure native.
        assert_eq!(tx.capacity(), 16 - 2);
        assert_eq!(expect_data(body.poll_chunk()), b"two");
        assert_eq!(expect_data(body.poll_chunk()), b"three");
        assert_eq!(tx.capacity(), 16);
    }

    #[test]
    fn an_empty_open_channel_is_pending_not_finished() {
        let (_tx, mut body) = channel(default_config());
        assert!(matches!(body.poll_chunk(), ChunkPoll::Empty));
        assert!(matches!(body.poll_chunk(), ChunkPoll::Empty));
    }

    #[test]
    fn a_closed_channel_ends_the_body_once() {
        let (tx, mut body) = channel(default_config());
        tx.try_send(data(b"x")).expect("queue frame");
        drop(tx);

        assert_eq!(expect_data(body.poll_chunk()), b"x");
        assert!(matches!(
            body.poll_chunk(),
            ChunkPoll::Chunk(ResponseChunk::End)
        ));
        assert!(matches!(body.poll_chunk(), ChunkPoll::Disconnected));
    }

    #[test]
    fn empty_data_frames_are_skipped() {
        let (tx, mut body) = channel(default_config());
        tx.try_send(data(b"")).expect("queue empty frame");
        tx.try_send(data(b"real")).expect("queue frame");
        assert_eq!(expect_data(body.poll_chunk()), b"real");
    }

    #[test]
    fn large_frames_are_split_to_the_configured_chunk_size() {
        let cfg = config(1 << 20, 4, Duration::from_secs(30), Duration::from_secs(60));
        let (tx, mut body) = channel(cfg);
        tx.try_send(data(b"0123456789")).expect("queue frame");

        assert_eq!(expect_data(body.poll_chunk()), b"0123");
        assert_eq!(expect_data(body.poll_chunk()), b"4567");
        assert_eq!(expect_data(body.poll_chunk()), b"89");
        assert!(matches!(body.poll_chunk(), ChunkPoll::Empty));
    }

    #[test]
    fn trailers_are_forwarded_and_empty_trailers_are_skipped() {
        let (tx, mut body) = channel(default_config());
        tx.try_send(Ok(UpstreamBodyFrame::Trailers(http::HeaderMap::new())))
            .expect("queue empty trailers");
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        tx.try_send(Ok(UpstreamBodyFrame::Trailers(trailers)))
            .expect("queue trailers");

        match body.poll_chunk() {
            ChunkPoll::Chunk(ResponseChunk::Trailers { headers }) => {
                assert!(
                    headers
                        .iter()
                        .any(|(name, value)| name == b"grpc-status" && value == b"0")
                );
            }
            ChunkPoll::Chunk(other) => panic!("expected trailers, got {other:?}"),
            _ => panic!("expected trailers"),
        }
    }

    #[test]
    fn an_upstream_error_ends_the_body_with_that_error() {
        let (tx, mut body) = channel(default_config());
        tx.try_send(Err(ProxyError::Timeout)).expect("queue error");
        tx.try_send(data(b"never delivered")).expect("queue frame");

        assert!(matches!(
            body.poll_chunk(),
            ChunkPoll::Chunk(ResponseChunk::Error(ProxyError::Timeout))
        ));
        assert!(matches!(body.poll_chunk(), ChunkPoll::Disconnected));
    }

    #[test]
    fn a_frame_over_the_size_cap_is_rejected() {
        let cfg = config(
            8,
            usize::MAX,
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let (tx, mut body) = channel(cfg);
        tx.try_send(data(b"01234")).expect("queue frame");
        tx.try_send(data(b"56789")).expect("queue frame");

        assert_eq!(expect_data(body.poll_chunk()), b"01234");
        assert!(matches!(
            body.poll_chunk(),
            ChunkPoll::Chunk(ResponseChunk::Error(ProxyError::Pool(
                PoolError::BackendOverloaded(_)
            )))
        ));
        assert!(matches!(body.poll_chunk(), ChunkPoll::Disconnected));
    }

    #[test]
    fn an_idle_response_times_out_without_any_frame_arriving() {
        let cfg = config(
            1 << 20,
            usize::MAX,
            Duration::from_millis(30),
            Duration::from_secs(60),
        );
        let (tx, mut body) = channel(cfg);
        tx.try_send(data(b"first")).expect("queue frame");
        assert_eq!(expect_data(body.poll_chunk()), b"first");

        std::thread::sleep(Duration::from_millis(80));
        assert!(matches!(
            body.poll_chunk(),
            ChunkPoll::Chunk(ResponseChunk::Timeout(TimeoutReason::ResponseBodyIdle))
        ));
        assert!(matches!(body.poll_chunk(), ChunkPoll::Disconnected));
    }

    #[test]
    fn an_overlong_response_times_out_on_the_total_deadline() {
        let cfg = config(
            1 << 20,
            usize::MAX,
            Duration::from_secs(30),
            Duration::from_millis(30),
        );
        let (_tx, mut body) = channel(cfg);

        std::thread::sleep(Duration::from_millis(80));
        assert!(matches!(
            body.poll_chunk(),
            ChunkPoll::Chunk(ResponseChunk::Timeout(TimeoutReason::ResponseBodyTotal))
        ));
    }

    #[test]
    fn dropping_the_source_closes_the_upstream_channel() {
        let (tx, body) = channel(default_config());
        drop(body);
        assert!(
            tx.try_send(data(b"x")).is_err(),
            "the transport must see the receiver gone and stop"
        );
    }

    #[test]
    fn the_pump_variant_still_reports_empty_and_disconnected() {
        let (tx, rx) = mpsc::channel::<ResponseChunk>(4);
        let mut source = ResponseSource::from(rx);
        assert!(matches!(source.try_next(), ChunkPoll::Empty));
        tx.try_send(ResponseChunk::End).expect("queue chunk");
        assert!(matches!(
            source.try_next(),
            ChunkPoll::Chunk(ResponseChunk::End)
        ));
        drop(tx);
        assert!(matches!(source.try_next(), ChunkPoll::Disconnected));
    }
}
