use std::{
    ops::{Deref, DerefMut},
    time::Instant,
};

use impulse_contracts::{BackendId, RequestId};
use pingora_core::Result;
use pingora_http::RequestHeader;

pub(crate) struct PingoraRequestContext<T> {
    state: T,
    pub started_at: Instant,
    pub method: Option<String>,
    pub path: Option<String>,
    pub authority: Option<String>,
    pub content_length: Option<usize>,
    pub body_bytes_received: usize,
    pub request_body_last_progress_at: Instant,
    pub response_body_bytes_received: usize,
    pub response_body_started_at: Option<Instant>,
    pub response_body_last_progress_at: Option<Instant>,
    pub response_body_suppressed: bool,
    pub response_body_limit_exempt: bool,
    pub response_content_length: Option<usize>,
    pub request_body_replayable: bool,
    pub retry_count: u8,
    pub retry_backend: Option<(BackendId, usize)>,
    pub lb_key: Option<String>,
    pub request_id: RequestId,
}

impl<T> PingoraRequestContext<T> {
    pub(crate) fn new(state: T, request_id: RequestId) -> Self {
        let now = Instant::now();
        Self {
            state,
            started_at: now,
            method: None,
            path: None,
            authority: None,
            content_length: None,
            body_bytes_received: 0,
            request_body_last_progress_at: now,
            response_body_bytes_received: 0,
            response_body_started_at: None,
            response_body_last_progress_at: None,
            response_body_suppressed: false,
            response_body_limit_exempt: false,
            response_content_length: None,
            request_body_replayable: false,
            retry_count: 0,
            retry_backend: None,
            lb_key: None,
            request_id,
        }
    }
}

impl<T> Deref for PingoraRequestContext<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<T> DerefMut for PingoraRequestContext<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

pub(super) fn apply_normalized_request_headers(
    target: &mut RequestHeader,
    headers: &http::HeaderMap,
) -> Result<()> {
    while let Some(name) = target.headers.keys().next().cloned() {
        target.remove_header(&name);
    }
    for (name, value) in headers {
        target.append_header(name.clone(), value.clone())?;
    }
    Ok(())
}
