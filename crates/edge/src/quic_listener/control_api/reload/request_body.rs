use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Body;
use serde::{Deserialize, de::DeserializeOwned};

use super::*;

pub(super) const MAX_CONTROL_API_JSON_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::quic_listener::control_api) struct ControlApiRuntimePlanRequest {
    pub(in crate::quic_listener::control_api) config_path: Option<String>,
    #[serde(rename = "requested_by")]
    pub(in crate::quic_listener::control_api) _requested_by_annotation: Option<String>,
    pub(in crate::quic_listener::control_api) reason: Option<String>,
    pub(in crate::quic_listener::control_api) expected_generation: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::quic_listener::control_api) struct ControlApiRuntimeRollbackPayload {
    pub(in crate::quic_listener::control_api) target_generation: u64,
    #[serde(rename = "requested_by")]
    pub(in crate::quic_listener::control_api) _requested_by_annotation: Option<String>,
    pub(in crate::quic_listener::control_api) reason: Option<String>,
    pub(in crate::quic_listener::control_api) expected_active_generation: Option<u64>,
}

impl Http3Service {
    pub(super) async fn control_api_json_body<T>(
        req: Request<Incoming>,
    ) -> Result<T, Box<Response<Full<Bytes>>>>
    where
        T: DeserializeOwned,
    {
        let body = Self::collect_control_api_json_body_bounded(req.into_body()).await?;
        if body.is_empty() {
            return Err(Box::new(Self::json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": "request body is required" }),
            )));
        }
        serde_json::from_slice(&body).map_err(|err| {
            Box::new(Self::json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("invalid request body: {err}") }),
            ))
        })
    }

    pub(super) async fn control_api_json_body_or_default<T>(
        req: Request<Incoming>,
    ) -> Result<T, Box<Response<Full<Bytes>>>>
    where
        T: DeserializeOwned + Default,
    {
        let body = Self::collect_control_api_json_body_bounded(req.into_body()).await?;
        if body.is_empty() {
            return Ok(T::default());
        }
        serde_json::from_slice(&body).map_err(|err| {
            Box::new(Self::json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("invalid request body: {err}") }),
            ))
        })
    }

    pub(super) async fn collect_control_api_json_body_bounded<B>(
        mut body: B,
    ) -> Result<Vec<u8>, Box<Response<Full<Bytes>>>>
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display,
    {
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(err) => {
                    return Err(Box::new(Self::json_response(
                        StatusCode::BAD_REQUEST,
                        json!({ "error": format!("invalid request body: {err}") }),
                    )));
                }
            };
            let Ok(chunk) = frame.into_data() else {
                continue;
            };
            let next_len = bytes.len().saturating_add(chunk.len());
            if next_len > MAX_CONTROL_API_JSON_BODY_BYTES {
                return Err(Box::new(Self::json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({
                        "error": format!(
                            "request body exceeded {} bytes",
                            MAX_CONTROL_API_JSON_BODY_BYTES
                        )
                    }),
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
