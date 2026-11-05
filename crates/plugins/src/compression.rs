use http::HeaderMap;
pub use impulse_policy::ResponseCompressionEvaluation;
use impulse_policy::{
    ResponseCompressionAction, ResponseCompressionBypassReason,
    ResponseCompressionInput as PolicyCompressionInput, ResponseCompressionPolicyInput,
    apply_gzip_response_headers, ensure_vary_accept_encoding, evaluate_response_compression,
};

use crate::ResponseCompressionInput;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledResponseCompression {
    input: ResponseCompressionInput,
}

impl CompiledResponseCompression {
    pub(crate) const fn new(input: ResponseCompressionInput) -> Self {
        Self { input }
    }

    #[must_use]
    pub const fn disabled_evaluation() -> ResponseCompressionEvaluation {
        ResponseCompressionEvaluation {
            action: ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::Disabled),
            vary_accept_encoding: false,
        }
    }

    #[must_use]
    pub fn evaluate(
        &self,
        request_method: &str,
        request_headers: &HeaderMap,
        response_status: http::StatusCode,
        response_headers: &HeaderMap,
    ) -> ResponseCompressionEvaluation {
        evaluate_response_compression(PolicyCompressionInput {
            policy: ResponseCompressionPolicyInput {
                enabled: true,
                minimum_size_bytes: self.input.minimum_size_bytes,
            },
            request_method,
            request_headers,
            response_status,
            response_headers,
        })
    }

    pub fn apply_negotiation_headers(
        &self,
        headers: &mut HeaderMap,
        evaluation: ResponseCompressionEvaluation,
    ) {
        if evaluation.vary_accept_encoding {
            ensure_vary_accept_encoding(headers);
        }
    }

    pub fn apply_selected_representation_headers(
        &self,
        headers: &mut HeaderMap,
        evaluation: ResponseCompressionEvaluation,
    ) {
        self.apply_negotiation_headers(headers, evaluation);
        if matches!(evaluation.action, ResponseCompressionAction::Gzip) {
            apply_gzip_response_headers(headers);
        }
    }
}
