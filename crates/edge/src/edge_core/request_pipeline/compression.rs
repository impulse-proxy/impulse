pub(crate) use impulse_policy::{
    ResponseCompressionAction, ResponseCompressionInput, ResponseCompressionPolicyInput,
    apply_gzip_response_headers, ensure_vary_accept_encoding, evaluate_response_compression,
};
