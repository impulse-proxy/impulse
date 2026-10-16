use std::{net::SocketAddr, sync::Arc};

use crate::{routing::decision::RouteDecisionReason, runtime::activation::GenerationId};

pub(crate) type RequestHeaderLookup<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// Protocol-neutral request data supplied to the shared policy pipeline.
pub(crate) struct PipelineRequest<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) authority: Option<&'a str>,
    pub(crate) peer_address: SocketAddr,
    pub(crate) headers: Option<&'a RequestHeaderLookup<'a>>,
    pub(crate) runtime_generation: GenerationId,
}

/// The route selected by the shared routing service before backend selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedRouteTarget {
    pub(crate) upstream_name: Arc<str>,
    pub(crate) matched_path_len: usize,
    pub(crate) host_specific: bool,
    pub(crate) method_specific: bool,
    pub(crate) reason: RouteDecisionReason,
}
