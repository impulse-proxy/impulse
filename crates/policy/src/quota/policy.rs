use super::*;

impl QuotaWindowPolicy {
    #[cfg(test)]
    fn from_runtime(value: &ConfigRuntimeQuotaWindow) -> Self {
        Self {
            requests: value.requests,
            window: value.window,
        }
    }

    #[cfg(test)]
    fn from_raw(value: &RawDistributedQuotaWindow) -> Self {
        Self {
            requests: value.requests.max(1),
            window: Duration::from_secs(value.window_secs.max(1)),
        }
    }

    pub(super) fn introspection_snapshot(&self) -> QuotaWindowIntrospectionSnapshot {
        QuotaWindowIntrospectionSnapshot {
            requests: self.requests,
            window_secs: self.window.as_secs(),
        }
    }
}

impl QuotaLocalFallbackPolicy {
    #[cfg(test)]
    pub(super) fn from_runtime(value: &ConfigRuntimeQuotaLocalFallback) -> Self {
        Self {
            key_prefix: value.key_prefix.clone(),
            max_entries: value.max_entries,
        }
    }

    #[cfg(test)]
    pub(super) fn from_raw(value: &impulse_config::config::QuotaLocalFallbackConfig) -> Self {
        Self {
            key_prefix: value.key_prefix.trim().to_string(),
            max_entries: value.max_entries.max(1),
        }
    }

    pub(super) fn build_store(&self) -> Arc<InMemoryDistributedQuotaCounterStore> {
        Arc::new(InMemoryDistributedQuotaCounterStore::bounded(
            &self.key_prefix,
            self.max_entries,
        ))
    }
}

impl QuotaPolicyRuntime {
    #[cfg(test)]
    pub(super) fn from_runtime(value: &ConfigRuntimeQuotaPolicy) -> Self {
        Self {
            name: value.name.clone(),
            route_allowlist: value.route_allowlist.iter().cloned().collect(),
            selector: QuotaSelectorMatcher::from_runtime(&value.selector),
            burst: value.burst.as_ref().map(QuotaWindowPolicy::from_runtime),
            sustained: value
                .sustained
                .as_ref()
                .map(QuotaWindowPolicy::from_runtime),
        }
    }

    #[cfg(test)]
    pub(super) fn from_raw(value: &RawDistributedQuotaPolicy) -> Self {
        Self {
            name: value.name.trim().to_string(),
            route_allowlist: value
                .route_allowlist
                .iter()
                .map(|route| route.trim())
                .filter(|route| !route.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            selector: QuotaSelectorMatcher::from_raw(&value.selector),
            burst: value.burst.as_ref().map(QuotaWindowPolicy::from_raw),
            sustained: value.sustained.as_ref().map(QuotaWindowPolicy::from_raw),
        }
    }

    pub fn counter_request(
        &self,
        composite_key: QuotaCompositeKey,
    ) -> QuotaCounterEvaluationRequest {
        QuotaCounterEvaluationRequest {
            policy_name: self.name.clone(),
            composite_key,
            cost: 1,
            burst: self.burst.clone(),
            sustained: self.sustained.clone(),
        }
    }

    pub(super) fn applies_to_route(&self, route: &str) -> bool {
        self.route_allowlist.is_empty() || self.route_allowlist.contains(route)
    }
}

impl QuotaSelectorMatcher {
    #[cfg(test)]
    fn from_raw(value: &RawDistributedQuotaSelector) -> Self {
        Self {
            route: value.route,
            tenant: value
                .tenant
                .as_ref()
                .map(|source| QuotaSelectorKeySpec::from_raw_key(&source.key)),
            token: value
                .token
                .as_ref()
                .map(|source| QuotaSelectorKeySpec::from_raw_key(&source.key)),
            client: value
                .client
                .as_ref()
                .map(|source| QuotaSelectorKeySpec::from_raw_key(&source.key)),
        }
    }
}

impl QuotaSelectorDimensions {
    pub fn slug(self) -> String {
        let mut parts = Vec::with_capacity(4);
        if self.route {
            parts.push("route");
        }
        if self.tenant {
            parts.push("tenant");
        }
        if self.token {
            parts.push("token");
        }
        if self.client {
            parts.push("client");
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join("+")
        }
    }
}

impl QuotaSelectorKeySpec {
    pub fn from_raw_key(value: &str) -> Self {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "path" => Self::Path,
            "authority" => Self::Authority,
            "method" => Self::Method,
            "cid" => Self::Cid,
            "sticky-cid" => Self::StickyCid,
            "peer_ip" => Self::PeerIp,
            "client_ip" => Self::ClientIp,
            "bearer_token" => Self::BearerToken,
            _ => {
                if let Some((source, key)) = normalized.split_once(':') {
                    return match source {
                        "header" => Self::Header(key.trim().to_string()),
                        "cookie" => Self::Cookie(key.trim().to_string()),
                        "query" => Self::Query(key.trim().to_string()),
                        _ => Self::Header(normalized),
                    };
                }
                Self::Header(normalized)
            }
        }
    }

    pub fn with_legacy_default_fallback(self) -> Self {
        Self::LegacyFallback(Box::new(self))
    }

    pub fn descriptor(&self) -> String {
        match self {
            Self::Path => "path".to_string(),
            Self::Authority => "authority".to_string(),
            Self::Method => "method".to_string(),
            Self::Cid => "cid".to_string(),
            Self::StickyCid => "sticky-cid".to_string(),
            Self::PeerIp => "peer_ip".to_string(),
            Self::ClientIp => "client_ip".to_string(),
            Self::BearerToken => "bearer_token".to_string(),
            Self::Header(name) => format!("header:{name}"),
            Self::Cookie(name) => format!("cookie:{name}"),
            Self::Query(name) => format!("query:{name}"),
            Self::LegacyFallback(inner) => inner.descriptor(),
        }
    }
}
