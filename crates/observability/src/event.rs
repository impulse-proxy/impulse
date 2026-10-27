use std::fmt;

use impulse_contracts::RequestId;

#[derive(Clone, Copy, Debug, Default)]
pub struct OperationalEventContext<'a> {
    pub request_id: Option<RequestId>,
    pub route: Option<&'a str>,
    pub upstream: Option<&'a str>,
    pub backend: Option<&'a str>,
    pub decision_reason: Option<&'a str>,
    pub failure_class: Option<&'a str>,
}

impl<'a> OperationalEventContext<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    #[must_use]
    pub fn with_upstream(mut self, upstream: &'a str) -> Self {
        self.upstream = Some(upstream);
        self
    }

    #[must_use]
    pub fn with_backend(mut self, backend: &'a str) -> Self {
        self.backend = Some(backend);
        self
    }

    #[must_use]
    pub fn with_reason(mut self, reason: &'a str) -> Self {
        self.decision_reason = Some(reason);
        self
    }
}

impl fmt::Display for OperationalEventContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut field = |key: &str, value: &dyn fmt::Display| -> fmt::Result {
            if !first {
                formatter.write_str(" ")?;
            }
            first = false;
            write!(formatter, "{key}={value}")
        };

        if let Some(request_id) = self.request_id {
            field("request_id", &request_id)?;
        }
        if let Some(route) = self.route {
            field("route", &route)?;
        }
        if let Some(upstream) = self.upstream {
            field("upstream", &upstream)?;
        }
        if let Some(backend) = self.backend {
            field("backend", &backend)?;
        }
        if let Some(reason) = self.decision_reason {
            field("reason", &reason)?;
        }
        if let Some(failure_class) = self.failure_class {
            field("failure_class", &failure_class)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricReasonLabels<'a> {
    pub outcome: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub failure_class: Option<&'a str>,
}
