# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0-beta] - 2026-08-22

### Added

- Secret references for sensitive config fields — a new top-level `secrets:` block declares providers (`kind: file`, `base_dir`), and any secret-bearing field gains a `*_ref` sibling accepting `literal:<value>` or `file://<path>` (relative paths resolve against the provider's `base_dir`). Resolved secrets are tracked with a source kind, SHA-256 fingerprint, byte length, and load timestamp; plaintext values are never logged, and control-API/audit output only ever exposes the fingerprint or a sanitized reference.
- Upstream mTLS — per-upstream `tls.client_certificate` / `tls.client_certificate_ref` and `tls.client_key` / `tls.client_key_ref` let Impulse present a client certificate to backends, alongside the existing `verify_certificates`, `strict_sni`, `ca_file`, and `ca_dir` options. Client certificate expiry (`not_after`) is parsed and tracked at runtime.
- Secret and certificate lifecycle observability: Prometheus metrics `impulse_secret_reload_total`, `impulse_secret_resolve_total`, `impulse_secret_last_success_unixtime`, `impulse_upstream_client_certificate_not_after_seconds` / `..._days_remaining`, and `impulse_control_plane_cert_reload_total`; a `secrets` block and per-upstream TLS material (fingerprint, expiry, sanitized reference) in the control-API runtime snapshot; and new audit event types `UpstreamMtlsMaterialChanged` / `UpstreamMtlsMaterialInvalid`.
- New validation rules: a secret-bearing field and its `*_ref` sibling are mutually exclusive (`ConflictingSources`); mTLS client certificate and key must be configured as a complete pair; unsupported reference schemes, missing files, empty secrets, and malformed PEM material are rejected at config load with descriptive errors.

### Changed

- Project rebranded from Spooky to **Impulse** across the codebase, packaging (Debian package, Docker images, systemd unit), documentation, configuration samples, and scripts. Binaries, config paths (`/etc/impulse/`), log paths (`/var/log/impulse/`), and the systemd unit (`impulse.service`) now use the `impulse` name. This is a naming change only — no behavioral changes accompany the rename itself.

### Compatibility

- Fully additive and backward compatible. Existing plaintext secret fields (`secret`, `client_secret`, `auth_token`, `client_certificate`/`client_key` as file paths) continue to work unchanged; the `secrets:` block and all `*_ref` fields are optional. No config migration is required for the secrets/mTLS work.
- The Spooky → Impulse rename changes binary name, default install paths, and systemd unit name. Existing deployments upgrading from a `spooky`-named install should review packaging paths before rolling out; this release does not ship an automated migration.

## [0.5.1-beta] - 2026-08-14

### Added

- Packaged operator observability bundle under `deploy/observability/` — Prometheus recording rules (`prometheus/recording-rules.yaml`), production alert rules (`prometheus/alerts.yaml`), an SLO package (`slo/definitions.promql`, `slo/README.md`), and six Grafana dashboards (`grafana/edge-traffic.json`, `admission-overload.json`, `backend-health.json`, `retries-hedges.json`, `tls-certificates.json`, `control-plane.json`) covering traffic, admission, backend health, retries/hedges, TLS certificate expiry, quota, auth, and control-plane activity.
- Canonical operator correlation fields on admin audit events — `event_id`, `schema_version`, `request_id`, `trace_id`, `span_id`, and `listener`, plus a stable `failure_class` (`authentication`, `authorization`, `source_policy`, `request_validation`, `runtime_config`, `runtime_state`, `listener_tls`, `watchdog`) attached to non-success events so failures can be grouped without parsing free-form reason strings.
- `GET /admin/runtime` and the runtime history endpoints gained an `observability` block — contract version, audit schema version, current generation, backend and quota backend health summaries, recent tracked admin actions, and repository-relative dashboard/documentation references, so operators and automation have one canonical entry point into the packaged bundle.
- `h3_client` now accepts `--method` (default `GET`) and repeatable `--header name=value` flags (including pseudo-headers such as `:protocol`), for exercising non-GET and header-sensitive observability traffic in the lab.
- Documentation covered the shipped dashboards, alerts, SLOs, incident-correlation workflow, audit schema, and the runtime `observability` block.

### Changed

- The Debian package's default `config.yaml` now ships the control API **disabled** (`observability.control_api.enabled: false`) with a placeholder-token comment block instead of an enabled control API with a literal `replace-with-strong-token` credential — a fresh install no longer boots with a live, weakly-credentialed admin surface.
- The systemd unit (`packaging/deb/debian/impulse.service`) restarts with `Restart=always` instead of `Restart=on-failure`, adds `StartLimitIntervalSec=60`/`StartLimitBurst=5` under `[Unit]`, raises `LimitNOFILE=65535`, and tightens sandboxing (`ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictAddressFamilies`, `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality`); `/etc/impulse` is no longer in `ReadWritePaths`, so only `/var/log/impulse` stays writable.

### Fixed

- OTLP tracing is now initialized inside the Tokio runtime rather than before it. The OTLP tonic exporter spawns a background task while building its gRPC channel, which previously panicked with "there is no reactor running" whenever tracing was enabled.
- Docker image builds and clippy warnings introduced during the observability bundle work.

### Compatibility

- Purely additive for existing deployments. The new `observability` block in `/admin/runtime` and the `audit.rs` event fields are additive JSON fields; existing consumers that don't read them are unaffected.
- The Debian package's default config and systemd unit changes apply only to fresh installs/packages built from this version — existing deployed configs and units are not modified in place. Operators upgrading the package should review the new Impulse service sandboxing and `ReadWritePaths` restriction before rolling out, particularly if `resilience.watchdog.restart_command` or any in-process config write depends on `/etc/impulse` being writable.

## [0.5.0-beta] - 2026-08-10

### Added

- Distributed quota policies under `resilience.quota` — cluster-wide request budgets enforced at admission, evaluated before forwarding. Disabled by default (`enabled: false`), so an unchanged 0.4.3 config engages none of this machinery.
- Composite quota policies via `resilience.quota.policies[]`, each carrying a `name`, an optional `route_allowlist`, a `selector`, and one or both of a `burst` and `sustained` window (`requests`, `window_secs`). A policy's identity is the composite of its selected dimensions, so one policy can budget per tenant-and-route without collapsing distinct callers into a shared counter.
- Quota identity extraction via `selector` — `route` (bool), plus `tenant`, `token`, and `client`, each resolved from a request `key`. `tenant`/`token` accept `header:*`, `cookie:*`, `query:*`, and `bearer_token`; `client` additionally accepts `peer_ip` and `client_ip`.
- Redis-backed counter store (`resilience.quota.backend.kind: redis`) with `url`, `key_prefix` (default `impulse:quota`), `connect_timeout_ms` (default `250`), `command_timeout_ms` (default `100`), and `max_inflight` (default `1024`). Burst and sustained windows are incremented and tested in a single atomic Lua evaluation, so a request never charges one window and abandons the other.
- In-memory counter backend (`kind: in_memory`, the default) for single-node deployments and tests, sharing the fixed-window semantics of the Redis path.
- Bounded local fallback via `resilience.quota.local_fallback` (Redis backends only) with `key_prefix` and a required `max_entries`. Fallback engages only for outage-style failures — backend timeout and unavailability — and never for protocol, config, or logic errors, which stay hard failures rather than silently degrading to a weaker budget.
- Enforcement modes via `resilience.quota.enforcement` — `shadow` records what would have been denied without blocking, `enforce` (default) rejects. Shadow mode lets a policy be sized against live traffic before it starts turning requests away.
- Backend failure policy via `resilience.quota.backend_failure_policy` — `fail_closed` (default) rejects with `503` when the counter store is unreachable, `fail_open` admits. The default is fail-closed: an unreachable Redis stops enforcing budgets, and admitting unbounded traffic is the worse outcome.
- Quota metrics — `impulse_quota_policy_outcomes_total{policy,decision,reason,selector_dimensions,backend_mode}` and `impulse_quota_backend_health_total{backend_mode,reason}`. Decisions are `allowed`, `denied`, `shadow_denied`, `failed_open`, `failed_closed`, and `not_applied`; degraded operation is visible in `backend_mode` as `<kind>_local_fallback_<reason>`, so running on fallback counters is distinguishable from running on the real backend.
- Runtime introspection for quota — `GET /admin/runtime` gained a `quota` block carrying `enabled`, `enforcement`, `backend_failure_policy`, `active_backend`, a `backend_status` object (`availability`, `degraded`, `health_reason`, `last_observed_at_unix_ms`, `recent_errors[]`), and the resolved `policies[]` with their selectors and windows.
- Documentation covered quota policy semantics, backend selection, degraded operation, and migration from scoped rate limiting.

### Changed

- Scoped rate limiting was rebuilt on the quota pipeline's evaluation contract. Buckets now evaluate a request cost and return remaining tokens with a computed `retry_after` derived from the token deficit and refill rate, replacing the previous boolean consume. Existing `resilience.scoped_rate_limits` configuration is unchanged and continues to behave as before.
- A poisoned scoped rate-limit bucket lock is now reported as a backend unavailability rather than being treated as an implicit allow inside the bucket layer. The legacy scoped path still resolves that to fail-open, preserving its prior behavior.

### Fixed

- Every route-matching quota policy is evaluated, not only the first. Previously a route matched by more than one policy consumed only the first policy's budget — later policies validated at startup and appeared in the runtime snapshot while enforcing nothing, so a narrow policy layered after a broad one was silently dead. A denial now short-circuits so remaining budgets are not charged for a request that is about to be rejected, while shadow denials continue evaluating so each policy still records its outcome.
- A request missing the identity a later policy selects on is denied with `selector_identity_missing` instead of being admitted by an earlier, broader policy that happened to match first.

### Security

- Quota enforcement is fail-closed by default. A counter-store outage rejects with `503` rather than admitting unmetered traffic, and local fallback is deliberately scoped to outages only — a misconfigured or protocol-mismatched backend fails hard instead of quietly enforcing a weaker, node-local budget.
- Config validation rejects incoherent quota policy at startup: a `burst` window that is not shorter than its `sustained` window, a selector with no dimensions, zero-valued `requests` or `window_secs`, duplicate policy names, duplicate selector/window fingerprints, the same request key bound to two identity dimensions, `local_fallback` configured against a non-Redis backend, and `enabled: true` with no policies.

### Compatibility

- Purely additive for existing deployments. `resilience.quota` defaults to `enabled: false` with an empty `policies` list, so a 0.4.3 config runs unchanged and scoped rate limiting keeps working as before — it is not deprecated.
- **One-way config compatibility.** `resilience.quota` and its nested structs use strict `deny_unknown_fields`: a 0.5.0 binary accepts a 0.4.3 config, but a 0.4.3 binary rejects any config carrying a `resilience.quota` block. Plan rollbacks accordingly.
- Automation reading `GET /admin/runtime` sees a new top-level `quota` object, and metrics scrapers see two new counter families. Optional fields are omitted rather than emitted as null.

## [0.4.3-beta] - 2026-08-06

### Added

- Asymmetric JWT validation — `RS256` and `ES256` join `HS256` on the local, synchronous request-path verifier. Signature checking never makes a network call.
- Static public-key material via `auth.jwt.static_keys[]`, given either as PEM (`kind: pem`, `public_key_pem`) or as a JWK document (`kind: jwk`, `jwk`), each carrying a `kid` and `alg`.
- Remote JWKS key sources via `auth.jwt.jwks_url`, with a background-refreshed in-memory cache tuned by `jwks_refresh_interval_secs` (default `300`), `jwks_cache_ttl_secs` (default `900`), `jwks_stale_if_error_secs` (default `3600`), and `jwks_request_timeout_ms`. An unknown `kid` triggers a rate-limited on-demand refresh rather than a per-request fetch.
- JWKS cache state machine with explicit states — `never_fetched`, `fresh`, `stale`, `refresh_failed_retained`, `quarantined_retained`, `empty_unusable` — so retained last-known-good keys are distinguishable from an unusable key set.
- Startup readiness gating via `auth.jwt.jwks_startup_behavior`. Under `require_ready`, a source that cannot load fails startup rather than admitting traffic with no keys, and reload activation preflights the same condition instead of committing a generation that cannot validate tokens.
- Explicit algorithm policy — `auth.jwt.allowed_algorithms` and `require_kid` are configured independently of the key material present, and multi-valued `issuers`/`audiences` complement the existing singular `issuer`/`audience` fields.
- JWT and JWKS metrics: `impulse_jwt_validation_failures_total{reason}`, `impulse_jwt_algorithm_rejections_total{algorithm}`, and per-source `impulse_jwks_unknown_kid_total`, `impulse_jwks_refresh_success_total`, `impulse_jwks_refresh_failure_total`, `impulse_jwks_age_seconds`, `impulse_jwks_state`, `impulse_jwks_active_keys`, `impulse_jwks_last_refresh_attempt_seconds`, and `impulse_jwks_last_refresh_success_seconds`.
- Runtime introspection for auth — `GET /admin/runtime` gained a `jwks.sources[]` block (source id, sanitized endpoint, cache state, active key count, refresh timestamps, last failure reason) and per-upstream JWT provider state under `auth.providers[]`, alongside validation-failure and algorithm-rejection counters.
- Structured JWT rejection logs carrying the canonical reason, token `alg` and `kid`, JWKS source id, cache state, and whether the staleness window had expired.

### Changed

- JWT validation was restructured into a canonical pipeline (JOSE parse → algorithm policy → key resolution → signature → claims) with a stable rejection-reason vocabulary, replacing ad-hoc failure paths. Reasons include `algorithm_not_allowed`, `missing_verification_key`, `key_source_unavailable`, `ambiguous_verification_key`, `issuer_mismatch`, `audience_mismatch`, and `token_expired`.
- Key selection is re-checked at verification time, so an asymmetric public key can never satisfy an `HS256` token and vice versa, and `alg: none` never maps to a verification mode.
- OIDC external auth documentation now points at JWT `jwks_url` for local signature validation; the OIDC provider itself still does discovery and introspection only.

### Fixed

- JWKS cache entries in `refresh_failed_retained` and `quarantined_retained` states are preserved for the remainder of the TTL window instead of being dropped, so a transient issuer outage no longer causes an immediate auth outage.
- Two JWKS sources configured with the same URL but different policies are merged deterministically rather than depending on upstream iteration order.
- Tokens presenting no `kid` are accepted only when exactly one algorithm-compatible key survives issuer/policy filtering; multiple candidates are rejected as ambiguous instead of the verifier guessing which key the issuer intended.

### Security

- JWKS telemetry is labelled by an opaque `jwks_source_id` rather than the configured URL, and endpoint values surfaced in logs and the runtime snapshot are sanitized of query strings, so credentials embedded in a JWKS URL cannot leak through the metrics endpoint, logs, or `/admin/runtime`.
- RSA keys shorter than 2048 bits are rejected, whether configured statically or published by a JWKS endpoint.
- A refresh failure never widens access: last-known-good keys keep validating until `jwks_stale_if_error_secs` elapses, after which requests are rejected rather than admitted.
- Config validation rejects incoherent JWT policy at startup: a shared `secret` configured without `HS256` in `allowed_algorithms`, `HS256` allowed with an empty `secret`, and a JWT provider with no key material at all. A token matching both a static key and a JWKS key is rejected as ambiguous rather than resolved by precedence.

### Compatibility

- Existing `HS256` JWT configs are unaffected. `allowed_algorithms` defaults to `HS256` only, `static_keys` is empty, and `jwks_url` is unset, so no JWKS machinery is engaged and an unchanged 0.4.2 config behaves exactly as it did. Note that `jwks_startup_behavior` defaults to `require_ready` — it applies only once `jwks_url` is set, so adopting JWKS is fail-closed at startup by default; choose `allow_degraded` explicitly if you would rather boot without keys.
- **One-way config compatibility.** `JwtAuth` uses strict `deny_unknown_fields`: a 0.4.3 binary accepts a 0.4.2 config, but a 0.4.2 binary rejects any config using `static_keys`, `jwks_url`, `allowed_algorithms`, `require_kid`, `issuers`, `audiences`, or the `jwks_*` tuning fields. Plan rollbacks accordingly.

## [0.4.2-beta] - 2026-08-02

### Added

- Control API mTLS — `observability.control_api.tls.client_auth` supports `disabled`, `optional`, and `required` modes with a client-certificate verifier scoped to the control API endpoint, built independently of the data-plane listener's client-auth policy.
- Admin-plane RBAC — `viewer`, `operator`, and `admin` roles enforced per route. Runtime snapshot and history reads require `viewer`; validate, preview, activate, rollback, reload, and cert reload require `operator`; restart requires `admin`. Minimum roles are configurable under `observability.control_api.authorization`.
- Role-scoped admin credentials via `observability.control_api.auth.bearer_tokens[]`, each carrying a `role` and an optional `actor_id` used for audit attribution.
- mTLS client-certificate identity — subject, common name, and DNS/URI SANs are extracted from the handshake certificate, with roles resolved from a configurable subject attribute via `auth.identity_source`.
- Structured admin audit stream with a stable JSON schema (`event_type`, `time_unix_ms`, `actor`, `action`, `target`, `generation`, `result`, `reason`, `event_id`, `peer_addr`, `authn`). Events cover authentication success and failure, authorization denial, runtime snapshot reads, and attempt/result pairs for reload, activate, rollback, restart, cert reload, validate, and preview.
- Dedicated audit sink under `observability.control_api.audit` — either a `impulse.control_api.audit` log target that emits raw JSON lines regardless of the application log format, or a file sink that keeps audit records out of the application log entirely.
- Optional source-address gating via `observability.control_api.ip_allowlist`, evaluated before credential validation. The source is always the TCP peer address.

### Changed

- Privileged control API routes now distinguish authentication from authorization failure: a valid but under-scoped caller receives `403 Forbidden` with `reason: insufficient_role`, while missing or invalid authentication remains `401 Unauthorized`. **Breaking for automation that treats every rejection as `401`.** Denial bodies gained `reason` and `required_role` fields; mutation routes retain their existing `accepted`/`reloaded` flags.
- The control API builds its own TLS server configuration rather than reusing the primary listener's bootstrap config. It advertises only `http/1.1` in ALPN — HTTP/2 was already rejected, but the rejection now happens during ALPN negotiation rather than after the handshake.
- Plain-text log lines now include the log target (`<ts> <level> [<target>] <message>`). JSON log output is unchanged.
- Control API TLS handshake failures are logged with a stable client-auth reason code alongside the underlying error detail, distinct from data-plane listener failures.
- Control-plane authentication and authorization code moved to dedicated `admin_identity`, `admin_auth`, and `audit` modules, with no shared types between admin-plane and request-path auth.

### Security

- Bearer-token matching is constant-time across the entire configured token set, with no early return on match.
- Configured admin tokens are never serialized into the `/admin/runtime` snapshot and are redacted in debug output.
- Config validation rejects unsafe admin-plane combinations at startup: mTLS enabled without CA material, `optional` mTLS as the only authentication mechanism, inverted role ordering (for example a mutation role less privileged than the read role), a file audit sink without a path, and malformed CIDRs.

### Compatibility

- `observability.control_api.auth_token` continues to work and is mapped internally to an `admin`-scoped identity, so existing reload and restart automation is unaffected. All new admin-plane settings default to inert values — mTLS `disabled`, no static tokens, audit off, empty allowlist — so an unchanged config behaves exactly as it did in 0.4.1.
- **One-way config compatibility.** `ControlApi` uses strict `deny_unknown_fields`: a 0.4.2 binary accepts a 0.4.1 config, but a 0.4.1 binary rejects any config using the new nested admin-plane fields. Plan rollbacks accordingly.

## [0.4.1-beta] - 2026-07-31

### Added

- Staged runtime activation — `POST /admin/runtime/validate`, `/preview`, and `/activate` plan a config change (read, validate, compatibility-gate, per-domain diff) and commit it as an explicit transaction, returning the diff and structured rejections instead of a bare success flag.
- Rollback by generation id via `POST /admin/runtime/rollback`, backed by retained rollback-candidate generations.
- Runtime generation history — `GET /admin/runtime/history` and `/history/{generation}` expose the operation log plus retained-generation records (`status`, `rollback_candidate`, `has_bundle`, and a `note` explaining failed staged prepares) so operators can pick a safe rollback target.
- Runtime activation observability and canonical rejection reasons normalized across operator surfaces.

### Changed

- Operator-conflict responses are now classified instead of collapsing into `500`: stale-generation and restart-required conflicts return `409`, and an unknown rollback target returns `404`. **Breaking for automation that matches on `500`** — genuine runtime faults still return `500`.
- `POST /admin/runtime/reload` now defaults to the currently active runtime config source rather than always re-reading the startup path, and accepts an optional `config_path` body field to activate an alternate file. It remains a shortcut over the same staged pipeline as `/activate`.
- Config defaults co-located with the types they belong to, and serde default patterns normalized.
- Test suite restructured by behavioral domain, with shared integration harnesses for the request path, bootstrap/QUIC parity, runtime swap, and backend lifecycle.

### Fixed

- Activating an alternate `config_path` now makes that file the active runtime source, so later reloads read the activated file instead of silently falling back to the startup path.
- Generation history records only the operation actually requested — `validate` and `activate` no longer write synthetic `preview` entries, which previously consumed three history slots per activation and made the audit trail misleading.

## [0.4.0-beta] - 2026-07-27

### Added

- Canonical observability vocabulary — reasons and event fields (admission outcomes, local reason enums, overload metric labels, backend health-failure reasons) now map to a single canonical set, with bounded connect-attempt label cardinality.
- Deterministic runtime lifecycle state machine that gates reload commits, driving drain and shutdown through explicit lifecycle states.
- Unified backend refresh classification with explicit traffic-continuity reporting, and canonical backend health-failure reason surfaced in the control-plane snapshot.
- Structured operator-facing reload rejections with preflight messages, backed by a typed operational-policy vocabulary for runtime ownership and reload rules.
- Live `log.level` changes applied on config reload via a runtime `set_log_level` on the logger.
- Fine-grained rejection and backend-failure kinds carried through terminal outcome mapping; bootstrap terminal outcomes observed and aligned with the request lifecycle model.

### Fixed

- Drain and shutdown now flow through the runtime lifecycle state machine instead of ad-hoc paths.
- Process-shared watchdog and DNS resolver are carried across reload instead of being rebuilt.
- Bundle-lock panic and control-API unreachable paths replaced with fail-safe recovery; backend client-rotation failure is now an explicit operator-visible outcome.
- Pre-response requests still reading the body now time out under the request-body bucket.
- Restored stateful round-robin backend selection, failover availability on circuit-open retries, and streaming guardrail failure semantics.
- WebSocket upgrade headers preserved in bootstrap `101` responses.
- Upstreams iterated in name order so route conflicts report deterministically.

### Changed

- Public API surface locked down across crates — crate-internal items demoted, `unreachable_pub` enabled, dead code removed, and public runtime bundle/listener/connection surfaces documented.
- Documentation realigned to the post-refactor architecture: edge runtime ownership, runtime generation and backend lifecycle, request lifecycle and transport boundaries, observability, control plane, and reload behavior.
- Integration and unit tests hardened with per-contract cases asserting QUIC/bootstrap parity, metric label vocabularies, retry/hedge accounting, and wire-shape stability.

## [0.3.1-beta] - 2026-06-27

### Added

- Full config hot reload via `POST /admin/runtime/reload` — atomically swaps the runtime bundle without restarting the process or dropping connections.
- Listener group reconciliation on reload — new listener groups are started and removed groups are retired gracefully per the incoming config.
- Live admin endpoint rebinding — control API and metrics endpoint addresses are updated in place on reload without requiring a restart.
- `RuntimeTaskRegistry` — generation-aware background task tracking; retired tasks drain on a configurable timeout when a new generation is activated.

### Fixed

- Hot reload now correctly rejects configs that remove a listener or change its bind address, returning `409 Conflict`.
- Hot reload now correctly rejects changes to startup-owned settings (log level, thread counts, listen address), returning `409 Conflict`.
- Control API and cert reload endpoints now target the live runtime bundle after a hot reload instead of the original startup bundle.
- Metrics endpoint, bootstrap listener, and control API settings are now refreshed from the live runtime bundle on each reload.

### Changed

- Large runtime modules split into focused submodules: `quic_listener/mod.rs` → `bootstrap_tls`, `control_api/`, `forwarding`, `metrics_endpoint`, `tls_runtime`; `impulse/main.rs` → `app`, `listener_group`; `config/validator.rs` → `helpers`; `config/runtime.rs` → `listeners`, `upstreams`.
- Integration tests extracted into per-subsystem modules (`h3_edge/`, `h3_bridge/protocol`, `lb/tests`, `control_api/tests`).

## [0.3.0-beta] - 2026-06-20

### Added

- HTTP/1.1 upstream transport — `http://` backends are now forwarded over a pooled HTTP/1.1 connection via new `H1Client` and `H1Pool` primitives.
- Scheme-aware dispatch in the data plane — backend scheme determines transport: `https://` uses HTTP/2, `http://` uses HTTP/1.1.
- Mixed HTTP/1.1 and HTTP/2 backend deployments supported within the same upstream pool.
- DNS refresh client rotation wired through `UpstreamTransportPool` for H1 backends, matching existing H2 behavior.
- Health checks routed through the scheme-aware transport pool — `http://` backends are now probed over HTTP/1.1.
- `TE: trailers` header added to H1 upstream requests to preserve trailer forwarding semantics.

### Fixed

- Config validator no longer applies TLS trust-store checks to `http://` upstreams — HTTP-only configs boot without requiring CA paths or TLS material.

### Changed

- Upstream transport layer unified under `UpstreamTransportPool`, which dispatches by `BackendTransportKind` (`Http1` or `H2`).

## [0.2.1-beta] - 2026-06-20

### Fixed

- `ProxyError::Pool` displayed as `"transport error: ..."` — disambiguated to `"pool error: ..."` so pool and transport errors have distinct display text in logs.
- Watchdog mutex poison is now logged and recovered instead of silently causing the coordinator to skip state updates — watchdog restart logic remains operational after a worker panic.
- OTLP tracing endpoint is now configurable via `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` environment variables, with the resolved source logged at startup alongside the endpoint.
- `validate()` now returns a structured `ValidationError` instead of `bool`, making the first validation failure available to callers as a typed error value.
- `take_validation_error` clears the slot on read, preventing stale validation errors from leaking across test cases.
- Logger fallback error messages now include both the file path and directory path when log directory creation fails.

### Changed

- `validate_config` call site updated to handle the new `Result` return type from the validator.

## [0.2.0-beta] - 2026-06-18

### Added

**TLS**
- Live listener certificate reload — certificates can be reloaded without restarting the process.
- SNI-based server certificate selection with fallback for listener TLS, plus native QUIC SNI cert selection.
- Per-upstream TLS policy override — each upstream can now specify its own TLS settings independent of the global config.
- Certificate expiry telemetry — expiry timestamps exposed for monitoring.
- Downstream handshake telemetry — TLS handshake metrics on the listener path.
- Upstream TLS failure classification — failures are now categorized (cert, SNI mismatch, timeout, etc.) in logs and metrics.

**Routing**
- Wildcard host pattern matching in the route index with correct precedence over exact-host routes.
- Multi-listener support — independent listener worker groups can be spawned per listener entry.

**Forwarding**
- CONNECT tunnel support — HTTP CONNECT requests are validated, translated, and lifecycle-managed over H3.
- Response trailer forwarding over H3 — upstream response trailers are now relayed to the downstream client.
- Configurable `X-Forwarded-For` policy — choose append vs. overwrite semantics per deployment.
- Configurable Host header forwarding policy — preserve the original downstream `Host` or rewrite to the upstream authority.

**DNS**
- Periodic backend DNS refresh loop — backends are re-resolved at runtime without restart.
- Shared DNS resolver cache with atomic update semantics.
- Backend DNS refresh configuration (`performance.backend_dns_refresh_enabled`, `performance.backend_dns_refresh_interval_ms`).
- Backend connect and rotation telemetry — metrics for DNS refresh events, connection rotation, and backend selection.

**Config**
- Canonical runtime config model — a normalized intermediate config representation validated before startup.
- Cross-field normalization checks enforced at startup with classified error types.
- Runtime startup drives from the normalized config rather than raw YAML structs.

**Load Harness**
- H3 client timeout retry and reconnect controls.
- Config-gated inflight admission micro-wait.
- Matrix profile override and selection knobs.
- Improved worker model and ramp handling in load scenarios.

### Fixed

- `H2Client::default()` panicked on invalid TLS config — default construction no longer panics.
- Bootstrap response streaming lacked a running body-size cap — body size is now enforced incrementally.
- Hop-by-hop headers were not stripped from bootstrap responses.
- Ambiguous route conflicts (overlapping prefix + host combinations) are now rejected at startup.
- Backend hostnames are now validated more strictly at config load time.
- Upstream send/connect failures are classified into backend health states instead of being silently swallowed.
- SNI certificate hostnames containing whitespace are now rejected at config load.
- Route decision reasons were unstable for wildcard and trie-level routes.
- Authority/host normalization adapted to avoid unnecessary allocations on the hot path.
- Insecure upstream TLS (`verify_certificates: false`) now always emits a startup warning log.

### Changed

- Bootstrap forwarding policy unified into a single code path.
- Route precedence decisions made explicit in the routing layer.
- Backend health identity made explicit — health checks align with live backend resolution.
- Pooled clients are rotated when backend DNS changes are detected.
- Listener TLS material loading centralized.

## [0.1.1-beta] - 2026-05-28

### Added
- `upstream_tls.verify_certificates: false` — new config option to disable upstream TLS certificate verification, useful for backends with self-signed certs in development or trusted internal environments. Matches the opt-out behavior of Nginx (`proxy_ssl_verify off`) and Envoy (`ACCEPT_UNTRUSTED`). A warning is logged at startup when disabled.

### Fixed
- Upstream send errors now log the full error cause chain instead of the opaque `client error (Connect)`, making TLS failures (missing SAN, untrusted root, cert/SNI mismatch) immediately diagnosable from logs without requiring a packet trace.
- Validator no longer hard-rejects `upstream_tls.verify_certificates=false`; it now emits a warning and allows startup to continue.
- Debian package and systemd unit: TLS certificate files must be owned `root:impulse` with mode `640` so the `impulse` service user can read them. Documentation and all installation examples corrected accordingly.

### Changed
- Packaging layout cleanup: Debian assets moved under `packaging/deb/` (`make-deb.sh`, systemd unit, default config).
- Installation and Docker docs updated to match current packaging paths and runtime behavior.
- Debian package version bumped to `0.1.1-beta`.

## [0.1.0-beta] - 2026-05-12

Initial release of Impulse HTTP/3 edge proxy and load balancer.

### Core Features

**Protocol Support**
- HTTP/3 termination using quiche (RFC 9114)
- QUIC transport (RFC 9000)
- HTTP/2 backend connectivity (RFC 9113)
- TLS 1.3 with certificate chain loading (RFC 8446)
- TLS bootstrap ingress for HTTP/1.1 + HTTP/2 compatibility and Alt-Svc upgrade flow

**Routing and Load Balancing**
- Upstream pool architecture with per-upstream configuration
- Route matching based on path prefix and host headers with longest-match selection
- Method-aware route matching support (`route.method`)
- Multiple load balancing algorithms: random, round-robin, consistent hashing (64 replicas), least-connections, latency-aware, sticky-cid
- Configurable load-balancing key sourcing (`load_balancing.key`)
- Backend weight configuration for weighted load balancing

**Health Management**
- Active health checking with HTTP probes
- Configurable interval, timeout, failure/success thresholds, and cooldown
- Automatic backend removal and recovery

**Connection Management**
- Connection ID-based routing for QUIC packets
- Prefix matching for Short packets with extended DCIDs
- Peer-based fallback for connection migration scenarios
- Version negotiation packet handling
- Proper 0-RTT handling to prevent crypto failures
- Config-driven graceful shutdown drain timeout

**Ingress and Resilience**
- Sharded ingress dispatch — per-worker UDP sockets for parallel packet processing
- Global route-queue cap with `503 + Retry-After` shedding under overload
- LB fallback, health probe, and streaming timeout semantics
- Panic handling hardened for worker and control-plane tasks

**Bootstrap (HTTP/1.1 + HTTP/2 TCP Path)**
- Dual ingress: QUIC/HTTP3 and TCP/TLS bootstrap for browser compatibility
- Bootstrap path enforces LB strategy and health-aware backend resolution (parity with QUIC path)
- Bootstrap route-resolution parity with QUIC path (host/path/method decision flow)
- Bootstrap path enforces QUIC request policy pipeline (method/path/header policies)
- Bootstrap path enforces downstream mTLS policy
- Bootstrap header sanitization and RFC 7239-compliant IPv6 normalization in `Forwarded`
- Bootstrap connection limiter and per-connection timeout guard
- Bootstrap backend request/response streaming support with deterministic unsupported-upgrade behavior for WebSocket

**Configuration**
- YAML-based configuration with comprehensive validation at startup
- Per-upstream load balancing strategy and embedded routing rules
- Packet shard ingress controls
- `performance.control_plane_threads` applied to startup runtime configuration
- Upstream TLS verification enforced by default; cleartext backends require explicit opt-in
- Downstream mTLS support via `listen.tls.client_auth.*`

**Observability**
- Structured JSON logging with standard and impulse-themed log levels
- Request/response metrics: total requests, successes, failures, timeouts
- Backend selection and health transition logging
- QUIC connection error classification and deduplication

**Control API**
- Bearer token authentication with constant-time comparison
- Metrics endpoint, health and ready probes
- TLS-enabled control-plane listener path support and startup hardening

**Operational**
- Debian package with systemd unit, system user/group, and config at `/etc/impulse/config.yaml`
- Docker packaging with compose bootstrap and operator smoke-test scripts
- CLI with `--config` flag
- Streaming request/response handling with bounded queues and hard body caps
- Deterministic cap-breach behavior via HTTP errors (`413`/`503`) under pressure
- Concurrent connection handling (10,000+ connections tested)
- Per-backend concurrency limiting (64 max in-flight requests)

### Known Limitations

1. No dynamic backend discovery (service discovery remains static config-driven).
2. No configuration hot reload (restart-based config apply model).
3. Project is pre-GA and still requires extended soak/failure-mode hardening for broad production rollout.

---

## Version Numbering

- **Major version** (X.0.0): Breaking changes to configuration or API
- **Minor version** (0.X.0): New features, non-breaking changes
- **Patch version** (0.0.X): Bug fixes, documentation updates

## Contributing

See [contributing guide](CONTRIBUTING.md) for development guidelines.

## License

GNU General Public License v3.0 (GPLv3) — see [LICENSE.md](LICENSE.md)
