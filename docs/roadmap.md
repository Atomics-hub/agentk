# Roadmap

AgentK should advance in small, reviewable steps. Security claims only move from planned to implemented when they have tests.

The release-shaped v0.1 target is tracked in
[`docs/v0.1-target.md`](v0.1-target.md). That document is the decision frame for
whether the project is moving toward a credible MCP security shim instead of
accumulating unrelated prototype features.

## Milestone 0: Local Prototype

Status: in progress.

- [x] Rust CLI scaffold
- [x] Context labels
- [x] Hard deny for secret/private network egress
- [x] Hash-chained flight log
- [x] Flight log verifier
- [x] Security policy and threat model
- [x] Public-readiness checklist
- [x] Parsed TOML policy file
- [x] Local readiness gate

## Milestone 1: Policy Kernel

- [x] Replace string `when` expressions with a typed policy AST.
- [x] Add full rule tests for every allow and deny path.
- [x] Add deny-by-default behavior for unknown syscalls.
- [x] Add explicit label propagation tests.
- [x] Add policy examples for coding-agent, browser-agent, and research-agent profiles.

## Milestone 2: Secret FDs

- [x] Implement opaque secret handles.
- [x] Prevent raw secret material from being serialized into flight logs.
- [x] Add tests proving raw secret bytes never appear in flight logs.
- [x] Add Ed25519 development signatures for secret handles.
- [x] Add expiry, scope, and receipt binding.
- [x] Add release-audit smoke coverage for brokered secret handles.
- [x] Replace raw dummy secret registration with target-only broker registration.
- [x] Add external secret reference registration without logging provider refs.
- [x] Retain external secret reference metadata behind redacted broker records.
- [x] Add a metadata-only secret store adapter boundary for external refs.
- [x] Add an env-backed local secret store presence adapter.
- [x] Add a secret-reference manifest parser for external refs.
- [x] Add redacted CLI validation for secret-reference manifests.
- [x] Require a configured store before external refs mint handles by default.
- [x] Scope secret store adapters to explicitly supported providers.
- [x] Allow multiple provider-scoped secret stores to coexist.
- [x] Validate secret-reference provider ids before registration.
- [x] Add release-audit smoke coverage for secret-reference validation redaction.
- [x] Add redacted secret-store availability reporting for secret-reference manifests.
- [ ] Add production secret storage integration.

## Milestone 3: MCP Proxy

- [x] Add an MCP-shaped proxy command that mediates one `tool.invoke` request without execution.
- [x] Record MCP request argument hashes instead of raw arguments.
- [x] Expose AgentK as a minimal MCP JSON-RPC stdio server.
- [x] Mediate tool descriptors.
- [x] Record MCP response hashes.
- [x] Attach labels to tool outputs.
- [x] Reject oversized MCP JSON-RPC lines and invalid request ids without reflecting raw payloads.
- [x] Stream MCP JSON-RPC stdin with bounded per-line reads.
- [x] Bound `mcp-stdio` and `mcp-lines` stdin handling.
- [x] Enforce MCP initialize-before-tool lifecycle ordering.
- [x] Validate MCP `initialize` protocol version before exposing tools.
- [x] Require the MCP `notifications/initialized` lifecycle signal before exposing tools.
- [x] Gate pre-ready MCP methods without exposing the method surface.
- [x] Add an in-memory MCP proxy harness for end-to-end descriptor, invoke, response, and tainted follow-up mediation.
- [x] Add a JSON-RPC-facing in-memory MCP proxy harness for list/call mediation.
- [x] Add a subprocess stdio MCP proxy path that mediates real client/server JSON-RPC traffic.
- [x] Add a poisoned subprocess MCP demo transcript and release-audit smoke coverage.
- [x] Add optional subprocess proxy trace output for `trace-inspect` review.
- [x] Strip AgentK-only metadata from subprocess proxy forwarded traffic.
- [x] Return sanitized JSON-RPC errors for malformed downstream subprocess responses.
- [x] Add release-audit smoke coverage for malformed and mismatched downstream responses.
- [x] Drop malformed downstream tool descriptors with hash-only evidence.
- [x] Return sanitized JSON-RPC errors when downstream subprocess transport closes mid-session.
- [x] Add release-audit smoke coverage for downstream subprocess transport close.
- [x] Bound downstream subprocess response waits with a configurable timeout.
- [x] Validate downstream subprocess initialize protocol before exposing tools.
- [x] Add release-audit smoke coverage for downstream initialize protocol rejection.
- [x] Validate downstream subprocess `tools/list` shape before exposing tools.
- [x] Validate downstream subprocess `tools/call` result shape before recording responses.
- [x] Add release-audit smoke coverage for downstream tool result shape guards.
- [x] Sanitize downstream subprocess lifecycle error bodies before returning them.
- [x] Sanitize downstream subprocess `tools/list` error bodies before returning them.
- [x] Sanitize downstream subprocess `tools/call` error bodies before returning them.
- [x] Add a poisoned downstream error-body demo transcript and release-audit smoke coverage.
- [x] Add release-audit smoke coverage for subprocess MCP lifecycle/list redaction.
- [x] Spawn downstream subprocess MCP servers with an explicit environment boundary.
- [x] Add CLI allowlisting for downstream subprocess MCP environment variables.
- [x] Suppress downstream subprocess MCP stderr so diagnostics cannot bypass redaction.
- [x] Accept hyphen-prefixed downstream subprocess MCP command arguments.
- [x] Validate subprocess MCP proxy config before spawning the child.
- [x] Add release-audit smoke coverage for subprocess MCP proxy config guards.
- [x] Add release-audit smoke coverage for invalid AgentK metadata redaction.
- [x] Hash client-provided AgentK intent metadata in subprocess MCP evidence.
- [x] Reject empty subprocess MCP tool, resource, and prompt identifiers before
      forwarding.
- [x] Surface compact denial summaries in blocked MCP tool/resource/prompt
      responses.
- [x] Add CLI coverage for the `mcp-proxy-stdio --trace-out` operator path.
- [x] Add an operator contract for subprocess MCP proxy boundaries.
- [x] Default-deny unsupported subprocess MCP request methods instead of generic passthrough.
- [x] Add release-audit smoke coverage for unsupported subprocess MCP no-passthrough.
- [x] Add release-audit smoke coverage for unsupported MCP resource subscription no-passthrough.
- [x] Mediate downstream subprocess MCP `resources/list` and `resources/read` with hash-only evidence.
- [x] Add release-audit smoke coverage for subprocess MCP resource mediation.
- [x] Mediate downstream subprocess MCP `prompts/list` and `prompts/get` with hash-only evidence.
- [x] Add release-audit smoke coverage for subprocess MCP prompt mediation.
- [x] Add release-audit smoke coverage for mixed subprocess MCP interoperability.
- [x] Add public MCP interoperability transcript fixtures backed by release-audit.
- [x] Add release-audit smoke coverage for pre-ready subprocess MCP notification no-passthrough.
- [x] Add release-audit smoke coverage for duplicate initialized notification no-passthrough.
- [x] Add release-audit smoke coverage for downstream notification bursts.
- [x] Add release-audit smoke coverage for bounded downstream notification floods.
- [x] Add prompt error redaction and malformed prompt result coverage for the subprocess MCP proxy.
- [x] Add release-audit smoke coverage for malformed resource and prompt result shape guards.
- [x] Add a killer MCP demo where poisoned output tries exfiltration and an unsafe patch, then AgentK blocks both follow-up calls with trace evidence.
- [x] Add a one-command MCP killer demo runner for reviewable redacted traces.
- [x] Add a before/after MCP shim eval scorecard comparing baseline passthrough with AgentK mediation.
- [x] Add redacted subprocess MCP session summaries for gateway observability.
- [ ] Build a complete production MCP proxy/server transport.
- [x] Block tainted flows at tool-call boundaries.
- [x] Add release-audit smoke coverage for MCP taint flow.

## Milestone 4: Deterministic Replay

- [x] Re-run an event log without side effects.
- [x] Count stubbed model/tool/network side effects.
- [x] Fork replay with changed policy.
- [x] Add redacted flight-log inspect output for human review.
- [x] Include policy reasons and missing capabilities in trace-inspect summaries.
- [x] Summarize blocked policy rules in trace-inspect output.
- [x] Summarize syscall and evidence-ref counts in trace-inspect output.
- [x] Record stub outputs for model/tool/network syscalls.
- [x] Summarize blocked policy rules in deterministic replay output.
- [x] Summarize decision transitions in fork replay output.
- [x] Surface blocked MCP denial details directly at the response boundary.
- [x] Fork replay with changed model/tool behavior.
- [x] Emit divergence reports.

## Milestone 4.5: Signed Evidence

- [x] Add Ed25519 development signatures for receipts and secret handles.
- [x] Add tamper-failure tests for signed proofs.
- [x] Add configurable signing key via `AGENTK_SIGNING_KEY_HEX`.
- [x] Add signing-key file source for release gates.
- [x] Validate signing-key file permissions in readiness.
- [x] Validate signing-key parent directory custody in readiness.
- [x] Add signing-key lifecycle runbook and readiness coverage.
- [x] Add release gate for requiring a configured signing key.
- [x] Add local key generation command.
- [x] Add signature verification CLI output.
- [x] Add trusted public-key pinning for signature verification.
- [x] Summarize signature signer fingerprints without printing raw keys.
- [x] Add a public trusted-signer manifest for verifier pinning.
- [x] Add signed key rotation manifest.
- [x] Add key rotation manifest verification.
- [ ] Add production key storage and operational lifecycle.
- [ ] Remove static development key before production use.

## Milestone 5: Public Release Gate

- [x] No git remote until explicit release approval.
- [x] `cargo fmt --check` passes.
- [x] `cargo test` passes.
- [x] `cargo clippy --all-targets --all-features` passes.
- [x] `cargo run -- readiness` passes.
- [x] Add one-command local release audit.
- [x] Manual tracked-file review completed.
- [x] README claims match implemented behavior.
- [x] Security disclosure instructions are real.
- [x] GitHub private vulnerability reporting enabled before announcement.

## Milestone 5.5: Maintainer Guardrails

- [x] Add CI release-audit workflow.
- [x] Protect the default branch with the CI `audit` check.
- [x] Add contributor guidelines for security-sensitive changes.
- [x] Add a signed release checklist for tagged versions.
- [x] Add an explicit remote-approval signal for strict release gates.

## Milestone 6: v0.1 Release Shape

- [x] Add an explicit v0.1 target that defines release-ready behavior,
      accepted limits, release blockers, and the autonomous work order.
- [x] Verify the before/after MCP shim eval remains the clearest public proof.
- [x] Close or explicitly defer each accepted v0.1 limit before tagging.
- [x] Run a signed release checklist dry run against current master.
- [x] Prepare v0.1 release notes draft with accepted limits.
- [ ] Run the signed release checklist against the final v0.1 commit.

## Milestone 7: Team Product Sidecar

The post-v0.1 productization plan lives in
[`docs/productization-plan.md`](productization-plan.md). The product wedge is an
agent action firewall and flight recorder for MCP/tool-call governance. The
gateway is the delivery surface, not a pivot into a generic AI gateway.

- [x] Generate a team sidecar starter bundle for MCP client onboarding.
- [x] Add a sidecar preflight checker for generated bundles.
- [x] Add a CLI audit inbox for pending approvals and allowed side effects.
- [x] Package a no-credential GitHub/Postgres/Slack/filesystem safe-agent demo.
- [x] Add a package-local safe-agent demo launcher for team onboarding.
- [x] Wire packaged demo traces into dashboard and store onboarding.
- [x] Add config-driven sidecar launch for generated bundles.
- [x] Add a local audit and approval review surface.
- [x] Add local multi-user permissions for approval review.
- [x] Add a local static HTML dashboard for approvals and audit review.
- [x] Validate Claude/Codex/Cursor sidecar client snippets in sidecar checks.
- [x] Add packaged sidecar launcher/client snippets for local deployment.
- [x] Add a package-local sidecar validator launcher for deployment checks.
- [x] Add a durable store export and Postgres schema contract.
- [x] Add dashboard server UI for approvals and audit review.
- [x] Add browser approve/deny controls to the served dashboard UI.
- [x] Add deploy templates for packaged sidecar operation.
- [x] Add MCP HTTP gateway service templates to packaged deployments.
- [x] Preflight packaged dashboard service starts with the package validator.
- [x] Add a versioned package manifest for installable sidecar inventory.
- [x] Add package self-checks for copied/deployed sidecar artifacts.
- [x] Validate deploy-template hardening in package self-checks.
- [x] Validate Dockerfile non-root runtime hardening in package self-checks.
- [x] Add a packaged team approval/audit handoff checker for dashboard and durable store review.
- [x] Add a packaged operator handoff report for one-command local/team archive evidence.
- [x] Add a packaged sidecar doctor for install/update support and remediation reports.
- [x] Preflight packaged sidecar launchers with the package validator.
- [x] Preflight packaged demo/dashboard/store workflow launchers with the package validator.
- [x] Add redacted dashboard readiness probes for service supervisors.
- [x] Add live durable team audit and approval storage.
- [x] Validate live durable team stores with store-check.
- [x] Add reviewer-scoped dashboard API reads backed by team permissions.
- [x] Add role-aware served dashboard views backed by reviewer scopes.
- [x] Add requester-scoped dashboard views backed by signed agent identity.
- [x] Surface redacted trace-inspect evidence in approval dashboards.
- [x] Add normalized evidence summary tables to durable and Postgres audit stores.
- [x] Add a credential-free durable notification outbox for approval events.
- [x] Add local Slack/GitHub/email delivery bridges for approval notifications.
- [x] Add a bounded TCP JSON-RPC sidecar gateway for internal adapters.
- [x] Add explicit TCP gateway concurrency bounds for service operation.
- [x] Add a subprocess MCP client message cap for runaway-session backpressure.
- [x] Add graceful downstream subprocess shutdown on client EOF.
- [x] Add a bounded localhost Streamable HTTP POST sidecar gateway for local adapters.
- [x] Add local HTTP gateway health/readiness probes for service supervisors.
- [x] Add Streamable HTTP protocol-version header enforcement.
- [x] Add configurable MCP HTTP active-session bounds.
- [x] Add configurable MCP HTTP idle-session cleanup.
- [x] Add configurable MCP HTTP request body bounds.
- [x] Add browser CORS preflight handling for local MCP HTTP adapters.
- [x] Add env-configured MCP HTTP allowed browser origins.
- [x] Forward packaged MCP HTTP launcher arguments for operator overrides.
- [x] Add redacted MCP HTTP allowed-origin readiness metadata.
- [x] Package a stable sidecar-check launcher for team bundle validation.
- [x] Require explicit opt-in for non-loopback MCP HTTP binds.
- [x] Require HTTP auth for non-loopback MCP HTTP binds.
- [x] Add browser safety headers to dashboard and MCP HTTP responses.
- [x] Add accepted-stream I/O timeouts to the MCP HTTP gateway.
- [x] Add configurable MCP HTTP header byte bounds.
- [x] Drain active MCP HTTP sessions on bounded gateway shutdown.
- [x] Add redacted MCP HTTP gateway metrics for service supervisors.
- [x] Add cumulative MCP HTTP request and session lifecycle counters.
- [x] Require auth for MCP HTTP readiness and metrics when auth is configured.
- [x] Use constant-time checks for MCP HTTP bearer tokens.
- [x] Reject malformed MCP HTTP request/header lines and framing.
- [x] Reject ambiguous MCP HTTP control headers and invalid JSON media types.
- [x] Reject malformed MCP HTTP session ids before session lookup.
- [x] Enforce MCP HTTP Host header requirements for HTTP/1.1 requests.
- [x] Reject incomplete MCP HTTP header blocks and fixed-length bodies.
- [x] Reject unexpected bodies on non-POST MCP HTTP and operational requests.
- [x] Validate MCP HTTP CORS preflight requested methods and headers.
- [x] Require allowed Origin headers on MCP HTTP CORS preflights.
- [x] Count MCP HTTP CORS preflight validation rejections in readiness and metrics.
- [x] Reject query strings on the MCP HTTP endpoint path.
- [x] Validate MCP HTTP endpoint configuration before bind.
- [x] Reject non-UTF-8 MCP HTTP request and header lines as bad framing.
- [x] Require CRLF MCP HTTP request and header line framing.
- [x] Require strict MCP HTTP request-line spacing and header-name tokens.
- [x] Reject MCP HTTP header value controls and all transfer-encoding headers.
- [x] Validate MCP HTTP allowed-origin syntax and local-origin ports.
- [x] Fail closed and count unsupported MCP HTTP SSE GET requests.
- [x] Validate MCP/dashboard HTTP Host and origin authority syntax.
- [x] Reject MCP/dashboard HTTP expectation and upgrade headers.
- [x] Reject MCP/dashboard HTTP hop-by-hop connection negotiation.
- [x] Reject MCP/dashboard HTTP request-target fragments.
- [x] Reject MCP/dashboard HTTP operational probe query strings.
- [x] Reject MCP/dashboard HTTP non-decimal Content-Length values.
- [x] Omit bodies from MCP HTTP HEAD responses.
- [x] Reject dashboard operational probe query strings.
- [x] Reject MCP/dashboard HTTP network-path request targets.
- [x] Reject unexpected dashboard HTTP request bodies.
- [x] Require JSON media types on dashboard write requests.
- [x] Reject ambiguous dashboard admin token carriers.
- [x] Reject ambiguous dashboard reviewer token carriers.
- [x] Reject HTTP proxy authentication headers.
- [x] Reject duplicate dashboard token carriers.
- [x] Reject duplicate dashboard decision Content-Type headers.
- [x] Reject duplicate dashboard decision JSON keys.
- [x] Reject unsupported dashboard decision JSON keys.
- [x] Reject duplicate dashboard scope query selectors.
- [x] Reject mixed dashboard scope query selectors.
- [x] Reject unsupported dashboard review query parameters.
- [x] Reject unscoped dashboard reviewer-token carriers.
- [x] Reject dashboard decision endpoint query strings.
- [x] Require authenticated opt-in for non-loopback dashboard binds.
- [x] Gate non-loopback dashboard reads with admin auth.
- [x] Add accepted-stream I/O timeouts to the dashboard server.
- [x] Add redacted dashboard metrics gauges for service supervisors.
- [x] Add tunable dashboard HTTP body/header caps with sanitized 413/431 responses.
- [x] Enforce MCP/dashboard HTTP header byte caps during line reads.
- [x] Use per-session runtime locks for MCP HTTP sessions.
- [x] Count MCP HTTP stream framing rejections in readiness and metrics.
- [x] Require valid Host authority on all dashboard and MCP HTTP requests.
- [x] Reject MCP HTTP request bodies before unknown-route fallback.
- [x] Require valid session ids on unsupported MCP HTTP SSE GET requests.
- [x] Require existing sessions on unsupported MCP HTTP SSE GET requests.
- [x] Require explicit opt-in for MCP HTTP `Origin: null` requests.
- [x] Require local Host authority for built-in MCP HTTP browser origins.
- [x] Reject invalid bracketed MCP/dashboard HTTP authority literals.
- [x] Reject invalid DNS-label MCP/dashboard HTTP authority names.
- [x] Reject untrusted forwarded MCP/dashboard HTTP proxy metadata.
- [x] Reject ambient MCP/dashboard HTTP cookie credential headers.
- [x] Reject MCP/dashboard HTTP method override headers.
- [x] Reject MCP/dashboard HTTP proxy and trace methods.
- [x] Reject MCP HTTP Private Network Access CORS preflights.
- [x] Reject MCP/dashboard HTTP request content encodings.
- [x] Reject MCP/dashboard HTTP WebSocket handshake headers.
- [x] Preflight packaged AgentK binary resolution before launcher work.
- [x] Embed redacted trace-inspect evidence in the safe-agent demo report.
- [ ] Continue bounded local MCP gateway transport hardening.
