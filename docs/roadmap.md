# Roadmap

AgentK should advance in small, reviewable steps. Security claims only move from planned to implemented when they have tests.

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
- [x] Drop malformed downstream tool descriptors with hash-only evidence.
- [x] Return sanitized JSON-RPC errors when downstream subprocess transport closes mid-session.
- [x] Add release-audit smoke coverage for downstream subprocess transport close.
- [x] Bound downstream subprocess response waits with a configurable timeout.
- [x] Validate downstream subprocess initialize protocol before exposing tools.
- [x] Validate downstream subprocess `tools/list` shape before exposing tools.
- [x] Validate downstream subprocess `tools/call` result shape before recording responses.
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
- [x] Add an operator contract for subprocess MCP proxy boundaries.
- [x] Default-deny unsupported subprocess MCP request methods instead of generic passthrough.
- [x] Add release-audit smoke coverage for unsupported subprocess MCP no-passthrough.
- [x] Mediate downstream subprocess MCP `resources/list` and `resources/read` with hash-only evidence.
- [x] Add release-audit smoke coverage for subprocess MCP resource mediation.
- [x] Mediate downstream subprocess MCP `prompts/list` and `prompts/get` with hash-only evidence.
- [x] Add release-audit smoke coverage for subprocess MCP prompt mediation.
- [x] Add prompt error redaction and malformed prompt result coverage for the subprocess MCP proxy.
- [x] Add a killer MCP demo where poisoned output tries exfiltration and an unsafe patch, then AgentK blocks both follow-up calls with trace evidence.
- [x] Add a one-command MCP killer demo runner for reviewable redacted traces.
- [x] Add a before/after MCP shim eval scorecard comparing baseline passthrough with AgentK mediation.
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
- [x] Record stub outputs for model/tool/network syscalls.
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
