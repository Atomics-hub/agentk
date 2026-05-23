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
- [ ] Add production secret storage integration.

## Milestone 3: MCP Proxy

- [x] Add an MCP-shaped proxy command that mediates one `tool.invoke` request without execution.
- [x] Record MCP request argument hashes instead of raw arguments.
- [x] Expose AgentK as a minimal MCP JSON-RPC stdio server.
- [x] Mediate tool descriptors.
- [x] Record MCP response hashes.
- [x] Attach labels to tool outputs.
- [ ] Build a complete production MCP proxy/server transport.
- [x] Block tainted flows at tool-call boundaries.
- [x] Add release-audit smoke coverage for MCP taint flow.

## Milestone 4: Deterministic Replay

- [x] Re-run an event log without side effects.
- [x] Count stubbed model/tool/network side effects.
- [x] Fork replay with changed policy.
- [x] Add redacted flight-log inspect output for human review.
- [x] Record stub outputs for model/tool/network syscalls.
- [x] Fork replay with changed model/tool behavior.
- [x] Emit divergence reports.

## Milestone 4.5: Signed Evidence

- [x] Add Ed25519 development signatures for receipts and secret handles.
- [x] Add tamper-failure tests for signed proofs.
- [x] Add configurable signing key via `AGENTK_SIGNING_KEY_HEX`.
- [x] Add local key generation command.
- [x] Add signature verification CLI output.
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
