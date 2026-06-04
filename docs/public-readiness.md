# Public Readiness Checklist

AgentK should stay local until the pre-public checklist is boring. After the first public push,
keep the same checks in CI and protect the default branch.

## Pre-Public Repository Hygiene

- [ ] No git remote configured before first public push, or
      `AGENTK_RELEASE_REMOTE_APPROVED=1` is set only after explicit release
      approval and branch-protection review.
- [ ] No generated `.agentk/` logs tracked.
- [ ] No local paths, usernames, real URLs, or private traces in docs/tests.
- [ ] No API keys, tokens, certs, private keys, or `.env` files.
- [ ] `cargo run -- readiness` passes.
- [ ] Signing key file, if generated, lives outside the repo.
- [ ] Signing key file, if configured on Unix, is owner-only.
- [ ] Signing key parent directory, if configured on Unix, blocks group/other writes.
- [ ] Rotated signing key files, if generated, live outside the repo.
- [ ] License files present and intentional.
- [ ] `Cargo.lock` is present for reproducible application builds.
- [ ] README claims match implemented behavior.
- [ ] `docs/productization-plan.md` distinguishes ready behavior from accepted
      alpha limits and post-alpha work.
- [ ] Historical v0.1 target/limit/dry-run docs are treated as archived
      evidence, not the current release source of truth.
- [ ] `docs/v0.2-alpha-release-notes.md`, or the release-specific successor
      notes file, lists implemented behavior, accepted limits, and final
      evidence without overclaiming production readiness.
- [ ] `docs/key-lifecycle.md` covers signing-key generation, custody, rotation, retirement, revocation, and incident response.

## Code Quality

- [ ] `cargo fmt` passes.
- [ ] `cargo test` passes.
- [ ] `cargo clippy` reviewed.
- [ ] `cargo run -- release-audit` passes.
- [ ] `cargo run --locked -- release-status --json` reports the shipped alpha
      surfaces, accepted limits, final blockers, and verification gates.
- [ ] `cargo run --locked -- release-candidate-smoke --json` passes and writes
      package, archive, install receipt, release manifest, demo trace, dashboard,
      durable store, notification payload, and deploy-template artifacts.
- [ ] `cargo run --locked -- sidecar-package-http-handoff-check --root
      dist/agentk-sidecar --json` passes and the reviewer handoff includes
      `clients/http-sse-handoff.md` with bounded local HTTP/SSE alpha language.
- [ ] `cargo run --locked -- sidecar-package-team-handoff-check --root
      dist/agentk-sidecar --json` passes and the reviewer handoff includes
      `clients/team-audit-dashboard-handoff.md` with local/team approval,
      dashboard, durable store, and not-hosted-SaaS alpha language.
- [ ] `agentk sidecar-package-release-manifest` output is attached to the
      release handoff or deployment ticket.
- [ ] Errors do not leak sensitive syscall payloads by default.
- [ ] All policy deny paths have tests.
- [ ] All receipt/hash verification paths have tests.
- [ ] Secret FD tests prove raw secret material is not logged.
- [ ] Secret FD dummy registration is target-only and does not accept raw secret material.
- [ ] Secret FD tests prove external secret provider refs are not logged.
- [ ] Secret FD tests prove external secret provider refs are redacted from broker debug output.
- [ ] Secret FD tests prove external refs without a configured store do not mint handles by default.
- [ ] Secret store adapter tests prove unsupported providers are not looked up.
- [ ] Secret store adapter tests prove multiple provider-scoped stores can coexist.
- [ ] Secret store adapter tests prove unavailable external refs do not mint secret handles.
- [ ] Secret store availability reports expose only counts and no provider refs.
- [ ] Env secret store tests prove env values and references are not logged.
- [ ] Secret reference manifest tests prove invalid provider ids are rejected without logging refs.
- [ ] Release audit checks secret-reference validation rejects invalid refs without logging them.
- [ ] Release audit checks secret-store availability reporting does not log refs.
- [ ] Secret reference manifest tests prove provider refs are redacted from debug output.
- [ ] Secret reference manifest CLI reports only version and count.
- [ ] Flight-log inspect tests prove raw input refs are redacted.
- [ ] Replay tests prove allowed model/tool/network side effects get synthetic stub output refs.
- [ ] Behavior fork replay tests prove raw output overrides are rejected.
- [ ] MCP proxy tests prove tools are mediated without execution.
- [ ] MCP descriptor/response tests prove raw descriptor and response content are not logged into event inputs.
- [ ] Receipt and handle signatures verify, and tampered proofs fail.
- [ ] Signature verification can pin receipts and handles to trusted public keys.
- [ ] Trusted-signer manifest tests prove verifier pinning works without printing keys.
- [ ] Key rotation tests prove private key bytes are not written into manifests.

## Security Claims

- [ ] Each feature is marked implemented, planned, or experimental.
- [ ] Threat model is current.
- [ ] GitHub private vulnerability reporting is enabled before public announcement.
- [ ] `SECURITY.md` has disclosure instructions and a supported-version policy.
- [ ] Examples use `example.invalid` or dummy paths only.
- [ ] Static development signing key is either removed or clearly documented as non-production.
- [ ] No claim of production readiness.
- [ ] `CONTRIBUTING.md` describes security-sensitive change rules.
- [ ] `docs/release-checklist.md` describes signed release steps.

## Public Repository Controls

- [x] CI runs `cargo run --locked -- release-audit` on pushes and pull requests.
- [x] Default branch requires the CI `audit` check before merging.
- [x] Default branch blocks force pushes and deletion.
- [x] Secret scanning and push protection are enabled.
- [x] Dependabot vulnerability alerts and security updates are enabled.
- [x] GitHub private vulnerability reporting is enabled.

## Release Gate

Before first public push:

```txt
git remote -v
git status --short
AGENTK_REQUIRE_SIGNING_KEY=1 \
AGENTK_RELEASE_REMOTE_APPROVED=1 \
AGENTK_SIGNING_KEY_FILE=../agentk-signing-key \
cargo run -- release-audit --strict
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features
cargo run --locked -- release-status --json
cargo run --locked -- release-candidate-smoke --json
cargo run --locked -- sidecar-package-http-handoff-check --root dist/agentk-sidecar --json
cargo run -- readiness
cargo run -- signing-key
cargo run -- verify-signatures .agentk/runs/latest.jsonl --trusted-public-key <hex-public-key>
cargo run -- trusted-signers-check --manifest examples/trusted-signers.toml
cargo run -- trace-inspect .agentk/runs/latest.jsonl
cargo run -- fork-replay .agentk/runs/latest.jsonl --policy examples/policies/research-agent.toml
cargo run -- fork-replay-behavior .agentk/runs/latest.jsonl --behavior examples/replay-behavior-overrides.json
cargo run -- mcp-server < examples/mcp-server-session.jsonl
```

Then manually inspect every tracked file.

After first public push:

```txt
git status --short
cargo run -- release-audit
gh repo view Atomics-hub/agentk --json visibility,url,defaultBranchRef
gh api repos/Atomics-hub/agentk/private-vulnerability-reporting --jq '.enabled'
gh api repos/Atomics-hub/agentk/automated-security-fixes --jq '.enabled'
gh api repos/Atomics-hub/agentk --jq '.security_and_analysis'
```
