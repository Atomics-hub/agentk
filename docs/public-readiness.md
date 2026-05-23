# Public Readiness Checklist

AgentK should stay local until the pre-public checklist is boring. After the first public push,
keep the same checks in CI and protect the default branch.

## Pre-Public Repository Hygiene

- [ ] No git remote configured.
- [ ] No generated `.agentk/` logs tracked.
- [ ] No local paths, usernames, real URLs, or private traces in docs/tests.
- [ ] No API keys, tokens, certs, private keys, or `.env` files.
- [ ] `cargo run -- readiness` passes.
- [ ] Signing key file, if generated, lives outside the repo.
- [ ] Signing key file, if configured on Unix, is owner-only.
- [ ] Rotated signing key files, if generated, live outside the repo.
- [ ] License files present and intentional.
- [ ] `Cargo.lock` is present for reproducible application builds.
- [ ] README claims match implemented behavior.
- [ ] `docs/key-lifecycle.md` covers signing-key generation, custody, rotation, retirement, revocation, and incident response.

## Code Quality

- [ ] `cargo fmt` passes.
- [ ] `cargo test` passes.
- [ ] `cargo clippy` reviewed.
- [ ] `cargo run -- release-audit` passes.
- [ ] Errors do not leak sensitive syscall payloads by default.
- [ ] All policy deny paths have tests.
- [ ] All receipt/hash verification paths have tests.
- [ ] Secret FD tests prove raw secret material is not logged.
- [ ] Secret FD dummy registration is target-only and does not accept raw secret material.
- [ ] Secret FD tests prove external secret provider refs are not logged.
- [ ] Secret FD tests prove external secret provider refs are redacted from broker debug output.
- [ ] Secret store adapter tests prove unavailable external refs do not mint secret handles.
- [ ] Env secret store tests prove env values and references are not logged.
- [ ] Flight-log inspect tests prove raw input refs are redacted.
- [ ] Replay tests prove allowed model/tool/network side effects get synthetic stub output refs.
- [ ] Behavior fork replay tests prove raw output overrides are rejected.
- [ ] MCP proxy tests prove tools are mediated without execution.
- [ ] MCP descriptor/response tests prove raw descriptor and response content are not logged into event inputs.
- [ ] Receipt and handle signatures verify, and tampered proofs fail.
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
AGENTK_REQUIRE_SIGNING_KEY=1 AGENTK_SIGNING_KEY_FILE=../agentk-signing-key cargo run -- release-audit --strict
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features
cargo run -- readiness
cargo run -- signing-key
cargo run -- verify-signatures .agentk/runs/latest.jsonl
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
