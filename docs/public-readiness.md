# Public Readiness Checklist

AgentK should stay local until this checklist is boring.

## Repository Hygiene

- [ ] No git remote configured.
- [ ] No generated `.agentk/` logs tracked.
- [ ] No local paths, usernames, real URLs, or private traces in docs/tests.
- [ ] No API keys, tokens, certs, private keys, or `.env` files.
- [ ] `cargo run -- readiness` passes.
- [ ] Signing key file, if generated, lives outside the repo.
- [ ] Rotated signing key files, if generated, live outside the repo.
- [ ] License files present and intentional.
- [ ] `Cargo.lock` is present for reproducible application builds.
- [ ] README claims match implemented behavior.

## Code Quality

- [ ] `cargo fmt` passes.
- [ ] `cargo test` passes.
- [ ] `cargo clippy` reviewed.
- [ ] Errors do not leak sensitive syscall payloads by default.
- [ ] All policy deny paths have tests.
- [ ] All receipt/hash verification paths have tests.
- [ ] Secret FD tests prove raw secret material is not logged.
- [ ] Flight-log inspect tests prove raw input refs are redacted.
- [ ] MCP proxy tests prove tools are mediated without execution.
- [ ] MCP descriptor/response tests prove raw descriptor and response content are not logged into event inputs.
- [ ] Receipt and handle signatures verify, and tampered proofs fail.
- [ ] Key rotation tests prove private key bytes are not written into manifests.

## Security Claims

- [ ] Each feature is marked implemented, planned, or experimental.
- [ ] Threat model is current.
- [ ] `SECURITY.md` has real disclosure instructions.
- [ ] Examples use `example.invalid` or dummy paths only.
- [ ] Static development signing key is either removed or clearly documented as non-production.
- [ ] No claim of production readiness.

## Release Gate

Before first public push:

```txt
git remote -v
git status --short
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features
cargo run -- readiness
cargo run -- signing-key
cargo run -- verify-signatures .agentk/runs/latest.jsonl
cargo run -- trace-inspect .agentk/runs/latest.jsonl
cargo run -- fork-replay .agentk/runs/latest.jsonl --policy examples/policies/research-agent.toml
cargo run -- mcp-server < examples/mcp-server-session.jsonl
```

Then manually inspect every tracked file.
