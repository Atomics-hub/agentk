# AgentK

[![CI](https://github.com/Atomics-hub/agentk/actions/workflows/ci.yml/badge.svg)](https://github.com/Atomics-hub/agentk/actions/workflows/ci.yml)

AgentK is a tiny prototype of an **agent security kernel**.

Status: public prototype, not production-ready.

It is not another agent framework. It is the syscall boundary agent frameworks should run through:

```txt
model.call
context.read
memory.write
tool.describe
tool.invoke
tool.response
secret.open
network.send
file.patch
human.approve
agent.spawn
```

Every syscall carries provenance, taint labels, a policy decision, and a hash-chained flight recorder event.

## The Hook

AgentK treats prompt context like memory.

The **Context MMU** labels every context page:

```txt
trusted
untrusted
external
private
secret
poisoned-suspect
```

Then it blocks unsafe flows:

```txt
untrusted_webpage -> shell_exec
private_email     -> external_http_post
secret_fd         -> raw_model_context
```

The first demo shows a poisoned webpage trying to exfiltrate `~/.ssh/id_rsa`. AgentK blocks the raw secret read and the network send, then writes a tamper-evident JSONL flight log.

## Run It

```sh
cargo run
```

Verify the latest flight log:

```sh
cargo run -- verify .agentk/runs/latest.jsonl
```

Verify receipt and secret-handle signatures:

```sh
cargo run -- verify-signatures .agentk/runs/latest.jsonl
```

Inspect the latest flight log without printing raw input refs:

```sh
cargo run -- trace-inspect .agentk/runs/latest.jsonl
```

Replay the latest flight log without side effects:

```sh
cargo run -- replay .agentk/runs/latest.jsonl
```

Fork-replay the latest flight log against another policy:

```sh
cargo run -- fork-replay .agentk/runs/latest.jsonl --policy examples/policies/research-agent.toml
```

Check the prototype policy:

```sh
cargo run -- policy-check examples/agentk.policy.toml
```

Example profiles live in:

```txt
examples/policies/research-agent.toml
examples/policies/coding-agent.toml
examples/policies/browser-agent.toml
```

Run the public-readiness gate:

```sh
cargo run -- readiness
```

Run the full local release audit:

```sh
cargo run -- release-audit
```

Run the strict pre-push audit with a configured signing key:

```sh
AGENTK_SIGNING_KEY_HEX=$(cat ../agentk-signing-key) cargo run -- release-audit --strict
```

Contribution and release rules live in [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/release-checklist.md](docs/release-checklist.md).

Mediate a demo MCP-shaped tool request without executing it:

```sh
cargo run -- mcp-proxy --request examples/mcp-tool-request.json
```

Mediate one MCP-shaped request over stdin:

```sh
cargo run -- mcp-stdio < examples/mcp-tool-request.json
```

Mediate newline-delimited MCP-shaped requests over stdin:

```sh
cargo run -- mcp-lines < examples/mcp-tool-requests.jsonl
```

Run the minimal MCP JSON-RPC stdio server:

```sh
cargo run -- mcp-server < examples/mcp-server-session.jsonl
```

Print the active proof-signing public key:

```sh
cargo run -- signing-key
```

Generate a local signing key file outside git:

```sh
cargo run -- keygen --out ../agentk-signing-key
```

Rotate a local signing key and write a public signed manifest:

```sh
cargo run -- key-rotate --current ../agentk-signing-key --next-out ../agentk-signing-key-next --manifest ../agentk-rotation.json
```

Verify a public key-rotation manifest:

```sh
cargo run -- key-rotate-verify --manifest ../agentk-rotation.json
```

Emit the demo report as JSON:

```sh
cargo run -- demo --json
```

## Why This Exists

Most agent security tools either:

- sandbox code without understanding semantic data flow,
- trace LLM calls without enforcing anything,
- ask models to behave safely,
- or gate individual tools without preserving provenance.

AgentK's thesis:

> Autonomous actions need OS-style mediation: typed syscalls, capability receipts, taint-aware egress, secret handles, and replayable evidence.

## MVP Scope

This repo currently includes:

- a Rust CLI,
- a typed TOML policy AST,
- label propagation for demo syscalls,
- default-deny behavior for unknown syscalls,
- Ed25519-signed development capability receipts,
- opaque secret FD handles scoped to signed receipts,
- Ed25519-signed development secret handles with expiry and receipt binding,
- a hash-chained flight recorder,
- log verification,
- receipt and secret-handle signature verification,
- redacted flight-log inspection for human review,
- deterministic side-effect-free replay,
- fork replay with policy comparison,
- an MCP proxy MVP that mediates `tool.invoke` without execution,
- MCP descriptor mediation that hashes untrusted tool metadata before model exposure,
- MCP response recording that hashes raw tool output instead of logging it,
- stdin mediation for one MCP-shaped request,
- newline-delimited stdin mediation for repeated MCP-shaped requests,
- a minimal MCP JSON-RPC stdio server exposing `agentk.mediate`, `agentk.mediate_descriptor`, and `agentk.record_response`,
- signing key generation to a caller-chosen local file,
- signed key-rotation manifests that do not include private key material,
- key-rotation manifest verification,
- a one-command local release audit,
- a local public-readiness gate,
- and tests for tainted egress, capability receipts, secret redaction, secret-handle binding, replay, MCP mediation, descriptor/response hashing, key rotation, and unknown syscall denial.

Next obvious pieces:

- production key storage and operational key lifecycle,
- fuller MCP proxy/server compliance,
- filesystem diff capture,
- fork replay with changed model/tool behavior,
- eBPF/cgroup adapters for Linux resource accounting,
- and a visual trace viewer.

## Security Posture

This project is security-sensitive and intentionally conservative.

Implemented today:

- toy Context MMU labels,
- typed TOML policy validation,
- Ed25519-signed development capability receipts,
- opaque secret FD handle minting,
- Ed25519-signed development secret handles with expiry, scope, and receipt binding,
- JSONL flight log hash chain,
- local log verification,
- redacted flight-log inspection that replaces raw input refs with hash evidence,
- deterministic replay that stubs side effects,
- fork replay with policy comparison,
- MCP-shaped tool mediation without execution,
- MCP descriptor and response hash evidence without raw descriptor/response logging,
- conservative MCP tool-output labels for recorded responses,
- tainted tool-input blocking at `tool.invoke` boundaries,
- a minimal MCP JSON-RPC stdio server,
- local key generation and signed key-rotation manifests,
- a local release audit that runs formatting, tests, clippy, readiness, replay, signature, secret-handle, MCP taint-flow, inspect, and MCP server smoke checks.

Not implemented yet:

- production key storage and complete key lifecycle management,
- production MCP server transport,
- production secret storage,
- real sandboxing,
- eBPF/cgroup enforcement,
- fork replay with changed model/tool behavior.

By default AgentK signs evidence with a static development key. Set `AGENTK_SIGNING_KEY_HEX` to a 32-byte hex Ed25519 signing key for non-demo runs. The CLI only prints the public key.

See [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md), and [docs/public-readiness.md](docs/public-readiness.md).

## Name

**AgentK**: short for Agent Kernel.

Small name. Sharp edges.
