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

Pin verification to an expected public signing key:

```sh
cargo run -- verify-signatures .agentk/runs/latest.jsonl --trusted-public-key <hex-public-key>
```

Pin verification to a public trusted-signer manifest:

```sh
cargo run -- verify-signatures .agentk/runs/latest.jsonl --trusted-key-manifest examples/trusted-signers.toml
```

Validate a trusted-signer manifest without printing keys:

```sh
cargo run -- trusted-signers-check --manifest examples/trusted-signers.toml
```

Inspect the latest flight log without printing raw input refs:

```sh
cargo run -- trace-inspect .agentk/runs/latest.jsonl
```

Replay the latest flight log without side effects:

```sh
cargo run -- replay .agentk/runs/latest.jsonl
```

Replay records synthetic `stub_output_sha256` refs for allowed model, tool, and network side-effect syscalls. It does not execute those syscalls or invent raw outputs.

Fork-replay the latest flight log against another policy:

```sh
cargo run -- fork-replay .agentk/runs/latest.jsonl --policy examples/policies/research-agent.toml
```

Fork-replay with changed hashed behavior outputs:

```sh
cargo run -- fork-replay-behavior .agentk/runs/latest.jsonl --behavior examples/replay-behavior-overrides.json
```

Check the prototype policy:

```sh
cargo run -- policy-check examples/agentk.policy.toml
```

Validate a secret-reference manifest without printing provider refs:

```sh
cargo run -- secret-refs-check --manifest examples/secret-refs.toml
```

Check whether secret references are available through the local env store without
printing refs:

```sh
AGENTK_DEMO_REF=present cargo run -- secret-refs-store-check --manifest examples/secret-refs.toml
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

Run the strict pre-push audit with a configured signing key file:

```sh
AGENTK_REQUIRE_SIGNING_KEY=1 AGENTK_SIGNING_KEY_FILE=../agentk-signing-key cargo run -- release-audit --strict
```

Contribution and release rules live in [CONTRIBUTING.md](CONTRIBUTING.md),
[docs/v0.1-target.md](docs/v0.1-target.md), and
[docs/release-checklist.md](docs/release-checklist.md). Accepted v0.1 limits
are tracked in
[docs/v0.1-limit-disposition.md](docs/v0.1-limit-disposition.md), and the
current pre-tag dry run is recorded in
[docs/v0.1-release-dry-run.md](docs/v0.1-release-dry-run.md).

Mediate a demo MCP-shaped tool request without executing it:

```sh
cargo run -- mcp-proxy --request examples/mcp-tool-request.json
```

Mediate one bounded MCP-shaped request over stdin:

```sh
cargo run -- mcp-stdio < examples/mcp-tool-request.json
```

Mediate newline-delimited MCP-shaped requests over bounded stdin:

```sh
cargo run -- mcp-lines < examples/mcp-tool-requests.jsonl
```

Run the minimal MCP JSON-RPC stdio server. The prototype accepts
newline-delimited JSON-RPC messages, rejects batches, enforces bounded request
ids, streams stdin with a per-line message size cap, and does not execute the
underlying tool. Tool listing and calls require a prior `initialize` request
with the supported protocol version followed by the `notifications/initialized`
notification. Before that lifecycle completes, only `initialize` and `ping`
requests receive method-specific handling:

```sh
cargo run -- mcp-server < examples/mcp-server-session.jsonl
```

Run AgentK as a stdio proxy in front of a downstream MCP server process. The
proxy forwards JSON-RPC to the child server only after mediating `tools/list`
descriptors, `tools/call` arguments, `resources/list` descriptors, and
`resources/read` requests, plus `prompts/list` descriptors and `prompts/get`
requests. It strips AgentK-only policy metadata before forwarding, starts the
child with only explicitly configured environment variables, validates proxy
configuration before spawn, records hash evidence for tool, resource, and
prompt responses, and refuses denied tool/resource/prompt actions before the
child sees them. MCP methods that do not yet have an AgentK policy contract are
rejected instead of being forwarded as generic passthrough. Downstream
responses are bounded by a configurable timeout so a hung child cannot stall
the proxy indefinitely:

```sh
cargo run -- mcp-proxy-stdio --server-id poisoned-demo --trace-out .agentk/runs/mcp-proxy-demo.jsonl --command sh --arg examples/mcp-poisoned-server.sh < examples/mcp-proxy-client-session.jsonl
cargo run -- trace-inspect .agentk/runs/mcp-proxy-demo.jsonl
```

Use `--allow-env NAME` to copy a named parent environment variable into the
cleared child environment. Repeat the flag for multiple variables.
Repeat `--arg` for each downstream argument; hyphen-prefixed child args are
accepted, for example `--arg -c`.
Use `--response-timeout-ms` to set the downstream response timeout; the default
is 30000 ms.

The subprocess proxy operator contract lives in
[docs/mcp-proxy.md](docs/mcp-proxy.md).

Run the MCP killer demo. The downstream server returns poisoned tool output
that tells the agent to exfiltrate a private marker and patch the repository.
AgentK records the poisoned output by hash, then blocks both dangerous
follow-up tool calls before the child server sees them:

```sh
cargo run -- mcp-killer-demo
cargo run -- trace-inspect .agentk/runs/mcp-killer-demo.jsonl
```

Run the before/after shim eval. It drives the same poisoned MCP flow through a
baseline passthrough and through AgentK, then prints a scorecard showing which
dangerous transitions executed versus which were blocked with evidence:

```sh
cargo run -- mcp-shim-eval
cargo run -- trace-inspect .agentk/runs/mcp-shim-eval-agentk.jsonl
```

The reviewer guide for this proof lives in
[docs/mcp-shim-eval.md](docs/mcp-shim-eval.md).

Run a second proxy transcript where the downstream MCP server returns a
poisoned JSON-RPC error body. AgentK returns only a sanitized error summary to
the client while preserving hash evidence in the trace:

```sh
cargo run -- mcp-proxy-stdio --server-id poisoned-error-demo --trace-out .agentk/runs/mcp-proxy-error-demo.jsonl --command sh --arg examples/mcp-poisoned-error-server.sh < examples/mcp-proxy-poisoned-error-session.jsonl
cargo run -- trace-inspect .agentk/runs/mcp-proxy-error-demo.jsonl
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
- target-only dummy secret registrations for local tests,
- redacted external secret reference records that require a configured store before minting handles by default,
- a metadata-only secret store registry that checks provider support and external reference availability without returning secret bytes,
- an env-backed local secret store presence adapter for `env` references,
- a versioned secret-reference manifest parser with provider-id validation for registering external refs without secret values,
- a redacted secret-reference manifest validation command,
- a redacted secret-reference store availability command,
- a hash-chained flight recorder,
- log verification,
- receipt and secret-handle signature verification with optional trusted-key pinning,
- a redacted public trusted-signer manifest for verifier pinning,
- redacted flight-log inspection for human review,
- deterministic side-effect-free replay,
- fork replay with policy comparison,
- an MCP proxy MVP that mediates `tool.invoke` without execution,
- MCP descriptor mediation that hashes untrusted tool metadata before model exposure,
- MCP response recording that hashes raw tool output instead of logging it,
- subprocess MCP resource mediation for `resources/list` and `resources/read`
  with hash-only evidence,
- subprocess MCP prompt mediation for `prompts/list` and `prompts/get` with
  hash-only evidence,
- subprocess MCP stderr suppression so child diagnostics cannot bypass the
  redacted JSON-RPC and trace-evidence path,
- an MCP killer demo where poisoned tool output tries to trigger secret
  exfiltration and an unsafe file patch, but both follow-up calls are blocked
  with inspectable trace evidence,
- a one-command MCP killer demo runner that writes a redacted trace without
  dumping the poisoned raw content into the review path,
- a before/after MCP shim eval that contrasts unsafe baseline passthrough with
  AgentK blocking and replayable evidence,
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

- close the remaining [v0.1 target](docs/v0.1-target.md) gaps,
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
- external secret references that require a configured store before minting handles by default,
- JSONL flight log hash chain,
- local log verification,
- redacted flight-log inspection that replaces raw input refs with hash evidence,
- trace inspection summaries that group blocked events by policy rule,
- deterministic replay that stubs side effects,
- fork replay with policy comparison,
- MCP-shaped tool mediation without execution,
- MCP descriptor and response hash evidence without raw descriptor/response logging,
- conservative MCP tool-output labels for recorded responses,
- tainted tool-input blocking at `tool.invoke` boundaries,
- MCP resource descriptor/read/response evidence with explicit read
  capabilities,
- MCP prompt descriptor/get/response evidence with explicit get capabilities,
- mixed subprocess MCP interoperability coverage across tools, resources,
  prompts, and notifications,
- public MCP interoperability transcript coverage that blocks poisoned follow-up
  network egress and unsafe patch attempts,
- downstream subprocess MCP notification-burst handling without raw payload
  reflection,
- downstream subprocess MCP notification-flood bounds without raw payload
  reflection,
- subprocess MCP stderr suppression for downstream diagnostics,
- subprocess MCP lifecycle error redaction for downstream `initialize` and
  `ping` failures,
- subprocess MCP initialize protocol guards before the proxy becomes ready,
- subprocess MCP `tools/list` error redaction before descriptors are exposed,
- subprocess MCP tool-shape guards for malformed `tools/list` and successful
  `tools/call` results,
- subprocess MCP bad-response redaction for malformed JSON and mismatched
  response ids,
- subprocess MCP response timeout handling for hung downstream servers,
- subprocess MCP transport-close handling for child exits and broken pipes,
- a runnable MCP killer demo that blocks poisoned-output exfiltration and
  unsafe patch attempts,
- a one-command `mcp-killer-demo` runner for reviewable demo traces,
- a one-command `mcp-shim-eval` scorecard for showing why the shim matters,
- a minimal MCP JSON-RPC stdio server,
- local key generation and signed key-rotation manifests,
- a local release audit that runs formatting, tests, clippy, readiness, replay,
  signature, signer-pinning, trusted-signer manifest, secret-handle,
  secret-reference validation, secret-store availability, MCP taint-flow,
  subprocess MCP boundaries, lifecycle/list redaction, initialize guards,
  tool/resource/prompt shape guards, bad-response redaction, response timeouts,
  transport-close checks, mixed interop, public interop transcripts,
  notification-burst/flood checks, config guards, no-passthrough checks, the MCP
  shim eval, inspect, and MCP server smoke checks.

Not implemented yet:

- production key storage and complete key lifecycle management,
- production MCP server transport,
- production secret storage,
- real sandboxing,
- eBPF/cgroup enforcement.

By default AgentK signs evidence with a static development key. Set `AGENTK_SIGNING_KEY_FILE` to a private key file created by `agentk keygen`, or set `AGENTK_SIGNING_KEY_HEX` to a 32-byte hex Ed25519 signing key for non-demo runs. Set `AGENTK_REQUIRE_SIGNING_KEY=1` in release gates to fail readiness if the configured signer falls back to the development key. On Unix, readiness also fails if the configured key file is readable by group/other users or if its parent directory is group/other writable. The CLI only prints the public key.

See [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md), [docs/key-lifecycle.md](docs/key-lifecycle.md), [docs/mcp-proxy.md](docs/mcp-proxy.md), and [docs/public-readiness.md](docs/public-readiness.md).

## Name

**AgentK**: short for Agent Kernel.

Small name. Sharp edges.
