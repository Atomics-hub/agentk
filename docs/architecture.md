# AgentK Architecture

AgentK is a user-space kernel for agent actions.

The goal is to make agent behavior auditable and enforceable before side effects happen.

## Core Concepts

### Agent Syscalls

Agent frameworks can plan however they want. When they act, they cross AgentK:

```txt
context.read
model.call
memory.read
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

Each syscall has:

- kind,
- target,
- intent,
- inputs,
- labels,
- policy decision,
- optional capability receipt,
- optional secret handle,
- previous event hash,
- event hash.

### Context MMU

The Context MMU treats prompt inputs as memory pages with labels.

Example labels:

```txt
trusted
untrusted
external
private
secret
poisoned-suspect
```

Policies are flow rules over labels and sinks:

```txt
deny secret -> network.send
deny private -> external_http_post
deny untrusted -> shell_exec
deny poisoned-suspect -> tool.invoke(high-risk)
```

The prototype policy is a typed TOML AST with ordered rules. Rules can match:

```txt
syscalls
labels_any
labels_all
labels_none
capability present/missing
```

If no rule matches, `default-deny` fires.

### Capability Receipts

Allowed actions get one-shot receipts.

Receipts bind:

```txt
agent_id
syscall
target
scope
expiry
previous_event_hash
```

The current prototype hashes these fields and signs the proof hash with an Ed25519 development key. A production runtime must replace that static development key with real key management.

Signer source:

```txt
AGENTK_SIGNING_KEY_HEX set   -> environment signing key
AGENTK_SIGNING_KEY_FILE set  -> file signing key
unset                        -> static development key
invalid                      -> readiness failure
AGENTK_REQUIRE_SIGNING_KEY=1 -> readiness failure unless AGENTK_SIGNING_KEY_HEX or AGENTK_SIGNING_KEY_FILE is valid
AGENTK_RELEASE_REMOTE_APPROVED=1 -> strict release gate accepts approved git remote
```

On Unix, readiness also verifies that an `AGENTK_SIGNING_KEY_FILE` path is owner-only and that its parent directory is not group/other writable, so loose custody permissions block release gates without printing the local path.

### Secret FDs

Agents should not receive raw secrets.

Instead:

```txt
secret.open github_token -> secret_fd:github_read_15min
```

The agent can use the handle through a broker, but cannot print, copy, or send the secret itself.

The current prototype can register either target-only dummy secret entries for tests or external secret references for adapter experiments. The dummy path deliberately does not accept secret bytes. External references are retained with private fields and explicit accessors for future adapters, while broker debug output prints provider/reference hashes instead of raw values. Configured secret store adapters form a small provider-scoped registry; each adapter must declare support for the reference provider before AgentK checks whether the external reference is available. The adapter boundary returns only availability, never raw secret bytes. The local `env` adapter recognizes provider `env`, validates the reference as a safe environment variable name, and checks only for a non-empty value. A versioned TOML secret-reference manifest can bulk-register external refs; it validates provider ids, is allowed to contain provider references but not secret values, and its debug output redacts provider/reference values. `agentk secret-refs-check` validates a manifest and reports only version and count. `agentk secret-refs-store-check` checks availability through the local env store and reports only counts for available, missing, and unsupported references. Without a configured store, external references do not mint handles by default; explicit demo mode is required to preserve the old adapter-experiment behavior. AgentK serializes the handle, proof, signature, public key, and labels, not raw secret bytes or external provider references.

Secret handles are scoped to the same capability string as the `secret.open`
receipt, share the receipt expiry step, and carry the receipt id and proof hash.
Signature verification recomputes both proof hashes from visible event fields,
then checks that the handle is bound to the receipt before accepting the proof.

### Flight Recorder

Every syscall is written as JSONL with a hash chain.

Replay modes:

- trace inspect: verify the log and emit a redacted human-review summary,
- deterministic replay: verify the log and stub model/tool/network side effects with synthetic output refs,
- fork replay: compare recorded decisions against a different policy and summarize decision transitions.
- behavior fork replay: compare recorded stub output refs against changed hashed output refs.

`agentk verify-signatures` verifies receipt and secret-handle signatures and prints redacted signer-fingerprint summaries with receipt and secret-handle counts. Reviewers can pass one or more `--trusted-public-key` values, or `--trusted-key-manifest examples/trusted-signers.toml`, to pin verification to known release signer identities; mathematically valid signatures from unknown keys then fail review. `agentk trusted-signers-check` validates a trusted-signer manifest and reports only version and key count.

`agentk trace-inspect` is the human review path. It verifies the hash chain, summarizes signature status, groups blocked events by policy rule, groups boundary events by syscall and evidence-ref type, and prints one compact row per event. Known hash evidence refs such as `args_sha256`, `descriptor_sha256`, and `response_sha256` are preserved. Any raw input ref is replaced with a fresh `input_sha256` ref in the inspection report.

Blocked MCP tool, resource, and prompt responses also carry compact `denial` summaries at the response boundary. Those summaries surface verdict, policy rule, reason, syscall, target, and any missing capability without requiring reviewers to dig through the full nested event body.

`agentk replay` records deterministic `stub_output_sha256` evidence refs for allowed `model.call`, `tool.invoke`, and `network.send` events. Blocked side effects stay blocked, do not get stub outputs, and are summarized by policy rule.

`agentk fork-replay` compares the recorded log against another policy and reports both per-event changes and transition counts such as `deny:rule->allow:rule`. This makes policy drift reviewable without manually counting every changed event.

`agentk fork-replay-behavior` accepts a JSON array of changed hashed output refs and emits a divergence report. Overrides are bound to the recorded step, syscall, and target, and raw output strings are rejected.

`agentk release-audit` packages the local release ritual into one report. It runs readiness, git hygiene checks, formatting, tests, clippy, a fresh demo trace, signature verification with signer summaries, signer-pinning and trusted-signer manifest smoke coverage, brokered secret-handle, secret-reference validation, and secret-store availability smoke tests, MCP taint-flow, subprocess MCP boundary, lifecycle-redaction, initialize-guard, tool/resource/prompt shape guards, bad-response redaction, response-timeout, transport-close, mixed-interop, public interop transcript, resource subscription no-passthrough, pre-ready and duplicate-initialized notification no-passthrough, notification-burst/flood, no-passthrough, config-guard, AgentK metadata-redaction, client-intent hashing, invalid-client-param smoke tests, and denial-summary smoke tests, redacted inspect, replay blocked-rule summaries, fork replay decision summaries, behavior fork replay, and an MCP server smoke test. It does not configure remotes or push.

### MCP Proxy MVP

The current MCP proxy command reads one MCP-shaped JSON request, converts it to `tool.invoke`, hashes the arguments, and asks policy for a decision.

It does not execute the tool.

`agentk mcp-stdio` performs the same mediation over stdin/stdout for a single
bounded JSON request. This is still a prototype transport, not a complete MCP
server.

`agentk mcp-lines` streams bounded newline-delimited JSON requests on stdin and
emits newline-delimited mediation reports. This is useful for simple adapters
and tests.

`agentk mcp-server` is a minimal MCP JSON-RPC stdio server. It handles
`initialize`, `ping`, `tools/list`, and `tools/call`; rejects batches,
oversized JSON-RPC lines, and invalid request ids without reflecting raw id
payloads; streams stdin with bounded per-line reads; requires `initialize`
with the supported protocol version followed by `notifications/initialized`
before operation requests; only handles `initialize` and `ping` before
readiness; ignores other JSON-RPC notifications without advancing readiness;
and exposes three AgentK tools:

```txt
agentk.mediate
agentk.mediate_descriptor
agentk.record_response
```

`agentk.mediate_descriptor` converts an MCP `Tool` descriptor into a `tool.describe` syscall. AgentK hashes the full descriptor, hashes input/output schemas separately, marks suspicious descriptor text as `poisoned-suspect`, and does not put raw descriptor text into event inputs.

`agentk.record_response` converts an MCP tool result into a `tool.response` syscall. AgentK records a response hash, marks MCP tool output as `untrusted` and `external`, preserves caller-supplied labels, marks error responses as `poisoned-suspect`, and does not serialize raw tool output into event inputs.

Later `tool.invoke` calls deny `secret`, `private`, `untrusted`, or `poisoned-suspect`
inputs before capability receipts can allow the call. This keeps recorded tool output
from being laundered into another tool boundary as trusted input.

This is useful for integration experiments, but it is not a full MCP proxy and it still never executes the underlying tool.

`agentk mcp-proxy-stdio` sits between an MCP client and a downstream stdio MCP
server process. It mediates `tools/list` descriptors, `tools/call` requests,
`resources/list` descriptors, `resources/read` requests, `prompts/list`
descriptors, and `prompts/get` requests. Tool, resource, and prompt responses
are recorded with hash-first evidence, AgentK-only policy metadata is stripped
from forwarded covered messages, and post-ready MCP request methods without an
AgentK policy contract are rejected instead of being forwarded as generic
passthrough.

### Key Rotation Manifests

`agentk key-rotate` reads a current local private signing key, writes a next private signing key, and emits a public signed manifest.

The manifest includes:

```txt
algorithm
previous_public_key
next_public_key
generated_at_unix
payload_hash
signature
signer_public_key
```

The manifest does not include private key material. It is a local prototype for auditability, not a full production key-management system.

Operational signing-key generation, custody, activation, rotation, retirement, revocation, and incident response rules live in `docs/key-lifecycle.md`.

`agentk key-rotate-verify` recomputes the manifest payload hash and verifies the Ed25519 signature against the previous public key.

## First Demo

The poisoned webpage demo creates this flow:

```txt
context.read(untrusted webpage)       -> allowed
model.call(context)                   -> allowed
secret.open(~/.ssh/id_rsa)            -> blocked
network.send(evil.example.invalid)    -> blocked
```

The interesting part is not the block. The interesting part is the explanation:

```txt
source: untrusted, external, poisoned-suspect
sink:   network.send
data:   secret, private
rule:   taint-sensitive-egress
```

That is the AgentK thesis in one trace.
