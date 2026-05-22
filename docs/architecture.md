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
unset                        -> static development key
invalid                      -> readiness failure
```

### Secret FDs

Agents should not receive raw secrets.

Instead:

```txt
secret.open github_token -> secret_fd:github_read_15min
```

The agent can use the handle through a broker, but cannot print, copy, or send the secret itself.

The current prototype stores only dummy in-memory secrets in tests and serializes the handle, proof, signature, public key, and labels. It does not serialize raw secret material.

### Flight Recorder

Every syscall is written as JSONL with a hash chain.

Replay modes:

- trace inspect: verify the log and emit a redacted human-review summary,
- deterministic replay: verify the log and stub model/tool/network side effects,
- fork replay: compare recorded decisions against a different policy.

`agentk trace-inspect` is the human review path. It verifies the hash chain, summarizes signature status, and prints one compact row per event. Known hash evidence refs such as `args_sha256`, `descriptor_sha256`, and `response_sha256` are preserved. Any raw input ref is replaced with a fresh `input_sha256` ref in the inspection report.

`agentk release-audit` packages the local release ritual into one report. It runs readiness, git hygiene checks, formatting, tests, clippy, a fresh demo trace, signature verification, redacted inspect, replay, fork replay, and an MCP server smoke test. It does not configure remotes or push.

### MCP Proxy MVP

The current MCP proxy command reads one MCP-shaped JSON request, converts it to `tool.invoke`, hashes the arguments, and asks policy for a decision.

It does not execute the tool.

`agentk mcp-stdio` performs the same mediation over stdin/stdout for a single JSON request. This is still a prototype transport, not a complete MCP server.

`agentk mcp-lines` accepts newline-delimited JSON requests on stdin and emits newline-delimited mediation reports. This is useful for simple adapters and tests.

`agentk mcp-server` is a minimal MCP JSON-RPC stdio server. It handles `initialize`, `ping`, `tools/list`, and `tools/call`, and exposes three AgentK tools:

```txt
agentk.mediate
agentk.mediate_descriptor
agentk.record_response
```

`agentk.mediate_descriptor` converts an MCP `Tool` descriptor into a `tool.describe` syscall. AgentK hashes the full descriptor, hashes input/output schemas separately, marks suspicious descriptor text as `poisoned-suspect`, and does not put raw descriptor text into event inputs.

`agentk.record_response` converts an MCP tool result into a `tool.response` syscall. AgentK records a response hash and labels, but does not serialize raw tool output into event inputs.

This is useful for integration experiments, but it is not a full MCP proxy and it still never executes the underlying tool.

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
