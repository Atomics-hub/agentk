# MCP Proxy Operator Contract

AgentK's subprocess MCP proxy is a security boundary between an MCP client and
a downstream MCP server process. It is not an agent framework and it does not
decide what task an agent should perform. Its job is to ensure that MCP traffic
covered by this proxy crosses the boundary only with policy, provenance, and
evidence.

## Command

Run the proxy with a downstream stdio MCP server:

```sh
cargo run -- mcp-proxy-stdio \
  --server-id poisoned-demo \
  --trace-out .agentk/runs/mcp-proxy-demo.jsonl \
  --command sh \
  --arg examples/mcp-poisoned-server.sh \
  < examples/mcp-proxy-client-session.jsonl
```

Use `--command` for the child executable and repeat `--arg` for child argv.
Hyphen-prefixed child args are accepted:

```sh
cargo run -- mcp-proxy-stdio --command sh --arg -c --arg 'exec ./server'
```

The proxy validates non-empty `agent_id`, `server_id`, and child command values
before spawning. Spawn failures are reported without reflecting the command
string, so local executable paths or accidental command text do not become part
of client-visible diagnostics.

The proxy clears the child process environment by default. Use
`--allow-env NAME` to copy a named parent environment variable into the child
environment. Repeat the flag for multiple variables:

```sh
cargo run -- mcp-proxy-stdio \
  --command ./server \
  --allow-env MCP_SERVER_MODE \
  --allow-env MCP_SERVER_ENDPOINT
```

Do not put secret values directly in `--arg`; pass only names through
`--allow-env` when a downstream server needs an environment variable.
Allowed environment names must match `[A-Za-z_][A-Za-z0-9_]*`. Missing or
non-UTF-8 parent values fail before the child process is spawned, and values
are not printed in the error. The same name validation is enforced on the proxy
configuration before spawning the child.

Use `--response-timeout-ms` to set the downstream response timeout. The default
is 30000 ms. If the child does not produce a matching JSON-RPC response before
the timeout, AgentK terminates the child and returns a sanitized downstream
transport failure without reflecting the request payload.

The child server's stderr is not forwarded by the proxy. Downstream diagnostic
streams are outside the MCP protocol and can contain raw secrets, poisoned
tool output, local paths, or credentials. AgentK keeps the review path on
sanitized JSON-RPC responses and hash-only trace evidence instead of letting
child stderr bypass the boundary.

## Lifecycle

The client must send `initialize` with AgentK's supported MCP protocol version,
then `notifications/initialized`, before mediated tool, resource, or prompt
traffic is proxied.

Before readiness:

- `initialize` is validated and forwarded.
- `ping` is allowed.
- Tool methods are rejected with a sanitized not-initialized error.
- Unknown pre-ready methods do not expose the method surface.

The downstream server's `initialize` response must report the supported
protocol version before AgentK marks the session initialized. The downstream
`tools/list` result must be an object with a `tools` array before descriptors
are exposed. The downstream `resources/list` result must be an object with a
`resources` array before resource descriptors are exposed. The downstream
`prompts/list` result must be an object with a `prompts` array before prompt
descriptors are exposed.
Release-audit covers unsupported downstream initialize versions and verifies
that the proxy remains not-ready instead of exposing downstream descriptors.

After readiness, `initialize`, `ping`, `tools/list`, `tools/call`,
`resources/list`, `resources/read`, `prompts/list`, and `prompts/get` requests
are the only request methods covered by this proxy. Other MCP request methods
are rejected with a sanitized `Method not found` response until they have an
explicit AgentK policy contract. The proxy forwards `notifications/initialized`
and the cancellation notification, but drops other notifications.

Release-audit includes a mixed subprocess transcript that exercises tools,
resources, prompts, an allowed cancellation notification, and a dropped
unsupported notification in one session.

Release-audit also covers downstream notification bursts before a response.
Those notifications are tolerated while waiting for the matching response, but
their raw payloads are not returned to the client or written to AgentK evidence.
The proxy also bounds skipped downstream notifications while waiting for a
response, returning a sanitized bad-downstream-response error instead of
letting a notification flood stall the request indefinitely.

## Mediation

On `tools/list`, AgentK treats downstream tool descriptors as untrusted
external context. It records descriptor hashes, hashes schemas separately, marks
suspicious descriptor text as `poisoned-suspect`, and drops malformed
descriptors instead of reflecting raw descriptor payloads.

On `tools/call`, AgentK strips AgentK-only metadata before forwarding to the
downstream server. The metadata supplies local policy context:

- `intent`
- `labels`
- `capabilities`

If policy denies the call, AgentK returns an MCP-shaped blocked result and does
not forward the request to the child process.

If policy allows the call, AgentK forwards the sanitized request, records a
hash-only response event, and attaches AgentK evidence to the client-visible
response.

On `resources/list`, AgentK treats downstream resource descriptors as untrusted
external context. It records resource descriptor hashes, marks suspicious
descriptor text as `poisoned-suspect`, and drops malformed descriptors instead
of reflecting raw malformed payloads.

On `resources/read`, AgentK requires a target-scoped `resource.read` capability
before forwarding the request. The resource URI is represented in policy and
evidence by hash, AgentK-only metadata is stripped before forwarding, and the
resource response is recorded as a hash-only `resource.response` event before
evidence is attached to the client-visible response.

On `prompts/list`, AgentK treats downstream prompt descriptors as untrusted
external context. It records prompt descriptor hashes, marks suspicious
descriptor text as `poisoned-suspect`, and drops malformed descriptors instead
of reflecting raw malformed payloads.

On `prompts/get`, AgentK requires a target-scoped `prompt.get` capability
before forwarding the request. The prompt name and arguments are represented in
policy and evidence by hash, AgentK-only metadata is stripped before forwarding,
and the prompt response is recorded as a hash-only `prompt.response` event
before evidence is attached to the client-visible response.

## Redaction And Evidence

AgentK records evidence as hashes and policy decisions, not raw tool or
resource or prompt payloads.

The proxy sanitizes these downstream failures:

- malformed JSON-RPC responses
- mismatched response ids
- closed downstream stdout or send failures
- timed-out downstream responses
- downstream `initialize` and `ping` error bodies
- unsupported downstream initialize versions
- downstream `tools/list` error bodies
- malformed `tools/list` results
- malformed successful `tools/call` results
- downstream `tools/call` error bodies
- malformed `resources/list` results
- malformed successful `resources/read` results
- downstream `resources/read` error bodies
- malformed `prompts/list` results
- malformed successful `prompts/get` results
- downstream `prompts/get` error bodies
- child stderr diagnostics

Release-audit includes malformed JSON and mismatched response-id coverage to
verify that raw downstream response payloads are not reflected to the client or
written into AgentK evidence.
It also covers malformed `tools/list` and successful `tools/call` result shapes
so invalid downstream payloads cannot be exposed as mediated tool output.

For downstream tool errors, AgentK returns a sanitized error summary with the
downstream error code and redaction flags. Raw downstream error `message` and
`data` fields are not returned to the client. The original error body is still
represented by a response hash in the AgentK trace.

Downstream `resources/read` errors follow the same pattern: raw error text is
not reflected to the client, while hash evidence is kept in the trace.

Downstream `prompts/get` errors also follow this pattern: raw error text is not
reflected to the client, while hash evidence is kept in the trace.

## Trace Inspection

Use `--trace-out` to write the AgentK event log for proxied descriptor,
tool-invoke, resource-read, prompt-get, and response-record events:

```sh
cargo run -- mcp-proxy-stdio \
  --server-id poisoned-error-demo \
  --trace-out .agentk/runs/mcp-proxy-error-demo.jsonl \
  --command sh \
  --arg examples/mcp-poisoned-error-server.sh \
  < examples/mcp-proxy-poisoned-error-session.jsonl

cargo run -- trace-inspect .agentk/runs/mcp-proxy-error-demo.jsonl
```

Trace inspection should show hash-first evidence refs, policy reasons, missing
capabilities when relevant, and signature status. It should not require raw
descriptor text, raw tool arguments, raw tool output, local paths, or private
environment values to explain what happened.

For the before/after reviewer proof, run `cargo run -- mcp-shim-eval` and use
[`docs/mcp-shim-eval.md`](mcp-shim-eval.md) to interpret the scorecard and
trace evidence.

## Current Limits

This is the subprocess stdio proxy path. It is suitable for local review,
release-audit smoke coverage, and integration experiments. A complete
production MCP transport still needs a hardened server packaging story,
deployment guidance, and operational key management. The current boundary
mediates tool listing/calls, resource listing/reads, and prompt listing/gets;
child stderr is suppressed rather than treated as evidence. Resource
subscription flows still need explicit policy contracts and are not forwarded
as generic passthrough.
