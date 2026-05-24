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
are not printed in the error.

## Lifecycle

The client must send `initialize` with AgentK's supported MCP protocol version,
then `notifications/initialized`, before `tools/list` or `tools/call` traffic
is proxied.

Before readiness:

- `initialize` is validated and forwarded.
- `ping` is allowed.
- Tool methods are rejected with a sanitized not-initialized error.
- Unknown pre-ready methods do not expose the method surface.

The downstream server's `initialize` response must report the supported
protocol version before AgentK marks the session initialized. The downstream
`tools/list` result must be an object with a `tools` array before descriptors
are exposed.

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

## Redaction And Evidence

AgentK records evidence as hashes and policy decisions, not raw tool payloads.

The proxy sanitizes these downstream failures:

- malformed JSON-RPC responses
- mismatched response ids
- closed downstream stdout or send failures
- unsupported downstream initialize versions
- malformed `tools/list` results
- malformed successful `tools/call` results
- downstream `tools/call` error bodies

For downstream tool errors, AgentK returns a sanitized error summary with the
downstream error code and redaction flags. Raw downstream error `message` and
`data` fields are not returned to the client. The original error body is still
represented by a response hash in the AgentK trace.

## Trace Inspection

Use `--trace-out` to write the AgentK event log for proxied descriptor,
tool-invoke, and response-record events:

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

## Current Limits

This is the subprocess stdio proxy path. It is suitable for local review,
release-audit smoke coverage, and integration experiments. A complete
production MCP transport still needs a hardened server packaging story,
deployment guidance, and operational key management. The current boundary
mediates descriptor listing and tool calls; broader MCP resource and prompt
surfaces still need explicit policy contracts before they should be treated as
production-isolated flows.
