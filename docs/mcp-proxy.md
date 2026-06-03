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
  --session-report-out .agentk/runs/mcp-proxy-demo.session.json \
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

Use `--max-client-messages` to cap non-empty client messages per proxy session.
The default is 10000. If the cap is exceeded, AgentK returns a sanitized
JSON-RPC error and closes the session without forwarding the over-limit client
message.

Use `--session-report-out` to write a redacted JSON summary for the proxy
session. The report includes the AgentK agent id, downstream server id,
initialized/ready state, client message counts, configured message cap,
limit-exceeded status, and allow/deny event totals. It is safe to hand to
operators because it does not include raw MCP payloads or downstream stderr.

Use `mcp-proxy-tcp` when an internal adapter needs a local TCP JSONL endpoint
instead of stdio:

```sh
cargo run -- mcp-proxy-tcp \
  --host 127.0.0.1 \
  --port 9797 \
  --max-sessions 4 \
  --max-concurrent-sessions 2 \
  --server-id poisoned-demo \
  --trace-out .agentk/runs/mcp-proxy-tcp-demo.jsonl \
  --session-report-out .agentk/runs/mcp-proxy-tcp-demo.session.json \
  --command sh \
  --arg examples/mcp-poisoned-server.sh
```

The TCP gateway accepts newline-delimited MCP JSON-RPC over the socket, spawns a
fresh downstream process per accepted session, applies the same lifecycle,
redaction, timeout, and `--max-client-messages` behavior as `mcp-proxy-stdio`,
keeps at most `--max-concurrent-sessions` active sessions at once, and exits
after `--max-sessions` sessions. Use `sidecar-serve-tcp --root
<bundle>` or the packaged `bin/agentk-sidecar-tcp` launcher to serve a reviewed
sidecar bundle over the same bounded TCP transport.

Use `mcp-proxy-http` when a local integration can speak Streamable HTTP POST
instead of stdio or TCP JSONL:

```sh
cargo run -- mcp-proxy-http \
  --host 127.0.0.1 \
  --port 9798 \
  --endpoint /mcp \
  --max-concurrent-requests 16 \
  --server-id poisoned-demo \
  --trace-out .agentk/runs/mcp-proxy-http-demo.jsonl \
  --session-report-out .agentk/runs/mcp-proxy-http-demo.session.json \
  --command sh \
  --arg examples/mcp-poisoned-server.sh
```

The HTTP adapter accepts local POST requests at the configured endpoint, rejects
unsafe origins unless they are explicitly allowed, answers allowed browser CORS
preflights before bearer-token auth, and maps initialized MCP sessions onto the
same subprocess mediation path. Use repeated `--allow-origin` values or
comma-separated `AGENTK_MCP_HTTP_ALLOW_ORIGINS` values to permit approved
non-local browser adapters. If clients send `MCP-Protocol-Version`, AgentK
requires it to match the supported protocol on initialize and the negotiated
protocol on follow-up POST/DELETE requests. Follow-up `Mcp-Session-Id` values
must match AgentK's generated 32-character lowercase hex shape before any
session lookup runs. The adapter also serves local `GET`/`HEAD` probes at
`/healthz`, `/readyz`, and `/metrics`;
`/readyz` returns endpoint, supported protocol-version, active-session,
active-session cap, idle timeout, request-concurrency, request body cap,
configured allowed-origin count, and auth-required metadata without raw MCP
payloads or raw origin values. `/metrics` exposes the same operational posture
as redacted numeric gateway gauges plus cumulative request, rejection, and
session lifecycle counters for service supervisors. All MCP HTTP `HEAD`
responses omit bodies; `HEAD` on the MCP endpoint remains an unsupported method
response with the normal `Allow` header. When HTTP auth is
configured, `/readyz` and `/metrics` require the same bearer token as MCP
requests; `/healthz` remains open for minimal liveness checks.
`--max-active-sessions` caps initialized MCP HTTP
sessions and excess initialize requests return 429.
`--session-idle-timeout-ms` reaps idle initialized sessions and releases their
downstream process/capacity. `--max-body-bytes` bounds the POST body read before
JSON parsing; oversized requests return 413. `--max-header-bytes` bounds the
request line plus headers before body reads; oversized headers return 431.
SSE-shaped `GET` requests to the MCP endpoint require `Accept:
text/event-stream`, pass the same auth/origin/protocol/session-id checks, and
then fail closed with sanitized 501 responses plus a redacted
unsupported-SSE counter until resumable SSE support lands.
Malformed request lines or header lines, including invalid UTF-8, duplicate or
non-decimal `Content-Length` headers, LF-only line endings, control characters
in header values, and any `Transfer-Encoding`, `Expect`, or `Upgrade` header
are rejected
with sanitized 400 responses because the adapter only accepts origin-form
paths beginning with exactly one `/`, fragment-free, CRLF-delimited,
fixed-length HTTP/1.x requests with exactly space-delimited request lines and
token-shaped header names without whitespace before `:`.
Only `Connection: close` is accepted; other `Connection` values plus
`Proxy-Connection`, `Keep-Alive`, `TE`, and `Trailer` headers are rejected as
unsupported hop-by-hop negotiation.
HTTP/1.1 requests must
include exactly one syntactically valid `Host` authority with no userinfo,
wildcards, paths, queries, fragments, invalid ports, or unbracketed IPv6
literals; duplicate `Host` headers are rejected for all accepted HTTP versions.
EOF before the blank header terminator or before the declared fixed-length body
completes is rejected as invalid framing. Duplicate MCP control headers used for
auth/session/protocol/origin/media negotiation are rejected with sanitized 400
responses, and clients must choose either `Authorization` or
`X-AgentK-MCP-Token` per request. Malformed `Mcp-Session-Id` values are
rejected with sanitized 400 responses before session lookup. POSTs require an
exact `application/json` media type; parameters such as `charset` are allowed.
Request bodies are
accepted only on MCP `POST`; CORS preflights, DELETEs, GET/SSE placeholders, and
operational probes reject bodies before auth, session, or probe handling.
Additional `--allow-origin` or `AGENTK_MCP_HTTP_ALLOW_ORIGINS` values must be
exact `scheme://authority` origins or `null`; paths, queries, fragments,
wildcards, whitespace, invalid ports, and unbracketed IPv6 literals are
rejected before bind. Built-in localhost and loopback origins only match exact
hosts with optional numeric ports.
Allowed browser preflights must request `POST` or `DELETE` and only known MCP
HTTP headers; unsupported requested methods or headers return sanitized 400
responses with CORS visibility for allowed origins. The configured MCP endpoint
and operational probe paths are matched exactly; query strings on those paths
return sanitized 400 responses before auth, session, probe, or CORS handling.
Configured endpoints must be clean origin-form paths beginning with `/`,
without query strings, fragments, whitespace, or control characters, and cannot
reuse `/healthz`, `/readyz`, or `/metrics`.
`--stream-timeout-ms` applies read/write deadlines to accepted HTTP connections
so stalled clients do not hold gateway worker threads indefinitely. Use
`sidecar-serve-http --root
<bundle>` or the packaged `bin/agentk-sidecar-http` launcher for a reviewed
sidecar bundle. HTTP bind hosts must be loopback unless
`--allow-non-local-bind` is passed; the packaged launcher only passes that flag
when `AGENTK_MCP_HTTP_ALLOW_NON_LOCAL_BIND=true`. Non-loopback binds also
require a non-empty bearer token from `--auth-token-env`, so LAN/public exposure
is an explicit authenticated operator choice. When a bounded HTTP gateway exits,
it drains any still-active initialized sessions and writes their redacted
trace/session reports using the same per-session file names as DELETE cleanup.
The readiness and metrics probes expose only redacted numeric counters: parsed
request totals by method, client/server error totals, auth/origin/method
rejections, unsupported-SSE totals, and session create/delete/expire/not-found
totals.
This is still a local adapter: it does not provide a hosted production control
plane, TLS termination, SSE streaming, or external identity integration.

When the client closes stdin, AgentK closes the downstream server's stdin first
and gives the child a short grace period to exit cleanly. If the child keeps
running after that grace period, AgentK terminates it so stale team sidecar
sessions do not accumulate.

The child server's stderr is not forwarded by the proxy. Downstream diagnostic
streams are outside the MCP protocol and can contain raw secrets, poisoned
tool output, local paths, or credentials. AgentK keeps the review path on
sanitized JSON-RPC responses and hash-only trace evidence instead of letting
child stderr bypass the boundary.

For team onboarding, generate a starter sidecar bundle with
`agentk sidecar-init`, run `agentk sidecar-check`, then point Claude, Codex,
Cursor, or another MCP client at `agentk sidecar-run --root <bundle>`.
`sidecar-check` validates the Claude Desktop JSON and generic Codex/Cursor
command snippet shape without spawning downstream tools or touching
credentials.
For a more stable local deployment folder, run `agentk sidecar-package --root
<bundle> --out <package>` and point clients at `<package>/bin/agentk-sidecar`
or the generated snippets under `<package>/clients/`. After editing a packaged
bundle, run `<package>/bin/agentk-sidecar-check` to validate it without spawning
downstream tools. The package writes a relative-path `manifest.json` with the
AgentK version, schema version, launchers, client snippets, local transports,
store workflow, and deploy artifacts; `<package>/bin/agentk-package-info` prints
that manifest for support and deployment inventory checks.
`<package>/bin/agentk-package-check` validates the manifest, package artifacts,
launcher modes, and embedded sidecar bundle after a copy, deploy, or image
build. `<package>/bin/agentk-safe-agent-demo --json` runs the no-credential
GitHub/Postgres/Slack/filesystem workflow from the package and writes
`<package>/sidecar/.agentk/runs/safe-agent-demo.jsonl` for audit review. Set
`AGENTK_TRACE` to that path when running the packaged dashboard or store
launchers to review/sync/export the demo evidence instead of the default
team-sidecar trace.
Internal adapters can run `<package>/bin/agentk-sidecar-tcp`
for a local bounded TCP JSONL gateway; Claude, Codex, and Cursor should keep
using the stdio launcher unless their MCP client configuration supports that
adapter. Streamable HTTP POST-capable clients can run
`<package>/bin/agentk-sidecar-http`; keep it bound to localhost unless a separate
deployment layer supplies TLS, external auth, and network policy.
`sidecar-run` reads `agentk-sidecar.toml`, launches the configured downstream
MCP server, copies only the env vars named in `[downstream].allow_env`, and
writes the configured redacted JSONL audit log plus a
`*.session.json` summary beside it. Reviewers can run
`agentk permissions --path <bundle>/team-permissions.toml`, then append local
approve/deny decisions with `--permissions` so reviewer authority is checked
before the signed trace is reconciled. `agentk dashboard <trace> --permissions
<bundle>/team-permissions.toml` writes a local HTML review surface for the same
evidence, `agentk dashboard-serve <trace> --permissions
<bundle>/team-permissions.toml --store-root <bundle>/.agentk/team-store` serves
an interactive local review UI and `/api/review` JSON endpoint on localhost.
It also exposes `/healthz` and a redacted `/readyz` that reports trace,
decision-log, permissions, store, and admin-auth readiness without local paths or
approval payloads. Dashboard probe paths are matched exactly and reject query
strings; reviewer and requester query parameters remain scoped to the review
HTML/API routes.
Dashboard and MCP HTTP responses include no-store, no-sniff, no-referrer,
anti-framing, and local-only CSP headers for browser-facing deployments.
Reviewers can record approve/deny decisions from the browser page, and the
server also accepts permission-checked JSON decisions at `/api/approve` and
`/api/deny`, appending
to the local decision log without mutating the signed trace and refreshing the
durable team store. Set `AGENTK_DASHBOARD_ADMIN_TOKEN` to require an admin
bearer token or `X-AgentK-Admin-Token` header on dashboard write requests.
Reviewers can set `token_env` in `team-permissions.toml`; those users must
include `X-AgentK-Reviewer-Token` for scoped `/api/review?reviewer=<id>` reads
and matching `reviewer_token` values in dashboard write requests. `agentk
store-sync <trace> --permissions <bundle>/team-permissions.toml --root
<bundle>/.agentk/team-store` can also refresh the same live local durable store
with current redacted JSON snapshots, normalized JSONL tables, and a
credential-free notification outbox at `tables/notifications.jsonl` for pending
approval requests and recorded decisions. `agentk store-export
<trace> --permissions <bundle>/team-permissions.toml` writes normalized JSON
plus a Postgres schema contract, TSV rows, and `postgres/load.sql` for a shared
audit store.
The served browser dashboard includes a reviewer view that calls the same
scoped review API and redraws the approval and decision tables with only the
items that reviewer is authorized to see. Direct scoped HTML views are also
available at `/?reviewer=<id>`; token-protected reviewers must provide their
reviewer token by header or query parameter for that view. The same dashboard
also supports requester views at `/?requester=<agent-id>` and
`/api/review?requester=<agent-id>`, filtering approvals and decisions by the
signed AgentK agent identity recorded in each event.
`agentk store-check --root <store>` validates either the exported Postgres
artifacts or the live durable team store before a team relies on it. `agentk
store-push --root <store>` accepts only the export shape, preflights again, and
invokes `psql` with the redacted `$DATABASE_URL` connection string. The productization order is tracked in
[`docs/productization-plan.md`](productization-plan.md).

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
once after a successful initialize and forwards the cancellation notification
after readiness, but drops duplicate lifecycle notifications and other
notifications.
`resources/subscribe` and `resources/unsubscribe` are explicitly unsupported
for v0.1 and release-audit verifies that they are not forwarded as passthrough.

Release-audit includes a mixed subprocess transcript that exercises tools,
resources, prompts, an allowed cancellation notification, and a dropped
unsupported notification in one session. It also runs the public
`examples/mcp-interop-session.jsonl` transcript against
`examples/mcp-interop-server.sh`, including poisoned tool/resource/prompt output
followed by blocked network-egress and unsafe-patch attempts.

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

Client-provided `intent` text is represented in evidence as a
`client_intent_sha256` hash instead of raw text. The proxy keeps a method-level
default intent for human review while avoiding raw request metadata in client
responses and trace logs.

Empty `tools/call` names, `resources/read` URIs, and `prompts/get` names fail
closed as invalid client parameters before the downstream server sees the
request.

Invalid AgentK-only metadata fails before forwarding. Label parsing errors use
generic diagnostics so malformed labels cannot reflect raw marker text back to
the client.

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
- empty client-supplied tool names, resource URIs, and prompt names
- invalid AgentK-only metadata such as unsupported labels
- client-provided AgentK intent text

Release-audit includes malformed JSON and mismatched response-id coverage to
verify that raw downstream response payloads are not reflected to the client or
written into AgentK evidence.
It also covers malformed `tools/list` and successful `tools/call` result shapes
so invalid downstream payloads cannot be exposed as mediated tool output.
Release-audit also covers malformed `resources/list`, successful
`resources/read`, `prompts/list`, and successful `prompts/get` result shapes so
resource and prompt payloads fail closed with sanitized errors and hash-only
evidence.

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

This is the local subprocess proxy path: stdio for MCP clients that launch a
command directly, plus bounded localhost TCP JSONL and Streamable HTTP POST
adapters for internal integrations. It is suitable for local review,
release-audit smoke coverage, and integration experiments. A complete
production MCP transport still needs a hardened server packaging story, SSE
streaming, deployment guidance, external identity/auth integration, TLS
termination, and operational key management. The current boundary mediates tool
listing/calls, resource
listing/reads, and prompt listing/gets; child stderr is suppressed rather than
treated as evidence. Resource subscription flows still need explicit policy
contracts and are not forwarded as generic passthrough.

The v0.1 release disposition for these limits is tracked in
[`docs/v0.1-limit-disposition.md`](v0.1-limit-disposition.md).
