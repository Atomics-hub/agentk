# AgentK

[![CI](https://github.com/Atomics-hub/agentk/actions/workflows/ci.yml/badge.svg)](https://github.com/Atomics-hub/agentk/actions/workflows/ci.yml)

AgentK is a firewall and flight recorder for AI agents.

Status: v0.2 alpha release candidate; installable local/team sidecar, not hosted production SaaS.

Run a malicious MCP server. Watch baseline passthrough execute fake secret
exfiltration and repository patch markers. Then put AgentK in front of the same
flow: it blocks both transitions and writes replayable evidence.

## Start With The Attack

```sh
cargo run --locked -- mcp-shim-eval
```

Expected output:

```txt
check                                      baseline       AgentK
------------------------------------------ -------------- --------------
poisoned output triggers network egress    EXECUTED       BLOCKED
poisoned output triggers unsafe patch      EXECUTED       BLOCKED
AgentK metadata reaches downstream         LEAKED         STRIPPED
replayable boundary evidence               NONE           PRESENT
raw poison stored in trace                 no trace       REDACTED

verdict   AgentK improved 5/5 checks
```

Inspect and replay the AgentK evidence:

```sh
cargo run --locked -- trace-inspect .agentk/runs/mcp-shim-eval-agentk.jsonl
cargo run --locked -- replay .agentk/runs/mcp-shim-eval-agentk.jsonl
```

Why this matters: MCP servers are executable supply chain for AI agents. AgentK
does not make the agent less capable; it puts a policy and evidence boundary
around the high-risk transitions.

## What AgentK Is

AgentK is an **agent security kernel** and installable local/team MCP sidecar
alpha. It is not another agent framework. It is the syscall boundary agent
frameworks should run through:

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

AgentK treats prompt context and tool output like memory.

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

The primary v0.1 demo shows poisoned MCP output trying to exfiltrate a private
marker and patch the repository. AgentK blocks the network egress and unsafe
patch, strips AgentK-only metadata before downstream forwarding, and writes a
tamper-evident JSONL flight log.

## Run It

```sh
cargo run --locked -- mcp-killer-demo
```

Verify the latest flight log:

```sh
cargo run -- verify .agentk/runs/latest.jsonl
```

Verify receipt and secret-handle signatures:

```sh
cargo run -- verify-signatures .agentk/runs/latest.jsonl
```

Signature verification prints redacted signer fingerprints with receipt and
secret-handle counts, so reviewers can see which signing identities produced
evidence without printing raw public keys.

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

Summarize a flight log as an audit and approval inbox:

```sh
cargo run -- audit .agentk/runs/latest.jsonl
cargo run -- approvals .agentk/runs/latest.jsonl
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

Fork replay reports both per-event decision changes and a stable decision
summary, such as `deny:rule->allow:rule`, so policy drift is visible without
manual counting.

Fork-replay with changed hashed behavior outputs:

```sh
cargo run -- fork-replay-behavior .agentk/runs/latest.jsonl --behavior examples/replay-behavior-overrides.json
```

Check the starter policy:

```sh
cargo run -- policy-check examples/agentk.policy.toml
```

Validate a secret-reference manifest without printing provider refs:

```sh
cargo run -- secret-refs-check --manifest examples/secret-refs.toml
cargo run -- secret-refs-check --manifest examples/secret-refs-production.toml
```

`examples/secret-refs-production.toml` shows production-shaped references for
AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Vault, and
1Password. AgentK validates those provider-specific reference shapes without
fetching secret bytes, requiring cloud credentials, or printing raw refs.

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

This includes formatting, tests, clippy, runtime security smokes, and the
packaged sidecar release-candidate smoke.

Summarize the v0.2 alpha release train before running heavier gates:

```sh
cargo run --locked -- release-status
```

This prints the shipped team sidecar surfaces, accepted alpha limits, final
release blockers, and verification gates.

Write one offline release-candidate ticket bundle for reviewer handoff:

```sh
cargo run --locked -- release-ticket \
  --out dist/release-ticket \
  --force
```

This creates `release-status.json`, `release-candidate-smoke.json`,
`release-finalization.json`, and `release-ticket.json` under
`dist/release-ticket/` without tagging, pushing, uploading, or publishing. The
ticket summary includes explicit objective checks for the MCP gateway,
approval/audit dashboard, multi-user permissions, Claude/Codex/Cursor sidecar
onboarding, and safe-agent demo evidence so reviewers can see product coverage
without opening the full smoke report.

Or run the packaged sidecar release-candidate gates individually:

```sh
cargo run --locked -- release-candidate-smoke \
  --root dist/release-candidate-smoke \
  --force \
  --keep-root \
  --evidence-out dist/release-candidate-smoke.json
cargo run --locked -- release-evidence-check \
  --evidence dist/release-candidate-smoke.json \
  --root dist/release-candidate-smoke
cargo run --locked -- release-finalize \
  --release v0.2-alpha \
  --evidence dist/release-candidate-smoke.json \
  --root dist/release-candidate-smoke \
  --notes docs/v0.2-alpha-release-notes.md \
  --out dist/release-finalization.json
```

Run the strict pre-push audit with a configured signing key file:

```sh
AGENTK_REQUIRE_SIGNING_KEY=1 \
AGENTK_RELEASE_REMOTE_APPROVED=1 \
AGENTK_SIGNING_KEY_FILE=../agentk-signing-key \
cargo run -- release-audit --strict
```

Contribution and release rules live in [CONTRIBUTING.md](CONTRIBUTING.md),
[docs/productization-plan.md](docs/productization-plan.md), and
[docs/release-checklist.md](docs/release-checklist.md). Historical v0.1 scope,
accepted limits, and dry-run evidence remain archived in
[docs/v0.1-target.md](docs/v0.1-target.md),
[docs/v0.1-limit-disposition.md](docs/v0.1-limit-disposition.md), and
[docs/v0.1-release-dry-run.md](docs/v0.1-release-dry-run.md); current release
trains should use the productization plan and signed release checklist as the
source of truth. The current team-sidecar alpha release-note draft lives in
[docs/v0.2-alpha-release-notes.md](docs/v0.2-alpha-release-notes.md).

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

Run the minimal MCP JSON-RPC stdio server. The stdio server accepts
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
cargo run -- mcp-proxy-stdio --server-id poisoned-demo --trace-out .agentk/runs/mcp-proxy-demo.jsonl --session-report-out .agentk/runs/mcp-proxy-demo.session.json --command sh --arg examples/mcp-poisoned-server.sh < examples/mcp-proxy-client-session.jsonl
cargo run -- trace-inspect .agentk/runs/mcp-proxy-demo.jsonl
```

Use `--allow-env NAME` to copy a named parent environment variable into the
cleared child environment. Repeat the flag for multiple variables.
Repeat `--arg` for each downstream argument; hyphen-prefixed child args are
accepted, for example `--arg -c`.
Use `--response-timeout-ms` to set the downstream response timeout; the default
is 30000 ms. Use `--max-client-messages` to cap non-empty client messages in a
single proxy session; the default is 10000 and the proxy returns a sanitized
JSON-RPC error before closing the session when the limit is exceeded. Use
`--session-report-out` to write a redacted JSON summary with readiness state,
client message counts, cap status, and allow/deny event totals.

For internal adapters that cannot speak stdio directly, `mcp-proxy-tcp` exposes
the same mediated MCP JSON-RPC line protocol on a bounded local TCP listener:

```sh
cargo run -- mcp-proxy-tcp --host 127.0.0.1 --port 9797 --max-sessions 4 --max-concurrent-sessions 2 --server-id poisoned-demo --trace-out .agentk/runs/mcp-proxy-tcp-demo.jsonl --session-report-out .agentk/runs/mcp-proxy-tcp-demo.session.json --command sh --arg examples/mcp-poisoned-server.sh
```

The TCP gateway spawns a fresh downstream MCP process per accepted session,
uses the same lifecycle, redaction, timeout, and client-message cap behavior as
`mcp-proxy-stdio`, bounds simultaneous sessions with
`--max-concurrent-sessions`, and exits after `--max-sessions` sessions.

For MCP clients that support Streamable HTTP, `mcp-proxy-http` serves a local
stateful MCP endpoint:

```sh
cargo run -- mcp-proxy-http --host 127.0.0.1 --port 9798 --endpoint /mcp --max-concurrent-requests 16 --server-id poisoned-demo --trace-out .agentk/runs/mcp-proxy-http-demo.jsonl --session-report-out .agentk/runs/mcp-proxy-http-demo.session.json --command sh --arg examples/mcp-poisoned-server.sh
```

The HTTP gateway validates Origin headers, requires an allowed `Origin` for
browser CORS preflights, answers preflights for `POST`/`DELETE` plus known MCP
headers without requiring auth,
supports optional bearer auth via
`AGENTK_MCP_HTTP_TOKEN` with one token header per request, returns
`Mcp-Session-Id` on initialize, accepts subsequent POSTs with that session id,
rejects malformed session ids before lookup, rejects unsupported
`MCP-Protocol-Version` headers, returns direct JSON responses, and rejects
oversized request bodies with 413 and excess initialized sessions with 429.
POSTs require an exact `application/json` media type and a single JSON-RPC 2.0
request or notification object with a string `method`; batches, non-object
JSON, and response-shaped payloads fail closed before session lookup or
downstream forwarding.
Malformed request lines or header lines, including invalid UTF-8, duplicate or
non-decimal `Content-Length` headers, LF-only line endings, control characters
in header values, ambiguous MCP control headers, any `Transfer-Encoding` or
`Content-Encoding` header, and `Expect`/`Upgrade` headers are rejected as
invalid framing or control ambiguity; the gateway only accepts unencoded
fixed-length request bodies. WebSocket handshake headers such as
`Sec-WebSocket-Key` and `Sec-WebSocket-Protocol` are rejected because the
gateway is not a WebSocket transport. `Connection: close` is accepted, while
other `Connection` values and hop-by-hop negotiation headers such as
`Proxy-Connection`, `Keep-Alive`, `TE`, and `Trailer` are rejected, as are proxy auth headers such as
`Proxy-Authorization` and `Proxy-Authenticate`. Forwarded proxy metadata is
rejected by default; `--trust-proxy-headers` accepts only clean `Forwarded`,
`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP`
values from a reviewed reverse proxy, rejects duplicates or malformed values,
and reports only redacted readiness/metrics counts. Ambient cookie headers such as `Cookie` and
`Set-Cookie` are rejected because the gateway uses explicit bearer/reviewer
tokens instead. Method override headers such as `X-HTTP-Method-Override` and
`X-Method-Override` are rejected so gateway routes cannot be reinterpreted by
intermediaries. Proxy and trace methods such as `CONNECT`, `TRACE`, and `TRACK`
are rejected before route handling. Request lines must be exactly
space-delimited, request targets must begin with exactly one `/` and must not
contain fragments, and header names must be token-shaped without whitespace
before `:`. All HTTP gateway requests must include exactly one syntactically
valid `Host` authority with no userinfo, wildcards, paths, queries, fragments,
invalid ports, invalid DNS labels, percent escapes, or unbracketed IPv6
literals.
Incomplete header blocks and short fixed-length bodies are rejected before
request handling. Request bodies are accepted only on MCP `POST`; operational
probes and other MCP methods reject bodies before auth or session handling.
Missing preflight origins, unsupported preflight methods or headers, and
Private Network Access preflights return sanitized 400 responses, with CORS
visibility only for allowed origins and no private-network grant. Idle sessions
are reaped after the configured timeout so abandoned clients do not hold
downstream processes forever. Each initialized HTTP session has its own runtime
lock, so one busy downstream session does not block unrelated HTTP sessions
from initializing or progressing. The MCP endpoint and operational probe paths
are matched exactly; query strings on those paths are rejected before auth,
session, or probe handling. Configured endpoints must be clean origin-form
paths beginning with `/`, without query strings, fragments, whitespace, or
control characters, and cannot reuse `/healthz`, `/readyz`, or `/metrics`.
Use `--allow-origin` or comma-separated `AGENTK_MCP_HTTP_ALLOW_ORIGINS` values
to permit additional browser origins beyond the built-in local defaults. Extra
origins must be exact `scheme://authority` values or `null`, without paths,
queries, fragments, wildcards, whitespace, invalid ports, invalid bracketed IP
literals, invalid DNS labels, percent escapes, or unbracketed IPv6; built-in
localhost/loopback origins only match exact hosts with optional numeric ports
and require a localhost/loopback `Host` authority on the request.
Sandboxed/file `Origin: null` requests are allowed only when `null` is
explicitly configured.
SSE-shaped `GET` requests require `Accept: text/event-stream` plus an existing,
syntactically valid `Mcp-Session-Id`, then return a bounded authenticated
event-stream snapshot from the session buffer with `Last-Event-ID` resume. It also
serves local `GET`/`HEAD` operational probes at `/healthz`,
`/readyz`, and `/metrics`;
`/readyz` reports the supported MCP protocol version plus session,
idle-timeout, and request body caps, while `/metrics` exposes redacted numeric
gateway gauges plus cumulative request, preflight-rejection, session, and
framing-rejection counters for service supervisors. Downstream MCP spawn or
transport failures are returned as sanitized HTTP 502 JSON-RPC errors without
reflecting raw commands, environment values, request payloads, or downstream
stderr, and readiness/metrics count those failures separately from internal
gateway failures.
All MCP HTTP `HEAD` responses omit bodies; `HEAD` on the MCP endpoint remains
an unsupported method response with the normal `Allow` header.
When `AGENTK_MCP_HTTP_TOKEN` is set, `/readyz` and `/metrics` require the same
bearer token as MCP requests; `/healthz` remains open for minimal liveness
checks.

The subprocess proxy operator contract lives in
[docs/mcp-proxy.md](docs/mcp-proxy.md).

## Team Sidecar Starter

Generate the first installable-team bundle:

```sh
cargo install --path .
agentk sidecar-init --out agentk-sidecar
agentk sidecar-check --root agentk-sidecar
agentk sidecar-package --root agentk-sidecar --out dist/agentk-sidecar --archive-out dist/agentk-sidecar.tar --force
```

`sidecar-check` validates the TOML, policy, secret-reference, permission,
external identity mapping, and MCP client snippet shapes without spawning
downstream tools or touching credentials.

The bundle writes a reviewable starter layout:

```txt
agentk-sidecar/
  agentk-sidecar.toml
  team-permissions.toml
  team-identity.toml
  policies/team-sidecar.toml
  secrets.toml
  clients/claude-desktop.mcp.json
  clients/codex-cursor-mcp-command.txt
  demos/safe-agent-demo.md
```

Use it to put AgentK in front of one downstream MCP server, capture
`.agentk/runs/team-sidecar.jsonl` plus
`.agentk/runs/team-sidecar.session.json`, and review the boundary with:

```sh
cargo run --locked -- safe-agent-demo
agentk audit agentk-sidecar/.agentk/runs/team-sidecar.jsonl
agentk approvals agentk-sidecar/.agentk/runs/team-sidecar.jsonl
agentk permissions --path agentk-sidecar/team-permissions.toml
agentk identity-check --identity agentk-sidecar/team-identity.toml --permissions agentk-sidecar/team-permissions.toml
agentk dashboard agentk-sidecar/.agentk/runs/team-sidecar.jsonl --permissions agentk-sidecar/team-permissions.toml --out agentk-sidecar/.agentk/dashboard.html
agentk dashboard-serve agentk-sidecar/.agentk/runs/team-sidecar.jsonl --permissions agentk-sidecar/team-permissions.toml --identity agentk-sidecar/team-identity.toml --store-root agentk-sidecar/.agentk/team-store
agentk store-sync agentk-sidecar/.agentk/runs/team-sidecar.jsonl --permissions agentk-sidecar/team-permissions.toml --identity agentk-sidecar/team-identity.toml --root agentk-sidecar/.agentk/team-store
agentk store-export agentk-sidecar/.agentk/runs/team-sidecar.jsonl --permissions agentk-sidecar/team-permissions.toml --identity agentk-sidecar/team-identity.toml --out agentk-sidecar/.agentk/store
agentk store-check --root agentk-sidecar/.agentk/store
agentk store-push --root agentk-sidecar/.agentk/store --dry-run
agentk trace-inspect agentk-sidecar/.agentk/runs/team-sidecar.jsonl
```

Record local reviewer decisions without modifying the signed trace:

```sh
agentk approve agentk-sidecar/.agentk/runs/team-sidecar.jsonl appr_123456789abc --permissions agentk-sidecar/team-permissions.toml --reviewer tom --reason "one-shot support reply"
agentk deny agentk-sidecar/.agentk/runs/team-sidecar.jsonl appr_123456789abc --permissions agentk-sidecar/team-permissions.toml --reviewer tom --reason "too broad for this profile"
```

The generated `agentk-sidecar.toml` starts with AgentK's built-in minimal MCP
server so the sidecar can be launched immediately. Replace `[downstream]` with
the GitHub, Postgres, Slack, filesystem, or internal MCP server command you want
to govern. MCP clients can run the packaged sidecar launcher as:

```sh
dist/agentk-sidecar/bin/agentk-sidecar
```

Packaged Claude Desktop and generic Codex/Cursor command snippets are written
under `dist/agentk-sidecar/clients/`, alongside `clients/onboarding.md` as the
operator checklist for first-run package verification, client setup, demo,
dashboard/store, notification, and support-bundle steps,
`clients/http-sse-handoff.md` for teams whose MCP client explicitly supports
Streamable HTTP plus bearer-token headers and
`clients/team-audit-dashboard-handoff.md` for the installable local/team
approval, dashboard, and durable audit-store path. The package also writes a relative-path
`manifest.json` with the AgentK version, schema version, stable launchers,
client snippets, local transports, store workflow, and deploy artifacts, plus
`package.lock.json` with relative paths, byte counts, SHA-256 hashes, and
executable-bit expectations for every packaged install file; runtime state under
`sidecar/.agentk` is excluded. Pass `--archive-out dist/agentk-sidecar.tar` to
write a single uncompressed tar handoff after the package self-check passes; the
CLI also writes `dist/agentk-sidecar.tar.sha256` and includes the archive
SHA-256 plus checksum path in JSON for release notes or inventory systems. Run
`agentk sidecar-package-archive-check --archive dist/agentk-sidecar.tar` to
verify the handoff against `dist/agentk-sidecar.tar.sha256` before unpacking or
deploying it. Run
`agentk sidecar-package-install --archive dist/agentk-sidecar.tar --out installed/agentk-sidecar`
to verify, safely unpack, and run the package self-check into a reviewed install
directory; the install writes
`installed/agentk-sidecar/sidecar/.agentk/install-receipt.json` with the
archive filename, checksum filename, SHA-256, AgentK version, and installed file
count for deployment tickets. Run
`agentk sidecar-package-release-manifest --package installed/agentk-sidecar --archive dist/agentk-sidecar.tar --out dist/agentk-sidecar-release-manifest.json`
to write a machine-readable release handoff that binds the installed package,
package lock, archive checksum, and install receipt. Run
`agentk sidecar-package-release-manifest-check --manifest dist/agentk-sidecar-release-manifest.json`
to re-verify that handoff against current package, archive, checksum, and
install receipt files after copy, relocation, or deployment-ticket review. Run
`dist/agentk-sidecar/bin/agentk-package-info` to print the manifest after
copying or installing the package. Run
`dist/agentk-sidecar/bin/agentk-package-check` to validate the manifest,
package lock, package artifacts, launcher modes, launcher preflights,
deploy-template hardening, dummy deploy env examples, the configured
`AGENTK_BIN`, and embedded sidecar bundle after a copy, deploy, or image build.
Run `dist/agentk-sidecar/bin/agentk-sidecar-http-handoff-check --json` to
validate the bounded local HTTP/SSE handoff contract, including the launcher,
env template, manifest `Last-Event-ID` resume contract, and client handoff doc.
Run `dist/agentk-sidecar/bin/agentk-sidecar-team-handoff-check --json` to
validate the local/team approval and audit handoff contract, including the
safe-agent demo, dashboard server, reviewer-scoped permissions, identity
summary, durable team store, notification outbox, manifest, and handoff doc.
Run `dist/agentk-sidecar/bin/agentk-sidecar-ops-handoff --json` when a team
needs one operator artifact: it refreshes the packaged safe-agent demo,
dashboard, exported store, durable team store, Slack/GitHub/email payload
drafts, identity summary, and permissions summary, then writes
`sidecar/.agentk/operator-handoff/operator-handoff.json` and
`sidecar/.agentk/operator-handoff/operator-handoff.md` without sending
notifications or loading Postgres.
Run `dist/agentk-sidecar/bin/agentk-sidecar-doctor --json` after unpacking,
copying, or updating a package. It verifies required launchers, dummy env
templates, bounded HTTP/SSE handoff readiness, dashboard/store handoff
readiness, install receipt provenance, operator handoff artifacts, audit
evidence retention, optional release-manifest binding, and safe-agent demo
integrity, then writes
`sidecar/.agentk/doctor/sidecar-doctor.json` and
`sidecar/.agentk/doctor/sidecar-doctor.md` with concrete remediation steps.
Set `AGENTK_PACKAGE_RELEASE_MANIFEST=dist/agentk-sidecar-release-manifest.json`
or pass `--release-manifest` so the doctor can confirm the package manifest,
package lock, archive checksum, and install receipt hashes still line up.
Run `dist/agentk-sidecar/bin/agentk-sidecar-support-bundle --json` when an
operator needs one support artifact. It refreshes the operator handoff, runs
the sidecar doctor, inventories package manifest/lock/release manifest,
dashboard, store, trace, and notification evidence with byte counts and
SHA-256 hashes, then writes
`sidecar/.agentk/support-bundle/support-bundle.json` and
`sidecar/.agentk/support-bundle/support-bundle.md` without uploading anything
to a hosted service.
Run `dist/agentk-sidecar/bin/agentk-sidecar-permissions-handoff --json` to
write one permissions/identity proof for team review. It validates local
reviewer roles, reviewer-scoped reads, token coverage counts, identity mapping
coverage, authorized approval recording, and fail-closed unknown reviewer
rejection, then writes
`sidecar/.agentk/permissions-handoff/permissions-handoff.json` and
`sidecar/.agentk/permissions-handoff/permissions-handoff.md` without contacting
an IdP or claiming hosted SaaS.
Run `dist/agentk-sidecar/bin/agentk-sidecar-production-preflight --json` before
deployment review to validate supervisor env templates, `sidecar/secrets.toml`,
placeholder coverage, and non-local bind defaults. It writes
`sidecar/.agentk/production-preflight/production-preflight.json` and
`sidecar/.agentk/production-preflight/production-preflight.md` without reading
live secrets, configuring TLS, contacting an IdP, or claiming hosted SaaS.
Run `dist/agentk-sidecar/bin/agentk-sidecar-client-handoff --json` before
client onboarding to validate Claude Desktop, Codex, Cursor, stdio, TCP, and
Streamable HTTP setup artifacts. It writes
`sidecar/.agentk/client-handoff/client-handoff.json` and
`sidecar/.agentk/client-handoff/client-handoff.md` as one hashed onboarding
report.
Run `dist/agentk-sidecar/bin/agentk-sidecar-dashboard-handoff --json` before
dashboard review to refresh the safe-agent demo trace, render the static
approval/audit dashboard, sync the durable team store, and validate dashboard
env handoff evidence. It writes
`sidecar/.agentk/dashboard-handoff/dashboard-handoff.json` and
`sidecar/.agentk/dashboard-handoff/dashboard-handoff.md`.
Run `dist/agentk-sidecar/bin/agentk-sidecar-deploy-handoff --json` before a
service-manager, Docker, or reverse-proxy deployment review. It validates the
packaged service templates and supervisor env examples, then writes
`sidecar/.agentk/deploy-handoff/deploy-handoff.json` and
`sidecar/.agentk/deploy-handoff/deploy-handoff.md` with SHA-256 hashes for
deployment tickets.
Run `dist/agentk-sidecar/bin/agentk-sidecar-demo-handoff --json` for a
first-run team demo packet. It refreshes the credential-free
GitHub/Postgres/Slack/filesystem demo evidence through the operator handoff
path, then writes `sidecar/.agentk/demo-handoff/demo-handoff.json` and
`sidecar/.agentk/demo-handoff/demo-handoff.md` with SHA-256 hashes for the
trace, dashboard, store, and notification payload drafts.
Run `dist/agentk-sidecar/bin/agentk-sidecar-quickstart --json` as the packaged
first-run team command. It validates package health, HTTP/team handoff checks,
the demo handoff, deploy handoff, and support bundle, then writes
`sidecar/.agentk/quickstart/quickstart.json` and
`sidecar/.agentk/quickstart/quickstart.md` as one onboarding report.
Run `dist/agentk-sidecar/bin/agentk-sidecar-permissions-handoff --json` when
the permissions owner wants the narrower authorization handoff without rerunning
the full support bundle.
Run `dist/agentk-sidecar/bin/agentk-sidecar-production-preflight --json` when
the deployment owner wants the narrower env/secret-reference handoff without
rerunning the full support bundle.
Run `dist/agentk-sidecar/bin/agentk-sidecar-client-handoff --json` when the
client owner wants the narrower Claude/Codex/Cursor setup handoff without
rerunning the full support bundle.
Run `dist/agentk-sidecar/bin/agentk-sidecar-dashboard-handoff --json` when the
dashboard owner wants the narrower approval/audit UI and durable team-store
handoff without rerunning the full support bundle.
Set `AGENTK_BIN` to the reviewed AgentK executable path when `agentk` is not on
the service account's `PATH`. The package includes
`deploy/env/*.env.example` files for the HTTP gateway, dashboard, Postgres push,
and local Slack/GitHub/email payload exporters; replace only `CHANGE_ME` values in
service-manager or CI secret storage, not in the packaged examples.
Run `dist/agentk-sidecar/bin/agentk-safe-agent-demo --json` to exercise the
credential-free GitHub/Postgres/Slack/filesystem workflow from the packaged
install; it writes `dist/agentk-sidecar/sidecar/.agentk/runs/safe-agent-demo.jsonl`
for audit review and includes a redacted `trace-inspect` summary in the JSON
report. Set `AGENTK_TRACE` to that path when running
`dist/agentk-sidecar/bin/agentk-dashboard`,
`dist/agentk-sidecar/bin/agentk-dashboard-server`,
`dist/agentk-sidecar/bin/agentk-store-export`, or
`dist/agentk-sidecar/bin/agentk-store-sync` to review or store the packaged
demo trace instead of the default team-sidecar trace. Those packaged demo,
dashboard, sidecar-check, identity-check, and store workflow launchers run the
package self-check before touching package-local evidence or store artifacts.
The team handoff checker and
`dist/agentk-sidecar/clients/team-audit-dashboard-handoff.md` make this a
reviewable local/team sidecar alpha path, not hosted SaaS. The ops handoff
launcher adds a compact JSON/Markdown summary that teams can archive or attach
to a deployment ticket without reading every command output.
Run `dist/agentk-sidecar/bin/agentk-sidecar-check` after editing the packaged
bundle to validate policy, permissions, identity mappings, secret references,
and client snippets without spawning downstream tools. Run
`dist/agentk-sidecar/bin/agentk-identity-check --json` to verify that external
IdP groups map to configured local reviewers; the report prints counts only and
does not print issuers, groups, or claim values. Packaged dashboard-server,
store-export, and store-sync launchers pass the same identity manifest into
the durable store paths, which write redacted identity summaries plus
IdP group-to-reviewer mapping tables that omit issuer, audience, and claim
values for team review/control-plane ingestion.
For internal adapters that need a local TCP JSONL endpoint instead of stdio, run
`dist/agentk-sidecar/bin/agentk-sidecar-tcp`; it loads the same reviewed
sidecar bundle, runs the package self-check before binding, listens on
`127.0.0.1:9797` by default, bounds concurrent sessions with
`AGENTK_MCP_TCP_MAX_CONCURRENT_SESSIONS`, and writes per-session trace/session
reports.
For MCP clients or adapters that support Streamable HTTP POST locally, run
`dist/agentk-sidecar/bin/agentk-sidecar-http`; it loads the same reviewed
bundle, runs the package self-check before binding, binds localhost by default,
answers allowed browser preflights, requires `AGENTK_MCP_HTTP_TOKEN` when that
environment variable is set, enforces
origin/session checks, rejects malformed `Mcp-Session-Id` values before
lookup, and writes the same trace/session evidence. It serves local `GET`/`HEAD`
operational probes at `/healthz`, `/readyz`, and `/metrics`,
and rejects unsupported `MCP-Protocol-Version` headers, oversized request
bodies, or excess initialized sessions, and reaps idle sessions. `/readyz`
reports the configured allowed-origin count without raw origin values;
`/metrics` reports redacted numeric gateway gauges plus cumulative request,
rejection, and session lifecycle counters for supervisors. Additional allowed
origins must be exact `scheme://authority` values or `null`, not wildcard or
path-bearing URL patterns, and IPv6 origins must be bracketed with a valid
IPv6 literal. `Origin: null` is not a built-in local origin; list `null`
explicitly only for trusted sandboxed/file browser adapters. Built-in
localhost/loopback origins apply only to requests with localhost/loopback
`Host`; browser adapters that call a non-local gateway name must be listed
explicitly. Non-loopback HTTP binds fail closed unless
`--allow-non-local-bind` is passed; the packaged launcher only passes it when
`AGENTK_MCP_HTTP_ALLOW_NON_LOCAL_BIND=true`, and those binds also require a
non-empty `AGENTK_MCP_HTTP_TOKEN`. The packaged HTTP launcher forwards extra
arguments to `sidecar-serve-http`, so operators can add one-off flags such as
`--allow-origin` or `--auth-token-env` without editing the package script.
`dist/agentk-sidecar/clients/http-sse-handoff.md` documents the finite
authenticated buffered SSE alpha with `Accept: text/event-stream`,
`Mcp-Session-Id`, `MCP-Protocol-Version`, and optional `Last-Event-ID` resume;
it is a bounded local adapter, not a hosted production MCP control plane.
Malformed request lines or header lines,
including invalid UTF-8, duplicate or non-decimal `Content-Length`
headers, LF-only line endings, control characters in header values, and any
`Transfer-Encoding`, `Content-Encoding`, `Expect`, or `Upgrade` header are
rejected as invalid framing. Request bodies must be unencoded fixed-length
payloads, and MCP POST bodies must be single JSON-RPC 2.0 request or
notification objects with string `method` fields. WebSocket handshake headers
such as `Sec-WebSocket-Key` and `Sec-WebSocket-Protocol` are rejected because
this launcher serves the Streamable HTTP adapter, not WebSocket. Only
`Connection: close` is accepted; other `Connection` values plus
`Proxy-Connection`, `Keep-Alive`, `TE`, and `Trailer` headers are rejected.
Forwarded proxy metadata is rejected by default; set
`AGENTK_MCP_HTTP_TRUST_PROXY_HEADERS=1` only behind a reviewed reverse proxy
that strips untrusted inbound forwarded headers before adding clean
`Forwarded` or `X-Forwarded-*` metadata.
Ambient cookie headers such as `Cookie` and `Set-Cookie` are rejected because
the gateway uses explicit bearer/reviewer tokens instead.
Method override headers such as `X-HTTP-Method-Override` and
`X-Method-Override` are rejected so gateway routes cannot be reinterpreted by
intermediaries.
Proxy and trace methods such as `CONNECT`, `TRACE`, and `TRACK` are rejected
before route handling.
Request lines must be exactly space-delimited, header names must be
token-shaped without whitespace before `:`, request targets must begin with
exactly one `/` and must not contain fragments, and duplicate MCP control
headers and dual token-carrier headers are rejected as ambiguous.
All accepted HTTP requests must include exactly one clean `Host` authority with
no userinfo, wildcards, paths, queries, fragments, invalid ports, or
invalid DNS labels, percent escapes, or unbracketed IPv6 literals. Truncated
headers or bodies are rejected before request handling. The configured header
byte cap is enforced while each request line and header line is read, so
oversized unterminated lines fail closed before unbounded buffering. Request
bodies are accepted only on MCP endpoint `POST`; unknown routes, CORS
preflights, probes, and session-control requests reject bodies before route
fallback or auth handling. CORS preflights must include an allowed `Origin`, are
limited to `POST`, `DELETE`, and known MCP HTTP headers, and reject Private
Network Access requests until AgentK has an explicit private-network policy.
MCP endpoint and
operational probe paths
are matched exactly; query strings on those paths are rejected before auth,
session, or probe handling. The configured endpoint must be a clean origin-form
path beginning with `/`, without query strings, fragments, whitespace, or
control characters, and cannot reuse `/healthz`, `/readyz`, or `/metrics`.
LAN/public exposure is therefore an explicit authenticated operator choice. Set
`AGENTK_MCP_HTTP_MAX_ACTIVE_SESSIONS`,
`AGENTK_MCP_HTTP_SESSION_IDLE_TIMEOUT_MS`, and
`AGENTK_MCP_HTTP_MAX_BODY_BYTES` to tune packaged session/body behavior,
`AGENTK_MCP_HTTP_MAX_HEADER_BYTES` to bound request headers, and
`AGENTK_MCP_HTTP_STREAM_TIMEOUT_MS` to bound accepted connection reads and
writes. SSE-shaped `GET` requests require `Accept: text/event-stream` plus an
existing, syntactically valid `Mcp-Session-Id`, pass the same auth/origin/protocol
checks, and return bounded buffered events with `Last-Event-ID` resume. All MCP
HTTP `HEAD` responses omit bodies; `HEAD` on the MCP
endpoint remains an unsupported method response with the normal `Allow` header.
This is a bounded local adapter, not a hosted production
HTTP/SSE control plane. Set comma-separated `AGENTK_MCP_HTTP_ALLOW_ORIGINS`
when an approved browser adapter runs from a non-local origin. When the bounded
HTTP gateway exits, it drains active initialized sessions and writes their
redacted trace/session reports.
`dist/agentk-sidecar/bin/agentk-dashboard-server` serves the local review UI and
`/api/review` JSON endpoint on `127.0.0.1:8765` after running the packaged
sidecar check. It also serves `/healthz`, a redacted `/readyz`, and redacted
`/metrics` gauges for service supervisors; dashboard probe paths are matched
exactly and reject query strings.
The dashboard server binds to `127.0.0.1` by default; non-loopback binds require
`--allow-non-local-bind` plus a non-empty dashboard admin token so exposing the
review UI is an explicit authenticated operator choice. In that mode, dashboard
reads, `/readyz`, and `/metrics` require the same admin token; `/healthz`
remains open for liveness probes.
Accepted dashboard HTTP connections use a 30000 ms read/write timeout; set
`--stream-timeout-ms` or packaged `AGENTK_DASHBOARD_STREAM_TIMEOUT_MS` to tune
deployments.
Dashboard request buffering is bounded; set `--max-body-bytes`,
`--max-header-bytes`, or packaged `AGENTK_DASHBOARD_MAX_BODY_BYTES` and
`AGENTK_DASHBOARD_MAX_HEADER_BYTES` to tune deployments. Oversized dashboard
request bodies return sanitized 413 responses, and oversized request lines or
headers return sanitized 431 responses.
Reviewers can record approve/deny decisions from the browser page, and the same
permission-checked JSON decision API is available at
`/api/approve` and `/api/deny`. Dashboard request bodies are accepted only on
those decision endpoints and must declare `Content-Type: application/json`, so
review reads and probes cannot smuggle ignored payload bytes. Duplicate
`Content-Type` headers fail closed before decision parsing. Decision endpoint
paths are matched exactly and reject query strings. Dashboard decision JSON
object keys must be unique and limited to `id`, `reviewer`, `reason`, and
`reviewer_token`. Configure the dashboard admin-token environment
variable documented in
[docs/mcp-proxy.md](docs/mcp-proxy.md) to require an admin header on write
requests; clients must choose either the standard authorization bearer header or
`X-AgentK-Admin-Token`, not both, and the chosen carrier may appear only once.
If the reviewer has `token_env` in
`team-permissions.toml`, scoped
`/api/review?reviewer=<id>` reads must include `X-AgentK-Reviewer-Token`, and
write requests must include `reviewer_token` matching that environment
variable. Dashboard and MCP HTTP responses include no-store, no-sniff,
no-referrer, anti-framing, and local-only CSP headers:

```sh
curl -sS -H "X-AgentK-Reviewer-Token: <reviewer-secret>" \
  "http://127.0.0.1:8765/api/review?reviewer=tom"

curl -sS -H "X-AgentK-Admin-Token: <admin-secret>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:8765/api/approve \
  -d '{"id":"appr_123456789abc","reviewer":"tom","reason":"one-shot approval","reviewer_token":"<reviewer-secret>"}'
```

The served dashboard has a reviewer view. Enter a reviewer id and token, then
use **My View** to load only the approvals and decisions that reviewer is
authorized to see. Direct scoped HTML views are also available at
`/?reviewer=<id>` and enforce the same reviewer token checks. Token-protected
reviewer reads must choose either `X-AgentK-Reviewer-Token` or the
`reviewer_token` query parameter, not both, and the chosen carrier may appear
only once. Scoped `reviewer` and `requester` query parameters may appear only
once and cannot be combined in one request. Dashboard review routes reject
unsupported query parameters, and reviewer-token carriers are accepted only on
reviewer-scoped reads.
It also has a requester view: enter an AgentK agent id and use **Agent View**,
or open `/?requester=<agent-id>`, to see only approvals and decisions produced
by that signed agent identity.
Both the static and served dashboards include the same redacted inspect evidence
summary as the CLI: final hash, signature status, allow/block counts, blocked
policy rules, syscall rollups, and evidence-ref counts such as `args_sha256`,
`descriptor_sha256`, and `response_sha256`.

`agentk store-export` writes normalized audit, approval, and permission JSON
plus a Postgres schema contract and psql-loadable TSV files for teams that want
a shared audit store. `agentk store-sync` maintains a live local team store
with current redacted JSON snapshots plus normalized JSONL tables for dashboard
or control-plane processes, including blocked-rule, syscall, and evidence-ref
summary rows. It also writes `current/notifications.json` and
`tables/notifications.jsonl`, a credential-free outbox for pending approval
requests and recorded decisions that Slack, GitHub, email, or ticket bridges
can consume without AgentK storing delivery tokens. `agentk store-slack` turns
that durable outbox into local Slack-ready JSON payloads without reading Slack
tokens, and `agentk store-slack-send` can deliver those payloads through `curl`
with a webhook URL read only from environment. `agentk store-github` turns the
same outbox into local GitHub issue-ready JSON payloads, `agentk
store-github-send` can deliver them through `gh` with a token read only from
environment, `agentk store-email` exports sendmail-ready local payloads, and
`agentk store-email-send` can deliver them through a local mail relay. `agentk
store-check` validates both exported Postgres artifacts and the live durable
team store.
`dashboard-serve --store-root ...` refreshes the same durable store on review
reads and reviewer decisions:

```sh
agentk store-sync agentk-sidecar/.agentk/runs/team-sidecar.jsonl --permissions agentk-sidecar/team-permissions.toml --identity agentk-sidecar/team-identity.toml --root agentk-sidecar/.agentk/team-store
agentk store-check --root agentk-sidecar/.agentk/team-store
agentk store-slack --root agentk-sidecar/.agentk/team-store --out agentk-sidecar/.agentk/slack --channel '#agentk-approvals'
agentk store-slack-send --payload-root agentk-sidecar/.agentk/slack --webhook-url-env AGENTK_SLACK_WEBHOOK_URL --dry-run
agentk store-github --root agentk-sidecar/.agentk/team-store --out agentk-sidecar/.agentk/github --repository owner/repo --label agentk --label approvals
agentk store-github-send --payload-root agentk-sidecar/.agentk/github --github-token-env GITHUB_TOKEN --dry-run
agentk store-email --root agentk-sidecar/.agentk/team-store --out agentk-sidecar/.agentk/email --to agentk-alerts@example.com
agentk store-email-send --payload-root agentk-sidecar/.agentk/email --dry-run
```

For Postgres import:

```sh
cd agentk-sidecar/.agentk/store
agentk store-check --root .
agentk store-push --root . --dry-run
agentk store-push --root .
```

Packaged installs include the same workflow as stable launchers:

```sh
dist/agentk-sidecar/bin/agentk-package-info
AGENTK_BIN="$(command -v agentk)" dist/agentk-sidecar/bin/agentk-package-check
sed -n '1,220p' dist/agentk-sidecar/clients/onboarding.md
agentk sidecar-package-archive-check --archive dist/agentk-sidecar.tar
agentk sidecar-package-install --archive dist/agentk-sidecar.tar --out installed/agentk-sidecar
agentk sidecar-package-release-manifest --package installed/agentk-sidecar --archive dist/agentk-sidecar.tar --out dist/agentk-sidecar-release-manifest.json
agentk sidecar-package-release-manifest-check --manifest dist/agentk-sidecar-release-manifest.json
dist/agentk-sidecar/bin/agentk-sidecar-http-handoff-check --json
dist/agentk-sidecar/bin/agentk-sidecar-team-handoff-check --json
dist/agentk-sidecar/bin/agentk-sidecar-ops-handoff --json
AGENTK_PACKAGE_RELEASE_MANIFEST=dist/agentk-sidecar-release-manifest.json \
  installed/agentk-sidecar/bin/agentk-sidecar-doctor --json
AGENTK_PACKAGE_RELEASE_MANIFEST=dist/agentk-sidecar-release-manifest.json \
  installed/agentk-sidecar/bin/agentk-sidecar-support-bundle --json
installed/agentk-sidecar/bin/agentk-sidecar-deploy-handoff --json
installed/agentk-sidecar/bin/agentk-sidecar-demo-handoff --json
AGENTK_PACKAGE_RELEASE_MANIFEST=dist/agentk-sidecar-release-manifest.json \
  installed/agentk-sidecar/bin/agentk-sidecar-quickstart --json
installed/agentk-sidecar/bin/agentk-sidecar-permissions-handoff --json
installed/agentk-sidecar/bin/agentk-sidecar-production-preflight --json
installed/agentk-sidecar/bin/agentk-sidecar-client-handoff --json
installed/agentk-sidecar/bin/agentk-sidecar-dashboard-handoff --json
dist/agentk-sidecar/bin/agentk-safe-agent-demo --json
AGENTK_TRACE=dist/agentk-sidecar/sidecar/.agentk/runs/safe-agent-demo.jsonl \
  dist/agentk-sidecar/bin/agentk-dashboard --json
dist/agentk-sidecar/bin/agentk-sidecar-check
dist/agentk-sidecar/bin/agentk-store-export
dist/agentk-sidecar/bin/agentk-store-check
dist/agentk-sidecar/bin/agentk-store-sync
dist/agentk-sidecar/bin/agentk-store-push --dry-run
dist/agentk-sidecar/bin/agentk-store-slack --channel '#agentk-approvals'
dist/agentk-sidecar/bin/agentk-store-slack-send --dry-run
dist/agentk-sidecar/bin/agentk-store-github --repository owner/repo --label agentk --label approvals
dist/agentk-sidecar/bin/agentk-store-github-send --dry-run
dist/agentk-sidecar/bin/agentk-store-email --to agentk-alerts@example.com
dist/agentk-sidecar/bin/agentk-store-email-send --dry-run
```

Maintainers can run `cargo run --locked -- release-status` to summarize the
v0.2 alpha shipped surfaces, accepted limits, final blockers, and verification
gates. Run `cargo run --locked -- release-ticket --out dist/release-ticket --force`
to create one offline reviewer handoff directory containing release status,
release-candidate smoke evidence, evidence-check results, finalization evidence,
and a summary ticket JSON with explicit product-objective coverage checks,
without tagging, pushing, uploading, or publishing.
The individual steps remain available: run
`cargo run --locked -- release-candidate-smoke --root dist/release-candidate-smoke --force --keep-root --evidence-out dist/release-candidate-smoke.json`
to recreate the package, archive, checksum, and release manifest in a
repo-local smoke root, execute the packaged HTTP and team handoff checks,
safe-agent demo, dashboard, sidecar check, store export/check/sync, operator
handoff artifact, support bundle JSON/Markdown, deploy handoff JSON/Markdown,
release-manifest check, sidecar doctor release-manifest binding,
Slack/GitHub/email payload exporters, and Postgres dry-run push
launchers, then write one JSON evidence report with SHA-256 and byte counts for
the required handoff artifacts before a release branch or tag. Then run
`cargo run --locked -- release-evidence-check --evidence dist/release-candidate-smoke.json --root dist/release-candidate-smoke`
to re-verify that release-ticket evidence against the current package, archive,
release manifest, dashboard, store, notification, and handoff files.
Then run
`cargo run --locked -- release-finalize --release v0.2-alpha --evidence dist/release-candidate-smoke.json --root dist/release-candidate-smoke --notes docs/v0.2-alpha-release-notes.md --out dist/release-finalization.json`
to write the final local handoff report that binds the release commit, release
notes hash, package archive SHA-256, package release manifest, saved smoke
evidence, active evidence-signing public key, worktree state, and optional
signed tag verification. `release-finalize` does not create tags, push, or
publish a GitHub release; after a maintainer creates a signed tag, rerun it with
`--tag vX.Y.Z --strict` before publication.
Then run
`cargo run --locked -- release-publication-check --finalization dist/release-finalization.json --notes docs/v0.2-alpha-release-notes.md`
to verify the strict finalization report, signed-tag evidence, production-ready
evidence signer, package archive hash, release-manifest path, and final release
notes evidence fields before creating the GitHub release page. This check is
still offline; it does not tag, push, upload assets, or publish a release.
For a Homebrew tap handoff, generate a reviewed formula from the final source
tarball URL and SHA:

```sh
agentk release-homebrew-formula \
  --source-url https://github.com/OWNER/REPO/archive/refs/tags/vX.Y.Z.tar.gz \
  --sha256 <source-tarball-sha256> \
  --version X.Y.Z \
  --homepage https://github.com/OWNER/REPO \
  --out dist/homebrew/agentk.rb
agentk release-homebrew-formula-check \
  --formula dist/homebrew/agentk.rb \
  --source-archive dist/agentk-vX.Y.Z.tar.gz \
  --source-url https://github.com/OWNER/REPO/archive/refs/tags/vX.Y.Z.tar.gz \
  --sha256 <source-tarball-sha256> \
  --version X.Y.Z \
  --homepage https://github.com/OWNER/REPO
agentk release-homebrew-tap-handoff-check \
  --formula dist/homebrew/agentk.rb \
  --tap-root ../homebrew-agentk \
  --tap-formula-path Formula/agentk.rb \
  --source-archive dist/agentk-vX.Y.Z.tar.gz \
  --source-url https://github.com/OWNER/REPO/archive/refs/tags/vX.Y.Z.tar.gz \
  --sha256 <source-tarball-sha256> \
  --version X.Y.Z \
  --homepage https://github.com/OWNER/REPO \
  --tap OWNER/agentk
```

The commands write and verify a local formula, then verify that a local tap
checkout contains the same formula file and has no unrelated dirty paths.
AgentK does not publish a tap.

`dist/agentk-sidecar/deploy/` includes systemd, launchd, Docker Compose, and
reverse-proxy templates for running the packaged MCP HTTP sidecar gateway,
dashboard, and store workflow after review; packaged runtime launchers run the package
self-check before launching, serving, writing demo traces, rendering dashboards,
or updating store artifacts. `agentk-package-check` also verifies
baseline deploy-template hardening markers, including no-new-privileges systemd
services, a non-root package Dockerfile, and loopback-published,
capability-dropped, read-only Compose services, plus dummy env examples with
required variables and no real-looking credentials. `deploy/proxy/Caddyfile`
and `deploy/proxy/nginx.conf` route `/mcp` to `127.0.0.1:9798`, route
dashboard/API/probe paths to `127.0.0.1:8765`, strip ambient cookies and proxy
auth headers, and provide reviewed starting points for TLS, external auth, and
network policy in the deployment layer.
The packaged safe-agent demo JSON includes the same redacted inspect counts,
syscall summary, evidence-ref summary, and blocked policy rules that
`trace-inspect` would show separately.

This is the productization path: sidecar first, then approval broker,
dashboard, multi-user policy, and local packaging.
The concrete milestone plan lives in
[docs/productization-plan.md](docs/productization-plan.md).

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
- provider-specific reference-shape validation for AWS Secrets Manager, GCP
  Secret Manager, Azure Key Vault, Vault, and 1Password without contacting
  those services,
- a redacted secret-reference manifest validation command,
- a redacted secret-reference store availability command,
- a hash-chained flight recorder,
- log verification,
- receipt and secret-handle signature verification with optional trusted-key
  pinning and redacted signer summaries,
- a redacted public trusted-signer manifest for verifier pinning,
- redacted flight-log inspection for human review,
- deterministic side-effect-free replay,
- fork replay with policy comparison and decision-change summaries,
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

- complete the remaining [productization plan](docs/productization-plan.md)
  release gaps,
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
- trace inspection summaries that group boundary events by syscall and evidence
  ref type,
- deterministic replay that stubs side effects and summarizes blocked policy
  rules,
- fork replay with policy comparison and decision-change summaries,
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
- subprocess MCP pre-ready notification guards so client notifications cannot
  bypass lifecycle gating,
- subprocess MCP duplicate-initialized notification guards so lifecycle signals
  cannot be replayed downstream after readiness,
- downstream subprocess MCP notification-burst handling without raw payload
  reflection,
- downstream subprocess MCP notification-flood bounds without raw payload
  reflection,
- downstream subprocess MCP clean shutdown on client EOF, with forced cleanup
  only after a short grace period,
- subprocess MCP stderr suppression for downstream diagnostics,
- subprocess MCP lifecycle error redaction for downstream `initialize` and
  `ping` failures,
- subprocess MCP initialize protocol guards before the proxy becomes ready,
- subprocess MCP `tools/list` error redaction before descriptors are exposed,
- subprocess MCP tool-shape guards for malformed `tools/list` and successful
  `tools/call` results,
- subprocess MCP bad-response redaction for malformed JSON and mismatched
  response ids,
- subprocess MCP resource subscription no-passthrough coverage for unsupported
  `resources/subscribe` and `resources/unsubscribe`,
- subprocess MCP invalid AgentK metadata redaction before unsafe requests are
  forwarded,
- subprocess MCP client intent hashing so AgentK-only metadata does not leak
  through trace evidence,
- subprocess MCP invalid client-parameter guards before empty identifiers can
  reach downstream servers,
- compact denial summaries on blocked MCP tool, resource, and prompt responses,
- subprocess MCP response timeout handling for hung downstream servers,
- subprocess MCP transport-close handling for child exits and broken pipes,
- a runnable MCP killer demo that blocks poisoned-output exfiltration and
  unsafe patch attempts,
- a one-command `mcp-killer-demo` runner for reviewable demo traces,
- a one-command `mcp-shim-eval` scorecard for showing why the shim matters,
- a minimal MCP JSON-RPC stdio server,
- local key generation and signed key-rotation manifests,
- local Homebrew formula generation, formula/archive verification, and tap
  checkout handoff checks for a reviewed source release URL and SHA-256,
- offline release-publication preflight for final GitHub release notes, signed
  tag evidence, package archive hash, and finalization handoff consistency,
- a local release audit that runs formatting, tests, clippy, readiness, replay,
  signature, signer summaries, signer-pinning, trusted-signer manifest, secret-handle,
  secret-reference validation, secret-store availability, MCP taint-flow,
  subprocess MCP boundaries, lifecycle/list redaction, initialize guards,
  tool/resource/prompt shape guards, bad-response redaction, response timeouts,
  transport-close checks, mixed interop, public interop transcripts, resource
  subscription no-passthrough, pre-ready notification guards,
  notification-burst/flood checks, config and metadata guards,
  client-intent redaction, invalid client-parameter guards, denial summaries,
  no-passthrough checks, the MCP shim eval, inspect, and MCP server smoke
  checks.

Not implemented yet:

- production key storage and complete key lifecycle management,
- production MCP server transport,
- production secret storage,
- real sandboxing,
- eBPF/cgroup enforcement.

By default AgentK signs evidence with a static development key. Set `AGENTK_SIGNING_KEY_FILE` to a private key file created by `agentk keygen`, or set `AGENTK_SIGNING_KEY_HEX` to a 32-byte hex Ed25519 signing key for non-demo runs. Set `AGENTK_REQUIRE_SIGNING_KEY=1` in release gates to fail readiness if the configured signer falls back to the development key. Set `AGENTK_RELEASE_REMOTE_APPROVED=1` only after release approval and branch-protection review so strict release gates can pass with the approved public remote configured. On Unix, readiness also fails if the configured key file is readable by group/other users or if its parent directory is group/other writable. The CLI only prints the public key.

See [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md), [docs/key-lifecycle.md](docs/key-lifecycle.md), [docs/mcp-proxy.md](docs/mcp-proxy.md), and [docs/public-readiness.md](docs/public-readiness.md).

## Name

**AgentK**: short for Agent Kernel.

Small name. Sharp edges.
