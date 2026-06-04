# AgentK Productization Plan

AgentK should become a polished installable team product without losing its
wedge: an agent action firewall and flight recorder for MCP/tool-call
governance. The gateway is a delivery surface, not the product thesis.

The current v0.2 alpha release candidate keeps that security proof and packages
it as an installable local/team MCP sidecar. A team can generate or install the
sidecar, put it in front of Claude, Codex, Cursor, or another MCP client, run a
safe GitHub/Postgres/Slack/filesystem-shaped demo, and review approvals,
permissions, dashboard evidence, deploy handoff, support bundle, notification
payloads, and release-ticket artifacts without using a hosted control plane.

## Product Shape

AgentK should let a team put a sidecar between an MCP client and one or more
downstream tool servers, then answer four operator questions:

- What did the agent try to do?
- Which boundary did it cross?
- Which policy allowed or denied it?
- What evidence can we replay or review before widening access?

The public language can say "AI agent firewall" and "flight recorder", but the
implementation should stay narrow: MCP action governance, taint/capability
policy, approval hooks, and audit evidence. Do not turn AgentK into a generic
universal AI gateway, planner, memory system, or hosted agent framework.

## Current Baseline

Implemented today:

- local subprocess stdio MCP proxy for tools, resources, prompts, lifecycle
  checks, redaction, no-passthrough behavior, response timeouts, and trace
  output plus redacted session summaries;
- bounded local MCP Streamable HTTP adapter admission checks for malformed
  JSON-RPC request shapes and malformed `id` values before downstream
  forwarding, session lookup, message-budget use, or SSE buffer updates;
- before/after MCP shim eval and killer demo;
- hash-first trace inspection, replay, fork replay, and signature verification;
- `audit`, which turns a trace into a small audit and approval inbox with
  pending approvals, blocked-rule counts, and allowed side-effect summaries;
- `approvals`, `approve`, and `deny`, which provide an append-only local review
  surface over signed trace events without silently replaying blocked actions;
- local release audit, release-candidate smoke evidence, and v0.2 alpha
  release-ticket handoff evidence;
- `sidecar-init`, which generates a starter team sidecar bundle with policy,
  secret-reference, MCP client, and safe-agent demo files;
- secret-reference manifests that validate local env refs plus production-shaped
  AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Vault, and
  1Password refs without fetching secret bytes or printing raw refs;
- `sidecar-check`, which validates a generated sidecar bundle without spawning
  downstream tools or touching credentials, including Claude Desktop and
  Codex/Cursor client snippet shape.
- `safe-agent-demo`, which runs a no-credential mock GitHub/Postgres/Slack/
  filesystem workflow where risky writes and exfiltration are blocked while
  safe reads and drafts still work;
- `sidecar-package`, which writes a deployable sidecar folder plus optional
  single-file tar handoff and checksum with stable launchers,
  Claude/Codex/Cursor snippets, an operator onboarding checklist,
  service/container templates, dummy deploy env examples, `manifest.json`, and
  a hash/mode `package.lock.json`;
- `sidecar-package-archive-check`, which verifies the tar handoff against the
  generated checksum before a team unpacks or deploys it;
- `sidecar-package-install`, which verifies the tar handoff, safely unpacks it,
  runs the package self-check, and writes an install receipt before placing an
  installed sidecar directory;
- `sidecar-package-release-manifest`, which writes a machine-readable release
  handoff binding the installed package, package lock, archive checksum, and
  install receipt without changing the locked package directory;
- `sidecar-package-release-manifest-check`, which re-verifies that handoff
  against the current package, archive checksum, package lock, and install
  receipt before rollout or support handoff;
- `dashboard` and `dashboard-serve`, which provide static and local served
  approval/audit review surfaces with permission-checked approve/deny APIs;
- `team-permissions.toml`, scoped reviewer roles, reviewer tokens, and durable
  local audit-store sync/export/check/push with identity mapping metadata that
  omits issuer, audience, and claim values plus Slack/GitHub/email payload paths
  for team workflows;
- `store-slack`, `store-slack-send`, `store-github`, and
  `store-github-send`, `store-email`, and `store-email-send`, which export
  Slack-ready, GitHub issue-ready, and sendmail-ready JSON payloads from the
  durable notification outbox and can deliver those payloads with
  webhook/token/relay values read only from environment without storing delivery
  secrets;
- a release-candidate smoke gate that recreates the package/archive, runs the
  packaged safe-agent demo, dashboard, sidecar check, store export/check/sync,
  one compact operator handoff report, one sidecar doctor support/remediation
  report with release-manifest binding, release-manifest verification,
  Slack/GitHub/email payload exporters, and Postgres dry-run push flow.
- `release-evidence-check`, which re-validates a saved release-candidate smoke
  evidence JSON against the current package, archive, release manifest,
  dashboard, store, notification, and handoff artifact byte counts and
  SHA-256s before a maintainer attaches it to a release or deployment ticket.
- `release-finalize`, which writes one offline final release handoff report
  binding the release commit, release notes hash, package archive SHA-256,
  package release manifest, saved smoke evidence, active evidence-signing
  public key, worktree state, and optional signed-tag verification without
  tagging, pushing, uploading, or publishing.
- `release-homebrew-formula`, `release-homebrew-formula-check`, and
  `release-homebrew-tap-handoff-check`, which write and verify a reviewed local
  Homebrew formula from a source release URL plus SHA-256, then verify a local
  tap checkout has the exact reviewed formula and no unrelated dirty files
  without publishing a tap.
- `release-publication-check`, which verifies a strict finalization handoff,
  production-ready evidence signer, signed tag evidence, package archive
  SHA-256, release-manifest path, and final release-note evidence fields before
  a maintainer creates the GitHub release page without tagging, pushing,
  uploading, or publishing.
- `release-ticket`, which writes the offline reviewer bundle for the current
  v0.2 alpha release candidate, including release status, accepted-limit
  checks, smoke evidence, release finalization, product-objective checks, and a
  top-level artifact inventory for package, quickstart, dashboard, client,
  permissions, deploy, support, demo, store, notification, service-template,
  and Homebrew handoff files.

Still missing for a team product:

- final signed release publication on a protected public branch and actual
  GitHub release asset upload by a maintainer;
- production secret/key storage integrations beyond local env/file adapters and
  provider-specific reference-shape checks;
- live external identity verification, hosted/ticket notification
  delivery, and hosted control-plane integrations;
- published binary distribution channels such as a maintained Homebrew tap or
  package-manager formulas;
- long-running production operations hardening beyond the current local
  sidecar, service templates, env examples, and release-gated stdio/TCP/
  Streamable HTTP transports.

## Milestones

### P0: Team Sidecar Alpha

Goal: a team can install AgentK, generate a sidecar bundle, put it in front of a
single downstream stdio MCP server, and review a redacted audit trace.

Exit criteria:

- `agentk sidecar-init` creates a reviewable starter bundle.
- `agentk sidecar-check` validates the bundle before live use.
- README and generated bundle explain Claude/Codex/Cursor command wiring.
- The sidecar path requires no secrets in repo files and no public announcement.
- The generated policy starts audit-first and default-deny.

### P1: Safe-Agent Demo Pack

Goal: a low-risk packaged demo shows useful team workflows across GitHub,
Postgres, Slack, and filesystem-shaped tools without real credentials.

Exit criteria:

- local mock MCP servers or fixtures for each tool family;
- one command to run the demo through baseline and AgentK modes;
- expected blocks for writes, exfiltration, unsafe patches, and destructive SQL;
- trace-inspect output that a reviewer can understand without reading source.

### P2: Local Audit And Approval UX

Goal: an operator can review decisions without reading JSONL by hand.

Exit criteria:

- local dashboard or TUI reads trace files or a local event store;
- denials are grouped by policy rule, target, agent, and missing capability;
- replay/fork-replay/signature status is visible from the review surface;
- approval decisions are recorded as evidence instead of silently bypassing
  policy.

### P3: Team Control Plane

Goal: a small team can run AgentK with shared policy and audited permissions.

Exit criteria:

- multi-user identity model with roles such as owner, security reviewer,
  developer, and auditor;
- policy bundles scoped by team/project/server/tool;
- durable Postgres-backed audit and approval store;
- secret references remain references, not raw secret values;
- Slack/GitHub/email notification integrations can notify and review without granting
  broad tool execution authority.

### P4: Production MCP Gateway

Goal: teams can deploy AgentK as a hardened sidecar/gateway in front of MCP
clients and servers.

Exit criteria:

- production MCP transport support beyond local subprocess stdio;
- process lifecycle, concurrency, backpressure, observability, and graceful
  shutdown behavior;
- deployable package/container/Homebrew-style install path;
- documented key custody, rotation, and verification operations;
- compatibility guidance for Claude, Codex, Cursor, and common MCP servers.

## First Implementation Slice

The safest first productization slice is the local team sidecar path:

1. `sidecar-init` is the Alpha-0 onboarding command.
2. `sidecar-check` parses `agentk-sidecar.toml`, validates referenced policy
   and secret-reference manifests, checks client snippets for unresolved
   placeholders, verifies audit paths stay under the sidecar bundle, and prints
   a redacted readiness report.
3. The checker is non-spawning and credential-free. It does not contact GitHub,
   Slack, Postgres, or a live filesystem tool.
4. `safe-agent-demo` exercises the team workflow with no live credentials.
   Packaged sidecars include `bin/agentk-safe-agent-demo`, which runs the same
   no-credential GitHub/Postgres/Slack/filesystem workflow and writes a
   package-local trace for audit review. The packaged dashboard and store
   launchers accept `AGENTK_TRACE`, so the demo trace can feed the same
   dashboard, durable store sync, and Postgres export path as a live sidecar
   trace. The demo report embeds the redacted trace-inspect summary so one JSON
   run shows the scorecard, audit inbox, syscall summary, evidence-ref summary,
   and blocked rules without requiring source-code inspection.
   `release-audit` also runs the packaged release-candidate smoke so the
   generated sidecar, launchers, dashboard, durable store, Postgres export, and
   dry-run push path are release-gated together.
5. `sidecar-run --root agentk-sidecar` reads the reviewed TOML bundle, resolves
   the configured downstream MCP command, copies only explicit allowed env vars,
   proxies stdio through AgentK, and writes the configured audit log. The
   generated bundle defaults to AgentK's built-in minimal MCP server so teams
   can test the run path before attaching live GitHub, Postgres, Slack, or
   filesystem tools.
6. `approvals`, `approve`, and `deny` reconcile pending audit items against an
   append-only local decision log. Decisions are tied to event hashes and trace
   final hashes, so a changed trace makes old decisions stale instead of
   silently carrying them forward.
7. `team-permissions.toml` gives the starter bundle local users, reviewer roles,
   and approval scopes. `team-identity.toml` maps external IdP groups onto
   those local reviewers without storing or printing live identity claims.
   `agentk permissions` reports configured reviewers, `agentk identity-check`
   verifies mapped-reviewer coverage against permissions, and
   `approve`/`deny --permissions ...` enforce reviewer authority before
   appending a decision.
8. `dashboard` writes a static local HTML approval dashboard from the signed
   trace, append-only decisions, and optional permissions manifest. The static
   and served dashboards surface the redacted inspect evidence summary directly:
   final hash, signature status, allow/block counts, blocked policy rules,
   syscall rollups, and evidence-ref counts such as `args_sha256`,
   `descriptor_sha256`, and `response_sha256`.
9. `sidecar-package` validates a sidecar bundle and writes a local deployable
   package with launcher scripts, a package-local `agentk-sidecar-check`
   validator, a package-local safe-agent demo launcher, Claude/Codex/Cursor
   client snippets, and a relative-path
   `manifest.json` that records the AgentK version, schema version, launchers,
   local transports, store workflow, and deploy artifacts for support and
   inventory checks. It also writes `package.lock.json` with relative paths,
   byte counts, SHA-256 hashes, and executable-bit expectations for every
   packaged install file while excluding runtime state under `sidecar/.agentk`.
   A package-local `agentk-package-check` launcher validates the manifest,
   package lock, package artifacts, launcher modes, launcher preflights,
   deploy-template hardening, dummy deploy env examples, the configured
   `AGENTK_BIN`, and embedded sidecar bundle after copy/deploy/image-build
   steps. Packaged runtime launchers run that check before launching, serving,
   checking identity mappings, writing demo traces, rendering dashboards, or
   updating store artifacts. The package also includes
   `agentk-sidecar-team-handoff-check` and
   `clients/team-audit-dashboard-handoff.md` to validate the local/team approval
   dashboard, safe-agent demo, durable team store, and notification outbox
   handoff without claiming hosted SaaS.
   `--archive-out` writes a
   deterministic uncompressed tar only after that package self-check passes,
   writes a neighboring `.sha256` file, and reports the archive SHA-256 plus
   checksum path for release notes or inventory systems. The receiver-side
   `sidecar-package-archive-check` command verifies that handoff before
   unpacking, and `sidecar-package-install` verifies, safely unpacks, and
   package-checks the installed directory in one step while writing
   `sidecar/.agentk/install-receipt.json` with the archive filename, checksum
   filename, SHA-256, AgentK version, and installed file count.
   `sidecar-package-release-manifest` writes a separate JSON handoff manifest
   outside the package, binding the package manifest, `package.lock.json`, tar
   checksum, and install receipt hashes for release notes or deployment tickets.
   `sidecar-package-release-manifest-check` re-verifies that handoff after copy,
   relocation, or deployment-ticket review against the current package,
   archive, checksum, and install receipt files.
   The package includes systemd, launchd, and Docker Compose templates for both
   the MCP HTTP gateway and the dashboard. Package checks now validate baseline
   deploy-template hardening markers, including no-new-privileges systemd
   services, a non-root package Dockerfile, and loopback-published,
   capability-dropped, read-only Compose services, plus env examples for the
   HTTP gateway, dashboard, Postgres push, local Slack delivery, and
   Slack/GitHub/email payload exporters that must keep dummy `CHANGE_ME`
   credentials.
10. `store-export` writes normalized audit, approval, permission, and identity
    mapping JSON that omits issuer, audience, and claim values plus a Postgres
    schema contract, psql-loadable TSV rows, and `postgres/load.sql` for teams
    that want a shared audit store.
    `store-check` validates both those export artifacts and the live durable
    team store produced by `store-sync`, including identity mapping row counts
    when `--identity` is configured. `store-slack` exports Slack-ready local
    payloads from the durable notification outbox, `store-slack-send` delivers
    those payloads through `curl` using a webhook URL read only from
    environment, `store-github` exports GitHub issue-ready local payloads from
    the same outbox, `store-github-send` delivers them through `gh` using a
    token read only from environment, `store-email` exports sendmail-ready local
    payloads from the same outbox, `store-email-send` delivers them through a
    local mail relay, and `store-push` preflights the export shape then invokes
    `psql` without printing the database URL.
11. `dashboard-serve` serves the same approvals/audit UI plus `/api/review`
    JSON over localhost for team review without a hosted control plane. The
    served browser page has approve/deny controls backed by the same
    permission-checked `/api/approve` and `/api/deny` JSON requests, appending
    decisions without mutating the signed trace. Optional per-reviewer
    `token_env` entries bind dashboard writes and reviewer-scoped
    `/api/review?reviewer=<id>` reads to reviewer-held tokens, and
    `AGENTK_DASHBOARD_ADMIN_TOKEN` can gate the write API at the server edge.
    With `--store-root`, dashboard reads and reviewer decisions refresh the
    durable team store. The packaged dashboard server launcher runs the
    package-local package validator before serving. The server exposes
    `/healthz`, redacted `/readyz`, and redacted `/metrics` probes for service
    supervisors, and those probe paths are matched exactly with query strings
    rejected. Non-loopback dashboard binds require explicit
    `--allow-non-local-bind` opt-in plus a
    non-empty dashboard admin token, and then require that admin token for
    dashboard reads, `/readyz`, and `/metrics` while leaving `/healthz` open.
    Accepted dashboard connections use an operator-tunable read/write timeout via
    `--stream-timeout-ms` and packaged `AGENTK_DASHBOARD_STREAM_TIMEOUT_MS`.
    Dashboard request buffering is operator-tunable via `--max-body-bytes`,
    `--max-header-bytes`, and packaged `AGENTK_DASHBOARD_MAX_BODY_BYTES` /
    `AGENTK_DASHBOARD_MAX_HEADER_BYTES`, with sanitized 413/431 responses for
    oversized bodies, request lines, or headers.
    Dashboard request bodies are accepted only on approval decision endpoints,
    so review reads and probes cannot carry ignored payload bytes, and those write
    endpoints require `Content-Type: application/json`. Duplicate
    `Content-Type` headers fail closed before decision parsing. Decision
    endpoint paths are matched exactly and reject query strings. Dashboard
    decision JSON object keys must be unique and limited to `id`, `reviewer`,
    `reason`, and `reviewer_token`. When dashboard admin auth is enabled, write
    clients must
    choose one admin token carrier instead of sending both `Authorization` and
    `X-AgentK-Admin-Token`, and duplicated admin token carrier headers fail
    closed.
12. `store-sync` refreshes a live local durable team store with redacted current
    JSON views and normalized JSONL tables for traces, audit events, approval
    decisions, blocked rules, syscall summaries, evidence-ref summaries,
    notification outbox rows, and reviewers. `store-export` writes matching
    Postgres TSV/schema/load artifacts for the summary tables. It remains
    hash/evidence-first and does not store raw tool payloads or secret values.
13. `sidecar-package-ops-handoff` and the packaged
    `bin/agentk-sidecar-ops-handoff` launcher refresh the safe-agent demo,
    dashboard, exported store, durable team store, notification payload drafts,
    team permissions, and identity summary, then write `operator-handoff.json`
    and `operator-handoff.md` for archiveable local/team release review. This
    is a handoff artifact, not a hosted control plane.
    `sidecar-package-doctor` and the packaged `bin/agentk-sidecar-doctor`
    launcher can also validate a `sidecar-package-release-manifest` handoff
    when `--release-manifest` or `AGENTK_PACKAGE_RELEASE_MANIFEST` is provided,
    binding the installed package manifest, package lock, archive checksum, and
    install receipt hashes into the support report.
    `sidecar-package-support-bundle` and the packaged
    `bin/agentk-sidecar-support-bundle` launcher compose the operator handoff,
    sidecar doctor, and hashed evidence inventory into one archiveable
    support-bundle JSON/Markdown artifact.
14. The subprocess MCP gateway has an operator-configurable
    `max_client_messages` cap, exposed on `mcp-proxy-stdio` and generated
    sidecar bundles, so runaway clients cannot hold one proxy session forever.
15. The subprocess MCP gateway now performs clean downstream shutdown on client
    EOF: it closes child stdin, waits briefly for a normal exit, and only then
    escalates to termination.
16. `sidecar-check` validates the generated Claude Desktop JSON and generic
    Codex/Cursor command snippets, so broken client wiring is caught before a
    team pastes the config into an MCP client.
17. The subprocess MCP gateway writes redacted session summaries with readiness
    state, client message counts, configured caps, and allow/deny event totals.
    `mcp-proxy-stdio` exposes this as `--session-report-out`, and
    `sidecar-run` writes a `*.session.json` file beside the configured audit
    log automatically.
18. The served dashboard now has role-aware reviewer views. Reviewers can load
    their scoped inbox from the browser page, and direct `/?reviewer=<id>` HTML
    views use the same team-permission and reviewer-token checks as
    `/api/review?reviewer=<id>`. Token-protected reviewer reads reject requests
    that send both `X-AgentK-Reviewer-Token` and the `reviewer_token` query
    parameter, duplicated reviewer token carriers fail closed, and duplicated
    `reviewer` or `requester` scope selectors fail closed. Dashboard reads also
    reject requests that combine reviewer and requester scope selectors,
    unsupported review query parameters, or reviewer-token carriers without
    reviewer scope.
19. Trace events now carry hash-bound AgentK agent identity for new logs, while
    old logs without that field still verify. The served dashboard and review
    API use that identity for requester views at `/?requester=<agent-id>` and
    `/api/review?requester=<agent-id>`, and durable JSONL/Postgres exports carry
    the same `agent_id` into audit and approval decision rows.
19. The durable team store now writes `current/notifications.json` and
    `tables/notifications.jsonl`, a redacted credential-free outbox for pending
    approval requests and recorded decisions. Slack, GitHub, email, or ticket
    bridges can consume those rows without AgentK storing delivery credentials.
    `store-slack`, `store-github`, and `store-email` convert the durable outbox
    into Slack-ready, GitHub issue-ready, and sendmail-ready local JSON payloads
    for bridge processes while keeping delivery tokens outside AgentK.
    `store-slack-send` can deliver Slack payloads through `curl` using an
    env-held webhook URL that is not printed in AgentK output.
    `store-github-send` can upsert GitHub issue payloads through `gh` using an
    env-held token that is not printed in AgentK output. `store-email-send` can
    deliver email payloads through a local mail relay without storing relay
    credentials in AgentK payload artifacts.
20. `mcp-proxy-tcp` and `sidecar-serve-tcp` expose the same mediated JSON-RPC
    line protocol over a bounded local TCP listener. The packaged sidecar now
    includes `bin/agentk-sidecar-tcp`, which loads the reviewed bundle, spawns a
    fresh downstream process per session, writes trace/session reports, and
    exits after the configured session count. The packaged TCP launcher runs the
    package self-check before binding. The TCP gateway also has an
    explicit `max_concurrent_sessions` cap so an idle client cannot serialize
    every other accepted local session behind it.
21. `mcp-proxy-http` and `sidecar-serve-http` expose the same mediated
    subprocess path through a bounded localhost Streamable HTTP POST adapter.
    The packaged sidecar now includes `bin/agentk-sidecar-http`, which loads the
    reviewed bundle, enforces local endpoint/origin/session checks, answers
    allowed browser CORS preflights before bearer-token auth, supports an
    optional bearer token from environment, enforces HTTP protocol-version
    headers, supports env-configured additional browser origins, forwards extra
    launcher arguments for one-off operator flags, runs the package self-check
    before binding, caps active
    sessions, reaps idle sessions, bounds request bodies and headers, applies
    accepted connection read/write timeouts, uses per-session runtime locks so
    one busy downstream session does not block unrelated sessions, reports local
    health/readiness for service supervisors with redacted origin-count
    metadata, requires an explicit authenticated opt-in for non-loopback HTTP
    bind hosts, emits browser safety headers, drains active sessions on bounded
    shutdown, exposes token-gated redacted readiness and numeric gateway metrics
    for supervisors, tracks redacted cumulative request/rejection/session
    lifecycle counters plus CORS preflight and stream-framing rejection
    counters, reports current SSE retained-event buffer pressure, counts SSE
    retained-event evictions without exposing event data, uses constant-time
    bearer-token checks, and writes trace/session evidence. The HTTP parser
    rejects malformed or non-UTF-8
    request/header lines, LF-only line endings, duplicate or non-decimal
    `Content-Length` headers, control characters in header values, and any
    transfer-encoding, content-encoding, expectation, or upgrade header with
    sanitized 400 responses; HTTP request bodies must be unencoded and
    fixed-length. MCP POST bodies must be single JSON-RPC 2.0 request or
    notification objects with string `method` fields; batches, non-object JSON,
    response-shaped objects, and invalid JSON-RPC version fields fail before
    session lookup or downstream forwarding. WebSocket handshake headers are
    rejected because the gateway is a Streamable HTTP adapter, not a WebSocket
    transport. Method override headers are rejected so routes cannot be
    reinterpreted by intermediaries. Proxy and trace methods are rejected before
    route handling.
    Only `Connection: close` is accepted; other connection values and
    hop-by-hop negotiation headers are rejected, and proxy auth headers are
    rejected before request handling. Forwarded proxy metadata is rejected by
    default; explicit trusted-proxy mode accepts only clean `Forwarded`,
    `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and
    `X-Real-IP` values from a reviewed reverse proxy, rejects duplicates or
    malformed values, and exposes only redacted readiness/metrics counts.
    Ambient cookie headers such as `Cookie` and
    `Set-Cookie` are rejected because the gateway uses explicit bearer/reviewer
    tokens instead. Request lines must be exactly
    space-delimited, request targets must begin with exactly one `/` and cannot
    contain fragments, and header names cannot carry whitespace before `:`. The
    HTTP gateway validates configured
    browser origins before bind, matches built-in localhost/loopback origins
    only with optional numeric ports and a localhost/loopback request `Host`,
    rejects ambiguous duplicate MCP control headers, dual token-carrier
    headers, and invalid JSON POST media types before spawning downstream MCP
    work. Follow-up
    `Mcp-Session-Id` values must match AgentK's generated lowercase hex session
    shape before lookup. All accepted HTTP requests require exactly one
    syntactically valid `Host` authority with no userinfo, wildcards, paths,
    queries, fragments, invalid ports, invalid bracketed IP literals, or
    invalid DNS labels, percent escapes, or unbracketed IPv6 literals, so
    gateway handling does not guess across ambiguous authority metadata.
    Truncated header sections and short
    fixed-length bodies are rejected before request handling. The configured
    header byte cap is enforced
    while each request line and header line is read, so oversized unterminated
    lines fail closed before unbounded buffering. Request
    bodies are accepted only on MCP endpoint `POST`, so unknown routes and
    preflight/probe/session-control paths cannot smuggle ignored payload bytes.
    Browser CORS preflights must
    include an allowed `Origin`, treat sandboxed/file `Origin: null` as an
    explicit opt-in rather than a built-in local origin, are restricted to
    `POST`/`DELETE` and the known MCP HTTP header set, and reject Private
    Network Access preflights until AgentK has an explicit private-network
    policy. Built-in
    localhost/loopback origins require a localhost/loopback request `Host`, so
    non-local gateway names need explicit allowed-origin entries. The MCP
    endpoint and operational probe paths are matched exactly, and query strings
    on those paths are rejected before auth, session, or probe handling. MCP
    HTTP `HEAD` responses omit bodies, while `HEAD` on the MCP endpoint remains
    an unsupported method response with the normal `Allow` header.
    Operator-configured endpoints are validated before bind and must be clean
    origin-form paths that do not overlap operational probes. SSE-shaped `GET`
    requests require `Accept: text/event-stream` plus an existing,
    syntactically valid `Mcp-Session-Id`, pass the same auth/origin/protocol
    checks. The bounded local alpha serves already mediated session responses
    from a capped per-session buffer and supports `Last-Event-ID` resume while
    keeping metrics redacted. Downstream MCP spawn or transport failures now
    return sanitized HTTP 502 JSON-RPC errors with CORS for allowed origins
    instead of closing the socket, and readiness/metrics count those failures
    separately from AgentK internal gateway failures without reflecting raw
    command, environment, payload, or stderr values.
    Full hosted HTTP/SSE transport, TLS, and live external identity verification
    remain future production-gateway work.

Recommended file-level plan for the next slice:

- `src/lib.rs` and `src/main.rs`: continue production gateway hardening beyond
  the local TCP/HTTP adapters toward full Streamable HTTP/SSE service
  operation, deployment-grade auth, live external secret custody, and
  long-running observability.
- `README.md`: show the install/run/review path as `cargo install --path .`,
  then `agentk sidecar-init`, `agentk sidecar-check`, `agentk sidecar-package`,
  `agentk dashboard-serve`, `agentk store-sync`, `agentk store-export`,
  `agentk store-check`, `agentk store-push`, `agentk store-slack`,
  `agentk store-slack-send`, `agentk store-github`, `agentk store-github-send`,
  `agentk store-email`, `agentk store-email-send`, and the packaged
  launcher/review commands.
- `docs/mcp-proxy.md`: keep client-specific sidecar wiring guidance current
  for Claude, Codex, Cursor, and generic command/args MCP clients.

This advances the product without overclaiming a production dashboard or hosted
gateway. It gives teams something usable now: a local sidecar bundle they can
review, validate, run, and audit.
