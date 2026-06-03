# AgentK Productization Plan

AgentK should become a polished installable team product without losing its
wedge: an agent action firewall and flight recorder for MCP/tool-call
governance. The gateway is a delivery surface, not the product thesis.

The current v0.1 release proves the security shape locally: a poisoned MCP
server can try to trigger secret exfiltration and unsafe repository patching,
baseline passthrough lets the fake dangerous markers execute, and AgentK blocks
the transitions with policy, provenance, and replayable evidence.

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
- before/after MCP shim eval and killer demo;
- hash-first trace inspection, replay, fork replay, and signature verification;
- `audit`, which turns a trace into a small audit and approval inbox with
  pending approvals, blocked-rule counts, and allowed side-effect summaries;
- `approvals`, `approve`, and `deny`, which provide an append-only local review
  surface over signed trace events without silently replaying blocked actions;
- local release audit and signed v0.1 release evidence;
- `sidecar-init`, which generates a starter team sidecar bundle with policy,
  secret-reference, MCP client, and safe-agent demo files;
- `sidecar-check`, which validates a generated sidecar bundle without spawning
  downstream tools or touching credentials, including Claude Desktop and
  Codex/Cursor client snippet shape.
- `safe-agent-demo`, which runs a no-credential mock GitHub/Postgres/Slack/
  filesystem workflow where risky writes and exfiltration are blocked while
  safe reads and drafts still work.

Still missing for a team product:

- package/install path beyond building from source;
- production-grade MCP transport/deployment story;
- local approval broker and dashboard beyond the current CLI review surface;
- durable multi-user policy, identity, and audit storage;
- polished install/package flow for the sidecar and demo beyond `cargo run`.

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
- Slack/GitHub identity integration can notify and review without granting
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
   and approval scopes. `agentk permissions` reports configured reviewers, and
   `approve`/`deny --permissions ...` enforce reviewer authority before appending
   a decision.
8. `dashboard` writes a static local HTML approval dashboard from the signed
   trace, append-only decisions, and optional permissions manifest.
9. `sidecar-package` validates a sidecar bundle and writes a local deployable
   package with launcher scripts plus Claude/Codex/Cursor client snippets.
10. `store-export` writes normalized audit, approval, and permission JSON plus a
    Postgres schema contract, psql-loadable TSV rows, and `postgres/load.sql`
    for teams that want a shared audit store. `store-check` validates both
    those export artifacts and the live durable team store produced by
    `store-sync`, and `store-push` preflights the export shape then invokes
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
    durable team store.
12. `store-sync` refreshes a live local durable team store with redacted current
    JSON views and normalized JSONL tables for traces, audit events, approval
    decisions, notification outbox rows, and reviewers. It remains
    hash/evidence-first and does not store raw tool payloads or secret values.
13. The subprocess MCP gateway has an operator-configurable
    `max_client_messages` cap, exposed on `mcp-proxy-stdio` and generated
    sidecar bundles, so runaway clients cannot hold one proxy session forever.
14. The subprocess MCP gateway now performs clean downstream shutdown on client
    EOF: it closes child stdin, waits briefly for a normal exit, and only then
    escalates to termination.
15. `sidecar-check` validates the generated Claude Desktop JSON and generic
    Codex/Cursor command snippets, so broken client wiring is caught before a
    team pastes the config into an MCP client.
16. The subprocess MCP gateway writes redacted session summaries with readiness
    state, client message counts, configured caps, and allow/deny event totals.
    `mcp-proxy-stdio` exposes this as `--session-report-out`, and
    `sidecar-run` writes a `*.session.json` file beside the configured audit
    log automatically.
17. The served dashboard now has role-aware reviewer views. Reviewers can load
    their scoped inbox from the browser page, and direct `/?reviewer=<id>` HTML
    views use the same team-permission and reviewer-token checks as
    `/api/review?reviewer=<id>`.
18. Trace events now carry hash-bound AgentK agent identity for new logs, while
    old logs without that field still verify. The served dashboard and review
    API use that identity for requester views at `/?requester=<agent-id>` and
    `/api/review?requester=<agent-id>`, and durable JSONL/Postgres exports carry
    the same `agent_id` into audit and approval decision rows.
19. The durable team store now writes `current/notifications.json` and
    `tables/notifications.jsonl`, a redacted credential-free outbox for pending
    approval requests and recorded decisions. Slack, GitHub, email, or ticket
    bridges can consume those rows without AgentK storing delivery credentials.
20. `mcp-proxy-tcp` and `sidecar-serve-tcp` expose the same mediated JSON-RPC
    line protocol over a bounded local TCP listener. The packaged sidecar now
    includes `bin/agentk-sidecar-tcp`, which loads the reviewed bundle, spawns a
    fresh downstream process per session, writes trace/session reports, and
    exits after the configured session count. The TCP gateway also has an
    explicit `max_concurrent_sessions` cap so an idle client cannot serialize
    every other accepted local session behind it.
21. `mcp-proxy-http` and `sidecar-serve-http` expose the same mediated
    subprocess path through a bounded localhost Streamable HTTP POST adapter.
    The packaged sidecar now includes `bin/agentk-sidecar-http`, which loads the
    reviewed bundle, enforces local endpoint/origin/session checks, supports an
    optional bearer token from environment, enforces HTTP protocol-version
    headers, reports local health/readiness for service supervisors, and writes
    trace/session evidence.
    Full hosted HTTP/SSE transport, TLS, and external identity remain future
    production-gateway work.

Recommended file-level plan for the next slice:

- `src/lib.rs` and `src/main.rs`: continue production gateway hardening beyond
  the local TCP/HTTP adapters toward full Streamable HTTP/SSE service
  operation, deployment-grade auth, and long-running observability.
- `README.md`: show the install/run/review path as `cargo install --path .`,
  then `agentk sidecar-init`, `agentk sidecar-check`, `agentk sidecar-package`,
  `agentk dashboard-serve`, `agentk store-sync`, `agentk store-export`,
  `agentk store-check`, `agentk store-push`, and the packaged launcher/review
  commands.
- `docs/mcp-proxy.md`: keep client-specific sidecar wiring guidance current
  for Claude, Codex, Cursor, and generic command/args MCP clients.

This advances the product without overclaiming a production dashboard or hosted
gateway. It gives teams something usable now: a local sidecar bundle they can
review, validate, run, and audit.
