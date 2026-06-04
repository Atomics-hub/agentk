use agentk::{
    AgentKError, ApprovalDecision, ApprovalDecisionRecord, ApprovalReviewReport, AuditApprovalItem,
    MCP_PROTOCOL_VERSION, McpSubprocessProxy, McpSubprocessProxyConfig, Policy, ReadinessStatus,
    TeamPermissionsReport, Verdict, alpha_release_status_report, approval_review_jsonl,
    archive_sidecar_package, audit_inbox_jsonl, check_audit_store, check_audit_store_export,
    check_homebrew_formula, check_homebrew_tap_handoff, check_sidecar_bundle,
    check_sidecar_package, check_sidecar_package_archive, check_sidecar_package_http_handoff,
    check_sidecar_package_release_manifest, check_sidecar_package_team_handoff, default_log_path,
    export_audit_store, export_email_notification_payloads, export_github_notification_payloads,
    export_slack_notification_payloads, fork_replay_behavior_jsonl, fork_replay_jsonl,
    generate_signing_key_file, init_sidecar_bundle, inspect_jsonl, install_sidecar_package_archive,
    mcp_proxy_from_path, mcp_server_json_stream, mcp_subprocess_proxy_json_stream,
    mediate_mcp_json_reader, mediate_mcp_json_stream, package_sidecar_bundle, readiness_report,
    record_approval_decision_jsonl, record_approval_decision_jsonl_with_permissions,
    release_audit_report, replay_jsonl, rotate_signing_key_file, run_mcp_killer_demo,
    run_mcp_security_shim_eval, run_poisoned_webpage_demo, run_safe_agent_demo,
    scope_approval_review_for_reviewer, secret_reference_env_store_report_from_path,
    secret_reference_manifest_report_from_path, sidecar_run_config, signing_key_status,
    sync_durable_audit_store, team_identity_report_from_path, team_permissions_report_from_path,
    trusted_signing_key_manifest_keys_from_path, trusted_signing_key_manifest_report_from_path,
    verify_jsonl, verify_signatures_jsonl, verify_signatures_jsonl_with_trusted_keys,
    verify_signing_key_rotation_manifest_file, verify_team_reviewer_token,
    write_approval_dashboard_html, write_events_jsonl, write_homebrew_formula, write_latest_copy,
    write_sidecar_package_client_handoff, write_sidecar_package_dashboard_handoff,
    write_sidecar_package_demo_handoff, write_sidecar_package_deploy_handoff,
    write_sidecar_package_doctor, write_sidecar_package_ops_handoff,
    write_sidecar_package_permissions_handoff, write_sidecar_package_production_preflight,
    write_sidecar_package_quickstart, write_sidecar_package_release_manifest,
    write_sidecar_package_support_bundle,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MCP_HTTP_DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
const MCP_HTTP_DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;
const MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS: usize = 32;
const MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS: u64 = 15 * 60 * 1000;
const MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS: u64 = 30 * 1000;
const MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION: usize = 128;
const MCP_HTTP_JSON_RPC_MAX_ID_BYTES: usize = 128;
const MCP_HTTP_DEFAULT_ALLOW_ORIGINS_ENV: &str = "AGENTK_MCP_HTTP_ALLOW_ORIGINS";
const DASHBOARD_HTTP_MAX_HEADER_BYTES: usize = 16 * 1024;
const DASHBOARD_HTTP_MAX_BODY_BYTES: usize = 8 * 1024;
const DASHBOARD_HTTP_DEFAULT_STREAM_TIMEOUT_MS: u64 = 30 * 1000;

#[derive(Debug, Parser)]
#[command(name = "agentk")]
#[command(about = "AgentK: firewall and flight recorder for AI agents.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the poisoned-webpage Context MMU demo.
    Demo {
        /// Emit the full report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a hash-chained AgentK flight log.
    Verify {
        /// Path to a JSONL flight log.
        path: PathBuf,
    },
    /// Verify receipt and secret-handle signatures in a flight log.
    VerifySignatures {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Expected Ed25519 public signing key hex. Repeat to allow rotated keys.
        #[arg(long)]
        trusted_public_key: Vec<String>,
        /// TOML manifest containing trusted public signing keys.
        #[arg(long)]
        trusted_key_manifest: Option<PathBuf>,
    },
    /// Inspect a flight log with redacted hash-first evidence summaries.
    TraceInspect {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Emit the inspection report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Summarize a flight log as an audit and approval inbox.
    Audit {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Emit the audit inbox report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reconcile a flight log with local approval decisions.
    Approvals {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Path to the append-only local approval decision log.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Emit the approval review report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Record a local approval decision for a pending audit item.
    Approve {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Approval id from `agentk audit` or `agentk approvals`.
        id: String,
        /// Human or team identity making the decision.
        #[arg(long)]
        reviewer: String,
        /// Short review reason to store in the decision log.
        #[arg(long)]
        reason: String,
        /// Path to the append-only local approval decision log.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Optional team permissions manifest that authorizes the reviewer.
        #[arg(long)]
        permissions: Option<PathBuf>,
        /// Emit the recorded decision as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Record a local denial decision for a pending audit item.
    Deny {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Approval id from `agentk audit` or `agentk approvals`.
        id: String,
        /// Human or team identity making the decision.
        #[arg(long)]
        reviewer: String,
        /// Short review reason to store in the decision log.
        #[arg(long)]
        reason: String,
        /// Path to the append-only local approval decision log.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Optional team permissions manifest that authorizes the reviewer.
        #[arg(long)]
        permissions: Option<PathBuf>,
        /// Emit the recorded decision as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a team permissions manifest for local approval review.
    Permissions {
        /// Path to team-permissions.toml.
        #[arg(long, default_value = "agentk-sidecar/team-permissions.toml")]
        path: PathBuf,
        /// Emit the permissions report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect external identity-to-reviewer mappings without printing groups or token claims.
    IdentityCheck {
        /// Path to team-identity.toml.
        #[arg(long, default_value = "agentk-sidecar/team-identity.toml")]
        identity: PathBuf,
        /// Optional team permissions manifest used to verify mapped reviewers.
        #[arg(long)]
        permissions: Option<PathBuf>,
        /// Emit the redacted identity mapping report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a local HTML approval and audit dashboard.
    Dashboard {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Path to the append-only local approval decision log.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Optional team permissions manifest to summarize reviewers.
        #[arg(long)]
        permissions: Option<PathBuf>,
        /// Output HTML path.
        #[arg(long, default_value = ".agentk/dashboard.html")]
        out: PathBuf,
        /// Emit the dashboard write report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Serve a local approvals and audit dashboard over HTTP.
    DashboardServe {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Path to the append-only local approval decision log.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Optional team permissions manifest to summarize reviewers.
        #[arg(long)]
        permissions: Option<PathBuf>,
        /// Optional external identity mapping manifest to sync with the durable team store.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Bind host for the local dashboard server.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Bind port for the local dashboard server.
        #[arg(long, default_value_t = 8765)]
        port: u16,
        /// Env var containing an optional dashboard write API bearer token.
        #[arg(long, default_value = "AGENTK_DASHBOARD_ADMIN_TOKEN")]
        admin_token_env: String,
        /// Milliseconds before an accepted dashboard HTTP connection read/write operation times out.
        #[arg(long, default_value_t = DASHBOARD_HTTP_DEFAULT_STREAM_TIMEOUT_MS)]
        stream_timeout_ms: u64,
        /// Maximum accepted dashboard HTTP request body bytes.
        #[arg(long, default_value_t = DASHBOARD_HTTP_MAX_BODY_BYTES)]
        max_body_bytes: usize,
        /// Maximum accepted dashboard HTTP request header bytes.
        #[arg(long, default_value_t = DASHBOARD_HTTP_MAX_HEADER_BYTES)]
        max_header_bytes: usize,
        /// Allow binding the dashboard server to a non-loopback host.
        #[arg(long)]
        allow_non_local_bind: bool,
        /// Optional durable team store root to refresh on dashboard reads and writes.
        #[arg(long)]
        store_root: Option<PathBuf>,
    },
    /// Export a signed trace, approvals, and permissions into durable store files.
    StoreExport {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Path to the append-only local approval decision log.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Optional team permissions manifest to export as reviewer metadata.
        #[arg(long)]
        permissions: Option<PathBuf>,
        /// Optional external identity mapping manifest to export as reviewer metadata.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Output directory for normalized JSON and the Postgres schema contract.
        #[arg(long, default_value = ".agentk/store")]
        out: PathBuf,
        /// Emit the export report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate an exported audit store before loading it into Postgres.
    StoreCheck {
        /// Root directory produced by `agentk store-export`.
        #[arg(long, default_value = ".agentk/store")]
        root: PathBuf,
        /// Emit the store check report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Sync a signed trace and approvals into the live durable team store.
    StoreSync {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Path to the append-only local approval decision log.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Optional team permissions manifest to sync as reviewer metadata.
        #[arg(long)]
        permissions: Option<PathBuf>,
        /// Optional external identity mapping manifest to sync as reviewer metadata.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Durable team store root.
        #[arg(long, default_value = ".agentk/team-store")]
        root: PathBuf,
        /// Emit the sync report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Export durable notification outbox rows as Slack-ready JSON payloads.
    StoreSlack {
        /// Durable team store root produced by `agentk store-sync`.
        #[arg(long, default_value = ".agentk/team-store")]
        root: PathBuf,
        /// Output directory for Slack payload manifest and JSONL payloads.
        #[arg(long, default_value = ".agentk/slack")]
        out: PathBuf,
        /// Optional Slack channel id/name to include in each payload.
        #[arg(long)]
        channel: Option<String>,
        /// Emit the Slack payload export report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Deliver exported Slack payloads with a webhook URL read from environment.
    StoreSlackSend {
        /// Root directory produced by `agentk store-slack`.
        #[arg(long, default_value = ".agentk/slack")]
        payload_root: PathBuf,
        /// Environment variable containing the Slack webhook URL.
        #[arg(long, default_value = "AGENTK_SLACK_WEBHOOK_URL")]
        webhook_url_env: String,
        /// curl executable to run for delivery.
        #[arg(long, default_value = "curl")]
        curl: String,
        /// Print the redacted delivery plan without invoking curl.
        #[arg(long)]
        dry_run: bool,
        /// Emit the Slack delivery report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Export durable notification outbox rows as GitHub issue-ready JSON payloads.
    StoreGithub {
        /// Durable team store root produced by `agentk store-sync`.
        #[arg(long, default_value = ".agentk/team-store")]
        root: PathBuf,
        /// Output directory for GitHub payload manifest and JSONL payloads.
        #[arg(long, default_value = ".agentk/github")]
        out: PathBuf,
        /// Optional GitHub owner/repo to include in each payload.
        #[arg(long)]
        repository: Option<String>,
        /// GitHub label to include in each issue payload. Repeat for multiple labels.
        #[arg(long)]
        label: Vec<String>,
        /// Emit the GitHub payload export report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Deliver exported GitHub issue payloads with gh and a token read from environment.
    StoreGithubSend {
        /// Root directory produced by `agentk store-github`.
        #[arg(long, default_value = ".agentk/github")]
        payload_root: PathBuf,
        /// Environment variable containing the GitHub token for gh.
        #[arg(long, default_value = "GITHUB_TOKEN")]
        github_token_env: String,
        /// gh executable to run for delivery.
        #[arg(long, default_value = "gh")]
        gh: String,
        /// Print the redacted delivery plan without invoking gh.
        #[arg(long)]
        dry_run: bool,
        /// Emit the GitHub delivery report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Export durable notification outbox rows as sendmail-ready email payloads.
    StoreEmail {
        /// Durable team store root produced by `agentk store-sync`.
        #[arg(long, default_value = ".agentk/team-store")]
        root: PathBuf,
        /// Output directory for email payload manifest and JSONL messages.
        #[arg(long, default_value = ".agentk/email")]
        out: PathBuf,
        /// Email recipient to include in each message. Repeat for multiple recipients.
        #[arg(long)]
        to: Vec<String>,
        /// Emit the email payload export report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Deliver exported email payloads through local sendmail.
    StoreEmailSend {
        /// Root directory produced by `agentk store-email`.
        #[arg(long, default_value = ".agentk/email")]
        payload_root: PathBuf,
        /// sendmail executable to run for delivery.
        #[arg(long, default_value = "sendmail")]
        sendmail: String,
        /// Print the redacted delivery plan without invoking sendmail.
        #[arg(long)]
        dry_run: bool,
        /// Emit the email delivery report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Preflight and load an exported audit store into Postgres with psql.
    StorePush {
        /// Root directory produced by `agentk store-export`.
        #[arg(long, default_value = ".agentk/store")]
        root: PathBuf,
        /// Environment variable that contains the Postgres connection string.
        #[arg(long, default_value = "DATABASE_URL")]
        database_url_env: String,
        /// psql executable to run.
        #[arg(long, default_value = "psql")]
        psql: String,
        /// Print the redacted load plan without invoking psql.
        #[arg(long)]
        dry_run: bool,
        /// Emit the push report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Replay a hash-chained flight log without side effects.
    Replay {
        /// Path to a JSONL flight log.
        path: PathBuf,
    },
    /// Replay a flight log against a different policy and report decision changes.
    ForkReplay {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// Policy to compare against the recorded decisions.
        #[arg(long)]
        policy: PathBuf,
        /// Emit the comparison report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Replay with changed model/tool/network output refs and report divergences.
    ForkReplayBehavior {
        /// Path to a JSONL flight log.
        path: PathBuf,
        /// JSON array of changed hashed output refs.
        #[arg(long)]
        behavior: PathBuf,
        /// Emit the behavior divergence report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Mediate one MCP-shaped tool request without executing the tool.
    McpProxy {
        /// Path to a JSON MCP request.
        #[arg(long, default_value = "examples/mcp-tool-request.json")]
        request: PathBuf,
        /// Emit the mediated event as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Read one MCP-shaped JSON request from stdin and mediate it without execution.
    McpStdio,
    /// Read newline-delimited MCP-shaped JSON requests from stdin and emit JSONL decisions.
    McpLines,
    /// Run a minimal MCP JSON-RPC stdio server that exposes agentk.mediate.
    McpServer,
    /// Run the MCP poisoned-output exfiltration/patch blocking demo.
    McpKillerDemo {
        /// Optional JSONL path for the AgentK proxy flight log.
        #[arg(long, default_value = ".agentk/runs/mcp-killer-demo.jsonl")]
        trace_out: PathBuf,
        /// Emit the redacted inspection report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compare poisoned MCP behavior with and without the AgentK shim.
    McpShimEval {
        /// Optional JSONL path for the AgentK-mediated eval trace.
        #[arg(long, default_value = ".agentk/runs/mcp-shim-eval-agentk.jsonl")]
        trace_out: PathBuf,
        /// Emit the full eval report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the no-credential GitHub/Postgres/Slack/filesystem safe-agent demo.
    SafeAgentDemo {
        /// Optional JSONL path for the AgentK-mediated demo trace.
        #[arg(long, default_value = ".agentk/runs/safe-agent-demo.jsonl")]
        trace_out: PathBuf,
        /// Emit the full demo report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Proxy MCP JSON-RPC stdin/stdout through a downstream MCP server process.
    McpProxyStdio {
        /// Stable AgentK agent identifier for mediated tool calls.
        #[arg(long, default_value = "agent://mcp/proxy")]
        agent_id: String,
        /// Stable identifier for the downstream MCP server.
        #[arg(long, default_value = "downstream-mcp")]
        server_id: String,
        /// Downstream MCP server command to spawn.
        #[arg(long)]
        command: String,
        /// Argument passed to the downstream command. Repeat for multiple args.
        #[arg(long = "arg", num_args = 1, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Parent environment variable name to copy into the cleared child environment. Repeat for multiple vars.
        #[arg(long = "allow-env", value_name = "NAME")]
        allow_env: Vec<String>,
        /// Downstream response timeout in milliseconds.
        #[arg(long, default_value_t = 30000)]
        response_timeout_ms: u64,
        /// Maximum non-empty client messages to process before closing the session.
        #[arg(long, default_value_t = 10000)]
        max_client_messages: usize,
        /// Optional JSONL path for the AgentK proxy flight log.
        #[arg(long)]
        trace_out: Option<PathBuf>,
        /// Optional JSON path for a redacted AgentK proxy session summary.
        #[arg(long)]
        session_report_out: Option<PathBuf>,
    },
    /// Listen for MCP JSON-RPC over TCP and proxy one or more sessions through a downstream process.
    McpProxyTcp {
        /// Stable AgentK agent identifier for mediated tool calls.
        #[arg(long, default_value = "agent://mcp/proxy")]
        agent_id: String,
        /// Stable identifier for the downstream MCP server.
        #[arg(long, default_value = "downstream-mcp")]
        server_id: String,
        /// Host/IP address to bind.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// TCP port to bind. Use 0 to ask the OS for an available port.
        #[arg(long, default_value_t = 9797)]
        port: u16,
        /// Maximum accepted client sessions before the gateway exits.
        #[arg(long, default_value_t = 1)]
        max_sessions: usize,
        /// Maximum client sessions to proxy at the same time.
        #[arg(long, default_value_t = 1)]
        max_concurrent_sessions: usize,
        /// Downstream MCP server command to spawn per client session.
        #[arg(long)]
        command: String,
        /// Argument passed to the downstream command. Repeat for multiple args.
        #[arg(long = "arg", num_args = 1, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Parent environment variable name to copy into the cleared child environment. Repeat for multiple vars.
        #[arg(long = "allow-env", value_name = "NAME")]
        allow_env: Vec<String>,
        /// Downstream response timeout in milliseconds.
        #[arg(long, default_value_t = 30000)]
        response_timeout_ms: u64,
        /// Maximum non-empty client messages to process before closing each session.
        #[arg(long, default_value_t = 10000)]
        max_client_messages: usize,
        /// Optional JSONL path for the AgentK proxy flight log.
        #[arg(long)]
        trace_out: Option<PathBuf>,
        /// Optional JSON path for a redacted AgentK proxy session summary.
        #[arg(long)]
        session_report_out: Option<PathBuf>,
    },
    /// Serve MCP Streamable HTTP POST requests through a downstream MCP server process.
    McpProxyHttp {
        /// Stable AgentK agent identifier for mediated tool calls.
        #[arg(long, default_value = "agent://mcp/proxy")]
        agent_id: String,
        /// Stable identifier for the downstream MCP server.
        #[arg(long, default_value = "downstream-mcp")]
        server_id: String,
        /// Host/IP address to bind. Defaults to localhost for DNS rebinding safety.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// HTTP port to bind. Use 0 to ask the OS for an available port.
        #[arg(long, default_value_t = 9798)]
        port: u16,
        /// Streamable HTTP MCP endpoint path.
        #[arg(long, default_value = "/mcp")]
        endpoint: String,
        /// Maximum HTTP requests before the gateway exits. 0 means unlimited.
        #[arg(long, default_value_t = 0)]
        max_requests: usize,
        /// Maximum HTTP requests to handle at the same time.
        #[arg(long, default_value_t = 16)]
        max_concurrent_requests: usize,
        /// Maximum initialized HTTP MCP sessions to keep active.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS)]
        max_active_sessions: usize,
        /// Milliseconds before an idle initialized HTTP session is reaped.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS)]
        session_idle_timeout_ms: u64,
        /// Maximum HTTP request body size in bytes.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_MAX_BODY_BYTES)]
        max_body_bytes: usize,
        /// Maximum HTTP request line plus header bytes.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_MAX_HEADER_BYTES)]
        max_header_bytes: usize,
        /// Milliseconds before an accepted HTTP connection read/write operation times out.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS)]
        stream_timeout_ms: u64,
        /// Additional allowed Origin value. Repeat for multiple browser origins.
        #[arg(long = "allow-origin")]
        allow_origins: Vec<String>,
        /// Env var containing comma-separated additional allowed Origin values.
        #[arg(long, default_value = MCP_HTTP_DEFAULT_ALLOW_ORIGINS_ENV)]
        allow_origin_env: String,
        /// Allow binding the HTTP gateway to a non-loopback host.
        #[arg(long)]
        allow_non_local_bind: bool,
        /// Accept clean forwarded/proxy metadata from a trusted reverse proxy.
        #[arg(long)]
        trust_proxy_headers: bool,
        /// Optional env var containing a bearer token for HTTP MCP requests.
        #[arg(long, default_value = "AGENTK_MCP_HTTP_TOKEN")]
        auth_token_env: String,
        /// Downstream MCP server command to spawn per initialized HTTP session.
        #[arg(long)]
        command: String,
        /// Argument passed to the downstream command. Repeat for multiple args.
        #[arg(long = "arg", num_args = 1, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Parent environment variable name to copy into the cleared child environment. Repeat for multiple vars.
        #[arg(long = "allow-env", value_name = "NAME")]
        allow_env: Vec<String>,
        /// Downstream response timeout in milliseconds.
        #[arg(long, default_value_t = 30000)]
        response_timeout_ms: u64,
        /// Maximum non-empty client messages to process before closing each HTTP session.
        #[arg(long, default_value_t = 10000)]
        max_client_messages: usize,
        /// Optional JSONL path for the AgentK proxy flight log.
        #[arg(long)]
        trace_out: Option<PathBuf>,
        /// Optional JSON path for a redacted AgentK proxy session summary.
        #[arg(long)]
        session_report_out: Option<PathBuf>,
    },
    /// Generate a team sidecar starter bundle for MCP client onboarding.
    SidecarInit {
        /// Output directory for the starter bundle.
        #[arg(long, default_value = "agentk-sidecar")]
        out: PathBuf,
        /// Overwrite existing bundle files.
        #[arg(long)]
        force: bool,
        /// Emit the generated file list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a generated team sidecar bundle without spawning downstream tools.
    SidecarCheck {
        /// Root directory containing agentk-sidecar.toml.
        #[arg(long, default_value = "agentk-sidecar")]
        root: PathBuf,
        /// Emit the sidecar preflight report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the MCP sidecar described by agentk-sidecar.toml.
    SidecarRun {
        /// Root directory containing agentk-sidecar.toml.
        #[arg(long, default_value = "agentk-sidecar")]
        root: PathBuf,
    },
    /// Serve the generated sidecar bundle as a bounded TCP JSON-RPC gateway.
    SidecarServeTcp {
        /// Root directory containing agentk-sidecar.toml.
        #[arg(long, default_value = "agentk-sidecar")]
        root: PathBuf,
        /// Host/IP address to bind.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// TCP port to bind. Use 0 to ask the OS for an available port.
        #[arg(long, default_value_t = 9797)]
        port: u16,
        /// Maximum accepted client sessions before the gateway exits.
        #[arg(long, default_value_t = 1)]
        max_sessions: usize,
        /// Maximum client sessions to proxy at the same time.
        #[arg(long, default_value_t = 1)]
        max_concurrent_sessions: usize,
    },
    /// Serve the generated sidecar bundle as a local Streamable HTTP MCP gateway.
    SidecarServeHttp {
        /// Root directory containing agentk-sidecar.toml.
        #[arg(long, default_value = "agentk-sidecar")]
        root: PathBuf,
        /// Host/IP address to bind. Defaults to localhost for DNS rebinding safety.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// HTTP port to bind. Use 0 to ask the OS for an available port.
        #[arg(long, default_value_t = 9798)]
        port: u16,
        /// Streamable HTTP MCP endpoint path.
        #[arg(long, default_value = "/mcp")]
        endpoint: String,
        /// Maximum HTTP requests before the gateway exits. 0 means unlimited.
        #[arg(long, default_value_t = 0)]
        max_requests: usize,
        /// Maximum HTTP requests to handle at the same time.
        #[arg(long, default_value_t = 16)]
        max_concurrent_requests: usize,
        /// Maximum initialized HTTP MCP sessions to keep active.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS)]
        max_active_sessions: usize,
        /// Milliseconds before an idle initialized HTTP session is reaped.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS)]
        session_idle_timeout_ms: u64,
        /// Maximum HTTP request body size in bytes.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_MAX_BODY_BYTES)]
        max_body_bytes: usize,
        /// Maximum HTTP request line plus header bytes.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_MAX_HEADER_BYTES)]
        max_header_bytes: usize,
        /// Milliseconds before an accepted HTTP connection read/write operation times out.
        #[arg(long, default_value_t = MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS)]
        stream_timeout_ms: u64,
        /// Additional allowed Origin value. Repeat for multiple browser origins.
        #[arg(long = "allow-origin")]
        allow_origins: Vec<String>,
        /// Env var containing comma-separated additional allowed Origin values.
        #[arg(long, default_value = MCP_HTTP_DEFAULT_ALLOW_ORIGINS_ENV)]
        allow_origin_env: String,
        /// Allow binding the HTTP gateway to a non-loopback host.
        #[arg(long)]
        allow_non_local_bind: bool,
        /// Accept clean forwarded/proxy metadata from a trusted reverse proxy.
        #[arg(long)]
        trust_proxy_headers: bool,
        /// Optional env var containing a bearer token for HTTP MCP requests.
        #[arg(long, default_value = "AGENTK_MCP_HTTP_TOKEN")]
        auth_token_env: String,
    },
    /// Package a generated sidecar bundle with launcher scripts and client snippets.
    SidecarPackage {
        /// Root directory containing agentk-sidecar.toml.
        #[arg(long, default_value = "agentk-sidecar")]
        root: PathBuf,
        /// Output directory for the packaged sidecar.
        #[arg(long, default_value = "agentk-sidecar-package")]
        out: PathBuf,
        /// Optional tar archive path to write after package validation.
        #[arg(long)]
        archive_out: Option<PathBuf>,
        /// Overwrite an existing package directory.
        #[arg(long)]
        force: bool,
        /// Emit the package report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a packaged sidecar directory after copy/install.
    SidecarPackageCheck {
        /// Root directory containing manifest.json and sidecar/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Emit the package check report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate the packaged local HTTP/SSE sidecar handoff contract.
    SidecarPackageHttpHandoffCheck {
        /// Root directory containing manifest.json, clients/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Emit the HTTP/SSE handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate the packaged local team approval/audit dashboard handoff contract.
    SidecarPackageTeamHandoffCheck {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Emit the team handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged local/team operator handoff artifact.
    SidecarPackageOpsHandoff {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for operator-handoff.json and operator-handoff.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit the operator handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Diagnose a packaged sidecar install or update and write remediation reports.
    SidecarPackageDoctor {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for sidecar-doctor.json and sidecar-doctor.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional release handoff manifest produced by sidecar-package-release-manifest.
        #[arg(long)]
        release_manifest: Option<PathBuf>,
        /// Emit the doctor report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged support bundle with handoff, doctor, and hashed evidence metadata.
    SidecarPackageSupportBundle {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for support-bundle.json and support-bundle.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional release handoff manifest produced by sidecar-package-release-manifest.
        #[arg(long)]
        release_manifest: Option<PathBuf>,
        /// Emit the support bundle report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged deploy handoff artifact with hashed service/env templates.
    SidecarPackageDeployHandoff {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for deploy-handoff.json and deploy-handoff.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit the deploy handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged safe-agent demo onboarding handoff artifact.
    SidecarPackageDemoHandoff {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for demo-handoff.json and demo-handoff.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit the demo handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the packaged first-run quickstart and write one onboarding report.
    SidecarPackageQuickstart {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for quickstart.json and quickstart.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional release handoff manifest produced by sidecar-package-release-manifest.
        #[arg(long)]
        release_manifest: Option<PathBuf>,
        /// Emit the quickstart report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged permissions and identity handoff artifact.
    SidecarPackagePermissionsHandoff {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for permissions-handoff.json and permissions-handoff.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit the permissions handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged production preflight artifact for env and secret-reference review.
    SidecarPackageProductionPreflight {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for production-preflight.json and production-preflight.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit the production preflight report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged client onboarding handoff artifact.
    SidecarPackageClientHandoff {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for client-handoff.json and client-handoff.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit the client handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one packaged dashboard readiness handoff artifact.
    SidecarPackageDashboardHandoff {
        /// Root directory containing manifest.json, clients/, sidecar/, deploy/, and bin/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        root: PathBuf,
        /// Output directory for dashboard-handoff.json and dashboard-handoff.md.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit the dashboard handoff report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a packaged sidecar tar against its checksum file.
    SidecarPackageArchiveCheck {
        /// Tar archive written by sidecar-package --archive-out.
        #[arg(long)]
        archive: PathBuf,
        /// Optional checksum path. Defaults to <archive>.sha256.
        #[arg(long)]
        checksum: Option<PathBuf>,
        /// Emit the archive check report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify and install a packaged sidecar tar into a directory.
    SidecarPackageInstall {
        /// Tar archive written by sidecar-package --archive-out.
        #[arg(long)]
        archive: PathBuf,
        /// Output directory for the installed package.
        #[arg(long, default_value = "agentk-sidecar-package")]
        out: PathBuf,
        /// Optional checksum path. Defaults to <archive>.sha256.
        #[arg(long)]
        checksum: Option<PathBuf>,
        /// Overwrite an existing output directory.
        #[arg(long)]
        force: bool,
        /// Emit the install report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a verified package/archive/install handoff manifest.
    SidecarPackageReleaseManifest {
        /// Installed package directory containing manifest.json and sidecar/.
        #[arg(long, default_value = "agentk-sidecar-package")]
        package: PathBuf,
        /// Tar archive written by sidecar-package --archive-out.
        #[arg(long)]
        archive: PathBuf,
        /// Optional checksum path. Defaults to <archive>.sha256.
        #[arg(long)]
        checksum: Option<PathBuf>,
        /// Optional install receipt path. Defaults to <package>/sidecar/.agentk/install-receipt.json.
        #[arg(long)]
        install_receipt: Option<PathBuf>,
        /// Output JSON release handoff manifest path.
        #[arg(long, default_value = "agentk-sidecar-release-manifest.json")]
        out: PathBuf,
        /// Overwrite an existing output manifest.
        #[arg(long)]
        force: bool,
        /// Emit the release handoff manifest as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a package release handoff manifest against current package/archive files.
    SidecarPackageReleaseManifestCheck {
        /// Release handoff manifest produced by sidecar-package-release-manifest.
        #[arg(long, default_value = "agentk-sidecar-release-manifest.json")]
        manifest: PathBuf,
        /// Optional package directory override for relocated installs.
        #[arg(long)]
        package: Option<PathBuf>,
        /// Optional tar archive override for relocated release artifacts.
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Optional checksum override. Defaults to the manifest checksum path.
        #[arg(long)]
        checksum: Option<PathBuf>,
        /// Optional install receipt override. Defaults to the manifest receipt path.
        #[arg(long)]
        install_receipt: Option<PathBuf>,
        /// Emit the manifest check report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the active proof-signing public key and source.
    SigningKey {
        /// Emit the signer status as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate a local Ed25519 signing key file for AGENTK_SIGNING_KEY_FILE.
    Keygen {
        /// Output path for the private signing key hex. Keep this outside git.
        #[arg(long)]
        out: PathBuf,
        /// Overwrite an existing key file.
        #[arg(long)]
        force: bool,
        /// Emit the generated key metadata as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Rotate a local Ed25519 signing key and write a signed public manifest.
    KeyRotate {
        /// Existing private signing key hex file.
        #[arg(long)]
        current: PathBuf,
        /// Output path for the next private signing key hex file. Keep this outside git.
        #[arg(long)]
        next_out: PathBuf,
        /// Output path for the public rotation manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Overwrite an existing next key or manifest file.
        #[arg(long)]
        force: bool,
        /// Emit the rotation report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a signed public key-rotation manifest.
    KeyRotateVerify {
        /// Path to the public rotation manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Emit the verification report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Parse and validate an AgentK policy file.
    PolicyCheck {
        /// Path to an AgentK TOML policy.
        path: PathBuf,
    },
    /// Parse and validate a secret-reference manifest without printing refs.
    SecretRefsCheck {
        /// Path to an AgentK secret-reference TOML manifest.
        #[arg(long, default_value = "examples/secret-refs.toml")]
        manifest: PathBuf,
        /// Emit only redacted metadata counts as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check secret-reference availability through the env store without printing refs.
    SecretRefsStoreCheck {
        /// Path to an AgentK secret-reference TOML manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Emit only availability counts as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a trusted signer manifest without printing keys.
    TrustedSignersCheck {
        /// Path to an AgentK trusted-signers TOML manifest.
        #[arg(long, default_value = "examples/trusted-signers.toml")]
        manifest: PathBuf,
        /// Emit only version and count as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run local public-release readiness checks.
    Readiness {
        /// Emit the full report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the full local release-audit gate.
    ReleaseAudit {
        /// Emit the full audit report as JSON.
        #[arg(long)]
        json: bool,
        /// Treat warnings as blocking failures for final pre-push review.
        #[arg(long)]
        strict: bool,
    },
    /// Summarize the v0.2 alpha release train status without running heavy gates.
    ReleaseStatus {
        /// Emit the full release train status report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run an end-to-end local packaged sidecar release-candidate smoke test.
    ReleaseCandidateSmoke {
        /// Temporary root for the generated bundle and package.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Replace an existing --root directory before running.
        #[arg(long)]
        force: bool,
        /// Keep the auto-created temporary root after a successful run.
        #[arg(long)]
        keep_root: bool,
        /// Optional JSON evidence report to attach to a release or deployment ticket.
        #[arg(long)]
        evidence_out: Option<PathBuf>,
        /// Emit the full smoke report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify release-candidate smoke evidence and artifact hashes before handoff.
    ReleaseEvidenceCheck {
        /// JSON evidence report written by release-candidate-smoke --evidence-out.
        #[arg(long, default_value = "dist/release-candidate-smoke.json")]
        evidence: PathBuf,
        /// Optional relocated smoke root to rebase recorded artifact paths.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Emit the full evidence check report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write one offline release-candidate ticket bundle for reviewer handoff.
    ReleaseTicket {
        /// Release identifier to bind into the handoff report.
        #[arg(long, default_value = "v0.2-alpha")]
        release: String,
        /// Output directory for release-status, smoke evidence, finalization, and ticket JSON.
        #[arg(long, default_value = "dist/release-ticket")]
        out: PathBuf,
        /// Release notes file that reviewers will publish from.
        #[arg(long, default_value = "docs/v0.2-alpha-release-notes.md")]
        notes: PathBuf,
        /// Optional signed git tag to verify with git verify-tag.
        #[arg(long)]
        tag: Option<String>,
        /// Treat dirty worktree, draft notes, dev signer, or missing tag as blockers.
        #[arg(long)]
        strict: bool,
        /// Replace an existing release ticket directory.
        #[arg(long)]
        force: bool,
        /// Emit the full release ticket report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write an offline final release handoff report from verified evidence.
    ReleaseFinalize {
        /// Release identifier to bind into the handoff report.
        #[arg(long, default_value = "v0.2-alpha")]
        release: String,
        /// JSON evidence report written by release-candidate-smoke --evidence-out.
        #[arg(long, default_value = "dist/release-candidate-smoke.json")]
        evidence: PathBuf,
        /// Optional relocated smoke root to rebase recorded artifact paths.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Release notes file that reviewers will publish from.
        #[arg(long, default_value = "docs/v0.2-alpha-release-notes.md")]
        notes: PathBuf,
        /// Optional signed git tag to verify with git verify-tag.
        #[arg(long)]
        tag: Option<String>,
        /// Output JSON final release handoff report path.
        #[arg(long, default_value = "dist/release-finalization.json")]
        out: PathBuf,
        /// Treat dirty worktree, draft notes, dev signer, or missing tag as blockers.
        #[arg(long)]
        strict: bool,
        /// Overwrite an existing final release handoff report.
        #[arg(long)]
        force: bool,
        /// Emit the full finalization report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify final handoff evidence and notes before publishing a GitHub release.
    ReleasePublicationCheck {
        /// Final release handoff report written by release-finalize.
        #[arg(long, default_value = "dist/release-finalization.json")]
        finalization: PathBuf,
        /// Optional release notes path. Defaults to the path recorded in finalization.
        #[arg(long)]
        notes: Option<PathBuf>,
        /// Emit the full publication check report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a Homebrew formula for a reviewed AgentK source release tarball.
    ReleaseHomebrewFormula {
        /// HTTPS source release tarball URL for the formula.
        #[arg(long)]
        source_url: String,
        /// Expected SHA-256 for the source release tarball.
        #[arg(long)]
        sha256: Option<String>,
        /// Optional local source tarball to compute or verify the SHA-256.
        #[arg(long)]
        source_archive: Option<PathBuf>,
        /// Output Ruby formula path.
        #[arg(long, default_value = "dist/homebrew/agentk.rb")]
        out: PathBuf,
        /// Formula version. Defaults to the current Cargo package version.
        #[arg(long)]
        version: Option<String>,
        /// Formula homepage HTTPS URL.
        #[arg(long, default_value = "https://github.com/agentk/agentk")]
        homepage: String,
        /// Ruby formula class name.
        #[arg(long, default_value = "Agentk")]
        class_name: String,
        /// Replace an existing formula file.
        #[arg(long)]
        force: bool,
        /// Emit the formula write report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a reviewed local Homebrew formula before tap handoff.
    ReleaseHomebrewFormulaCheck {
        /// Local Ruby formula path.
        #[arg(long, default_value = "dist/homebrew/agentk.rb")]
        formula: PathBuf,
        /// Optional local source tarball to verify against the formula SHA-256.
        #[arg(long)]
        source_archive: Option<PathBuf>,
        /// Optional expected HTTPS source release tarball URL.
        #[arg(long)]
        source_url: Option<String>,
        /// Optional expected SHA-256 for the source release tarball.
        #[arg(long)]
        sha256: Option<String>,
        /// Optional expected formula version.
        #[arg(long)]
        version: Option<String>,
        /// Optional expected formula homepage HTTPS URL.
        #[arg(long)]
        homepage: Option<String>,
        /// Optional expected Ruby formula class name.
        #[arg(long)]
        class_name: Option<String>,
        /// Emit the formula check report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a Homebrew tap checkout before maintainer handoff.
    ReleaseHomebrewTapHandoffCheck {
        /// Reviewed local Ruby formula path.
        #[arg(long, default_value = "dist/homebrew/agentk.rb")]
        formula: PathBuf,
        /// Local Homebrew tap checkout root.
        #[arg(long, default_value = "dist/homebrew-tap")]
        tap_root: PathBuf,
        /// Relative formula path inside the tap checkout.
        #[arg(long, default_value = "Formula/agentk.rb")]
        tap_formula_path: String,
        /// Optional local source tarball to verify against the formula SHA-256.
        #[arg(long)]
        source_archive: Option<PathBuf>,
        /// Optional expected HTTPS source release tarball URL.
        #[arg(long)]
        source_url: Option<String>,
        /// Optional expected SHA-256 for the source release tarball.
        #[arg(long)]
        sha256: Option<String>,
        /// Optional expected formula version.
        #[arg(long)]
        version: Option<String>,
        /// Optional expected formula homepage HTTPS URL.
        #[arg(long)]
        homepage: Option<String>,
        /// Optional expected Ruby formula class name.
        #[arg(long)]
        class_name: Option<String>,
        /// Optional expected Homebrew tap name in owner/repo form.
        #[arg(long)]
        tap: Option<String>,
        /// Emit the tap handoff check report as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("agentk: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AgentKError> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Demo { json: false }) {
        Command::Demo { json } => demo(json),
        Command::Verify { path } => verify(path),
        Command::VerifySignatures {
            path,
            trusted_public_key,
            trusted_key_manifest,
        } => verify_signatures(path, trusted_public_key, trusted_key_manifest),
        Command::TraceInspect { path, json } => trace_inspect(path, json),
        Command::Audit { path, json } => audit(path, json),
        Command::Approvals {
            path,
            decisions,
            json,
        } => approvals(path, decisions, json),
        Command::Approve {
            path,
            id,
            reviewer,
            reason,
            decisions,
            permissions,
            json,
        } => approval_decision(
            path,
            decisions,
            permissions,
            id,
            ApprovalDecision::Approve,
            reviewer,
            reason,
            json,
        ),
        Command::Deny {
            path,
            id,
            reviewer,
            reason,
            decisions,
            permissions,
            json,
        } => approval_decision(
            path,
            decisions,
            permissions,
            id,
            ApprovalDecision::Deny,
            reviewer,
            reason,
            json,
        ),
        Command::Permissions { path, json } => permissions(path, json),
        Command::IdentityCheck {
            identity,
            permissions,
            json,
        } => identity_check(identity, permissions, json),
        Command::Dashboard {
            path,
            decisions,
            permissions,
            out,
            json,
        } => dashboard(path, decisions, permissions, out, json),
        Command::DashboardServe {
            path,
            decisions,
            permissions,
            identity,
            host,
            port,
            admin_token_env,
            stream_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            allow_non_local_bind,
            store_root,
        } => dashboard_serve(DashboardServeOptions {
            path,
            decisions,
            permissions,
            identity,
            host,
            port,
            admin_token_env,
            stream_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            allow_non_local_bind,
            store_root,
        }),
        Command::StoreExport {
            path,
            decisions,
            permissions,
            identity,
            out,
            json,
        } => store_export(path, decisions, permissions, identity, out, json),
        Command::StoreCheck { root, json } => store_check(root, json),
        Command::StoreSync {
            path,
            decisions,
            permissions,
            identity,
            root,
            json,
        } => store_sync(path, decisions, permissions, identity, root, json),
        Command::StoreSlack {
            root,
            out,
            channel,
            json,
        } => store_slack(root, out, channel, json),
        Command::StoreSlackSend {
            payload_root,
            webhook_url_env,
            curl,
            dry_run,
            json,
        } => store_slack_send(payload_root, webhook_url_env, curl, dry_run, json),
        Command::StoreGithub {
            root,
            out,
            repository,
            label,
            json,
        } => store_github(root, out, repository, label, json),
        Command::StoreGithubSend {
            payload_root,
            github_token_env,
            gh,
            dry_run,
            json,
        } => store_github_send(payload_root, github_token_env, gh, dry_run, json),
        Command::StoreEmail {
            root,
            out,
            to,
            json,
        } => store_email(root, out, to, json),
        Command::StoreEmailSend {
            payload_root,
            sendmail,
            dry_run,
            json,
        } => store_email_send(payload_root, sendmail, dry_run, json),
        Command::StorePush {
            root,
            database_url_env,
            psql,
            dry_run,
            json,
        } => store_push(root, database_url_env, psql, dry_run, json),
        Command::Replay { path } => replay(path),
        Command::ForkReplay { path, policy, json } => fork_replay(path, policy, json),
        Command::ForkReplayBehavior {
            path,
            behavior,
            json,
        } => fork_replay_behavior(path, behavior, json),
        Command::McpProxy { request, json } => mcp_proxy(request, json),
        Command::McpStdio => mcp_stdio(),
        Command::McpLines => mcp_lines(),
        Command::McpServer => mcp_server(),
        Command::McpKillerDemo { trace_out, json } => mcp_killer_demo(trace_out, json),
        Command::McpShimEval { trace_out, json } => mcp_shim_eval(trace_out, json),
        Command::SafeAgentDemo { trace_out, json } => safe_agent_demo(trace_out, json),
        Command::McpProxyStdio {
            agent_id,
            server_id,
            command,
            args,
            allow_env,
            response_timeout_ms,
            max_client_messages,
            trace_out,
            session_report_out,
        } => mcp_proxy_stdio(
            agent_id,
            server_id,
            command,
            args,
            allow_env,
            response_timeout_ms,
            max_client_messages,
            trace_out,
            session_report_out,
        ),
        Command::McpProxyTcp {
            agent_id,
            server_id,
            host,
            port,
            max_sessions,
            max_concurrent_sessions,
            command,
            args,
            allow_env,
            response_timeout_ms,
            max_client_messages,
            trace_out,
            session_report_out,
        } => mcp_proxy_tcp(
            agent_id,
            server_id,
            host,
            port,
            max_sessions,
            max_concurrent_sessions,
            command,
            args,
            allow_env,
            response_timeout_ms,
            max_client_messages,
            trace_out,
            session_report_out,
        ),
        Command::McpProxyHttp {
            agent_id,
            server_id,
            host,
            port,
            endpoint,
            max_requests,
            max_concurrent_requests,
            max_active_sessions,
            session_idle_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            stream_timeout_ms,
            allow_origins,
            allow_origin_env,
            allow_non_local_bind,
            trust_proxy_headers,
            auth_token_env,
            command,
            args,
            allow_env,
            response_timeout_ms,
            max_client_messages,
            trace_out,
            session_report_out,
        } => mcp_proxy_http(
            agent_id,
            server_id,
            host,
            port,
            endpoint,
            max_requests,
            max_concurrent_requests,
            max_active_sessions,
            session_idle_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            stream_timeout_ms,
            allow_origins,
            allow_origin_env,
            allow_non_local_bind,
            trust_proxy_headers,
            auth_token_env,
            command,
            args,
            allow_env,
            response_timeout_ms,
            max_client_messages,
            trace_out,
            session_report_out,
        ),
        Command::SidecarInit { out, force, json } => sidecar_init(out, force, json),
        Command::SidecarCheck { root, json } => sidecar_check(root, json),
        Command::SidecarRun { root } => sidecar_run(root),
        Command::SidecarServeTcp {
            root,
            host,
            port,
            max_sessions,
            max_concurrent_sessions,
        } => sidecar_serve_tcp(root, host, port, max_sessions, max_concurrent_sessions),
        Command::SidecarServeHttp {
            root,
            host,
            port,
            endpoint,
            max_requests,
            max_concurrent_requests,
            max_active_sessions,
            session_idle_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            stream_timeout_ms,
            allow_origins,
            allow_origin_env,
            allow_non_local_bind,
            trust_proxy_headers,
            auth_token_env,
        } => sidecar_serve_http(
            root,
            host,
            port,
            endpoint,
            max_requests,
            max_concurrent_requests,
            max_active_sessions,
            session_idle_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            stream_timeout_ms,
            allow_origins,
            allow_origin_env,
            allow_non_local_bind,
            trust_proxy_headers,
            auth_token_env,
        ),
        Command::SidecarPackage {
            root,
            out,
            archive_out,
            force,
            json,
        } => sidecar_package(root, out, archive_out, force, json),
        Command::SidecarPackageCheck { root, json } => sidecar_package_check(root, json),
        Command::SidecarPackageHttpHandoffCheck { root, json } => {
            sidecar_package_http_handoff_check(root, json)
        }
        Command::SidecarPackageTeamHandoffCheck { root, json } => {
            sidecar_package_team_handoff_check(root, json)
        }
        Command::SidecarPackageOpsHandoff { root, out, json } => {
            sidecar_package_ops_handoff(root, out, json)
        }
        Command::SidecarPackageDoctor {
            root,
            out,
            release_manifest,
            json,
        } => sidecar_package_doctor(root, out, release_manifest, json),
        Command::SidecarPackageSupportBundle {
            root,
            out,
            release_manifest,
            json,
        } => sidecar_package_support_bundle(root, out, release_manifest, json),
        Command::SidecarPackageDeployHandoff { root, out, json } => {
            sidecar_package_deploy_handoff(root, out, json)
        }
        Command::SidecarPackageDemoHandoff { root, out, json } => {
            sidecar_package_demo_handoff(root, out, json)
        }
        Command::SidecarPackageQuickstart {
            root,
            out,
            release_manifest,
            json,
        } => sidecar_package_quickstart(root, out, release_manifest, json),
        Command::SidecarPackagePermissionsHandoff { root, out, json } => {
            sidecar_package_permissions_handoff(root, out, json)
        }
        Command::SidecarPackageProductionPreflight { root, out, json } => {
            sidecar_package_production_preflight(root, out, json)
        }
        Command::SidecarPackageClientHandoff { root, out, json } => {
            sidecar_package_client_handoff(root, out, json)
        }
        Command::SidecarPackageDashboardHandoff { root, out, json } => {
            sidecar_package_dashboard_handoff(root, out, json)
        }
        Command::SidecarPackageArchiveCheck {
            archive,
            checksum,
            json,
        } => sidecar_package_archive_check(archive, checksum, json),
        Command::SidecarPackageInstall {
            archive,
            out,
            checksum,
            force,
            json,
        } => sidecar_package_install(archive, out, checksum, force, json),
        Command::SidecarPackageReleaseManifest {
            package,
            archive,
            checksum,
            install_receipt,
            out,
            force,
            json,
        } => sidecar_package_release_manifest(
            package,
            archive,
            checksum,
            install_receipt,
            out,
            force,
            json,
        ),
        Command::SidecarPackageReleaseManifestCheck {
            manifest,
            package,
            archive,
            checksum,
            install_receipt,
            json,
        } => sidecar_package_release_manifest_check(
            manifest,
            package,
            archive,
            checksum,
            install_receipt,
            json,
        ),
        Command::SigningKey { json } => signing_key(json),
        Command::Keygen { out, force, json } => keygen(out, force, json),
        Command::KeyRotate {
            current,
            next_out,
            manifest,
            force,
            json,
        } => key_rotate(current, next_out, manifest, force, json),
        Command::KeyRotateVerify { manifest, json } => key_rotate_verify(manifest, json),
        Command::PolicyCheck { path } => policy_check(path),
        Command::SecretRefsCheck { manifest, json } => secret_refs_check(manifest, json),
        Command::SecretRefsStoreCheck { manifest, json } => secret_refs_store_check(manifest, json),
        Command::TrustedSignersCheck { manifest, json } => trusted_signers_check(manifest, json),
        Command::Readiness { json } => readiness(json),
        Command::ReleaseAudit { json, strict } => release_audit(json, strict),
        Command::ReleaseStatus { json } => release_status(json),
        Command::ReleaseCandidateSmoke {
            root,
            force,
            keep_root,
            evidence_out,
            json,
        } => release_candidate_smoke(root, force, keep_root, evidence_out, json),
        Command::ReleaseEvidenceCheck {
            evidence,
            root,
            json,
        } => release_evidence_check(evidence, root, json),
        Command::ReleaseTicket {
            release,
            out,
            notes,
            tag,
            strict,
            force,
            json,
        } => release_ticket(release, out, notes, tag, strict, force, json),
        Command::ReleaseFinalize {
            release,
            evidence,
            root,
            notes,
            tag,
            out,
            strict,
            force,
            json,
        } => release_finalize(
            release, evidence, root, notes, tag, out, strict, force, json,
        ),
        Command::ReleasePublicationCheck {
            finalization,
            notes,
            json,
        } => release_publication_check(&finalization, notes.as_deref(), json),
        Command::ReleaseHomebrewFormula {
            source_url,
            sha256,
            source_archive,
            out,
            version,
            homepage,
            class_name,
            force,
            json,
        } => release_homebrew_formula(
            source_url,
            sha256,
            source_archive,
            out,
            version,
            homepage,
            class_name,
            force,
            json,
        ),
        Command::ReleaseHomebrewFormulaCheck {
            formula,
            source_archive,
            source_url,
            sha256,
            version,
            homepage,
            class_name,
            json,
        } => release_homebrew_formula_check(
            formula,
            source_archive,
            source_url,
            sha256,
            version,
            homepage,
            class_name,
            json,
        ),
        Command::ReleaseHomebrewTapHandoffCheck {
            formula,
            tap_root,
            tap_formula_path,
            source_archive,
            source_url,
            sha256,
            version,
            homepage,
            class_name,
            tap,
            json,
        } => release_homebrew_tap_handoff_check(
            formula,
            tap_root,
            tap_formula_path,
            source_archive,
            source_url,
            sha256,
            version,
            homepage,
            class_name,
            tap,
            json,
        ),
    }
}

fn demo(json: bool) -> Result<(), AgentKError> {
    let report = run_poisoned_webpage_demo(default_log_path())?;
    let latest = write_latest_copy(&report.log_path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK :: Context MMU demo");
    println!("agent     agent://demo/researcher");
    println!("scenario  poisoned webpage attempts secret exfiltration");
    println!();

    for event in &report.events {
        let marker = match event.decision.verdict {
            Verdict::Allow => "ALLOW",
            Verdict::Deny => "BLOCK",
        };
        let labels = event
            .syscall
            .labels
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        println!(
            "[{marker}] #{:<2} {:<13} {}",
            event.step, event.syscall.kind, event.syscall.target
        );
        println!("       intent: {}", event.syscall.intent);
        println!("       labels: {labels}");
        println!("       rule:   {}", event.decision.rule);
        println!("       reason: {}", event.decision.reason);
        if let Some(missing) = &event.decision.missing_capability {
            println!("       missing capability: {missing}");
        }
        if let Some(receipt) = &event.decision.receipt {
            println!(
                "       receipt: {} proof={}",
                receipt.id,
                &receipt.proof[..16]
            );
        }
        println!("       hash:   {}", &event.event_hash[..16]);
        println!();
    }

    println!("blocked   {}", report.blocked);
    println!("final     {}", report.final_hash);
    println!("log       {}", report.log_path.display());
    println!("latest    {}", latest.display());
    println!();
    println!("try       cargo run -- verify {}", latest.display());

    Ok(())
}

fn verify(path: PathBuf) -> Result<(), AgentKError> {
    let report = verify_jsonl(&path)?;
    println!("AgentK flight log verified");
    println!("events    {}", report.events_checked);
    println!("final     {}", report.final_hash);
    Ok(())
}

fn verify_signatures(
    path: PathBuf,
    mut trusted_public_keys: Vec<String>,
    trusted_key_manifest: Option<PathBuf>,
) -> Result<(), AgentKError> {
    if let Some(manifest) = trusted_key_manifest {
        trusted_public_keys.extend(trusted_signing_key_manifest_keys_from_path(manifest)?);
    }

    let report = if trusted_public_keys.is_empty() {
        verify_signatures_jsonl(&path)?
    } else {
        verify_signatures_jsonl_with_trusted_keys(&path, &trusted_public_keys)?
    };
    println!("AgentK signature verification complete");
    println!("events    {}", report.events_checked);
    println!("receipts  {}", report.receipts_checked);
    println!("handles   {}", report.secret_handles_checked);
    println!("signers   {}", report.public_keys_seen.len());
    println!("trusted   {}", report.trusted_public_keys);
    println!("pinned    {}", report.signer_identity_pinned);
    println!("ok        {}", report.ok);
    if !report.signer_summary.is_empty() {
        println!("signer summary");
        for (signer, summary) in &report.signer_summary {
            println!(
                "  {signer} receipts {} handles {} trusted {}",
                summary.receipts_checked, summary.secret_handles_checked, summary.trusted
            );
        }
    }

    for failure in &report.failures {
        println!("failure   {failure}");
    }

    if !report.ok {
        std::process::exit(2);
    }

    Ok(())
}

fn trusted_signers_check(manifest: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = trusted_signing_key_manifest_report_from_path(manifest)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK trusted signers verified");
    println!("version   {}", report.version);
    println!("keys      {}", report.trusted_key_count);
    println!("redacted  public keys were not printed");
    Ok(())
}

fn trace_inspect(path: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = inspect_jsonl(&path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK flight log inspect");
    println!("log       {}", report.path.display());
    println!("events    {}", report.events_checked);
    println!("allowed   {}", report.allowed);
    println!("blocked   {}", report.blocked);
    println!("stubbed   {}", report.side_effects_stubbed);
    println!("signatures {}", report.signatures_ok);
    println!("receipts  {}", report.receipts_checked);
    println!("handles   {}", report.secret_handles_checked);
    println!("final     {}", report.final_hash);
    if !report.blocked_rules.is_empty() {
        println!("blocked rules");
        for (rule, count) in &report.blocked_rules {
            println!("  {rule}: {count}");
        }
    }
    if !report.syscall_summary.is_empty() {
        println!("syscall summary");
        for (syscall, summary) in &report.syscall_summary {
            println!(
                "  {:<17} allow {:<3} block {:<3} targets {}",
                syscall, summary.allowed, summary.blocked, summary.targets
            );
        }
    }
    if !report.evidence_summary.is_empty() {
        println!("evidence refs");
        for (kind, count) in &report.evidence_summary {
            println!("  {kind}: {count}");
        }
    }
    println!();

    for event in &report.events {
        let marker = match event.verdict {
            Verdict::Allow => "ALLOW",
            Verdict::Deny => "BLOCK",
        };
        let labels = if event.labels.is_empty() {
            "-".to_string()
        } else {
            event.labels.join(", ")
        };
        let evidence = if event.evidence_refs.is_empty() {
            "-".to_string()
        } else {
            event.evidence_refs.join(", ")
        };

        println!(
            "[{marker}] #{:<2} {:<13} {}",
            event.step, event.syscall, event.target
        );
        println!("       rule:     {}", event.rule);
        println!("       reason:   {}", event.reason);
        if let Some(missing) = &event.missing_capability {
            println!("       missing:  {missing}");
        }
        println!("       labels:   {labels}");
        println!("       evidence: {evidence}");
        if event.redacted_inputs {
            println!("       redacted: raw input refs were replaced with input_sha256 evidence");
        }
        if let Some(receipt_id) = &event.receipt_id {
            println!("       receipt:  {receipt_id}");
        }
        if let Some(handle_id) = &event.secret_handle_id {
            println!("       handle:   {handle_id}");
        }
        println!("       hash:     {}", &event.event_hash[..16]);
        println!();
    }

    for failure in &report.signature_failures {
        println!("signature failure: {failure}");
    }

    if !report.signatures_ok {
        std::process::exit(2);
    }

    Ok(())
}

fn audit(path: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = audit_inbox_jsonl(&path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK audit inbox");
    println!("log        {}", report.path.display());
    println!("events     {}", report.events_checked);
    println!("allowed    {}", report.allowed);
    println!("blocked    {}", report.blocked);
    println!("signatures {}", report.signatures_ok);
    println!("pending    {}", report.pending_approvals.len());
    println!("sidefx     {}", report.allowed_side_effects.len());
    println!("final      {}", report.final_hash);

    if !report.blocked_rules.is_empty() {
        println!("blocked rules");
        for (rule, count) in &report.blocked_rules {
            println!("  {rule}: {count}");
        }
    }

    if !report.pending_approvals.is_empty() {
        println!("pending approvals");
        for item in &report.pending_approvals {
            println!(
                "  {} #{} {} {}",
                item.id, item.step, item.syscall, item.target
            );
            println!("       rule:   {}", item.rule);
            println!("       reason: {}", item.reason);
            if let Some(capability) = &item.missing_capability {
                println!("       missing capability: {capability}");
            }
            println!("       hint:   {}", item.review_hint);
        }
    }

    if !report.allowed_side_effects.is_empty() {
        println!("allowed side effects");
        for item in &report.allowed_side_effects {
            let receipt = item.receipt_id.as_deref().unwrap_or("-");
            println!(
                "  #{} {} {} receipt {}",
                item.step, item.syscall, item.target, receipt
            );
        }
    }

    if !report.signatures_ok {
        std::process::exit(2);
    }

    Ok(())
}

fn approvals(path: PathBuf, decisions: Option<PathBuf>, json: bool) -> Result<(), AgentKError> {
    let decisions = approval_decisions_path(&path, decisions);
    let report = approval_review_jsonl(&path, &decisions)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK approvals");
    println!("log        {}", report.trace_path.display());
    println!("decisions  {}", report.decisions_path.display());
    println!("events     {}", report.events_checked);
    println!("signatures {}", report.signatures_ok);
    println!("open       {}", report.open_approvals.len());
    println!("approved   {}", report.approved);
    println!("denied     {}", report.denied);
    println!("stale      {}", report.stale_decisions.len());

    if !report.open_approvals.is_empty() {
        println!("open approvals");
        for item in &report.open_approvals {
            println!(
                "  {} #{} {} {}",
                item.id, item.step, item.syscall, item.target
            );
            if let Some(capability) = &item.missing_capability {
                println!("       missing capability: {capability}");
            }
            println!("       hint:   {}", item.review_hint);
        }
    }

    if !report.decided_approvals.is_empty() {
        println!("decisions");
        for item in &report.decided_approvals {
            println!(
                "  {} #{} {} {} by {}",
                item.approval_id,
                item.step,
                item.decision.as_str(),
                item.target,
                item.reviewer
            );
            println!("       reason: {}", item.reason);
        }
    }

    if !report.signatures_ok {
        std::process::exit(2);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn approval_decision(
    path: PathBuf,
    decisions: Option<PathBuf>,
    permissions: Option<PathBuf>,
    id: String,
    decision: ApprovalDecision,
    reviewer: String,
    reason: String,
    json: bool,
) -> Result<(), AgentKError> {
    let decisions = approval_decisions_path(&path, decisions);
    let record = if let Some(permissions) = permissions {
        record_approval_decision_jsonl_with_permissions(
            &path,
            &decisions,
            &permissions,
            &id,
            decision,
            &reviewer,
            &reason,
        )?
    } else {
        record_approval_decision_jsonl(&path, &decisions, &id, decision, &reviewer, &reason)?
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }

    println!("AgentK approval decision recorded");
    println!("decision   {}", record.decision.as_str());
    println!("id         {}", record.approval_id);
    println!("target     {}", record.target);
    println!("reviewer   {}", record.reviewer);
    println!("decisions  {}", decisions.display());
    Ok(())
}

fn permissions(path: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = team_permissions_report_from_path(&path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK team permissions");
    println!("path       {}", report.path.display());
    println!("version    {}", report.version);
    println!("users      {}", report.users);
    println!("roles      {}", report.roles);
    println!("reviewers  {}", report.reviewers.len());
    println!("tokenized  {}", report.token_protected_reviewers);
    for reviewer in &report.reviewers {
        println!("  {reviewer}");
    }
    Ok(())
}

fn identity_check(
    identity: PathBuf,
    permissions: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = team_identity_report_from_path(&identity, permissions.as_deref())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK team identity mappings");
    println!("identity    {}", report.path.display());
    if let Some(path) = &report.permissions_path {
        println!("permissions {}", path.display());
    }
    println!("version     {}", report.version);
    println!("providers   {}", report.providers);
    println!("mappings    {}", report.mappings);
    println!("reviewers   {}", report.mapped_reviewers);
    if let Some(permission_reviewers) = report.permission_reviewers {
        println!("permission reviewers {}", permission_reviewers);
    }
    if let Some(covered) = report.covered_permission_reviewers {
        println!("covered permission reviewers {}", covered);
    }
    if let Some(token_protected) = report.token_protected_reviewers {
        println!("token-protected reviewers {}", token_protected);
    }
    println!("redacted    issuers, groups, and claim values were not printed");
    Ok(())
}

fn dashboard(
    path: PathBuf,
    decisions: Option<PathBuf>,
    permissions: Option<PathBuf>,
    out: PathBuf,
    json: bool,
) -> Result<(), AgentKError> {
    let decisions = approval_decisions_path(&path, decisions);
    let report = write_approval_dashboard_html(&path, &decisions, permissions.as_deref(), &out)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK dashboard written");
    println!("out        {}", report.output_path.display());
    println!("trace      {}", report.trace_path.display());
    println!("decisions  {}", report.decisions_path.display());
    if let Some(path) = &report.permissions_path {
        println!("permissions {}", path.display());
    }
    println!("signatures {}", report.signatures_ok);
    println!("open       {}", report.open);
    println!("approved   {}", report.approved);
    println!("denied     {}", report.denied);
    println!("stale      {}", report.stale);
    println!("reviewers  {}", report.reviewers);

    if !report.signatures_ok {
        std::process::exit(2);
    }

    Ok(())
}

struct DashboardServeOptions {
    path: PathBuf,
    decisions: Option<PathBuf>,
    permissions: Option<PathBuf>,
    identity: Option<PathBuf>,
    host: String,
    port: u16,
    admin_token_env: String,
    stream_timeout_ms: u64,
    max_body_bytes: usize,
    max_header_bytes: usize,
    allow_non_local_bind: bool,
    store_root: Option<PathBuf>,
}

struct DashboardHttpContext<'a> {
    trace_path: &'a PathBuf,
    decisions_path: &'a PathBuf,
    permissions_path: Option<&'a PathBuf>,
    identity_path: Option<&'a PathBuf>,
    admin_token: Option<&'a str>,
    admin_read_required: bool,
    max_body_bytes: usize,
    max_header_bytes: usize,
    store_root: Option<&'a PathBuf>,
}

fn dashboard_serve(options: DashboardServeOptions) -> Result<(), AgentKError> {
    let DashboardServeOptions {
        path,
        decisions,
        permissions,
        identity,
        host,
        port,
        admin_token_env,
        stream_timeout_ms,
        max_body_bytes,
        max_header_bytes,
        allow_non_local_bind,
        store_root,
    } = options;
    if !is_safe_env_name(&admin_token_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "admin-token-env must be a safe environment variable name".to_string(),
        ));
    }
    let decisions = approval_decisions_path(&path, decisions);
    let admin_token = env::var(&admin_token_env)
        .ok()
        .filter(|value| !value.is_empty());
    let stream_timeout = Duration::from_millis(stream_timeout_ms);
    validate_dashboard_stream_timeout(stream_timeout)?;
    validate_dashboard_http_size_limits(max_body_bytes, max_header_bytes)?;
    validate_dashboard_bind_security(&host, allow_non_local_bind, admin_token.is_some())?;
    let admin_read_required = !is_loopback_bind_host(&host);
    let bind = format!("{host}:{port}");
    let listener = TcpListener::bind(&bind)?;
    println!("AgentK dashboard server");
    println!("url        http://{bind}/");
    println!("trace      {}", path.display());
    println!("decisions  {}", decisions.display());
    println!("stream ms  {}", stream_timeout.as_millis());
    println!("body bytes {}", max_body_bytes);
    println!("header bytes {}", max_header_bytes);
    if let Some(path) = &store_root {
        println!("store      {}", path.display());
    }
    println!(
        "admin     {}",
        if admin_token.is_some() {
            format!("${admin_token_env}")
        } else {
            "not configured".to_string()
        }
    );
    if let Some(path) = &permissions {
        println!("permissions {}", path.display());
    }
    if let Some(path) = &identity {
        println!("identity   {}", path.display());
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let context = DashboardHttpContext {
                    trace_path: &path,
                    decisions_path: &decisions,
                    permissions_path: permissions.as_ref(),
                    identity_path: identity.as_ref(),
                    admin_token: admin_token.as_deref(),
                    admin_read_required,
                    max_body_bytes,
                    max_header_bytes,
                    store_root: store_root.as_ref(),
                };
                let result = configure_dashboard_http_stream(&stream, stream_timeout)
                    .and_then(|_| handle_dashboard_http_stream(&mut stream, &context));
                if let Err(error) = result {
                    eprintln!("dashboard request failed: {error}");
                }
            }
            Err(error) => eprintln!("dashboard connection failed: {error}"),
        }
    }

    Ok(())
}

fn validate_dashboard_stream_timeout(stream_timeout: Duration) -> Result<(), AgentKError> {
    if stream_timeout.is_zero() {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard stream-timeout-ms must be positive".to_string(),
        ));
    }
    Ok(())
}

fn validate_dashboard_http_size_limits(
    max_body_bytes: usize,
    max_header_bytes: usize,
) -> Result<(), AgentKError> {
    if max_body_bytes == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard max-body-bytes must be positive".to_string(),
        ));
    }
    if max_header_bytes == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard max-header-bytes must be positive".to_string(),
        ));
    }
    Ok(())
}

fn validate_dashboard_bind_security(
    host: &str,
    allow_non_local_bind: bool,
    admin_configured: bool,
) -> Result<(), AgentKError> {
    if is_loopback_bind_host(host) {
        return Ok(());
    }
    if !allow_non_local_bind {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard host must be loopback unless --allow-non-local-bind is set".to_string(),
        ));
    }
    if !admin_configured {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard non-loopback binds require a non-empty admin token".to_string(),
        ));
    }
    Ok(())
}

fn configure_dashboard_http_stream(
    stream: &TcpStream,
    stream_timeout: Duration,
) -> Result<(), AgentKError> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(stream_timeout))?;
    stream.set_write_timeout(Some(stream_timeout))?;
    Ok(())
}

fn handle_dashboard_http_stream(
    stream: &mut TcpStream,
    context: &DashboardHttpContext<'_>,
) -> Result<(), AgentKError> {
    let request = match read_dashboard_http_request_with_limits(
        stream,
        context.max_body_bytes,
        context.max_header_bytes,
        false,
    ) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(AgentKError::InvalidMcpRequest(message))
            if message == "HTTP request headers are too large" =>
        {
            let response = dashboard_http_headers_too_large_response(context.max_header_bytes);
            write_dashboard_http_response(stream, &response)?;
            return Ok(());
        }
        Err(AgentKError::InvalidMcpRequest(message))
            if message == "HTTP request body is too large" =>
        {
            let response = dashboard_http_payload_too_large_response(context.max_body_bytes);
            write_dashboard_http_response(stream, &response)?;
            return Ok(());
        }
        Err(AgentKError::InvalidMcpRequest(_)) => {
            let response =
                dashboard_http_text("400 Bad Request", "invalid dashboard HTTP request\n");
            write_dashboard_http_response(stream, &response)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let response = dashboard_http_response_with_read_auth_and_limits(&request, context);
    write_dashboard_http_response(stream, &response)?;
    Ok(())
}

fn dashboard_http_payload_too_large_response(max_body_bytes: usize) -> DashboardHttpResponse {
    dashboard_http_text(
        "413 Payload Too Large",
        &format!("dashboard HTTP request body must be at most {max_body_bytes} bytes\n"),
    )
}

fn dashboard_http_headers_too_large_response(max_header_bytes: usize) -> DashboardHttpResponse {
    dashboard_http_text(
        "431 Request Header Fields Too Large",
        &format!("dashboard HTTP request headers must be at most {max_header_bytes} bytes\n"),
    )
}

#[derive(Debug, Clone)]
struct DashboardHttpRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl DashboardHttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == &name)
            .map(|(_, value)| value.as_str())
    }

    fn header_count(&self, name: &str) -> usize {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(candidate, _)| candidate == &name)
            .count()
    }
}

fn read_dashboard_http_request_with_limits(
    stream: &mut TcpStream,
    max_body_bytes: usize,
    max_header_bytes: usize,
    allow_forwarded_headers: bool,
) -> Result<Option<DashboardHttpRequest>, AgentKError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    let mut bytes = read_dashboard_http_line(&mut reader, &mut request_line, max_header_bytes)?;
    if bytes == 0 {
        return Ok(None);
    }
    let (method, target, _version) = parse_dashboard_http_request_line(&request_line)?;
    if is_unsupported_proxy_http_method(&method) {
        return Err(AgentKError::InvalidMcpRequest(
            "HTTP proxy and trace methods are not supported".to_string(),
        ));
    }
    let mut content_length = 0usize;
    let mut content_length_seen = false;
    let mut host_seen = false;
    let mut headers = Vec::new();

    loop {
        let mut line = String::new();
        let remaining_header_bytes = max_header_bytes.saturating_sub(bytes);
        let read = read_dashboard_http_line(&mut reader, &mut line, remaining_header_bytes)?;
        if read == 0 {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP header block is incomplete".to_string(),
            ));
        }
        bytes += read;
        if line == "\r\n" {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP header line is invalid".to_string(),
            ));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP header line is invalid".to_string(),
            ));
        };
        if !is_valid_http_header_name(name) {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP header line is invalid".to_string(),
            ));
        }
        if !is_valid_http_header_value(value) {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP header line is invalid".to_string(),
            ));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_string();
        if name == "content-length" {
            if content_length_seen {
                return Err(AgentKError::InvalidMcpRequest(
                    "HTTP content-length header must appear at most once".to_string(),
                ));
            }
            content_length_seen = true;
            content_length = parse_http_content_length(&value)?;
            if content_length > max_body_bytes {
                return Err(AgentKError::InvalidMcpRequest(
                    "HTTP request body is too large".to_string(),
                ));
            }
        } else if name == "transfer-encoding" {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP transfer-encoding is not supported".to_string(),
            ));
        } else if name == "content-encoding" {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP content-encoding is not supported".to_string(),
            ));
        } else if matches!(name.as_str(), "expect" | "upgrade") {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP expectation and upgrade headers are not supported".to_string(),
            ));
        } else if is_unsupported_websocket_http_header(&name) {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP websocket headers are not supported".to_string(),
            ));
        } else if name == "connection" {
            if !is_supported_http_connection_header(&value) {
                return Err(AgentKError::InvalidMcpRequest(
                    "HTTP connection header is not supported".to_string(),
                ));
            }
        } else if matches!(
            name.as_str(),
            "proxy-connection" | "keep-alive" | "te" | "trailer"
        ) {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP hop-by-hop headers are not supported".to_string(),
            ));
        } else if matches!(name.as_str(), "proxy-authorization" | "proxy-authenticate") {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP proxy authentication headers are not supported".to_string(),
            ));
        } else if is_forwarded_http_header(&name) {
            if !allow_forwarded_headers || !is_supported_trusted_forwarded_http_header(&name) {
                return Err(AgentKError::InvalidMcpRequest(
                    "HTTP forwarded headers are not supported".to_string(),
                ));
            }
            if !is_clean_trusted_forwarded_header_value(&name, &value) {
                return Err(AgentKError::InvalidMcpRequest(
                    "HTTP forwarded header is invalid".to_string(),
                ));
            }
        } else if name.starts_with("x-forwarded-") {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP forwarded headers are not supported".to_string(),
            ));
        } else if is_unsupported_method_override_http_header(&name) {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP method override headers are not supported".to_string(),
            ));
        } else if is_unsupported_cookie_http_header(&name) {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP cookie headers are not supported".to_string(),
            ));
        } else if name == "host" {
            if host_seen || !is_valid_http_host_header(&value) {
                return Err(AgentKError::InvalidMcpRequest(
                    "HTTP host header is invalid".to_string(),
                ));
            }
            host_seen = true;
        }
        headers.push((name, value));
    }

    if !host_seen {
        return Err(AgentKError::InvalidMcpRequest(
            "HTTP host header is required".to_string(),
        ));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                AgentKError::InvalidMcpRequest("HTTP request body is incomplete".to_string())
            } else {
                AgentKError::Io(error)
            }
        })?;
    }

    Ok(Some(DashboardHttpRequest {
        method,
        target,
        headers,
        body,
    }))
}

fn read_dashboard_http_line(
    reader: &mut impl BufRead,
    line: &mut String,
    max_line_bytes: usize,
) -> Result<usize, AgentKError> {
    let mut line_bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        let bytes_to_take = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |position| position + 1);
        if line_bytes.len() + bytes_to_take > max_line_bytes {
            return Err(AgentKError::InvalidMcpRequest(
                "HTTP request headers are too large".to_string(),
            ));
        }
        line_bytes.extend_from_slice(&buffer[..bytes_to_take]);
        reader.consume(bytes_to_take);
        if line_bytes.ends_with(b"\n") {
            break;
        }
    }
    if !line_bytes.is_empty() && !line_bytes.ends_with(b"\r\n") {
        return Err(AgentKError::InvalidMcpRequest(
            "HTTP line ending is invalid".to_string(),
        ));
    }
    let line_text = std::str::from_utf8(&line_bytes)
        .map_err(|_| AgentKError::InvalidMcpRequest("HTTP request line is invalid".to_string()))?;
    line.push_str(line_text);
    Ok(line_bytes.len())
}

fn parse_dashboard_http_request_line(line: &str) -> Result<(String, String, String), AgentKError> {
    let Some(line) = line.strip_suffix("\r\n") else {
        return Err(AgentKError::InvalidMcpRequest(
            "HTTP request line is invalid".to_string(),
        ));
    };
    let parts = line.split(' ').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(AgentKError::InvalidMcpRequest(
            "HTTP request line is invalid".to_string(),
        ));
    };
    let [method, target, version] = parts.as_slice() else {
        unreachable!("request line part count was already validated");
    };
    if !matches!(*version, "HTTP/1.0" | "HTTP/1.1")
        || !target.starts_with('/')
        || target.starts_with("//")
        || method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || target.contains('#')
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(AgentKError::InvalidMcpRequest(
            "HTTP request line is invalid".to_string(),
        ));
    }
    Ok((method.to_string(), target.to_string(), version.to_string()))
}

fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_http_header_value(value: &str) -> bool {
    value
        .strip_suffix("\r\n")
        .unwrap_or(value)
        .bytes()
        .all(|byte| byte == b'\t' || !byte.is_ascii_control())
}

fn parse_http_content_length(value: &str) -> Result<usize, AgentKError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard HTTP content-length is invalid".to_string(),
        ));
    }
    value.parse::<usize>().map_err(|_| {
        AgentKError::InvalidMcpRequest("dashboard HTTP content-length is invalid".to_string())
    })
}

fn is_valid_http_host_header(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace() && byte != b',')
        && is_valid_http_authority(value)
}

fn is_supported_http_connection_header(value: &str) -> bool {
    value
        .split(',')
        .map(|part| part.trim())
        .all(|part| part.eq_ignore_ascii_case("close"))
}

fn is_forwarded_http_header(name: &str) -> bool {
    name == "forwarded" || name.starts_with("x-forwarded-") || name == "x-real-ip"
}

fn is_supported_trusted_forwarded_http_header(name: &str) -> bool {
    matches!(
        name,
        "forwarded" | "x-forwarded-for" | "x-forwarded-host" | "x-forwarded-proto" | "x-real-ip"
    )
}

fn is_clean_trusted_forwarded_header_value(name: &str, value: &str) -> bool {
    match name {
        "forwarded" => is_clean_forwarded_header_value(value),
        "x-forwarded-for" | "x-real-ip" => is_single_ip_address(value),
        "x-forwarded-host" => is_valid_http_host_header(value),
        "x-forwarded-proto" => {
            value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https")
        }
        _ => false,
    }
}

fn is_clean_forwarded_header_value(value: &str) -> bool {
    if value.is_empty()
        || value.contains(',')
        || value.contains('"')
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return false;
    }

    let mut seen = BTreeSet::new();
    let mut fields = 0usize;
    for part in value.split(';') {
        let Some((name, value)) = part.split_once('=') else {
            return false;
        };
        if name.is_empty() || value.is_empty() || !seen.insert(name) {
            return false;
        }
        match name {
            "for" => {
                let value = value
                    .strip_prefix('[')
                    .and_then(|inner| inner.strip_suffix(']'))
                    .unwrap_or(value);
                if !is_single_ip_address(value) {
                    return false;
                }
            }
            "host" => {
                if !is_valid_http_host_header(value) {
                    return false;
                }
            }
            "proto" => {
                if !(value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https")) {
                    return false;
                }
            }
            _ => return false,
        }
        fields += 1;
    }
    fields > 0
}

fn is_single_ip_address(value: &str) -> bool {
    !value.is_empty() && !value.contains(',') && value.parse::<IpAddr>().is_ok()
}

fn is_unsupported_proxy_http_method(method: &str) -> bool {
    matches!(method, "CONNECT" | "TRACE" | "TRACK")
}

fn is_unsupported_method_override_http_header(name: &str) -> bool {
    matches!(
        name,
        "x-http-method" | "x-http-method-override" | "x-method-override"
    )
}

fn is_unsupported_websocket_http_header(name: &str) -> bool {
    name == "sec-websocket-key"
        || name == "sec-websocket-accept"
        || name == "sec-websocket-version"
        || name == "sec-websocket-protocol"
        || name == "sec-websocket-extensions"
}

fn is_unsupported_cookie_http_header(name: &str) -> bool {
    matches!(name, "cookie" | "cookie2" | "set-cookie" | "set-cookie2")
}

#[derive(Debug, Clone)]
struct DashboardHttpResponse {
    status: &'static str,
    content_type: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Serialize)]
struct DashboardApiResponse<'a> {
    review: &'a ApprovalReviewReport,
    permissions: Option<&'a TeamPermissionsReport>,
    viewer: Option<DashboardReviewerScope>,
    requester: Option<DashboardRequesterScope>,
}

#[derive(Debug, Clone, Serialize)]
struct DashboardReviewerScope {
    reviewer: String,
    scoped: bool,
    open_before: usize,
    open_visible: usize,
    decided_before: usize,
    decided_visible: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DashboardRequesterScope {
    agent_id: String,
    scoped: bool,
    open_before: usize,
    open_visible: usize,
    decided_before: usize,
    decided_visible: usize,
    stale_before: usize,
    stale_visible: usize,
}

#[derive(Debug, Deserialize)]
struct DashboardDecisionRequest {
    id: String,
    reviewer: String,
    reason: String,
    #[serde(default)]
    reviewer_token: Option<String>,
}

struct DashboardDecisionUniqueKeys;

impl<'de> Deserialize<'de> for DashboardDecisionUniqueKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DashboardDecisionUniqueKeysVisitor)?;
        Ok(Self)
    }
}

struct DashboardDecisionUniqueKeysVisitor;

impl<'de> serde::de::Visitor<'de> for DashboardDecisionUniqueKeysVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a dashboard decision JSON object with supported unique keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !matches!(
                key.as_str(),
                "id" | "reviewer" | "reason" | "reviewer_token"
            ) {
                return Err(serde::de::Error::custom(
                    "dashboard decision JSON keys must be id, reviewer, reason, or reviewer_token",
                ));
            }
            if !keys.insert(key) {
                return Err(serde::de::Error::custom(
                    "dashboard decision JSON keys must appear at most once",
                ));
            }
            map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct DashboardDecisionResponse<'a> {
    decision: &'a agentk::ApprovalDecisionRecord,
    review: &'a ApprovalReviewReport,
}

struct DashboardOperationalState {
    ready: bool,
    trace_present: bool,
    decision_log_present: bool,
    permissions_configured: bool,
    permissions_present: bool,
    permissions_ready: bool,
    identity_configured: bool,
    identity_present: bool,
    identity_ready: bool,
    store_root_configured: bool,
    store_root_present: bool,
    admin_required: bool,
    max_body_bytes: usize,
    max_header_bytes: usize,
}

#[cfg(test)]
fn dashboard_http_response(
    request: &DashboardHttpRequest,
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    admin_token: Option<&str>,
    store_root: Option<&PathBuf>,
) -> DashboardHttpResponse {
    let context = DashboardHttpContext {
        trace_path,
        decisions_path,
        permissions_path,
        identity_path: None,
        admin_token,
        admin_read_required: false,
        max_body_bytes: DASHBOARD_HTTP_MAX_BODY_BYTES,
        max_header_bytes: DASHBOARD_HTTP_MAX_HEADER_BYTES,
        store_root,
    };
    dashboard_http_response_with_read_auth_and_limits(request, &context)
}

#[cfg(test)]
fn dashboard_http_response_with_read_auth(
    request: &DashboardHttpRequest,
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    admin_token: Option<&str>,
    admin_read_required: bool,
    store_root: Option<&PathBuf>,
) -> DashboardHttpResponse {
    let context = DashboardHttpContext {
        trace_path,
        decisions_path,
        permissions_path,
        identity_path: None,
        admin_token,
        admin_read_required,
        max_body_bytes: DASHBOARD_HTTP_MAX_BODY_BYTES,
        max_header_bytes: DASHBOARD_HTTP_MAX_HEADER_BYTES,
        store_root,
    };
    dashboard_http_response_with_read_auth_and_limits(request, &context)
}

fn dashboard_http_response_with_read_auth_and_limits(
    request: &DashboardHttpRequest,
    context: &DashboardHttpContext<'_>,
) -> DashboardHttpResponse {
    let (route, has_query) = match request.target.split_once('?') {
        Some((route, _)) => (route, true),
        None => (request.target.as_str(), false),
    };
    let mut response = if has_query && dashboard_http_is_operational_path(route) {
        dashboard_http_text(
            "400 Bad Request",
            "dashboard operational probes must not include query strings\n",
        )
    } else if has_query && dashboard_http_is_decision_path(route) {
        dashboard_http_text(
            "400 Bad Request",
            "dashboard decision endpoints must not include query strings\n",
        )
    } else if context.admin_read_required && dashboard_http_requires_admin_read(route) {
        match dashboard_verify_admin_token_for_request(
            request,
            context.admin_token,
            "dashboard admin token is required for read requests",
        ) {
            Ok(()) => {
                if let Some(response) = dashboard_http_unexpected_body_error(request, route) {
                    response
                } else {
                    dashboard_http_route_response(request, route, context)
                }
            }
            Err((status, error)) => dashboard_http_text(status, &format!("{error}\n")),
        }
    } else if let Some(response) = dashboard_http_unexpected_body_error(request, route) {
        response
    } else {
        dashboard_http_route_response(request, route, context)
    };

    if request.method == "HEAD" {
        response.body.clear();
    }
    response
}

fn dashboard_http_route_response(
    request: &DashboardHttpRequest,
    route: &str,
    context: &DashboardHttpContext<'_>,
) -> DashboardHttpResponse {
    match (request.method.as_str(), route) {
        ("GET" | "HEAD", "/" | "/index.html") => dashboard_http_html(
            request,
            context.trace_path,
            context.decisions_path,
            context.permissions_path,
            context.identity_path,
            context.store_root,
        ),
        ("GET" | "HEAD", "/api/review") => dashboard_http_json(
            request,
            context.trace_path,
            context.decisions_path,
            context.permissions_path,
            context.identity_path,
            context.store_root,
        ),
        ("GET" | "HEAD", "/healthz") => DashboardHttpResponse {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body: br#"{"ok":true}"#.to_vec(),
        },
        ("GET" | "HEAD", "/readyz") => dashboard_http_ready_response(context),
        ("GET" | "HEAD", "/metrics") => dashboard_http_metrics_response(context),
        ("POST", "/api/approve") => {
            dashboard_http_decision(request, context, ApprovalDecision::Approve)
        }
        ("POST", "/api/deny") => dashboard_http_decision(request, context, ApprovalDecision::Deny),
        ("GET" | "HEAD" | "POST", _) => dashboard_http_text("404 Not Found", "not found\n"),
        _ => dashboard_http_text("405 Method Not Allowed", "method not allowed\n"),
    }
}

fn dashboard_http_requires_admin_read(path: &str) -> bool {
    matches!(
        path,
        "/" | "/index.html" | "/api/review" | "/readyz" | "/metrics"
    )
}

fn dashboard_http_is_operational_path(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz" | "/metrics")
}

fn dashboard_http_is_decision_path(path: &str) -> bool {
    matches!(path, "/api/approve" | "/api/deny")
}

fn dashboard_http_unexpected_body_error(
    request: &DashboardHttpRequest,
    route: &str,
) -> Option<DashboardHttpResponse> {
    if request.body.is_empty()
        || matches!(
            (request.method.as_str(), route),
            ("POST", "/api/approve" | "/api/deny")
        )
    {
        return None;
    }

    Some(dashboard_http_text(
        "400 Bad Request",
        "dashboard HTTP request bodies are only accepted on approval decision endpoints\n",
    ))
}

fn dashboard_http_ready_response(context: &DashboardHttpContext<'_>) -> DashboardHttpResponse {
    let state = dashboard_operational_state(context);
    match serde_json::to_vec(&serde_json::json!({
        "ready": state.ready,
        "trace_present": state.trace_present,
        "decision_log_present": state.decision_log_present,
        "permissions_configured": state.permissions_configured,
        "permissions_present": state.permissions_present,
        "permissions_ready": state.permissions_ready,
        "identity_configured": state.identity_configured,
        "identity_present": state.identity_present,
        "identity_ready": state.identity_ready,
        "store_root_configured": state.store_root_configured,
        "store_root_present": state.store_root_present,
        "admin_required": state.admin_required,
        "max_body_bytes": state.max_body_bytes,
        "max_header_bytes": state.max_header_bytes
    })) {
        Ok(body) => DashboardHttpResponse {
            status: if state.ready {
                "200 OK"
            } else {
                "503 Service Unavailable"
            },
            content_type: "application/json",
            headers: Vec::new(),
            body,
        },
        Err(error) => dashboard_http_text("500 Internal Server Error", &format!("{error}\n")),
    }
}

fn dashboard_http_metrics_response(context: &DashboardHttpContext<'_>) -> DashboardHttpResponse {
    let state = dashboard_operational_state(context);
    DashboardHttpResponse {
        status: "200 OK",
        content_type: "text/plain; version=0.0.4; charset=utf-8",
        headers: Vec::new(),
        body: dashboard_http_metrics_body(&state).into_bytes(),
    }
}

fn dashboard_operational_state(context: &DashboardHttpContext<'_>) -> DashboardOperationalState {
    let trace_present = context.trace_path.exists();
    let decision_log_present = context.decisions_path.exists();
    let permissions_configured = context.permissions_path.is_some();
    let permissions_present = context.permissions_path.is_some_and(|path| path.exists());
    let permissions_ready = !permissions_configured || permissions_present;
    let identity_configured = context.identity_path.is_some();
    let identity_present = context.identity_path.is_some_and(|path| path.exists());
    let identity_ready = !identity_configured || identity_present;
    let store_root_configured = context.store_root.is_some();
    let store_root_present = context.store_root.is_some_and(|path| path.exists());
    DashboardOperationalState {
        ready: trace_present && permissions_ready && identity_ready,
        trace_present,
        decision_log_present,
        permissions_configured,
        permissions_present,
        permissions_ready,
        identity_configured,
        identity_present,
        identity_ready,
        store_root_configured,
        store_root_present,
        admin_required: context.admin_token.is_some(),
        max_body_bytes: context.max_body_bytes,
        max_header_bytes: context.max_header_bytes,
    }
}

fn dashboard_http_metrics_body(state: &DashboardOperationalState) -> String {
    format!(
        "# HELP agentk_dashboard_ready Dashboard readiness state.\n\
# TYPE agentk_dashboard_ready gauge\n\
agentk_dashboard_ready {ready}\n\
# HELP agentk_dashboard_trace_present Whether the configured dashboard trace path exists.\n\
# TYPE agentk_dashboard_trace_present gauge\n\
agentk_dashboard_trace_present {trace_present}\n\
# HELP agentk_dashboard_decision_log_present Whether the configured dashboard decision log exists.\n\
# TYPE agentk_dashboard_decision_log_present gauge\n\
agentk_dashboard_decision_log_present {decision_log_present}\n\
# HELP agentk_dashboard_permissions_configured Whether dashboard permissions were configured.\n\
# TYPE agentk_dashboard_permissions_configured gauge\n\
agentk_dashboard_permissions_configured {permissions_configured}\n\
# HELP agentk_dashboard_permissions_present Whether the configured dashboard permissions file exists.\n\
# TYPE agentk_dashboard_permissions_present gauge\n\
agentk_dashboard_permissions_present {permissions_present}\n\
# HELP agentk_dashboard_permissions_ready Whether dashboard permissions are absent or present.\n\
# TYPE agentk_dashboard_permissions_ready gauge\n\
agentk_dashboard_permissions_ready {permissions_ready}\n\
# HELP agentk_dashboard_identity_configured Whether dashboard identity mappings were configured.\n\
# TYPE agentk_dashboard_identity_configured gauge\n\
agentk_dashboard_identity_configured {identity_configured}\n\
# HELP agentk_dashboard_identity_present Whether the configured dashboard identity mapping file exists.\n\
# TYPE agentk_dashboard_identity_present gauge\n\
agentk_dashboard_identity_present {identity_present}\n\
# HELP agentk_dashboard_identity_ready Whether dashboard identity mappings are absent or present.\n\
# TYPE agentk_dashboard_identity_ready gauge\n\
agentk_dashboard_identity_ready {identity_ready}\n\
# HELP agentk_dashboard_store_root_configured Whether dashboard durable store sync is configured.\n\
# TYPE agentk_dashboard_store_root_configured gauge\n\
agentk_dashboard_store_root_configured {store_root_configured}\n\
# HELP agentk_dashboard_store_root_present Whether the configured dashboard durable store root exists.\n\
# TYPE agentk_dashboard_store_root_present gauge\n\
agentk_dashboard_store_root_present {store_root_present}\n\
# HELP agentk_dashboard_admin_required Whether dashboard admin auth is configured.\n\
# TYPE agentk_dashboard_admin_required gauge\n\
agentk_dashboard_admin_required {admin_required}\n\
# HELP agentk_dashboard_max_body_bytes Configured dashboard maximum HTTP request body bytes.\n\
# TYPE agentk_dashboard_max_body_bytes gauge\n\
agentk_dashboard_max_body_bytes {max_body_bytes}\n\
# HELP agentk_dashboard_max_header_bytes Configured dashboard maximum HTTP request header bytes.\n\
# TYPE agentk_dashboard_max_header_bytes gauge\n\
agentk_dashboard_max_header_bytes {max_header_bytes}\n",
        ready = usize::from(state.ready),
        trace_present = usize::from(state.trace_present),
        decision_log_present = usize::from(state.decision_log_present),
        permissions_configured = usize::from(state.permissions_configured),
        permissions_present = usize::from(state.permissions_present),
        permissions_ready = usize::from(state.permissions_ready),
        identity_configured = usize::from(state.identity_configured),
        identity_present = usize::from(state.identity_present),
        identity_ready = usize::from(state.identity_ready),
        store_root_configured = usize::from(state.store_root_configured),
        store_root_present = usize::from(state.store_root_present),
        admin_required = usize::from(state.admin_required),
        max_body_bytes = state.max_body_bytes,
        max_header_bytes = state.max_header_bytes
    )
}

fn dashboard_http_html(
    request: &DashboardHttpRequest,
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    identity_path: Option<&PathBuf>,
    store_root: Option<&PathBuf>,
) -> DashboardHttpResponse {
    if let Err(error) = dashboard_read_query_param_error(request) {
        return dashboard_http_text("400 Bad Request", &format!("{error}\n"));
    }
    let reviewer = match dashboard_query_param(&request.target, "reviewer") {
        Ok(reviewer) => reviewer,
        Err(error) => return dashboard_http_text("400 Bad Request", &format!("{error}\n")),
    };
    let requester = match dashboard_query_param(&request.target, "requester") {
        Ok(requester) => requester,
        Err(error) => return dashboard_http_text("400 Bad Request", &format!("{error}\n")),
    };

    if let Some(reviewer) = &reviewer {
        let Some(permissions_path) = permissions_path else {
            return dashboard_http_text(
                "400 Bad Request",
                "reviewer-scoped dashboard views require --permissions\n",
            );
        };
        if let Err(error) = dashboard_reviewer_token_carrier_error(request) {
            return dashboard_http_text("400 Bad Request", &format!("{error}\n"));
        }
        if let Err(error) =
            dashboard_verify_reviewer_token_from_request(request, permissions_path, reviewer)
        {
            return dashboard_http_text("401 Unauthorized", &format!("{error}\n"));
        }
    }

    match dashboard_sync_store(
        trace_path,
        decisions_path,
        permissions_path,
        identity_path,
        store_root,
    )
    .and_then(|_| dashboard_review(trace_path, decisions_path, permissions_path))
    .and_then(|(review, permissions)| {
        let (review, viewer) = if let Some(reviewer) = reviewer.as_deref() {
            let Some(permissions_path) = permissions_path else {
                return Err(AgentKError::InvalidMcpRequest(
                    "reviewer-scoped dashboard views require --permissions".to_string(),
                ));
            };
            let (review, viewer) =
                dashboard_scope_review_for_reviewer(review, permissions_path, reviewer)?;
            (review, Some(viewer))
        } else {
            (review, None)
        };
        let (review, requester) = if let Some(requester) = requester.as_deref() {
            let (review, requester) = dashboard_scope_review_for_requester(review, requester)?;
            (review, Some(requester))
        } else {
            (review, None)
        };
        Ok((review, permissions, viewer, requester))
    }) {
        Ok((review, permissions, viewer, requester)) => DashboardHttpResponse {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            headers: Vec::new(),
            body: dashboard_server_html(
                &review,
                permissions.as_ref(),
                viewer.as_ref(),
                requester.as_ref(),
            )
            .into_bytes(),
        },
        Err(error) => dashboard_http_text("500 Internal Server Error", &format!("{error}\n")),
    }
}

fn dashboard_server_html(
    review: &ApprovalReviewReport,
    permissions: Option<&TeamPermissionsReport>,
    viewer: Option<&DashboardReviewerScope>,
    requester: Option<&DashboardRequesterScope>,
) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>AgentK Review</title><style>");
    html.push_str("body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;margin:0;background:#f7f8fa;color:#17181c}main{max-width:1180px;margin:0 auto;padding:28px 20px 44px}h1{font-size:28px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 10px}.muted{color:#626873}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.badge{display:inline-flex;align-items:center;border:1px solid #cfd4dc;border-radius:999px;padding:4px 10px;background:white;font-size:13px}.ok{color:#136c43;border-color:#9fd7b8;background:#effaf3}.bad{color:#9a3412;border-color:#fdba74;background:#fff7ed}.scope{border-color:#b7c7e6;background:#f8fbff}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}.metric,.panel,.controls{background:white;border:1px solid #d9dee7;border-radius:8px}.metric{padding:14px}.metric strong{display:block;font-size:26px}.panel{overflow:hidden;margin-top:10px}.scope-note{padding:12px}.controls{display:grid;grid-template-columns:1fr 1fr 1fr 1fr 2fr auto auto auto;gap:10px;align-items:end;padding:12px;margin-top:20px}label{display:block;font-size:12px;color:#4b5563;font-weight:650}input{box-sizing:border-box;width:100%;border:1px solid #cfd4dc;border-radius:6px;padding:8px 9px;font:inherit;background:white}button{border:1px solid #bcc5d3;border-radius:6px;background:#fff;color:#17181c;padding:8px 10px;font:inherit;font-weight:650;cursor:pointer}button:hover{background:#f3f5f8}.approve{border-color:#8bc6a3;color:#136c43}.deny{border-color:#f0a68e;color:#9a3412}.status{min-height:18px;font-size:13px;color:#626873}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;border-bottom:1px solid #edf0f5;padding:10px;vertical-align:top}th{background:#fafbfc;color:#4b5563;font-weight:650}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.reason{max-width:360px}.actions{white-space:nowrap}.empty{padding:16px;color:#626873}.footer{margin-top:28px;font-size:13px;color:#626873}@media(max-width:1180px){.top{display:block}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.controls{grid-template-columns:1fr}.actions{white-space:normal}th:nth-child(5),td:nth-child(5){display:none}}");
    html.push_str("</style></head><body><main data-agentk-dashboard=\"server\">");
    html.push_str("<div class=\"top\"><div><h1>AgentK Approval Dashboard</h1><div class=\"muted\">Local review over signed trace evidence</div></div>");
    html.push_str(&format!(
        "<span class=\"badge {}\">signatures {}</span></div>",
        if review.signatures_ok { "ok" } else { "bad" },
        if review.signatures_ok { "ok" } else { "failed" }
    ));
    if let Some(viewer) = viewer {
        html.push_str(&format!(
            "<div class=\"panel scope\" id=\"viewer-scope\"><div class=\"scope-note\"><strong>Reviewer view: <span class=\"mono\">{}</span></strong><br><span class=\"muted\">{} of {} open approvals visible, {} of {} decided approvals visible.</span></div></div>",
            dashboard_html_escape(&viewer.reviewer),
            viewer.open_visible,
            viewer.open_before,
            viewer.decided_visible,
            viewer.decided_before
        ));
    } else {
        html.push_str("<div class=\"panel scope\" id=\"viewer-scope\" hidden><div class=\"scope-note\"></div></div>");
    }
    if let Some(requester) = requester {
        html.push_str(&format!(
            "<div class=\"panel scope\" id=\"requester-scope\"><div class=\"scope-note\"><strong>Requester view: <span class=\"mono\">{}</span></strong><br><span class=\"muted\">{} of {} open approvals visible, {} of {} decided approvals visible, {} of {} stale decisions visible.</span></div></div>",
            dashboard_html_escape(&requester.agent_id),
            requester.open_visible,
            requester.open_before,
            requester.decided_visible,
            requester.decided_before,
            requester.stale_visible,
            requester.stale_before
        ));
    } else {
        html.push_str("<div class=\"panel scope\" id=\"requester-scope\" hidden><div class=\"scope-note\"></div></div>");
    }
    html.push_str("<div class=\"grid\">");
    dashboard_server_metric(&mut html, "Open", review.open_approvals.len());
    dashboard_server_metric(&mut html, "Approved", review.approved);
    dashboard_server_metric(&mut html, "Denied", review.denied);
    dashboard_server_metric(&mut html, "Stale", review.stale_decisions.len());
    html.push_str("</div>");
    html.push_str("<form class=\"controls\" id=\"decision-controls\">");
    html.push_str("<div><label for=\"reviewer\">Reviewer</label><input id=\"reviewer\" name=\"reviewer\" autocomplete=\"username\"></div>");
    html.push_str("<div><label for=\"reviewer-token\">Reviewer Token</label><input id=\"reviewer-token\" name=\"reviewer-token\" type=\"password\" autocomplete=\"current-password\"></div>");
    html.push_str("<div><label for=\"requester\">Requester</label><input id=\"requester\" name=\"requester\" autocomplete=\"off\"></div>");
    html.push_str("<div><label for=\"admin-token\">Admin Token</label><input id=\"admin-token\" name=\"admin-token\" type=\"password\" autocomplete=\"off\"></div>");
    html.push_str("<div><label for=\"reason\">Reason</label><input id=\"reason\" name=\"reason\" autocomplete=\"off\"></div>");
    html.push_str("<div><button type=\"button\" id=\"load-reviewer-view\">My View</button></div>");
    html.push_str(
        "<div><button type=\"button\" id=\"load-requester-view\">Agent View</button></div>",
    );
    html.push_str("<div><button type=\"button\" id=\"refresh-review\">Refresh</button><div class=\"status\" id=\"dashboard-status\"></div></div>");
    html.push_str("</form>");
    html.push_str(&format!(
        "<div class=\"panel\"><table><tbody><tr><th>Trace</th><td class=\"mono\">{}</td></tr><tr><th>Decisions</th><td class=\"mono\">{}</td></tr>",
        dashboard_html_escape(&review.trace_path.display().to_string()),
        dashboard_html_escape(&review.decisions_path.display().to_string())
    ));
    if let Some(permissions) = permissions {
        html.push_str(&format!(
            "<tr><th>Permissions</th><td><span class=\"mono\">{}</span><br>{} users, {} roles, {} reviewers, {} token-protected</td></tr>",
            dashboard_html_escape(&permissions.path.display().to_string()),
            permissions.users,
            permissions.roles,
            permissions.reviewers.len(),
            permissions.token_protected_reviewers
        ));
    }
    html.push_str("</tbody></table></div>");
    dashboard_server_evidence_summary(&mut html, review);
    dashboard_server_open_table(&mut html, &review.open_approvals);
    dashboard_server_decisions_table(&mut html, &review.decided_approvals);
    dashboard_server_stale_table(&mut html, &review.stale_decisions);
    if let Some(permissions) = permissions {
        html.push_str("<h2>Reviewers</h2><div class=\"panel\"><table><thead><tr><th>User</th></tr></thead><tbody>");
        for reviewer in &permissions.reviewers {
            html.push_str(&format!(
                "<tr><td class=\"mono\">{}</td></tr>",
                dashboard_html_escape(reviewer)
            ));
        }
        html.push_str("</tbody></table></div>");
    }
    html.push_str("<div class=\"footer\">Generated by AgentK. Approval decisions are append-only records; this dashboard does not mutate policy or replay blocked actions.</div>");
    html.push_str(dashboard_server_script());
    html.push_str("</main></body></html>");
    html
}

fn dashboard_server_metric(html: &mut String, label: &str, value: usize) {
    html.push_str(&format!(
        "<div class=\"metric\"><span class=\"muted\">{}</span><strong>{}</strong></div>",
        dashboard_html_escape(label),
        value
    ));
}

fn dashboard_server_evidence_summary(html: &mut String, review: &ApprovalReviewReport) {
    html.push_str("<h2>Evidence Summary</h2>");
    html.push_str("<div class=\"panel\"><table><tbody>");
    html.push_str(&format!(
        "<tr><th>Final Hash</th><td class=\"mono\">{}</td></tr>",
        dashboard_html_escape(&review.trace_final_hash)
    ));
    html.push_str(&format!(
        "<tr><th>Events</th><td>{} checked, {} allowed, {} blocked</td></tr>",
        review.events_checked, review.allowed, review.blocked
    ));
    html.push_str(&format!(
        "<tr><th>Signatures</th><td>{}</td></tr>",
        if review.signatures_ok { "ok" } else { "failed" }
    ));
    html.push_str("</tbody></table></div>");

    if !review.blocked_rules.is_empty() {
        html.push_str("<div class=\"panel\"><table><thead><tr><th>Blocked Rule</th><th>Count</th></tr></thead><tbody>");
        for (rule, count) in &review.blocked_rules {
            html.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td></tr>",
                dashboard_html_escape(rule),
                count
            ));
        }
        html.push_str("</tbody></table></div>");
    }

    if !review.syscall_summary.is_empty() {
        html.push_str("<div class=\"panel\"><table><thead><tr><th>Syscall</th><th>Allowed</th><th>Blocked</th><th>Targets</th></tr></thead><tbody>");
        for (syscall, summary) in &review.syscall_summary {
            html.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                dashboard_html_escape(syscall),
                summary.allowed,
                summary.blocked,
                summary.targets
            ));
        }
        html.push_str("</tbody></table></div>");
    }

    if !review.evidence_summary.is_empty() {
        html.push_str("<div class=\"panel\"><table><thead><tr><th>Evidence Ref</th><th>Count</th></tr></thead><tbody>");
        for (kind, count) in &review.evidence_summary {
            html.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td></tr>",
                dashboard_html_escape(kind),
                count
            ));
        }
        html.push_str("</tbody></table></div>");
    }
}

fn dashboard_server_open_table(html: &mut String, approvals: &[AuditApprovalItem]) {
    html.push_str("<h2>Open Approvals</h2>");
    if approvals.is_empty() {
        html.push_str("<div class=\"panel\" id=\"open-approvals-panel\"><div class=\"empty\">No open approvals.</div></div>");
        return;
    }
    html.push_str("<div class=\"panel\" id=\"open-approvals-panel\"><table><thead><tr><th>ID</th><th>Step</th><th>Syscall</th><th>Target</th><th>Reason</th><th>Decision</th></tr></thead><tbody>");
    for item in approvals {
        html.push_str(&format!(
            "<tr data-approval-id=\"{}\"><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"reason\">{}<br><span class=\"muted\">{}</span></td><td class=\"actions\"><button type=\"button\" class=\"approve\" data-agentk-decision=\"approve\" data-agentk-id=\"{}\">Approve</button> <button type=\"button\" class=\"deny\" data-agentk-decision=\"deny\" data-agentk-id=\"{}\">Deny</button></td></tr>",
            dashboard_html_escape(&item.id),
            dashboard_html_escape(&item.id),
            item.step,
            dashboard_html_escape(&item.syscall),
            dashboard_html_escape(&item.target),
            dashboard_html_escape(&item.reason),
            dashboard_html_escape(&item.review_hint),
            dashboard_html_escape(&item.id),
            dashboard_html_escape(&item.id)
        ));
    }
    html.push_str("</tbody></table></div>");
}

fn dashboard_server_decisions_table(html: &mut String, decisions: &[ApprovalDecisionRecord]) {
    html.push_str("<h2>Decisions</h2>");
    if decisions.is_empty() {
        html.push_str(
            "<div class=\"panel\" id=\"decisions-panel\"><div class=\"empty\">No decisions recorded.</div></div>",
        );
        return;
    }
    html.push_str("<div class=\"panel\" id=\"decisions-panel\"><table><thead><tr><th>ID</th><th>Decision</th><th>Reviewer</th><th>Target</th><th>Reason</th></tr></thead><tbody>");
    for item in decisions {
        html.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            dashboard_html_escape(&item.approval_id),
            dashboard_html_escape(item.decision.as_str()),
            dashboard_html_escape(&item.reviewer),
            dashboard_html_escape(&item.target),
            dashboard_html_escape(&item.reason)
        ));
    }
    html.push_str("</tbody></table></div>");
}

fn dashboard_server_stale_table(html: &mut String, decisions: &[ApprovalDecisionRecord]) {
    html.push_str("<h2>Stale Decisions</h2>");
    if decisions.is_empty() {
        html.push_str("<div class=\"panel\" id=\"stale-decisions-panel\"><div class=\"empty\">No stale decisions.</div></div>");
        return;
    }
    html.push_str("<div class=\"panel\" id=\"stale-decisions-panel\"><table><thead><tr><th>ID</th><th>Decision</th><th>Reviewer</th><th>Target</th><th>Trace Hash</th></tr></thead><tbody>");
    for item in decisions {
        html.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>",
            dashboard_html_escape(&item.approval_id),
            dashboard_html_escape(item.decision.as_str()),
            dashboard_html_escape(&item.reviewer),
            dashboard_html_escape(&item.target),
            dashboard_html_escape(&item.trace_final_hash)
        ));
    }
    html.push_str("</tbody></table></div>");
}

fn dashboard_server_script() -> &'static str {
    r#"<script>
(() => {
  const status = document.getElementById("dashboard-status");
  const reviewer = document.getElementById("reviewer");
  const reviewerToken = document.getElementById("reviewer-token");
  const requester = document.getElementById("requester");
  const adminToken = document.getElementById("admin-token");
  const reason = document.getElementById("reason");
  const scope = document.getElementById("viewer-scope");
  const requesterScope = document.getElementById("requester-scope");
  const metricValues = document.querySelectorAll(".metric strong");
  const openPanel = document.getElementById("open-approvals-panel");
  const decisionsPanel = document.getElementById("decisions-panel");
  const stalePanel = document.getElementById("stale-decisions-panel");
  const setStatus = (text) => { status.textContent = text; };
  const headers = () => {
    const values = {"Content-Type": "application/json"};
    if (adminToken.value.trim()) values.Authorization = `Bearer ${adminToken.value.trim()}`;
    return values;
  };
  const textCell = (row, value, className) => {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value == null ? "" : String(value);
    row.appendChild(cell);
    return cell;
  };
  const replaceWithEmpty = (panel, text) => {
    panel.textContent = "";
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = text;
    panel.appendChild(empty);
  };
  const tableShell = (panel, headings) => {
    panel.textContent = "";
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const head = document.createElement("tr");
    headings.forEach((heading) => {
      const th = document.createElement("th");
      th.textContent = heading;
      head.appendChild(th);
    });
    thead.appendChild(head);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    table.appendChild(tbody);
    panel.appendChild(table);
    return tbody;
  };
  const decisionButton = (id, decision) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = decision;
    button.dataset.agentkDecision = decision;
    button.dataset.agentkId = id;
    button.textContent = decision === "approve" ? "Approve" : "Deny";
    return button;
  };
  const renderOpenApprovals = (items) => {
    if (!items.length) {
      replaceWithEmpty(openPanel, "No open approvals.");
      return;
    }
    const tbody = tableShell(openPanel, ["ID", "Step", "Syscall", "Target", "Reason", "Decision"]);
    items.forEach((item) => {
      const row = document.createElement("tr");
      row.dataset.approvalId = item.id;
      textCell(row, item.id, "mono");
      textCell(row, item.step);
      textCell(row, item.syscall, "mono");
      textCell(row, item.target, "mono");
      const reasonCell = textCell(row, item.reason, "reason");
      reasonCell.appendChild(document.createElement("br"));
      const hint = document.createElement("span");
      hint.className = "muted";
      hint.textContent = item.review_hint || "";
      reasonCell.appendChild(hint);
      const actions = document.createElement("td");
      actions.className = "actions";
      actions.appendChild(decisionButton(item.id, "approve"));
      actions.appendChild(document.createTextNode(" "));
      actions.appendChild(decisionButton(item.id, "deny"));
      row.appendChild(actions);
      tbody.appendChild(row);
    });
  };
  const renderDecisionRecords = (panel, records, emptyText, stale) => {
    if (!records.length) {
      replaceWithEmpty(panel, emptyText);
      return;
    }
    const headings = stale ? ["ID", "Decision", "Reviewer", "Target", "Trace Hash"] : ["ID", "Decision", "Reviewer", "Target", "Reason"];
    const tbody = tableShell(panel, headings);
    records.forEach((record) => {
      const row = document.createElement("tr");
      textCell(row, record.approval_id, "mono");
      textCell(row, record.decision);
      textCell(row, record.reviewer, "mono");
      textCell(row, record.target, "mono");
      textCell(row, stale ? record.trace_final_hash : record.reason, stale ? "mono" : "");
      tbody.appendChild(row);
    });
  };
  const renderReview = (payload) => {
    const review = payload.review;
    metricValues[0].textContent = review.open_approvals.length;
    metricValues[1].textContent = review.approved;
    metricValues[2].textContent = review.denied;
    metricValues[3].textContent = review.stale_decisions.length;
    renderOpenApprovals(review.open_approvals || []);
    renderDecisionRecords(decisionsPanel, review.decided_approvals || [], "No decisions recorded.", false);
    renderDecisionRecords(stalePanel, review.stale_decisions || [], "No stale decisions.", true);
    if (payload.viewer) {
      scope.hidden = false;
      const note = scope.querySelector(".scope-note");
      note.textContent = "";
      const strong = document.createElement("strong");
      strong.textContent = `Reviewer view: ${payload.viewer.reviewer}`;
      note.appendChild(strong);
      note.appendChild(document.createElement("br"));
      const muted = document.createElement("span");
      muted.className = "muted";
      muted.textContent = `${payload.viewer.open_visible} of ${payload.viewer.open_before} open approvals visible, ${payload.viewer.decided_visible} of ${payload.viewer.decided_before} decided approvals visible.`;
      note.appendChild(muted);
    }
    if (payload.requester) {
      requesterScope.hidden = false;
      const note = requesterScope.querySelector(".scope-note");
      note.textContent = "";
      const strong = document.createElement("strong");
      strong.textContent = `Requester view: ${payload.requester.agent_id}`;
      note.appendChild(strong);
      note.appendChild(document.createElement("br"));
      const muted = document.createElement("span");
      muted.className = "muted";
      muted.textContent = `${payload.requester.open_visible} of ${payload.requester.open_before} open approvals visible, ${payload.requester.decided_visible} of ${payload.requester.decided_before} decided approvals visible, ${payload.requester.stale_visible} of ${payload.requester.stale_before} stale decisions visible.`;
      note.appendChild(muted);
    }
  };
  async function loadReviewerView() {
    if (!reviewer.value.trim()) {
      setStatus("Reviewer required");
      reviewer.focus();
      return;
    }
    const requestHeaders = {"Accept": "application/json"};
    if (reviewerToken.value) requestHeaders["X-AgentK-Reviewer-Token"] = reviewerToken.value;
    setStatus("Loading reviewer view");
    const response = await fetch(`/api/review?reviewer=${encodeURIComponent(reviewer.value.trim())}`, {
      headers: requestHeaders
    });
    if (!response.ok) {
      setStatus((await response.text()).trim() || "reviewer view failed");
      return;
    }
    renderReview(await response.json());
    setStatus("Reviewer view loaded");
  }
  async function loadRequesterView() {
    if (!requester.value.trim()) {
      setStatus("Requester required");
      requester.focus();
      return;
    }
    setStatus("Loading requester view");
    const response = await fetch(`/api/review?requester=${encodeURIComponent(requester.value.trim())}`, {
      headers: {"Accept": "application/json"}
    });
    if (!response.ok) {
      setStatus((await response.text()).trim() || "requester view failed");
      return;
    }
    renderReview(await response.json());
    setStatus("Requester view loaded");
  }
  async function submitDecision(id, decision) {
    if (!reviewer.value.trim()) {
      setStatus("Reviewer required");
      reviewer.focus();
      return;
    }
    const body = {
      id,
      reviewer: reviewer.value.trim(),
      reason: reason.value.trim() || `${decision} via dashboard`,
      reviewer_token: reviewerToken.value || null
    };
    setStatus(`${decision} pending`);
    const response = await fetch(`/api/${decision}`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body)
    });
    if (!response.ok) {
      setStatus((await response.text()).trim() || `${decision} failed`);
      return;
    }
    setStatus(`${decision} recorded`);
    if (reviewer.value.trim()) {
      await loadReviewerView();
    } else {
      window.location.reload();
    }
  }
  document.addEventListener("click", (event) => {
    const button = event.target && event.target.closest ? event.target.closest("[data-agentk-decision]") : null;
    if (button) submitDecision(button.dataset.agentkId, button.dataset.agentkDecision);
  });
  document.getElementById("load-reviewer-view").addEventListener("click", () => {
    loadReviewerView();
  });
  document.getElementById("load-requester-view").addEventListener("click", () => {
    loadRequesterView();
  });
  document.getElementById("refresh-review").addEventListener("click", () => {
    window.location.reload();
  });
})();
</script>"#
}

fn dashboard_html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn dashboard_http_json(
    request: &DashboardHttpRequest,
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    identity_path: Option<&PathBuf>,
    store_root: Option<&PathBuf>,
) -> DashboardHttpResponse {
    if let Err(error) = dashboard_read_query_param_error(request) {
        return dashboard_http_text("400 Bad Request", &format!("{error}\n"));
    }
    let reviewer = match dashboard_query_param(&request.target, "reviewer") {
        Ok(reviewer) => reviewer,
        Err(error) => return dashboard_http_text("400 Bad Request", &format!("{error}\n")),
    };
    let requester = match dashboard_query_param(&request.target, "requester") {
        Ok(requester) => requester,
        Err(error) => return dashboard_http_text("400 Bad Request", &format!("{error}\n")),
    };

    if let Some(reviewer) = &reviewer {
        let Some(permissions_path) = permissions_path else {
            return dashboard_http_text(
                "400 Bad Request",
                "reviewer-scoped dashboard reads require --permissions\n",
            );
        };
        if let Err(error) = dashboard_reviewer_token_carrier_error(request) {
            return dashboard_http_text("400 Bad Request", &format!("{error}\n"));
        }
        if let Err(error) =
            dashboard_verify_reviewer_token_from_request(request, permissions_path, reviewer)
        {
            return dashboard_http_text("401 Unauthorized", &format!("{error}\n"));
        }
    }

    match dashboard_sync_store(
        trace_path,
        decisions_path,
        permissions_path,
        identity_path,
        store_root,
    )
    .and_then(|_| dashboard_review(trace_path, decisions_path, permissions_path))
    .and_then(|(review, permissions)| {
        let open_before = review.open_approvals.len();
        let decided_before = review.decided_approvals.len();
        let (review, viewer) = if let Some(reviewer) = reviewer.as_deref() {
            let Some(permissions_path) = permissions_path else {
                return Err(AgentKError::InvalidMcpRequest(
                    "reviewer-scoped dashboard reads require --permissions".to_string(),
                ));
            };
            let (review, mut viewer) =
                dashboard_scope_review_for_reviewer(review, permissions_path, reviewer)?;
            viewer.open_before = open_before;
            viewer.decided_before = decided_before;
            (review, Some(viewer))
        } else {
            (review, None)
        };
        let (review, requester) = if let Some(requester) = requester.as_deref() {
            let (review, requester) = dashboard_scope_review_for_requester(review, requester)?;
            (review, Some(requester))
        } else {
            (review, None)
        };
        serde_json::to_vec_pretty(&DashboardApiResponse {
            review: &review,
            permissions: permissions.as_ref(),
            viewer,
            requester,
        })
        .map_err(AgentKError::from)
    }) {
        Ok(body) => DashboardHttpResponse {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body,
        },
        Err(error) => dashboard_http_text("500 Internal Server Error", &format!("{error}\n")),
    }
}

fn dashboard_scope_review_for_reviewer(
    review: ApprovalReviewReport,
    permissions_path: &PathBuf,
    reviewer: &str,
) -> Result<(ApprovalReviewReport, DashboardReviewerScope), AgentKError> {
    let open_before = review.open_approvals.len();
    let decided_before = review.decided_approvals.len();
    let review = scope_approval_review_for_reviewer(review, permissions_path, reviewer)?;
    let viewer = DashboardReviewerScope {
        reviewer: reviewer.to_string(),
        scoped: true,
        open_before,
        open_visible: review.open_approvals.len(),
        decided_before,
        decided_visible: review.decided_approvals.len(),
    };
    Ok((review, viewer))
}

fn dashboard_scope_review_for_requester(
    review: ApprovalReviewReport,
    requester: &str,
) -> Result<(ApprovalReviewReport, DashboardRequesterScope), AgentKError> {
    let requester = requester.trim();
    if requester.is_empty() {
        return Err(AgentKError::InvalidMcpRequest(
            "requester must be non-empty".to_string(),
        ));
    }
    let open_before = review.open_approvals.len();
    let decided_before = review.decided_approvals.len();
    let stale_before = review.stale_decisions.len();

    let open_approvals = review
        .open_approvals
        .into_iter()
        .filter(|item| item.agent_id.as_deref() == Some(requester))
        .collect::<Vec<_>>();
    let decided_approvals = review
        .decided_approvals
        .into_iter()
        .filter(|record| record.agent_id.as_deref() == Some(requester))
        .collect::<Vec<_>>();
    let stale_decisions = review
        .stale_decisions
        .into_iter()
        .filter(|record| record.agent_id.as_deref() == Some(requester))
        .collect::<Vec<_>>();
    let approved = decided_approvals
        .iter()
        .filter(|record| record.decision == ApprovalDecision::Approve)
        .count();
    let denied = decided_approvals
        .iter()
        .filter(|record| record.decision == ApprovalDecision::Deny)
        .count();
    let requester_scope = DashboardRequesterScope {
        agent_id: requester.to_string(),
        scoped: true,
        open_before,
        open_visible: open_approvals.len(),
        decided_before,
        decided_visible: decided_approvals.len(),
        stale_before,
        stale_visible: stale_decisions.len(),
    };
    let review = ApprovalReviewReport {
        open_approvals,
        decided_approvals,
        stale_decisions,
        approved,
        denied,
        ..review
    };
    Ok((review, requester_scope))
}

fn dashboard_http_decision(
    request: &DashboardHttpRequest,
    context: &DashboardHttpContext<'_>,
    decision: ApprovalDecision,
) -> DashboardHttpResponse {
    if context.admin_token.is_some()
        && let Err(error) = dashboard_admin_token_carrier_error(request)
    {
        return dashboard_http_text("400 Bad Request", &format!("{error}\n"));
    }
    if let Err(error) = dashboard_verify_admin_token(request, context.admin_token) {
        return dashboard_http_text("401 Unauthorized", &format!("{error}\n"));
    }
    if let Some(response) = dashboard_http_json_content_type_error(request) {
        return response;
    }
    match dashboard_record_decision(
        context.trace_path,
        context.decisions_path,
        context.permissions_path,
        context.identity_path,
        context.store_root,
        decision,
        &request.body,
    ) {
        Ok(body) => DashboardHttpResponse {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body,
        },
        Err(error) => dashboard_http_text("400 Bad Request", &format!("{error}\n")),
    }
}

fn dashboard_http_json_content_type_error(
    request: &DashboardHttpRequest,
) -> Option<DashboardHttpResponse> {
    if request.header_count("content-type") > 1 {
        return Some(dashboard_http_text(
            "400 Bad Request",
            "dashboard decision Content-Type header must appear at most once\n",
        ));
    }
    if request
        .header("content-type")
        .is_some_and(|value| http_media_type_matches(value, "application/json"))
    {
        return None;
    }

    Some(dashboard_http_text(
        "415 Unsupported Media Type",
        "dashboard decision API requires application/json\n",
    ))
}

fn dashboard_verify_admin_token(
    request: &DashboardHttpRequest,
    admin_token: Option<&str>,
) -> Result<(), AgentKError> {
    dashboard_verify_admin_token_with_message(
        request,
        admin_token,
        "dashboard admin token is required for write requests",
    )
}

fn dashboard_verify_admin_token_for_request(
    request: &DashboardHttpRequest,
    admin_token: Option<&str>,
    missing_message: &'static str,
) -> Result<(), (&'static str, AgentKError)> {
    if let Err(error) = dashboard_admin_token_carrier_error(request) {
        return Err(("400 Bad Request", error));
    }
    dashboard_verify_admin_token_with_message(request, admin_token, missing_message)
        .map_err(|error| ("401 Unauthorized", error))
}

fn dashboard_verify_admin_token_with_message(
    request: &DashboardHttpRequest,
    admin_token: Option<&str>,
    missing_message: &'static str,
) -> Result<(), AgentKError> {
    let Some(expected) = admin_token else {
        return Ok(());
    };
    let provided = dashboard_admin_token_from_request(request)
        .ok_or_else(|| AgentKError::InvalidMcpRequest(missing_message.to_string()))?;
    if !constant_time_token_eq(expected, &provided) {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard admin token did not match".to_string(),
        ));
    }
    Ok(())
}

fn dashboard_admin_token_carrier_error(request: &DashboardHttpRequest) -> Result<(), AgentKError> {
    let authorization_count = request.header_count("authorization");
    let explicit_count = request.header_count("x-agentk-admin-token");
    if authorization_count > 1 || explicit_count > 1 {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard admin token carrier must appear at most once".to_string(),
        ));
    }
    if authorization_count == 1 && explicit_count == 1 {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard admin token must use either Authorization or X-AgentK-Admin-Token"
                .to_string(),
        ));
    }
    Ok(())
}

fn dashboard_admin_token_from_request(request: &DashboardHttpRequest) -> Option<String> {
    if let Some(value) = request.header("x-agentk-admin-token") {
        return Some(value.to_string());
    }
    if let Some(value) = request.header("authorization")
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return Some(token.trim().to_string());
    }
    None
}

fn dashboard_reviewer_token_from_request(
    request: &DashboardHttpRequest,
) -> Result<Option<String>, AgentKError> {
    if let Some(value) = request.header("x-agentk-reviewer-token") {
        return Ok(Some(value.to_string()));
    }
    dashboard_query_param(&request.target, "reviewer_token")
}

fn dashboard_reviewer_token_carrier_error(
    request: &DashboardHttpRequest,
) -> Result<(), AgentKError> {
    let header_count = request.header_count("x-agentk-reviewer-token");
    let query_count = dashboard_query_param_count(&request.target, "reviewer_token")?;
    if header_count > 1 || query_count > 1 {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard reviewer token carrier must appear at most once".to_string(),
        ));
    }
    let has_header = header_count == 1;
    let has_query = query_count == 1;
    if has_header && has_query {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard reviewer token must use either X-AgentK-Reviewer-Token or reviewer_token query parameter"
                .to_string(),
        ));
    }
    Ok(())
}

fn dashboard_read_query_param_error(request: &DashboardHttpRequest) -> Result<(), AgentKError> {
    let counts = dashboard_query_param_counts(&request.target)?;
    for name in counts.keys() {
        if !matches!(name.as_str(), "reviewer" | "requester" | "reviewer_token") {
            return Err(AgentKError::InvalidMcpRequest(
                "dashboard review query parameters must be reviewer, requester, or reviewer_token"
                    .to_string(),
            ));
        }
    }
    let reviewer_count = *counts.get("reviewer").unwrap_or(&0);
    let requester_count = *counts.get("requester").unwrap_or(&0);
    let reviewer_token_query_count = *counts.get("reviewer_token").unwrap_or(&0);
    let reviewer_token_header_count = request.header_count("x-agentk-reviewer-token");
    for (name, count) in [("reviewer", reviewer_count), ("requester", requester_count)] {
        if count > 1 {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "dashboard {name} query parameter must appear at most once"
            )));
        }
    }
    if reviewer_token_query_count > 1 || reviewer_token_header_count > 1 {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard reviewer token carrier must appear at most once".to_string(),
        ));
    }
    if reviewer_count == 1 && requester_count == 1 {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard scope query must use either reviewer or requester, not both".to_string(),
        ));
    }
    if reviewer_count == 0 && (reviewer_token_query_count > 0 || reviewer_token_header_count > 0) {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard reviewer token requires reviewer scope".to_string(),
        ));
    }
    Ok(())
}

fn dashboard_verify_reviewer_token_from_request(
    request: &DashboardHttpRequest,
    permissions_path: &PathBuf,
    reviewer: &str,
) -> Result<(), AgentKError> {
    let reviewer_token = dashboard_reviewer_token_from_request(request)?;
    verify_team_reviewer_token(permissions_path, reviewer, reviewer_token.as_deref())
}

fn dashboard_query_param(target: &str, name: &str) -> Result<Option<String>, AgentKError> {
    let Some((_, query)) = target.split_once('?') else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if dashboard_query_decode(raw_name)? == name {
            return Ok(Some(dashboard_query_decode(raw_value)?));
        }
    }
    Ok(None)
}

fn dashboard_query_param_count(target: &str, name: &str) -> Result<usize, AgentKError> {
    Ok(*dashboard_query_param_counts(target)?
        .get(name)
        .unwrap_or(&0))
}

fn dashboard_query_param_counts(target: &str) -> Result<BTreeMap<String, usize>, AgentKError> {
    let Some((_, query)) = target.split_once('?') else {
        return Ok(BTreeMap::new());
    };
    let mut counts = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_name, _) = pair.split_once('=').unwrap_or((pair, ""));
        *counts.entry(dashboard_query_decode(raw_name)?).or_insert(0) += 1;
    }
    Ok(counts)
}

fn dashboard_query_decode(value: &str) -> Result<String, AgentKError> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let high = input.next().ok_or_else(|| {
                    AgentKError::InvalidMcpRequest(
                        "dashboard query parameter has an incomplete percent escape".to_string(),
                    )
                })?;
                let low = input.next().ok_or_else(|| {
                    AgentKError::InvalidMcpRequest(
                        "dashboard query parameter has an incomplete percent escape".to_string(),
                    )
                })?;
                let Some(high) = dashboard_hex_digit(high) else {
                    return Err(AgentKError::InvalidMcpRequest(
                        "dashboard query parameter has an invalid percent escape".to_string(),
                    ));
                };
                let Some(low) = dashboard_hex_digit(low) else {
                    return Err(AgentKError::InvalidMcpRequest(
                        "dashboard query parameter has an invalid percent escape".to_string(),
                    ));
                };
                bytes.push((high << 4) | low);
            }
            _ => bytes.push(byte),
        }
    }
    String::from_utf8(bytes).map_err(|_| {
        AgentKError::InvalidMcpRequest("dashboard query parameter is not valid UTF-8".to_string())
    })
}

fn dashboard_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn constant_time_token_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

fn dashboard_record_decision(
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    identity_path: Option<&PathBuf>,
    store_root: Option<&PathBuf>,
    decision: ApprovalDecision,
    body: &[u8],
) -> Result<Vec<u8>, AgentKError> {
    dashboard_verify_decision_json_keys(body)?;
    let request = serde_json::from_slice::<DashboardDecisionRequest>(body).map_err(|error| {
        AgentKError::InvalidMcpRequest(format!("dashboard decision JSON did not parse: {error}"))
    })?;
    let record = if let Some(permissions_path) = permissions_path {
        verify_team_reviewer_token(
            permissions_path,
            &request.reviewer,
            request.reviewer_token.as_deref(),
        )?;
        record_approval_decision_jsonl_with_permissions(
            trace_path,
            decisions_path,
            permissions_path,
            &request.id,
            decision,
            &request.reviewer,
            &request.reason,
        )?
    } else {
        record_approval_decision_jsonl(
            trace_path,
            decisions_path,
            &request.id,
            decision,
            &request.reviewer,
            &request.reason,
        )?
    };
    dashboard_sync_store(
        trace_path,
        decisions_path,
        permissions_path,
        identity_path,
        store_root,
    )?;
    let review = approval_review_jsonl(trace_path, decisions_path)?;
    serde_json::to_vec_pretty(&DashboardDecisionResponse {
        decision: &record,
        review: &review,
    })
    .map_err(AgentKError::from)
}

fn dashboard_verify_decision_json_keys(body: &[u8]) -> Result<(), AgentKError> {
    serde_json::from_slice::<DashboardDecisionUniqueKeys>(body)
        .map(|_| ())
        .map_err(|error| {
            AgentKError::InvalidMcpRequest(format!(
                "dashboard decision JSON did not parse: {error}"
            ))
        })
}

fn dashboard_sync_store(
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    identity_path: Option<&PathBuf>,
    store_root: Option<&PathBuf>,
) -> Result<(), AgentKError> {
    if let Some(root) = store_root {
        sync_durable_audit_store(
            trace_path,
            decisions_path,
            permissions_path.map(|path| path.as_path()),
            identity_path.map(|path| path.as_path()),
            root,
        )?;
    }
    Ok(())
}

fn dashboard_review(
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
) -> Result<(ApprovalReviewReport, Option<TeamPermissionsReport>), AgentKError> {
    let review = approval_review_jsonl(trace_path, decisions_path)?;
    let permissions = match permissions_path {
        Some(path) => Some(team_permissions_report_from_path(path)?),
        None => None,
    };
    Ok((review, permissions))
}

fn dashboard_http_text(status: &'static str, body: &str) -> DashboardHttpResponse {
    DashboardHttpResponse {
        status,
        content_type: "text/plain; charset=utf-8",
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
}

fn write_dashboard_http_response(
    stream: &mut TcpStream,
    response: &DashboardHttpResponse,
) -> Result<(), AgentKError> {
    write!(
        stream,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nConnection: close\r\n",
        response.status,
        response.content_type,
        response.body.len()
    )?;
    for (name, value) in &response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

fn store_export(
    path: PathBuf,
    decisions: Option<PathBuf>,
    permissions: Option<PathBuf>,
    identity: Option<PathBuf>,
    out: PathBuf,
    json: bool,
) -> Result<(), AgentKError> {
    let decisions = approval_decisions_path(&path, decisions);
    let report = export_audit_store(
        &path,
        &decisions,
        permissions.as_deref(),
        identity.as_deref(),
        &out,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK audit store exported");
    println!("out        {}", report.output_dir.display());
    println!("files      {}", report.files.len());
    println!("trace      {}", report.trace_path.display());
    println!("decisions  {}", report.decisions_path.display());
    if let Some(path) = &report.permissions_path {
        println!("permissions {}", path.display());
    }
    if let Some(path) = &report.identity_path {
        println!("identity   {}", path.display());
    }
    println!("events     {}", report.events_checked);
    println!("signatures {}", report.signatures_ok);
    println!("open       {}", report.open);
    println!("approved   {}", report.approved);
    println!("denied     {}", report.denied);
    println!("stale      {}", report.stale);
    println!("mappings   {}", report.identity_mappings);

    if !report.signatures_ok {
        std::process::exit(2);
    }

    Ok(())
}

fn store_check(root: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = check_audit_store(&root)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK audit store check");
        println!("root      {}", report.root.display());
        println!(
            "verdict   {}",
            if report.passed { "valid" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "audit store preflight failed".to_string(),
        ));
    }

    Ok(())
}

fn store_sync(
    path: PathBuf,
    decisions: Option<PathBuf>,
    permissions: Option<PathBuf>,
    identity: Option<PathBuf>,
    root: PathBuf,
    json: bool,
) -> Result<(), AgentKError> {
    let decisions = approval_decisions_path(&path, decisions);
    let report = sync_durable_audit_store(
        &path,
        &decisions,
        permissions.as_deref(),
        identity.as_deref(),
        &root,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK durable team store synced");
    println!("root       {}", report.root.display());
    println!("trace      {}", report.trace_path.display());
    println!("trace-id   {}", report.trace_id);
    println!("decisions  {}", report.decisions_path.display());
    if let Some(path) = &report.permissions_path {
        println!("permissions {}", path.display());
    }
    if let Some(path) = &report.identity_path {
        println!("identity   {}", path.display());
    }
    println!("files      {}", report.files.len());
    println!("events     {}", report.audit_events);
    println!("signatures {}", report.signatures_ok);
    println!("open       {}", report.open);
    println!("approved   {}", report.approved);
    println!("denied     {}", report.denied);
    println!("stale      {}", report.stale);
    println!("reviewers  {}", report.reviewers);
    println!("mappings   {}", report.identity_mappings);
    println!("notifications {}", report.notifications);

    if !report.signatures_ok {
        std::process::exit(2);
    }

    Ok(())
}

fn store_slack(
    root: PathBuf,
    out: PathBuf,
    channel: Option<String>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = export_slack_notification_payloads(&root, &out, channel.as_deref())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK Slack notification payloads exported");
    println!("root       {}", report.root.display());
    println!("out        {}", report.out.display());
    if let Some(channel) = &report.channel {
        println!("channel    {channel}");
    }
    println!("files      {}", report.files.len());
    println!("payloads   {}", report.payloads);
    println!("pending    {}", report.pending);
    println!("decided    {}", report.decided);
    println!("warning    payloads are local JSON only; AgentK did not send Slack messages");
    Ok(())
}

#[derive(Debug, Deserialize)]
struct SlackPayloadManifest {
    schema: String,
    payloads: String,
}

#[derive(Debug, Serialize)]
struct SlackDeliveryAttempt {
    index: usize,
    delivered: bool,
    exit_code: Option<i32>,
}

#[derive(Debug, Serialize)]
struct StoreSlackSendReport {
    payload_root: PathBuf,
    payloads_path: PathBuf,
    webhook_url_env: String,
    webhook_url_present: bool,
    curl: String,
    dry_run: bool,
    command: Vec<String>,
    payloads: usize,
    delivered: usize,
    failed: usize,
    attempts: Vec<SlackDeliveryAttempt>,
}

fn store_slack_send(
    payload_root: PathBuf,
    webhook_url_env: String,
    curl: String,
    dry_run: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_store_slack_send(payload_root, webhook_url_env, curl, dry_run)?;
    let failed = !report.dry_run && report.failed > 0;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK Slack notification delivery");
        println!("payloads  {}", report.payloads_path.display());
        println!("webhook   ${}", report.webhook_url_env);
        println!("curl      {}", report.curl);
        println!("dry-run   {}", report.dry_run);
        println!("payloads  {}", report.payloads);
        println!("delivered {}", report.delivered);
        println!("failed    {}", report.failed);
        println!("command   {}", report.command.join(" "));
        println!(
            "verdict   {}",
            if report.dry_run {
                "ready"
            } else if report.failed == 0 {
                "delivered"
            } else {
                "blocked"
            }
        );
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "Slack notification delivery failed".to_string(),
        ));
    }

    Ok(())
}

fn run_store_slack_send(
    payload_root: PathBuf,
    webhook_url_env: String,
    curl: String,
    dry_run: bool,
) -> Result<StoreSlackSendReport, AgentKError> {
    if !is_safe_env_name(&webhook_url_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "webhook-url-env must be a safe environment variable name".to_string(),
        ));
    }
    if curl.trim().is_empty() {
        return Err(AgentKError::InvalidMcpRequest(
            "curl executable must be non-empty".to_string(),
        ));
    }

    let manifest_path = payload_root.join("manifest.json");
    let manifest: SlackPayloadManifest = serde_json::from_str(&fs::read_to_string(&manifest_path)?)
        .map_err(|error| {
            AgentKError::InvalidMcpRequest(format!("Slack payload manifest did not parse: {error}"))
        })?;
    if manifest.schema != "agentk.slack_notification_payloads" {
        return Err(AgentKError::InvalidMcpRequest(
            "store-slack-send requires a Slack payload export from store-slack".to_string(),
        ));
    }
    if manifest.payloads != "payloads.jsonl" {
        return Err(AgentKError::InvalidMcpRequest(
            "Slack payload manifest must reference payloads.jsonl".to_string(),
        ));
    }

    let payloads_path = payload_root.join(&manifest.payloads);
    let payloads = read_slack_payload_export(&payloads_path)?;
    let webhook_url = env::var(&webhook_url_env).ok();
    let webhook_url_present = webhook_url
        .as_deref()
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    if !dry_run {
        let webhook_url = webhook_url.as_deref().unwrap_or_default();
        if webhook_url.is_empty() {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "environment variable {webhook_url_env} must be set before store-slack-send"
            )));
        }
        validate_slack_webhook_url(webhook_url)?;
    }

    let command = vec![curl.clone(), "--config".to_string(), "-".to_string()];
    if dry_run {
        return Ok(StoreSlackSendReport {
            payload_root,
            payloads_path,
            webhook_url_env,
            webhook_url_present,
            curl,
            dry_run,
            command,
            payloads: payloads.len(),
            delivered: 0,
            failed: 0,
            attempts: Vec::new(),
        });
    }

    let webhook_url = webhook_url.unwrap_or_default();
    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for (index, payload) in payloads.iter().enumerate() {
        let status = send_slack_payload_with_curl(&curl, &webhook_url, payload, index)?;
        let ok = status.success();
        if ok {
            delivered += 1;
        } else {
            failed += 1;
        }
        attempts.push(SlackDeliveryAttempt {
            index,
            delivered: ok,
            exit_code: status.code(),
        });
    }

    Ok(StoreSlackSendReport {
        payload_root,
        payloads_path,
        webhook_url_env,
        webhook_url_present,
        curl,
        dry_run,
        command,
        payloads: payloads.len(),
        delivered,
        failed,
        attempts,
    })
}

fn read_slack_payload_export(path: &Path) -> Result<Vec<serde_json::Value>, AgentKError> {
    let content = fs::read_to_string(path)?;
    let mut payloads = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let payload: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            AgentKError::InvalidMcpRequest(format!(
                "Slack payload export line {} did not parse: {error}",
                index + 1
            ))
        })?;
        if !payload.is_object()
            || payload
                .get("text")
                .and_then(|value| value.as_str())
                .is_none()
        {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "Slack payload export line {} is missing text",
                index + 1
            )));
        }
        payloads.push(payload);
    }
    Ok(payloads)
}

fn validate_slack_webhook_url(url: &str) -> Result<(), AgentKError> {
    if !url.starts_with("https://") || url.chars().any(char::is_control) {
        return Err(AgentKError::InvalidMcpRequest(
            "Slack webhook URL must be an HTTPS URL without control characters".to_string(),
        ));
    }
    Ok(())
}

fn send_slack_payload_with_curl(
    curl: &str,
    webhook_url: &str,
    payload: &serde_json::Value,
    index: usize,
) -> Result<std::process::ExitStatus, AgentKError> {
    let payload_path = write_temp_slack_payload(payload, index)?;
    let result = (|| {
        let payload_path_string = payload_path.display().to_string();
        let config = format!(
            "url = \"{}\"\nrequest = \"POST\"\nheader = \"Content-Type: application/json\"\ndata-binary = \"@{}\"\nfail\nsilent\nshow-error\n",
            curl_config_value(webhook_url)?,
            curl_config_value(&payload_path_string)?,
        );
        let mut child = ProcessCommand::new(curl)
            .arg("--config")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        {
            let Some(mut stdin) = child.stdin.take() else {
                return Err(AgentKError::InvalidMcpRequest(
                    "curl stdin was not available".to_string(),
                ));
            };
            stdin.write_all(config.as_bytes())?;
        }
        Ok(child.wait()?)
    })();
    fs::remove_file(&payload_path).ok();
    result
}

fn write_temp_slack_payload(
    payload: &serde_json::Value,
    index: usize,
) -> Result<PathBuf, AgentKError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "agentk-slack-payload-{}-{index}-{nonce}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_vec(payload)?)?;
    Ok(path)
}

fn curl_config_value(value: &str) -> Result<String, AgentKError> {
    if value.chars().any(|ch| ch.is_control()) {
        return Err(AgentKError::InvalidMcpRequest(
            "curl config values must not contain control characters".to_string(),
        ));
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn store_github(
    root: PathBuf,
    out: PathBuf,
    repository: Option<String>,
    labels: Vec<String>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = export_github_notification_payloads(&root, &out, repository.as_deref(), &labels)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK GitHub notification payloads exported");
    println!("root       {}", report.root.display());
    println!("out        {}", report.out.display());
    if let Some(repository) = &report.repository {
        println!("repository {repository}");
    }
    println!("labels     {}", report.labels.join(","));
    println!("files      {}", report.files.len());
    println!("payloads   {}", report.payloads);
    println!("pending    {}", report.pending);
    println!("decided    {}", report.decided);
    println!("warning    payloads are local JSON only; AgentK did not call the GitHub API");
    Ok(())
}

#[derive(Debug, Deserialize)]
struct GitHubPayloadManifest {
    schema: String,
    payloads: String,
}

#[derive(Debug, Serialize)]
struct GitHubDeliveryAttempt {
    index: usize,
    repository: String,
    operation: String,
    delivered: bool,
    issue_number: Option<u64>,
    exit_code: Option<i32>,
}

#[derive(Debug, Serialize)]
struct StoreGithubSendReport {
    payload_root: PathBuf,
    payloads_path: PathBuf,
    github_token_env: String,
    github_token_present: bool,
    gh: String,
    dry_run: bool,
    command: Vec<String>,
    payloads: usize,
    delivered: usize,
    failed: usize,
    attempts: Vec<GitHubDeliveryAttempt>,
}

struct GitHubSendResult {
    operation: String,
    delivered: bool,
    issue_number: Option<u64>,
    exit_code: Option<i32>,
}

fn store_github_send(
    payload_root: PathBuf,
    github_token_env: String,
    gh: String,
    dry_run: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_store_github_send(payload_root, github_token_env, gh, dry_run)?;
    let failed = !report.dry_run && report.failed > 0;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK GitHub notification delivery");
        println!("payloads  {}", report.payloads_path.display());
        println!("token     ${}", report.github_token_env);
        println!("gh        {}", report.gh);
        println!("dry-run   {}", report.dry_run);
        println!("payloads  {}", report.payloads);
        println!("delivered {}", report.delivered);
        println!("failed    {}", report.failed);
        println!("command   {}", report.command.join(" "));
        println!(
            "verdict   {}",
            if report.dry_run {
                "ready"
            } else if report.failed == 0 {
                "delivered"
            } else {
                "blocked"
            }
        );
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "GitHub notification delivery failed".to_string(),
        ));
    }

    Ok(())
}

fn run_store_github_send(
    payload_root: PathBuf,
    github_token_env: String,
    gh: String,
    dry_run: bool,
) -> Result<StoreGithubSendReport, AgentKError> {
    if !is_safe_env_name(&github_token_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "github-token-env must be a safe environment variable name".to_string(),
        ));
    }
    if gh.trim().is_empty() {
        return Err(AgentKError::InvalidMcpRequest(
            "gh executable must be non-empty".to_string(),
        ));
    }

    let manifest_path = payload_root.join("manifest.json");
    let manifest: GitHubPayloadManifest =
        serde_json::from_str(&fs::read_to_string(&manifest_path)?).map_err(|error| {
            AgentKError::InvalidMcpRequest(format!(
                "GitHub payload manifest did not parse: {error}"
            ))
        })?;
    if manifest.schema != "agentk.github_notification_payloads" {
        return Err(AgentKError::InvalidMcpRequest(
            "store-github-send requires a GitHub payload export from store-github".to_string(),
        ));
    }
    if manifest.payloads != "payloads.jsonl" {
        return Err(AgentKError::InvalidMcpRequest(
            "GitHub payload manifest must reference payloads.jsonl".to_string(),
        ));
    }

    let payloads_path = payload_root.join(&manifest.payloads);
    let payloads = read_github_payload_export(&payloads_path)?;
    let token = env::var(&github_token_env).ok();
    let github_token_present = token
        .as_deref()
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    if !dry_run && token.as_deref().unwrap_or_default().is_empty() {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "environment variable {github_token_env} must be set before store-github-send"
        )));
    }

    let command = vec![
        gh.clone(),
        "api".to_string(),
        "repos/<payload-repository>/issues".to_string(),
    ];
    if dry_run {
        return Ok(StoreGithubSendReport {
            payload_root,
            payloads_path,
            github_token_env,
            github_token_present,
            gh,
            dry_run,
            command,
            payloads: payloads.len(),
            delivered: 0,
            failed: 0,
            attempts: Vec::new(),
        });
    }

    let token = token.unwrap_or_default();
    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for (index, payload) in payloads.iter().enumerate() {
        let repository = github_payload_repository(payload)?;
        let result = send_github_payload_with_gh(&gh, &token, payload, index)?;
        if result.delivered {
            delivered += 1;
        } else {
            failed += 1;
        }
        attempts.push(GitHubDeliveryAttempt {
            index,
            repository,
            operation: result.operation,
            delivered: result.delivered,
            issue_number: result.issue_number,
            exit_code: result.exit_code,
        });
    }

    Ok(StoreGithubSendReport {
        payload_root,
        payloads_path,
        github_token_env,
        github_token_present,
        gh,
        dry_run,
        command,
        payloads: payloads.len(),
        delivered,
        failed,
        attempts,
    })
}

fn read_github_payload_export(path: &Path) -> Result<Vec<serde_json::Value>, AgentKError> {
    let content = fs::read_to_string(path)?;
    let mut payloads = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let payload: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            AgentKError::InvalidMcpRequest(format!(
                "GitHub payload export line {} did not parse: {error}",
                index + 1
            ))
        })?;
        if payload.get("operation").and_then(|value| value.as_str()) != Some("upsert_issue") {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "GitHub payload export line {} has unsupported operation",
                index + 1
            )));
        }
        github_payload_repository(&payload)?;
        github_payload_issue_title(&payload)?;
        github_payload_issue_body(&payload)?;
        github_payload_dedupe_key(&payload)?;
        payloads.push(payload);
    }
    Ok(payloads)
}

fn send_github_payload_with_gh(
    gh: &str,
    token: &str,
    payload: &serde_json::Value,
    index: usize,
) -> Result<GitHubSendResult, AgentKError> {
    let repository = github_payload_repository(payload)?;
    let dedupe_key = github_payload_dedupe_key(payload)?;
    let title = github_payload_issue_title(payload)?;
    let body = github_payload_issue_body(payload)?;
    let labels = github_payload_labels(payload)?;
    let desired_state = github_payload_desired_state(payload)?;
    let comment_body = github_payload_comment_body(payload)?;
    let existing = github_find_existing_issue_number(gh, token, &repository, &dedupe_key)?;

    let issue_body = format!("{body}\n\n<!-- agentk-dedupe: {dedupe_key} -->\n");
    let issue_path = write_temp_github_json(
        &serde_json::json!({
            "title": title,
            "body": issue_body,
            "labels": labels
        }),
        "issue",
        index,
    )?;
    let mut temp_paths = vec![issue_path.clone()];

    let result = (|| {
        let (operation, issue_number, output) = if let Some(number) = existing {
            let output = run_gh_api(
                gh,
                token,
                &[
                    "api",
                    "-X",
                    "PATCH",
                    &format!("repos/{repository}/issues/{number}"),
                    "--input",
                    issue_path.to_str().unwrap_or_default(),
                ],
            )?;
            ("updated".to_string(), Some(number), output)
        } else {
            let output = run_gh_api(
                gh,
                token,
                &[
                    "api",
                    "-X",
                    "POST",
                    &format!("repos/{repository}/issues"),
                    "--input",
                    issue_path.to_str().unwrap_or_default(),
                ],
            )?;
            let number = if output.status.success() {
                github_issue_number_from_create_output(&output.stdout)?
            } else {
                None
            };
            ("created".to_string(), number, output)
        };
        if !output.status.success() {
            return Ok(GitHubSendResult {
                operation,
                delivered: false,
                issue_number,
                exit_code: output.status.code(),
            });
        }

        if let (Some(number), Some(comment)) = (issue_number, comment_body.as_deref()) {
            let comment_path =
                write_temp_github_json(&serde_json::json!({ "body": comment }), "comment", index)?;
            temp_paths.push(comment_path.clone());
            let output = run_gh_api(
                gh,
                token,
                &[
                    "api",
                    "-X",
                    "POST",
                    &format!("repos/{repository}/issues/{number}/comments"),
                    "--input",
                    comment_path.to_str().unwrap_or_default(),
                ],
            )?;
            if !output.status.success() {
                return Ok(GitHubSendResult {
                    operation: format!("{operation}+comment"),
                    delivered: false,
                    issue_number,
                    exit_code: output.status.code(),
                });
            }
        }

        if desired_state.as_deref() == Some("closed") {
            let Some(number) = issue_number else {
                return Ok(GitHubSendResult {
                    operation: format!("{operation}+close"),
                    delivered: false,
                    issue_number,
                    exit_code: None,
                });
            };
            let close_path =
                write_temp_github_json(&serde_json::json!({ "state": "closed" }), "close", index)?;
            temp_paths.push(close_path.clone());
            let output = run_gh_api(
                gh,
                token,
                &[
                    "api",
                    "-X",
                    "PATCH",
                    &format!("repos/{repository}/issues/{number}"),
                    "--input",
                    close_path.to_str().unwrap_or_default(),
                ],
            )?;
            if !output.status.success() {
                return Ok(GitHubSendResult {
                    operation: format!("{operation}+close"),
                    delivered: false,
                    issue_number,
                    exit_code: output.status.code(),
                });
            }
        }

        Ok(GitHubSendResult {
            operation,
            delivered: true,
            issue_number,
            exit_code: Some(0),
        })
    })();

    for path in temp_paths {
        fs::remove_file(path).ok();
    }
    result
}

fn github_find_existing_issue_number(
    gh: &str,
    token: &str,
    repository: &str,
    dedupe_key: &str,
) -> Result<Option<u64>, AgentKError> {
    let query = format!("repo:{repository} {dedupe_key} in:body");
    let output = run_gh_api(
        gh,
        token,
        &[
            "api",
            "search/issues",
            "-f",
            &format!("q={query}"),
            "--jq",
            ".items[0].number // empty",
        ],
    )?;
    if !output.status.success() {
        return Err(AgentKError::InvalidMcpRequest(
            "GitHub issue search failed".to_string(),
        ));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        Ok(None)
    } else {
        value.parse::<u64>().map(Some).map_err(|error| {
            AgentKError::InvalidMcpRequest(format!(
                "GitHub issue search returned a non-numeric issue number: {error}"
            ))
        })
    }
}

fn run_gh_api(gh: &str, token: &str, args: &[&str]) -> Result<std::process::Output, AgentKError> {
    Ok(ProcessCommand::new(gh)
        .args(args)
        .env("GH_TOKEN", token)
        .env("GITHUB_TOKEN", token)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?)
}

fn github_issue_number_from_create_output(output: &[u8]) -> Result<Option<u64>, AgentKError> {
    let value: serde_json::Value = serde_json::from_slice(output).map_err(|error| {
        AgentKError::InvalidMcpRequest(format!(
            "GitHub issue create response did not parse: {error}"
        ))
    })?;
    Ok(value.get("number").and_then(|number| number.as_u64()))
}

fn github_payload_repository(payload: &serde_json::Value) -> Result<String, AgentKError> {
    let repository = payload
        .get("repository")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            AgentKError::InvalidMcpRequest(
                "GitHub delivery requires each payload to include repository".to_string(),
            )
        })?;
    if !is_valid_github_repository_for_send(repository) {
        return Err(AgentKError::InvalidMcpRequest(
            "GitHub payload repository must look like owner/name".to_string(),
        ));
    }
    Ok(repository.to_string())
}

fn github_payload_dedupe_key(payload: &serde_json::Value) -> Result<String, AgentKError> {
    github_payload_string(payload, &["dedupe_key"], "dedupe_key")
}

fn github_payload_issue_title(payload: &serde_json::Value) -> Result<String, AgentKError> {
    github_payload_string(payload, &["issue", "title"], "issue.title")
}

fn github_payload_issue_body(payload: &serde_json::Value) -> Result<String, AgentKError> {
    github_payload_string(payload, &["issue", "body"], "issue.body")
}

fn github_payload_desired_state(
    payload: &serde_json::Value,
) -> Result<Option<String>, AgentKError> {
    let Some(issue) = payload.get("issue") else {
        return Ok(None);
    };
    let Some(state) = issue.get("desired_state") else {
        return Ok(None);
    };
    let state = state.as_str().ok_or_else(|| {
        AgentKError::InvalidMcpRequest("GitHub issue desired_state must be a string".to_string())
    })?;
    if !matches!(state, "open" | "closed") {
        return Err(AgentKError::InvalidMcpRequest(
            "GitHub issue desired_state must be open or closed".to_string(),
        ));
    }
    Ok(Some(state.to_string()))
}

fn github_payload_comment_body(payload: &serde_json::Value) -> Result<Option<String>, AgentKError> {
    let Some(comment) = payload.get("comment") else {
        return Ok(None);
    };
    let Some(body) = comment.get("body") else {
        return Ok(None);
    };
    let body = body.as_str().ok_or_else(|| {
        AgentKError::InvalidMcpRequest("GitHub issue comment body must be a string".to_string())
    })?;
    if body
        .chars()
        .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
    {
        return Err(AgentKError::InvalidMcpRequest(
            "GitHub issue comment body must not contain control characters".to_string(),
        ));
    }
    Ok(Some(body.to_string()))
}

fn github_payload_labels(payload: &serde_json::Value) -> Result<Vec<String>, AgentKError> {
    let Some(labels) = payload
        .get("issue")
        .and_then(|issue| issue.get("labels"))
        .and_then(|labels| labels.as_array())
    else {
        return Ok(Vec::new());
    };
    labels
        .iter()
        .map(|label| {
            let label = label.as_str().ok_or_else(|| {
                AgentKError::InvalidMcpRequest("GitHub issue labels must be strings".to_string())
            })?;
            if label.is_empty() || label.chars().any(char::is_control) {
                return Err(AgentKError::InvalidMcpRequest(
                    "GitHub issue labels must be non-empty printable strings".to_string(),
                ));
            }
            Ok(label.to_string())
        })
        .collect()
}

fn github_payload_string(
    payload: &serde_json::Value,
    path: &[&str],
    name: &str,
) -> Result<String, AgentKError> {
    let mut value = payload;
    for part in path {
        value = value.get(*part).ok_or_else(|| {
            AgentKError::InvalidMcpRequest(format!("GitHub payload is missing {name}"))
        })?;
    }
    let value = value.as_str().ok_or_else(|| {
        AgentKError::InvalidMcpRequest(format!("GitHub payload {name} must be a string"))
    })?;
    if value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
    {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "GitHub payload {name} must be non-empty and printable"
        )));
    }
    Ok(value.to_string())
}

fn is_valid_github_repository_for_send(repository: &str) -> bool {
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    !owner.contains('/')
        && !name.contains('/')
        && is_valid_github_repository_part_for_send(owner)
        && is_valid_github_repository_part_for_send(name)
}

fn is_valid_github_repository_part_for_send(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value != "."
        && value != ".."
}

fn write_temp_github_json(
    payload: &serde_json::Value,
    kind: &str,
    index: usize,
) -> Result<PathBuf, AgentKError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "agentk-github-{kind}-{}-{index}-{nonce}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_vec(payload)?)?;
    Ok(path)
}

fn store_email(
    root: PathBuf,
    out: PathBuf,
    to: Vec<String>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = export_email_notification_payloads(&root, &out, &to)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK email notification payloads exported");
    println!("root       {}", report.root.display());
    println!("out        {}", report.out.display());
    println!("recipients {}", report.to.len());
    println!("files      {}", report.files.len());
    println!("payloads   {}", report.payloads);
    println!("pending    {}", report.pending);
    println!("decided    {}", report.decided);
    println!("warning    payloads are local JSON only; AgentK did not call sendmail");
    Ok(())
}

#[derive(Debug, Deserialize)]
struct EmailPayloadManifest {
    schema: String,
    payloads: String,
}

#[derive(Debug, Serialize)]
struct EmailDeliveryAttempt {
    index: usize,
    delivered: bool,
    exit_code: Option<i32>,
}

#[derive(Debug, Serialize)]
struct StoreEmailSendReport {
    payload_root: PathBuf,
    payloads_path: PathBuf,
    sendmail: String,
    dry_run: bool,
    command: Vec<String>,
    payloads: usize,
    delivered: usize,
    failed: usize,
    attempts: Vec<EmailDeliveryAttempt>,
}

fn store_email_send(
    payload_root: PathBuf,
    sendmail: String,
    dry_run: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_store_email_send(payload_root, sendmail, dry_run)?;
    let failed = !report.dry_run && report.failed > 0;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK email notification delivery");
        println!("payloads  {}", report.payloads_path.display());
        println!("sendmail  {}", report.sendmail);
        println!("dry-run   {}", report.dry_run);
        println!("payloads  {}", report.payloads);
        println!("delivered {}", report.delivered);
        println!("failed    {}", report.failed);
        println!("command   {}", report.command.join(" "));
        println!(
            "verdict   {}",
            if report.dry_run {
                "ready"
            } else if report.failed == 0 {
                "delivered"
            } else {
                "blocked"
            }
        );
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "email notification delivery failed".to_string(),
        ));
    }

    Ok(())
}

fn run_store_email_send(
    payload_root: PathBuf,
    sendmail: String,
    dry_run: bool,
) -> Result<StoreEmailSendReport, AgentKError> {
    if sendmail.trim().is_empty() {
        return Err(AgentKError::InvalidMcpRequest(
            "sendmail executable must be non-empty".to_string(),
        ));
    }
    let manifest_path = payload_root.join("manifest.json");
    let manifest: EmailPayloadManifest = serde_json::from_str(&fs::read_to_string(&manifest_path)?)
        .map_err(|error| {
            AgentKError::InvalidMcpRequest(format!("Email payload manifest did not parse: {error}"))
        })?;
    if manifest.schema != "agentk.email_notification_payloads" {
        return Err(AgentKError::InvalidMcpRequest(
            "store-email-send requires an email payload export from store-email".to_string(),
        ));
    }
    if manifest.payloads != "payloads.jsonl" {
        return Err(AgentKError::InvalidMcpRequest(
            "Email payload manifest must reference payloads.jsonl".to_string(),
        ));
    }

    let payloads_path = payload_root.join(&manifest.payloads);
    let messages = read_email_payload_export(&payloads_path)?;
    let command = vec![sendmail.clone(), "-t".to_string(), "-oi".to_string()];
    if dry_run {
        return Ok(StoreEmailSendReport {
            payload_root,
            payloads_path,
            sendmail,
            dry_run,
            command,
            payloads: messages.len(),
            delivered: 0,
            failed: 0,
            attempts: Vec::new(),
        });
    }

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for (index, message) in messages.iter().enumerate() {
        let status = send_email_payload_with_sendmail(&sendmail, message)?;
        let ok = status.success();
        if ok {
            delivered += 1;
        } else {
            failed += 1;
        }
        attempts.push(EmailDeliveryAttempt {
            index,
            delivered: ok,
            exit_code: status.code(),
        });
    }

    Ok(StoreEmailSendReport {
        payload_root,
        payloads_path,
        sendmail,
        dry_run,
        command,
        payloads: messages.len(),
        delivered,
        failed,
        attempts,
    })
}

fn read_email_payload_export(path: &Path) -> Result<Vec<String>, AgentKError> {
    let content = fs::read_to_string(path)?;
    let mut messages = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let payload: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            AgentKError::InvalidMcpRequest(format!(
                "Email payload export line {} did not parse: {error}",
                index + 1
            ))
        })?;
        let message = payload
            .get("message")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                AgentKError::InvalidMcpRequest(format!(
                    "Email payload export line {} is missing message",
                    index + 1
                ))
            })?;
        if !message.contains("\n\n")
            || !message.starts_with("To: ")
            || message
                .chars()
                .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
        {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "Email payload export line {} is not a safe RFC822-style message",
                index + 1
            )));
        }
        messages.push(message.to_string());
    }
    Ok(messages)
}

fn send_email_payload_with_sendmail(
    sendmail: &str,
    message: &str,
) -> Result<std::process::ExitStatus, AgentKError> {
    let mut child = ProcessCommand::new(sendmail)
        .arg("-t")
        .arg("-oi")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    {
        let Some(mut stdin) = child.stdin.take() else {
            return Err(AgentKError::InvalidMcpRequest(
                "sendmail stdin was not available".to_string(),
            ));
        };
        stdin.write_all(message.as_bytes())?;
    }
    Ok(child.wait()?)
}

#[derive(Debug, Serialize)]
struct StorePushReport {
    root: PathBuf,
    database_url_env: String,
    database_url_present: bool,
    psql: String,
    load_sql: PathBuf,
    dry_run: bool,
    preflight_passed: bool,
    command: Vec<String>,
    pushed: bool,
    exit_code: Option<i32>,
}

fn store_push(
    root: PathBuf,
    database_url_env: String,
    psql: String,
    dry_run: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_store_push(root, database_url_env, psql, dry_run)?;
    let failed = !report.preflight_passed || (!report.dry_run && !report.pushed);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK audit store push");
        println!("root      {}", report.root.display());
        println!("load      {}", report.load_sql.display());
        println!("database  ${}", report.database_url_env);
        println!("psql      {}", report.psql);
        println!("dry-run   {}", report.dry_run);
        println!(
            "verdict   {}",
            if report.pushed {
                "pushed"
            } else if report.dry_run {
                "ready"
            } else {
                "blocked"
            }
        );
        println!("command   {}", report.command.join(" "));
        if let Some(code) = report.exit_code {
            println!("exit      {code}");
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "audit store push failed".to_string(),
        ));
    }

    Ok(())
}

fn run_store_push(
    root: PathBuf,
    database_url_env: String,
    psql: String,
    dry_run: bool,
) -> Result<StorePushReport, AgentKError> {
    if !is_safe_env_name(&database_url_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "database-url-env must be a safe environment variable name".to_string(),
        ));
    }
    let preflight = check_audit_store_export(&root)?;
    if !preflight.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "audit store preflight failed".to_string(),
        ));
    }
    let load_sql = root.join("postgres/load.sql");
    let database_url = env::var(&database_url_env).ok();
    if !dry_run && database_url.as_deref().unwrap_or_default().is_empty() {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "environment variable {database_url_env} must be set before store-push"
        )));
    }
    let command = vec![
        psql.clone(),
        format!("${database_url_env}"),
        "-f".to_string(),
        load_sql.display().to_string(),
    ];
    if dry_run {
        return Ok(StorePushReport {
            root,
            database_url_env,
            database_url_present: database_url
                .as_deref()
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            psql,
            load_sql,
            dry_run,
            preflight_passed: true,
            command,
            pushed: false,
            exit_code: None,
        });
    }

    let status = std::process::Command::new(&psql)
        .arg(database_url.unwrap_or_default())
        .arg("-f")
        .arg(&load_sql)
        .current_dir(&root)
        .status()?;
    Ok(StorePushReport {
        root,
        database_url_env,
        database_url_present: true,
        psql,
        load_sql,
        dry_run,
        preflight_passed: true,
        command,
        pushed: status.success(),
        exit_code: status.code(),
    })
}

fn approval_decisions_path(trace_path: &Path, explicit: Option<PathBuf>) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }

    if let Some(parent) = trace_path.parent()
        && parent.file_name().and_then(|name| name.to_str()) == Some("runs")
        && let Some(agentk_dir) = parent.parent()
    {
        return agentk_dir.join("approvals.jsonl");
    }

    PathBuf::from(".agentk/approvals.jsonl")
}

fn replay(path: PathBuf) -> Result<(), AgentKError> {
    let report = replay_jsonl(&path)?;
    println!("AgentK deterministic replay complete");
    println!("events    {}", report.events_replayed);
    println!("blocked   {}", report.blocked);
    println!("stubbed   {}", report.side_effects_stubbed);
    if !report.blocked_rules.is_empty() {
        println!("blocked rules");
        for (rule, count) in &report.blocked_rules {
            println!("  {rule}: {count}");
        }
    }
    for output in &report.stub_outputs {
        println!(
            "stub      #{} {} {} -> {}",
            output.step, output.syscall, output.target, output.output_ref
        );
    }
    println!("final     {}", report.final_hash);
    Ok(())
}

fn fork_replay(path: PathBuf, policy: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = fork_replay_jsonl(path, policy)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK fork replay complete");
    println!("events    {}", report.events_replayed);
    println!("changed   {}", report.changed);
    if !report.decision_summary.is_empty() {
        println!("decision summary");
        for (transition, count) in &report.decision_summary {
            println!("  {transition}: {count}");
        }
    }
    for change in report.changes {
        println!(
            "change    #{} {} {}: {}:{} -> {}:{}",
            change.step,
            change.syscall,
            change.target,
            change.original_verdict,
            change.original_rule,
            change.fork_verdict,
            change.fork_rule
        );
    }
    Ok(())
}

fn fork_replay_behavior(path: PathBuf, behavior: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = fork_replay_behavior_jsonl(path, behavior)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK behavior fork replay complete");
    println!("events      {}", report.events_replayed);
    println!("baseline    {}", report.baseline_outputs);
    println!("overrides   {}", report.override_outputs);
    println!("divergences {}", report.divergences);
    for change in report.changes {
        println!(
            "divergence  #{} {} {}: {} -> {}",
            change.step,
            change.syscall,
            change.target,
            change.original_output_ref,
            change.fork_output_ref
        );
    }
    Ok(())
}

fn mcp_proxy(path: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = mcp_proxy_from_path(path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let event = &report.event;
    println!("AgentK MCP proxy MVP");
    println!("tool      {}", event.syscall.target);
    println!("verdict   {}", event.decision.verdict);
    println!("rule      {}", event.decision.rule);
    println!("reason    {}", event.decision.reason);
    println!("executed  {}", report.executed);
    println!("hash      {}", event.event_hash);
    Ok(())
}

fn mcp_stdio() -> Result<(), AgentKError> {
    let stdin = io::stdin();
    let report = mediate_mcp_json_reader(stdin.lock())?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn mcp_lines() -> Result<(), AgentKError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    mediate_mcp_json_stream(BufReader::new(stdin.lock()), stdout.lock())
}

fn mcp_server() -> Result<(), AgentKError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    mcp_server_json_stream(BufReader::new(stdin.lock()), stdout.lock())
}

fn mcp_killer_demo(trace_out: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = run_mcp_killer_demo(env!("CARGO_MANIFEST_DIR"), trace_out)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK MCP killer demo");
    println!("scenario  poisoned MCP output tries secret exfiltration and unsafe patching");
    println!("trace     {}", report.trace_path.display());
    println!("responses {}", report.protocol_responses);
    println!("events    {}", report.inspect.events_checked);
    println!("allowed   {}", report.inspect.allowed);
    println!("blocked   {}", report.inspect.blocked);
    println!("signatures {}", report.inspect.signatures_ok);
    println!();

    for event in report
        .inspect
        .events
        .iter()
        .filter(|event| event.verdict == Verdict::Deny)
    {
        println!(
            "blocked   #{} {} {} via {}",
            event.step, event.syscall, event.target, event.rule
        );
        println!("reason    {}", event.reason);
    }

    println!();
    println!(
        "inspect   cargo run -- trace-inspect {}",
        report.trace_path.display()
    );

    Ok(())
}

fn mcp_shim_eval(trace_out: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = run_mcp_security_shim_eval(env!("CARGO_MANIFEST_DIR"), trace_out)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK MCP security shim eval");
    println!("scenario  {}", report.scenario);
    println!("safety    fake downstream records execution; no real network or file writes");
    println!("trace     {}", report.trace_path.display());
    println!();
    println!("{:<42} {:<14} AgentK", "check", "baseline");
    println!("{:-<42} {:-<14} {:-<14}", "", "", "");
    for check in &report.scorecard {
        println!(
            "{:<42} {:<14} {}",
            check.check, check.baseline, check.agentk
        );
    }
    println!();
    println!(
        "verdict   AgentK improved {}/{} checks",
        report.improved_checks, report.total_checks
    );
    println!(
        "inspect   cargo run -- trace-inspect {}",
        report.trace_path.display()
    );

    Ok(())
}

fn safe_agent_demo(trace_out: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = run_safe_agent_demo(trace_out)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK safe-agent demo");
    println!("scenario    {}", report.scenario);
    println!("trace       {}", report.trace_path.display());
    println!(
        "verdict     improved {}/{} checks",
        report.improved_checks, report.total_checks
    );
    println!(
        "audit       pending {} sidefx {} signatures {}",
        report.audit.pending_approvals.len(),
        report.audit.allowed_side_effects.len(),
        report.audit.signatures_ok
    );
    println!(
        "inspect     events {} allowed {} blocked {} evidence-kinds {}",
        report.inspect.events_checked,
        report.inspect.allowed,
        report.inspect.blocked,
        report.inspect.evidence_summary.len()
    );
    println!();
    println!("{:<38} {:<14} AgentK", "check", "baseline");
    println!("{:-<38} {:-<14} {:-<14}", "", "", "");
    for check in &report.scorecard {
        println!(
            "{:<38} {:<14} {}",
            check.check, check.baseline, check.agentk
        );
    }
    println!();
    println!("try         agentk audit {}", report.trace_path.display());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mcp_proxy_stdio(
    agent_id: String,
    server_id: String,
    command: String,
    args: Vec<String>,
    allow_env: Vec<String>,
    response_timeout_ms: u64,
    max_client_messages: usize,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
) -> Result<(), AgentKError> {
    let config = mcp_proxy_config_from_cli(
        agent_id,
        server_id,
        command,
        args,
        allow_env,
        response_timeout_ms,
        max_client_messages,
    )?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    mcp_proxy_stdio_with_io(
        config,
        trace_out,
        session_report_out,
        BufReader::new(stdin.lock()),
        stdout.lock(),
    )
}

#[allow(clippy::too_many_arguments)]
fn mcp_proxy_tcp(
    agent_id: String,
    server_id: String,
    host: String,
    port: u16,
    max_sessions: usize,
    max_concurrent_sessions: usize,
    command: String,
    args: Vec<String>,
    allow_env: Vec<String>,
    response_timeout_ms: u64,
    max_client_messages: usize,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
) -> Result<(), AgentKError> {
    let config = mcp_proxy_config_from_cli(
        agent_id,
        server_id,
        command,
        args,
        allow_env,
        response_timeout_ms,
        max_client_messages,
    )?;
    mcp_proxy_tcp_with_config(
        config,
        host,
        port,
        max_sessions,
        max_concurrent_sessions,
        trace_out,
        session_report_out,
    )
}

fn mcp_proxy_config_from_cli(
    agent_id: String,
    server_id: String,
    command: String,
    args: Vec<String>,
    allow_env: Vec<String>,
    response_timeout_ms: u64,
    max_client_messages: usize,
) -> Result<McpSubprocessProxyConfig, AgentKError> {
    let mut config = McpSubprocessProxyConfig::new(agent_id, server_id, command)
        .with_args(args)
        .with_response_timeout(Duration::from_millis(response_timeout_ms))
        .with_max_client_messages(max_client_messages);
    for (name, value) in collect_mcp_proxy_allowed_env(&allow_env, |name| env::var(name).ok())? {
        config = config.with_env(name, value);
    }
    Ok(config)
}

fn mcp_proxy_tcp_with_config(
    config: McpSubprocessProxyConfig,
    host: String,
    port: u16,
    max_sessions: usize,
    max_concurrent_sessions: usize,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
) -> Result<(), AgentKError> {
    if max_sessions == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP TCP gateway max-sessions must be positive".to_string(),
        ));
    }
    if max_concurrent_sessions == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP TCP gateway max-concurrent-sessions must be positive".to_string(),
        ));
    }

    let listener = TcpListener::bind((host.as_str(), port))?;
    let bind = listener.local_addr()?;
    println!("AgentK MCP TCP gateway listening");
    println!("bind        {bind}");
    println!("sessions    {max_sessions}");
    println!("concurrent  {max_concurrent_sessions}");

    mcp_proxy_tcp_accept_loop(
        config,
        listener,
        max_sessions,
        max_concurrent_sessions,
        trace_out,
        session_report_out,
    )
}

fn mcp_proxy_tcp_accept_loop(
    config: McpSubprocessProxyConfig,
    listener: TcpListener,
    max_sessions: usize,
    max_concurrent_sessions: usize,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
) -> Result<(), AgentKError> {
    if max_concurrent_sessions == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP TCP gateway max-concurrent-sessions must be positive".to_string(),
        ));
    }

    let (completion_tx, completion_rx) = mpsc::channel();
    let mut active_sessions = 0usize;
    let mut first_error: Option<String> = None;

    for session_index in 0..max_sessions {
        while active_sessions >= max_concurrent_sessions {
            if let Err(error) = receive_mcp_tcp_session_completion(&completion_rx) {
                first_error.get_or_insert(error);
            }
            active_sessions = active_sessions.saturating_sub(1);
        }

        let (stream, peer) = listener.accept()?;
        stream.set_nodelay(true)?;
        println!("accepted   {} {}", session_index + 1, peer);
        let reader = BufReader::new(stream.try_clone()?);
        let trace_path = trace_out
            .as_ref()
            .map(|path| mcp_gateway_session_path(path, max_sessions, session_index));
        let report_path = session_report_out
            .as_ref()
            .map(|path| mcp_gateway_session_path(path, max_sessions, session_index));
        let session_config = config.clone();
        let session_completion = completion_tx.clone();
        thread::spawn(move || {
            let result =
                mcp_proxy_stdio_with_io(session_config, trace_path, report_path, reader, stream)
                    .map_err(|error| error.to_string());
            let _ = session_completion.send((session_index, result));
        });
        active_sessions += 1;
    }

    drop(completion_tx);
    while active_sessions > 0 {
        if let Err(error) = receive_mcp_tcp_session_completion(&completion_rx) {
            first_error.get_or_insert(error);
        }
        active_sessions -= 1;
    }

    if let Some(error) = first_error {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "one or more MCP TCP sessions failed: {error}"
        )));
    }

    Ok(())
}

fn receive_mcp_tcp_session_completion(
    completion_rx: &mpsc::Receiver<(usize, Result<(), String>)>,
) -> Result<(), String> {
    match completion_rx.recv() {
        Ok((session_index, Ok(()))) => {
            println!("completed  {}", session_index + 1);
            Ok(())
        }
        Ok((session_index, Err(error))) => {
            println!("failed     {} {}", session_index + 1, error);
            Err(error)
        }
        Err(error) => Err(format!(
            "MCP TCP session worker ended unexpectedly: {error}"
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn mcp_proxy_http(
    agent_id: String,
    server_id: String,
    host: String,
    port: u16,
    endpoint: String,
    max_requests: usize,
    max_concurrent_requests: usize,
    max_active_sessions: usize,
    session_idle_timeout_ms: u64,
    max_body_bytes: usize,
    max_header_bytes: usize,
    stream_timeout_ms: u64,
    allow_origins: Vec<String>,
    allow_origin_env: String,
    allow_non_local_bind: bool,
    trust_proxy_headers: bool,
    auth_token_env: String,
    command: String,
    args: Vec<String>,
    allow_env: Vec<String>,
    response_timeout_ms: u64,
    max_client_messages: usize,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
) -> Result<(), AgentKError> {
    if !is_safe_env_name(&auth_token_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "auth-token-env must be a safe environment variable name".to_string(),
        ));
    }
    let allow_origins = mcp_http_allowed_origins_from_env(allow_origins, &allow_origin_env)?;
    let config = mcp_proxy_config_from_cli(
        agent_id,
        server_id,
        command,
        args,
        allow_env,
        response_timeout_ms,
        max_client_messages,
    )?;
    let auth_token = env::var(&auth_token_env)
        .ok()
        .filter(|value| !value.is_empty());
    mcp_proxy_http_with_config(McpHttpGatewayConfig {
        proxy: config,
        host,
        port,
        endpoint,
        max_requests,
        max_concurrent_requests,
        max_active_sessions,
        session_idle_timeout: Duration::from_millis(session_idle_timeout_ms),
        max_body_bytes,
        max_header_bytes,
        stream_timeout: Duration::from_millis(stream_timeout_ms),
        allow_origins,
        auth_token,
        allow_non_local_bind,
        trust_proxy_headers,
        trace_out,
        session_report_out,
    })
}

#[derive(Debug, Clone)]
struct McpHttpGatewayConfig {
    proxy: McpSubprocessProxyConfig,
    host: String,
    port: u16,
    endpoint: String,
    max_requests: usize,
    max_concurrent_requests: usize,
    max_active_sessions: usize,
    session_idle_timeout: Duration,
    max_body_bytes: usize,
    max_header_bytes: usize,
    stream_timeout: Duration,
    allow_origins: Vec<String>,
    auth_token: Option<String>,
    allow_non_local_bind: bool,
    trust_proxy_headers: bool,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
}

struct McpHttpGatewayState {
    proxy: McpSubprocessProxyConfig,
    endpoint: String,
    max_concurrent_requests: usize,
    max_active_sessions: usize,
    session_idle_timeout: Duration,
    max_body_bytes: usize,
    max_header_bytes: usize,
    stream_timeout: Duration,
    allow_origins: Vec<String>,
    auth_token: Option<String>,
    trust_proxy_headers: bool,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
    metrics: Mutex<McpHttpGatewayMetrics>,
    sessions: Mutex<BTreeMap<String, Arc<Mutex<McpHttpSession>>>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct McpHttpGatewayMetrics {
    requests_total: usize,
    post_requests: usize,
    get_requests: usize,
    delete_requests: usize,
    options_requests: usize,
    other_method_requests: usize,
    client_error_responses: usize,
    server_error_responses: usize,
    auth_rejections: usize,
    origin_rejections: usize,
    method_rejections: usize,
    preflight_rejections: usize,
    sse_stream_requests: usize,
    sse_resume_requests: usize,
    sse_invalid_resume_requests: usize,
    sse_evicted_resume_requests: usize,
    sse_events_returned: usize,
    sse_event_buffer_evictions: usize,
    invalid_json_rpc_id_requests: usize,
    invalid_framing_responses: usize,
    header_too_large_responses: usize,
    body_too_large_responses: usize,
    trusted_proxy_header_requests: usize,
    downstream_transport_error_responses: usize,
    gateway_internal_error_responses: usize,
    sessions_created: usize,
    sessions_deleted: usize,
    sessions_expired: usize,
    session_not_found: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct McpHttpSseBufferSnapshot {
    active_sessions: usize,
    sessions_with_buffered_events: usize,
    buffered_events: usize,
    buffer_capacity: usize,
}

#[derive(Serialize)]
struct McpHttpReadinessBody<'a> {
    ready: bool,
    endpoint: &'a str,
    protocol_version: &'static str,
    active_sessions: usize,
    max_active_sessions: usize,
    session_idle_timeout_ms: u128,
    expired_sessions_reaped: usize,
    max_concurrent_requests: usize,
    max_body_bytes: usize,
    max_header_bytes: usize,
    stream_timeout_ms: u128,
    configured_allowed_origins: usize,
    auth_required: bool,
    trusted_proxy_headers: bool,
    requests_total: usize,
    post_requests: usize,
    get_requests: usize,
    delete_requests: usize,
    options_requests: usize,
    other_method_requests: usize,
    client_error_responses: usize,
    server_error_responses: usize,
    auth_rejections: usize,
    origin_rejections: usize,
    method_rejections: usize,
    preflight_rejections: usize,
    sse_stream_requests: usize,
    sse_resume_requests: usize,
    sse_invalid_resume_requests: usize,
    sse_evicted_resume_requests: usize,
    sse_events_returned: usize,
    sse_retained_events_per_session: usize,
    sse_sessions_with_buffered_events: usize,
    sse_buffered_events: usize,
    sse_buffer_capacity: usize,
    sse_event_buffer_evictions: usize,
    invalid_json_rpc_id_requests: usize,
    invalid_framing_responses: usize,
    header_too_large_responses: usize,
    body_too_large_responses: usize,
    trusted_proxy_header_requests: usize,
    downstream_transport_error_responses: usize,
    gateway_internal_error_responses: usize,
    sessions_created: usize,
    sessions_deleted: usize,
    sessions_expired: usize,
    session_not_found: usize,
}

struct McpHttpSession {
    proxy: McpSubprocessProxy,
    protocol_version: String,
    last_seen: Instant,
    next_sse_event_id: u64,
    sse_events: VecDeque<McpHttpSseEvent>,
}

#[derive(Debug, Clone)]
struct McpHttpSseEvent {
    id: u64,
    data: Vec<u8>,
}

fn mcp_proxy_http_with_config(config: McpHttpGatewayConfig) -> Result<(), AgentKError> {
    validate_mcp_http_endpoint(&config.endpoint)?;
    if config.max_concurrent_requests == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP max-concurrent-requests must be positive".to_string(),
        ));
    }
    if config.max_active_sessions == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP max-active-sessions must be positive".to_string(),
        ));
    }
    if config.session_idle_timeout.is_zero() {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP session-idle-timeout-ms must be positive".to_string(),
        ));
    }
    if config.max_body_bytes == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP max-body-bytes must be positive".to_string(),
        ));
    }
    if config.max_header_bytes == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP max-header-bytes must be positive".to_string(),
        ));
    }
    if config.stream_timeout.is_zero() {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP stream-timeout-ms must be positive".to_string(),
        ));
    }
    validate_mcp_http_bind_security(
        &config.host,
        config.allow_non_local_bind,
        config.auth_token.is_some(),
    )?;
    let bind = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&bind)?;
    let bind = listener.local_addr()?;
    println!("AgentK MCP Streamable HTTP gateway");
    println!("url         http://{bind}{}", config.endpoint);
    println!(
        "requests    {}",
        if config.max_requests == 0 {
            "unlimited".to_string()
        } else {
            config.max_requests.to_string()
        }
    );
    println!("concurrent  {}", config.max_concurrent_requests);
    println!("sessions    {}", config.max_active_sessions);
    println!("idle ms     {}", config.session_idle_timeout.as_millis());
    println!("body bytes  {}", config.max_body_bytes);
    println!("header bytes {}", config.max_header_bytes);
    println!("stream ms   {}", config.stream_timeout.as_millis());
    println!(
        "trusted proxy headers {}",
        if config.trust_proxy_headers {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "auth        {}",
        if config.auth_token.is_some() {
            "configured"
        } else {
            "not configured"
        }
    );

    let state = Arc::new(McpHttpGatewayState {
        proxy: config.proxy,
        endpoint: config.endpoint,
        max_concurrent_requests: config.max_concurrent_requests,
        max_active_sessions: config.max_active_sessions,
        session_idle_timeout: config.session_idle_timeout,
        max_body_bytes: config.max_body_bytes,
        max_header_bytes: config.max_header_bytes,
        stream_timeout: config.stream_timeout,
        allow_origins: config.allow_origins,
        auth_token: config.auth_token,
        trust_proxy_headers: config.trust_proxy_headers,
        trace_out: config.trace_out,
        session_report_out: config.session_report_out,
        metrics: Mutex::new(McpHttpGatewayMetrics::default()),
        sessions: Mutex::new(BTreeMap::new()),
    });
    mcp_proxy_http_accept_loop(
        listener,
        state,
        config.max_requests,
        config.max_concurrent_requests,
    )
}

fn validate_mcp_http_endpoint(endpoint: &str) -> Result<(), AgentKError> {
    if endpoint.is_empty() || !endpoint.starts_with('/') {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP endpoint must be an origin-form path beginning with /".to_string(),
        ));
    }
    if endpoint.contains('?') || endpoint.contains('#') {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP endpoint must not include query strings or fragments".to_string(),
        ));
    }
    if endpoint
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP endpoint must not include whitespace or control characters".to_string(),
        ));
    }
    if matches!(endpoint, "/healthz" | "/readyz" | "/metrics") {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP endpoint must not overlap operational probe paths".to_string(),
        ));
    }
    Ok(())
}

fn validate_mcp_http_bind_security(
    host: &str,
    allow_non_local_bind: bool,
    auth_configured: bool,
) -> Result<(), AgentKError> {
    if is_loopback_bind_host(host) {
        return Ok(());
    }
    if !allow_non_local_bind {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP host must be loopback unless --allow-non-local-bind is set".to_string(),
        ));
    }
    if !auth_configured {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP non-loopback binds require a non-empty auth token".to_string(),
        ));
    }
    Ok(())
}

fn is_loopback_bind_host(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback())
}

fn mcp_proxy_http_accept_loop(
    listener: TcpListener,
    state: Arc<McpHttpGatewayState>,
    max_requests: usize,
    max_concurrent_requests: usize,
) -> Result<(), AgentKError> {
    let (completion_tx, completion_rx) = mpsc::channel();
    let mut active_requests = 0usize;
    let mut accepted_requests = 0usize;
    let mut first_error: Option<String> = None;

    while max_requests == 0 || accepted_requests < max_requests {
        while active_requests >= max_concurrent_requests {
            if let Err(error) = receive_mcp_http_request_completion(&completion_rx) {
                first_error.get_or_insert(error);
            }
            active_requests = active_requests.saturating_sub(1);
        }

        let (mut stream, peer) = listener.accept()?;
        configure_mcp_http_stream(&stream, state.stream_timeout)?;
        accepted_requests += 1;
        println!("accepted   {} {}", accepted_requests, peer);
        let state = Arc::clone(&state);
        let completion = completion_tx.clone();
        let request_index = accepted_requests;
        thread::spawn(move || {
            let result =
                handle_mcp_http_stream(&mut stream, &state).map_err(|error| error.to_string());
            let _ = completion.send((request_index, result));
        });
        active_requests += 1;
    }

    drop(completion_tx);
    while active_requests > 0 {
        if let Err(error) = receive_mcp_http_request_completion(&completion_rx) {
            first_error.get_or_insert(error);
        }
        active_requests -= 1;
    }

    match mcp_http_drain_active_sessions(&state) {
        Ok(drained_sessions) => {
            if drained_sessions > 0 {
                println!("drained    {drained_sessions} active HTTP sessions");
            }
        }
        Err(error) => {
            first_error.get_or_insert(error.to_string());
        }
    }

    if let Some(error) = first_error {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "one or more MCP HTTP requests failed: {error}"
        )));
    }
    Ok(())
}

fn mcp_http_drain_active_sessions(state: &Arc<McpHttpGatewayState>) -> Result<usize, AgentKError> {
    let sessions = {
        let mut sessions = state.sessions.lock().map_err(|_| {
            AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
        })?;
        std::mem::take(&mut *sessions)
    };
    let drained = sessions.len();
    for (session_id, session) in sessions {
        let session = mcp_http_lock_session(&session)?;
        mcp_http_write_session_outputs(&session_id, &session.proxy, state)?;
    }
    Ok(drained)
}

fn mcp_http_lock_session(
    session: &Arc<Mutex<McpHttpSession>>,
) -> Result<MutexGuard<'_, McpHttpSession>, AgentKError> {
    session
        .lock()
        .map_err(|_| AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string()))
}

fn configure_mcp_http_stream(
    stream: &TcpStream,
    stream_timeout: Duration,
) -> Result<(), AgentKError> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(stream_timeout))?;
    stream.set_write_timeout(Some(stream_timeout))?;
    Ok(())
}

fn receive_mcp_http_request_completion(
    completion_rx: &mpsc::Receiver<(usize, Result<(), String>)>,
) -> Result<(), String> {
    match completion_rx.recv() {
        Ok((request_index, Ok(()))) => {
            println!("completed  {request_index}");
            Ok(())
        }
        Ok((request_index, Err(error))) => {
            println!("failed     {request_index} {error}");
            Err(error)
        }
        Err(error) => Err(format!(
            "MCP HTTP request worker ended unexpectedly: {error}"
        )),
    }
}

fn handle_mcp_http_stream(
    stream: &mut TcpStream,
    state: &Arc<McpHttpGatewayState>,
) -> Result<(), AgentKError> {
    let request = match read_dashboard_http_request_with_limits(
        stream,
        state.max_body_bytes,
        state.max_header_bytes,
        state.trust_proxy_headers,
    ) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(AgentKError::InvalidMcpRequest(message))
            if message == "HTTP request headers are too large" =>
        {
            mcp_http_update_metrics(state, |metrics| {
                metrics.client_error_responses += 1;
                metrics.header_too_large_responses += 1;
            })?;
            let response = mcp_http_headers_too_large_response(state.max_header_bytes);
            write_dashboard_http_response(stream, &response)?;
            return Ok(());
        }
        Err(AgentKError::InvalidMcpRequest(message))
            if message == "HTTP request body is too large" =>
        {
            mcp_http_update_metrics(state, |metrics| {
                metrics.client_error_responses += 1;
                metrics.body_too_large_responses += 1;
            })?;
            let response = mcp_http_payload_too_large_response(state.max_body_bytes);
            write_dashboard_http_response(stream, &response)?;
            return Ok(());
        }
        Err(AgentKError::InvalidMcpRequest(_)) => {
            mcp_http_update_metrics(state, |metrics| {
                metrics.client_error_responses += 1;
                metrics.invalid_framing_responses += 1;
            })?;
            let response = mcp_http_bad_request_response();
            write_dashboard_http_response(stream, &response)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let response = mcp_http_response(&request, state)?;
    write_dashboard_http_response(stream, &response)?;
    Ok(())
}

fn mcp_http_payload_too_large_response(max_body_bytes: usize) -> DashboardHttpResponse {
    dashboard_http_text(
        "413 Payload Too Large",
        &format!("MCP HTTP request body must be at most {max_body_bytes} bytes\n"),
    )
}

fn mcp_http_headers_too_large_response(max_header_bytes: usize) -> DashboardHttpResponse {
    dashboard_http_text(
        "431 Request Header Fields Too Large",
        &format!("MCP HTTP request headers must be at most {max_header_bytes} bytes\n"),
    )
}

fn mcp_http_bad_request_response() -> DashboardHttpResponse {
    dashboard_http_text("400 Bad Request", "invalid MCP HTTP request\n")
}

fn mcp_http_too_many_sessions_response(max_active_sessions: usize) -> DashboardHttpResponse {
    dashboard_http_text(
        "429 Too Many Requests",
        &format!("MCP HTTP active session limit reached: {max_active_sessions}\n"),
    )
}

fn mcp_http_preflight_response(origin: &str) -> DashboardHttpResponse {
    let mut response = DashboardHttpResponse {
        status: "204 No Content",
        content_type: "text/plain; charset=utf-8",
        headers: Vec::new(),
        body: Vec::new(),
    };
    mcp_http_apply_cors_headers(&mut response, origin);
    response.headers.push((
        "Access-Control-Allow-Methods".to_string(),
        "POST, GET, DELETE, OPTIONS".to_string(),
    ));
    response.headers.push((
        "Access-Control-Allow-Headers".to_string(),
        "Accept, Content-Type, Authorization, X-AgentK-MCP-Token, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID"
            .to_string(),
    ));
    response
        .headers
        .push(("Access-Control-Max-Age".to_string(), "600".to_string()));
    response
}

fn mcp_http_apply_cors_headers(response: &mut DashboardHttpResponse, origin: &str) {
    response.headers.push((
        "Access-Control-Allow-Origin".to_string(),
        origin.to_string(),
    ));
    response
        .headers
        .push(("Vary".to_string(), "Origin".to_string()));
    response.headers.push((
        "Access-Control-Expose-Headers".to_string(),
        "Mcp-Session-Id, Last-Event-ID, WWW-Authenticate".to_string(),
    ));
}

fn mcp_http_prune_expired_sessions(state: &Arc<McpHttpGatewayState>) -> Result<usize, AgentKError> {
    let now = Instant::now();
    let mut expired = Vec::new();
    {
        let mut sessions = state.sessions.lock().map_err(|_| {
            AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
        })?;
        let mut expired_ids = Vec::new();
        for (session_id, session) in sessions.iter() {
            match session.try_lock() {
                Ok(session) => {
                    if now.duration_since(session.last_seen) >= state.session_idle_timeout {
                        expired_ids.push(session_id.clone());
                    }
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Poisoned(_)) => {
                    return Err(AgentKError::InvalidMcpRequest(
                        "MCP HTTP session lock poisoned".to_string(),
                    ));
                }
            }
        }
        for session_id in expired_ids {
            if let Some(session) = sessions.remove(&session_id) {
                expired.push((session_id, session));
            }
        }
    }
    for (session_id, session) in &expired {
        let session = mcp_http_lock_session(session)?;
        mcp_http_write_session_outputs(session_id, &session.proxy, state)?;
    }
    if !expired.is_empty() {
        mcp_http_update_metrics(state, |metrics| {
            metrics.sessions_expired += expired.len();
        })?;
    }
    Ok(expired.len())
}

fn mcp_http_response(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
) -> Result<DashboardHttpResponse, AgentKError> {
    let mut response = match mcp_http_response_inner(request, state) {
        Ok(response) => response,
        Err(error) => mcp_http_gateway_error_response(request, state, &error),
    };
    mcp_http_record_response_metrics(request, &response, state)?;
    if request.method == "HEAD" {
        response.body.clear();
    }
    Ok(response)
}

fn mcp_http_response_inner(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
) -> Result<DashboardHttpResponse, AgentKError> {
    if let Some(response) = mcp_http_trusted_proxy_header_error(request, state.trust_proxy_headers)
    {
        return Ok(response);
    }
    let (path, has_query) = match request.target.split_once('?') {
        Some((path, _)) => (path, true),
        None => (request.target.as_str(), false),
    };
    if has_query && (path == state.endpoint || mcp_http_is_operational_path(path)) {
        return Ok(dashboard_http_text(
            "400 Bad Request",
            "MCP HTTP endpoint and probes must not include query strings\n",
        ));
    }
    if (path == state.endpoint || matches!(path, "/readyz" | "/metrics"))
        && let Some(response) = mcp_http_control_header_error(request)
    {
        return Ok(response);
    }
    if let Some(response) = mcp_http_unexpected_body_error(request, path, state.endpoint.as_str()) {
        return Ok(response);
    }
    if mcp_http_is_operational_path(path) {
        let response =
            if path != "/healthz" && !mcp_http_auth_allowed(request, state.auth_token.as_deref()) {
                mcp_http_token_required_response()
            } else {
                mcp_http_operational_response(request, state, path)?
            };
        return Ok(response);
    }
    if path != state.endpoint {
        return Ok(dashboard_http_text("404 Not Found", "not found\n"));
    }
    if !mcp_http_origin_allowed(request, &state.allow_origins) {
        return Ok(dashboard_http_text(
            "403 Forbidden",
            "origin is not allowed\n",
        ));
    }
    let cors_origin = mcp_http_cors_origin(request, &state.allow_origins);
    if request.method == "OPTIONS" {
        let Some(origin) = cors_origin.as_deref() else {
            return Ok(dashboard_http_text(
                "400 Bad Request",
                "MCP HTTP CORS preflight requires an allowed Origin\n",
            ));
        };
        if let Some(mut response) = mcp_http_preflight_error(request) {
            mcp_http_apply_cors_headers(&mut response, origin);
            return Ok(response);
        }
        return Ok(mcp_http_preflight_response(origin));
    }
    if !mcp_http_auth_allowed(request, state.auth_token.as_deref()) {
        let mut response = mcp_http_token_required_response();
        if let Some(origin) = cors_origin.as_deref() {
            mcp_http_apply_cors_headers(&mut response, origin);
        }
        return Ok(response);
    }
    mcp_http_prune_expired_sessions(state)?;

    let mut response = match request.method.as_str() {
        "POST" => mcp_http_post_response(request, state),
        "GET" => mcp_http_sse_response(request, state),
        "DELETE" => mcp_http_delete_response(request, state),
        _ => {
            let mut response =
                dashboard_http_text("405 Method Not Allowed", "method not allowed\n");
            response.headers.push((
                "Allow".to_string(),
                "POST, GET, DELETE, OPTIONS".to_string(),
            ));
            Ok(response)
        }
    }?;
    if let Some(origin) = cors_origin.as_deref() {
        mcp_http_apply_cors_headers(&mut response, origin);
    }
    Ok(response)
}

fn mcp_http_is_operational_path(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz" | "/metrics")
}

fn mcp_http_record_response_metrics(
    request: &DashboardHttpRequest,
    response: &DashboardHttpResponse,
    state: &Arc<McpHttpGatewayState>,
) -> Result<(), AgentKError> {
    mcp_http_update_metrics(state, |metrics| {
        metrics.requests_total += 1;
        match request.method.as_str() {
            "POST" => metrics.post_requests += 1,
            "GET" | "HEAD" => metrics.get_requests += 1,
            "DELETE" => metrics.delete_requests += 1,
            "OPTIONS" => metrics.options_requests += 1,
            _ => metrics.other_method_requests += 1,
        }

        if response.status.starts_with('4') {
            metrics.client_error_responses += 1;
        } else if response.status.starts_with('5') {
            metrics.server_error_responses += 1;
        }
        match response.status {
            "401 Unauthorized" => metrics.auth_rejections += 1,
            "403 Forbidden" => metrics.origin_rejections += 1,
            "405 Method Not Allowed" => metrics.method_rejections += 1,
            "502 Bad Gateway" => metrics.downstream_transport_error_responses += 1,
            "500 Internal Server Error" => metrics.gateway_internal_error_responses += 1,
            "404 Not Found"
                if request.target.split('?').next() == Some(state.endpoint.as_str()) =>
            {
                metrics.session_not_found += 1;
            }
            _ => {}
        }
        if mcp_http_is_preflight_rejection(request, response, state) {
            metrics.preflight_rejections += 1;
        }
        if state.trust_proxy_headers && mcp_http_has_forwarded_header(request) {
            metrics.trusted_proxy_header_requests += 1;
        }
    })
}

fn mcp_http_has_forwarded_header(request: &DashboardHttpRequest) -> bool {
    request
        .headers
        .iter()
        .any(|(name, _)| is_forwarded_http_header(name))
}

fn mcp_http_is_preflight_rejection(
    request: &DashboardHttpRequest,
    response: &DashboardHttpResponse,
    state: &Arc<McpHttpGatewayState>,
) -> bool {
    request.method == "OPTIONS"
        && request.target.split('?').next() == Some(state.endpoint.as_str())
        && response.status == "400 Bad Request"
        && response.body.starts_with(b"MCP HTTP CORS preflight ")
}

fn mcp_http_update_metrics(
    state: &Arc<McpHttpGatewayState>,
    update: impl FnOnce(&mut McpHttpGatewayMetrics),
) -> Result<(), AgentKError> {
    let mut metrics = state.metrics.lock().map_err(|_| {
        AgentKError::InvalidMcpRequest("MCP HTTP metrics lock poisoned".to_string())
    })?;
    update(&mut metrics);
    Ok(())
}

fn mcp_http_metrics_snapshot(
    state: &Arc<McpHttpGatewayState>,
) -> Result<McpHttpGatewayMetrics, AgentKError> {
    Ok(*state.metrics.lock().map_err(|_| {
        AgentKError::InvalidMcpRequest("MCP HTTP metrics lock poisoned".to_string())
    })?)
}

fn mcp_http_sse_buffer_snapshot(
    state: &Arc<McpHttpGatewayState>,
) -> Result<McpHttpSseBufferSnapshot, AgentKError> {
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string()))?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut snapshot = McpHttpSseBufferSnapshot {
        active_sessions: sessions.len(),
        buffer_capacity: sessions
            .len()
            .saturating_mul(MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION),
        ..McpHttpSseBufferSnapshot::default()
    };
    for session in sessions {
        let session = mcp_http_lock_session(&session)?;
        let buffered_events = session.sse_events.len();
        snapshot.buffered_events = snapshot.buffered_events.saturating_add(buffered_events);
        if buffered_events > 0 {
            snapshot.sessions_with_buffered_events += 1;
        }
    }
    Ok(snapshot)
}

fn mcp_http_preflight_error(request: &DashboardHttpRequest) -> Option<DashboardHttpResponse> {
    let Some(requested_method) = request.header("access-control-request-method") else {
        return Some(dashboard_http_text(
            "400 Bad Request",
            "MCP HTTP CORS preflight method is required\n",
        ));
    };
    if !matches!(requested_method, "POST" | "GET" | "DELETE") {
        return Some(dashboard_http_text(
            "400 Bad Request",
            "MCP HTTP CORS preflight method is not allowed\n",
        ));
    }

    if request
        .header("access-control-request-private-network")
        .is_some()
    {
        return Some(dashboard_http_text(
            "400 Bad Request",
            "MCP HTTP CORS preflight private-network request is not supported\n",
        ));
    }

    if let Some(headers) = request.header("access-control-request-headers") {
        for header in headers.split(',') {
            let header = header.trim().to_ascii_lowercase();
            if header.is_empty()
                || !matches!(
                    header.as_str(),
                    "accept"
                        | "authorization"
                        | "content-type"
                        | "last-event-id"
                        | "mcp-protocol-version"
                        | "mcp-session-id"
                        | "x-agentk-mcp-token"
                )
            {
                return Some(dashboard_http_text(
                    "400 Bad Request",
                    "MCP HTTP CORS preflight header is not allowed\n",
                ));
            }
        }
    }

    None
}

fn mcp_http_token_required_response() -> DashboardHttpResponse {
    let mut response = dashboard_http_text("401 Unauthorized", "MCP HTTP token is required\n");
    response.headers.push((
        "WWW-Authenticate".to_string(),
        "Bearer realm=\"agentk-mcp\"".to_string(),
    ));
    response
}

fn mcp_http_operational_response(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
    path: &str,
) -> Result<DashboardHttpResponse, AgentKError> {
    if request.method != "GET" && request.method != "HEAD" {
        let mut response = dashboard_http_text("405 Method Not Allowed", "method not allowed\n");
        response
            .headers
            .push(("Allow".to_string(), "GET, HEAD".to_string()));
        return Ok(response);
    }

    if path == "/healthz" {
        return Ok(DashboardHttpResponse {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body: br#"{"ok":true}"#.to_vec(),
        });
    }
    let expired_sessions = mcp_http_prune_expired_sessions(state)?;

    let sse_buffer = mcp_http_sse_buffer_snapshot(state)?;
    let metrics = mcp_http_metrics_snapshot(state)?;
    if path == "/metrics" {
        return Ok(DashboardHttpResponse {
            status: "200 OK",
            content_type: "text/plain; version=0.0.4; charset=utf-8",
            headers: Vec::new(),
            body: mcp_http_metrics_body(state, sse_buffer, expired_sessions, metrics).into_bytes(),
        });
    }
    Ok(DashboardHttpResponse {
        status: "200 OK",
        content_type: "application/json",
        headers: Vec::new(),
        body: serde_json::to_vec(&McpHttpReadinessBody {
            ready: true,
            endpoint: state.endpoint.as_str(),
            protocol_version: MCP_PROTOCOL_VERSION,
            active_sessions: sse_buffer.active_sessions,
            max_active_sessions: state.max_active_sessions,
            session_idle_timeout_ms: state.session_idle_timeout.as_millis(),
            expired_sessions_reaped: expired_sessions,
            max_concurrent_requests: state.max_concurrent_requests,
            max_body_bytes: state.max_body_bytes,
            max_header_bytes: state.max_header_bytes,
            stream_timeout_ms: state.stream_timeout.as_millis(),
            configured_allowed_origins: state.allow_origins.len(),
            auth_required: state.auth_token.is_some(),
            trusted_proxy_headers: state.trust_proxy_headers,
            requests_total: metrics.requests_total,
            post_requests: metrics.post_requests,
            get_requests: metrics.get_requests,
            delete_requests: metrics.delete_requests,
            options_requests: metrics.options_requests,
            other_method_requests: metrics.other_method_requests,
            client_error_responses: metrics.client_error_responses,
            server_error_responses: metrics.server_error_responses,
            auth_rejections: metrics.auth_rejections,
            origin_rejections: metrics.origin_rejections,
            method_rejections: metrics.method_rejections,
            preflight_rejections: metrics.preflight_rejections,
            sse_stream_requests: metrics.sse_stream_requests,
            sse_resume_requests: metrics.sse_resume_requests,
            sse_invalid_resume_requests: metrics.sse_invalid_resume_requests,
            sse_evicted_resume_requests: metrics.sse_evicted_resume_requests,
            sse_events_returned: metrics.sse_events_returned,
            sse_retained_events_per_session: MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION,
            sse_sessions_with_buffered_events: sse_buffer.sessions_with_buffered_events,
            sse_buffered_events: sse_buffer.buffered_events,
            sse_buffer_capacity: sse_buffer.buffer_capacity,
            sse_event_buffer_evictions: metrics.sse_event_buffer_evictions,
            invalid_json_rpc_id_requests: metrics.invalid_json_rpc_id_requests,
            invalid_framing_responses: metrics.invalid_framing_responses,
            header_too_large_responses: metrics.header_too_large_responses,
            body_too_large_responses: metrics.body_too_large_responses,
            trusted_proxy_header_requests: metrics.trusted_proxy_header_requests,
            downstream_transport_error_responses: metrics.downstream_transport_error_responses,
            gateway_internal_error_responses: metrics.gateway_internal_error_responses,
            sessions_created: metrics.sessions_created,
            sessions_deleted: metrics.sessions_deleted,
            sessions_expired: metrics.sessions_expired,
            session_not_found: metrics.session_not_found,
        })?,
    })
}

fn mcp_http_metrics_body(
    state: &McpHttpGatewayState,
    sse_buffer: McpHttpSseBufferSnapshot,
    expired_sessions_reaped: usize,
    metrics: McpHttpGatewayMetrics,
) -> String {
    format!(
        "# HELP agentk_mcp_http_ready MCP HTTP gateway readiness state.\n\
# TYPE agentk_mcp_http_ready gauge\n\
agentk_mcp_http_ready 1\n\
# HELP agentk_mcp_http_active_sessions Active initialized MCP HTTP sessions.\n\
# TYPE agentk_mcp_http_active_sessions gauge\n\
agentk_mcp_http_active_sessions {active_sessions}\n\
# HELP agentk_mcp_http_max_active_sessions Configured active MCP HTTP session cap.\n\
# TYPE agentk_mcp_http_max_active_sessions gauge\n\
agentk_mcp_http_max_active_sessions {max_active_sessions}\n\
# HELP agentk_mcp_http_expired_sessions_reaped Expired MCP HTTP sessions reaped while serving this operational request.\n\
# TYPE agentk_mcp_http_expired_sessions_reaped gauge\n\
agentk_mcp_http_expired_sessions_reaped {expired_sessions_reaped}\n\
# HELP agentk_mcp_http_max_concurrent_requests Configured concurrent MCP HTTP request cap.\n\
# TYPE agentk_mcp_http_max_concurrent_requests gauge\n\
agentk_mcp_http_max_concurrent_requests {max_concurrent_requests}\n\
# HELP agentk_mcp_http_max_body_bytes Configured MCP HTTP request body byte cap.\n\
# TYPE agentk_mcp_http_max_body_bytes gauge\n\
agentk_mcp_http_max_body_bytes {max_body_bytes}\n\
# HELP agentk_mcp_http_max_header_bytes Configured MCP HTTP request header byte cap.\n\
# TYPE agentk_mcp_http_max_header_bytes gauge\n\
agentk_mcp_http_max_header_bytes {max_header_bytes}\n\
# HELP agentk_mcp_http_session_idle_timeout_milliseconds Configured MCP HTTP idle-session timeout in milliseconds.\n\
# TYPE agentk_mcp_http_session_idle_timeout_milliseconds gauge\n\
agentk_mcp_http_session_idle_timeout_milliseconds {session_idle_timeout_ms}\n\
# HELP agentk_mcp_http_stream_timeout_milliseconds Configured accepted-stream read/write timeout in milliseconds.\n\
# TYPE agentk_mcp_http_stream_timeout_milliseconds gauge\n\
agentk_mcp_http_stream_timeout_milliseconds {stream_timeout_ms}\n\
# HELP agentk_mcp_http_configured_allowed_origins Configured additional allowed Origin count without raw origin values.\n\
# TYPE agentk_mcp_http_configured_allowed_origins gauge\n\
agentk_mcp_http_configured_allowed_origins {configured_allowed_origins}\n\
# HELP agentk_mcp_http_auth_required Whether this MCP HTTP gateway requires bearer auth.\n\
# TYPE agentk_mcp_http_auth_required gauge\n\
agentk_mcp_http_auth_required {auth_required}\n\
# HELP agentk_mcp_http_trusted_proxy_headers Whether clean forwarded proxy metadata is accepted.\n\
# TYPE agentk_mcp_http_trusted_proxy_headers gauge\n\
agentk_mcp_http_trusted_proxy_headers {trusted_proxy_headers}\n\
# HELP agentk_mcp_http_requests_total Parsed HTTP requests handled by this gateway.\n\
# TYPE agentk_mcp_http_requests_total counter\n\
agentk_mcp_http_requests_total {requests_total}\n\
# HELP agentk_mcp_http_post_requests_total Parsed HTTP POST requests handled by this gateway.\n\
# TYPE agentk_mcp_http_post_requests_total counter\n\
agentk_mcp_http_post_requests_total {post_requests}\n\
# HELP agentk_mcp_http_get_requests_total Parsed HTTP GET or HEAD requests handled by this gateway.\n\
# TYPE agentk_mcp_http_get_requests_total counter\n\
agentk_mcp_http_get_requests_total {get_requests}\n\
# HELP agentk_mcp_http_delete_requests_total Parsed HTTP DELETE requests handled by this gateway.\n\
# TYPE agentk_mcp_http_delete_requests_total counter\n\
agentk_mcp_http_delete_requests_total {delete_requests}\n\
# HELP agentk_mcp_http_options_requests_total Parsed HTTP OPTIONS requests handled by this gateway.\n\
# TYPE agentk_mcp_http_options_requests_total counter\n\
agentk_mcp_http_options_requests_total {options_requests}\n\
# HELP agentk_mcp_http_other_method_requests_total Parsed unsupported-method requests handled by this gateway.\n\
# TYPE agentk_mcp_http_other_method_requests_total counter\n\
agentk_mcp_http_other_method_requests_total {other_method_requests}\n\
# HELP agentk_mcp_http_client_error_responses_total HTTP 4xx responses returned by this gateway.\n\
# TYPE agentk_mcp_http_client_error_responses_total counter\n\
agentk_mcp_http_client_error_responses_total {client_error_responses}\n\
# HELP agentk_mcp_http_server_error_responses_total HTTP 5xx responses returned by this gateway.\n\
# TYPE agentk_mcp_http_server_error_responses_total counter\n\
agentk_mcp_http_server_error_responses_total {server_error_responses}\n\
# HELP agentk_mcp_http_auth_rejections_total Requests rejected because MCP HTTP auth failed.\n\
# TYPE agentk_mcp_http_auth_rejections_total counter\n\
agentk_mcp_http_auth_rejections_total {auth_rejections}\n\
# HELP agentk_mcp_http_origin_rejections_total Requests rejected because Origin was not allowed.\n\
# TYPE agentk_mcp_http_origin_rejections_total counter\n\
agentk_mcp_http_origin_rejections_total {origin_rejections}\n\
# HELP agentk_mcp_http_method_rejections_total Requests rejected because the HTTP method is not allowed.\n\
# TYPE agentk_mcp_http_method_rejections_total counter\n\
agentk_mcp_http_method_rejections_total {method_rejections}\n\
# HELP agentk_mcp_http_preflight_rejections_total CORS preflight requests rejected by MCP HTTP validation.\n\
# TYPE agentk_mcp_http_preflight_rejections_total counter\n\
agentk_mcp_http_preflight_rejections_total {preflight_rejections}\n\
# HELP agentk_mcp_http_sse_stream_requests_total Authenticated MCP SSE stream reads served from bounded session buffers.\n\
# TYPE agentk_mcp_http_sse_stream_requests_total counter\n\
agentk_mcp_http_sse_stream_requests_total {sse_stream_requests}\n\
# HELP agentk_mcp_http_sse_resume_requests_total MCP SSE stream reads using Last-Event-ID resume.\n\
# TYPE agentk_mcp_http_sse_resume_requests_total counter\n\
agentk_mcp_http_sse_resume_requests_total {sse_resume_requests}\n\
# HELP agentk_mcp_http_sse_invalid_resume_requests_total MCP SSE stream reads rejected for invalid Last-Event-ID values.\n\
# TYPE agentk_mcp_http_sse_invalid_resume_requests_total counter\n\
agentk_mcp_http_sse_invalid_resume_requests_total {sse_invalid_resume_requests}\n\
# HELP agentk_mcp_http_sse_evicted_resume_requests_total MCP SSE resume reads rejected because Last-Event-ID is older than the retained buffer.\n\
# TYPE agentk_mcp_http_sse_evicted_resume_requests_total counter\n\
agentk_mcp_http_sse_evicted_resume_requests_total {sse_evicted_resume_requests}\n\
# HELP agentk_mcp_http_sse_events_returned_total Buffered MCP SSE events returned to clients.\n\
# TYPE agentk_mcp_http_sse_events_returned_total counter\n\
agentk_mcp_http_sse_events_returned_total {sse_events_returned}\n\
# HELP agentk_mcp_http_sse_retained_events_per_session Configured retained MCP SSE events per active session.\n\
# TYPE agentk_mcp_http_sse_retained_events_per_session gauge\n\
agentk_mcp_http_sse_retained_events_per_session {sse_retained_events_per_session}\n\
# HELP agentk_mcp_http_sse_sessions_with_buffered_events Active MCP HTTP sessions with retained SSE events.\n\
# TYPE agentk_mcp_http_sse_sessions_with_buffered_events gauge\n\
agentk_mcp_http_sse_sessions_with_buffered_events {sse_sessions_with_buffered_events}\n\
# HELP agentk_mcp_http_sse_buffered_events Retained MCP SSE events currently buffered across active sessions.\n\
# TYPE agentk_mcp_http_sse_buffered_events gauge\n\
agentk_mcp_http_sse_buffered_events {sse_buffered_events}\n\
# HELP agentk_mcp_http_sse_buffer_capacity Retained MCP SSE event slots across active sessions.\n\
# TYPE agentk_mcp_http_sse_buffer_capacity gauge\n\
agentk_mcp_http_sse_buffer_capacity {sse_buffer_capacity}\n\
# HELP agentk_mcp_http_sse_event_buffer_evictions_total MCP SSE events dropped because a session buffer reached its retention cap.\n\
# TYPE agentk_mcp_http_sse_event_buffer_evictions_total counter\n\
agentk_mcp_http_sse_event_buffer_evictions_total {sse_event_buffer_evictions}\n\
# HELP agentk_mcp_http_invalid_json_rpc_id_requests_total MCP HTTP POST requests rejected before downstream forwarding because JSON-RPC id was malformed.\n\
# TYPE agentk_mcp_http_invalid_json_rpc_id_requests_total counter\n\
agentk_mcp_http_invalid_json_rpc_id_requests_total {invalid_json_rpc_id_requests}\n\
# HELP agentk_mcp_http_invalid_framing_responses_total Requests rejected before parsing due to invalid HTTP framing.\n\
# TYPE agentk_mcp_http_invalid_framing_responses_total counter\n\
agentk_mcp_http_invalid_framing_responses_total {invalid_framing_responses}\n\
# HELP agentk_mcp_http_header_too_large_responses_total Requests rejected before parsing because headers exceeded the configured cap.\n\
# TYPE agentk_mcp_http_header_too_large_responses_total counter\n\
agentk_mcp_http_header_too_large_responses_total {header_too_large_responses}\n\
# HELP agentk_mcp_http_body_too_large_responses_total Requests rejected before parsing because the declared body exceeded the configured cap.\n\
# TYPE agentk_mcp_http_body_too_large_responses_total counter\n\
agentk_mcp_http_body_too_large_responses_total {body_too_large_responses}\n\
# HELP agentk_mcp_http_trusted_proxy_header_requests_total Requests carrying clean trusted proxy metadata.\n\
# TYPE agentk_mcp_http_trusted_proxy_header_requests_total counter\n\
agentk_mcp_http_trusted_proxy_header_requests_total {trusted_proxy_header_requests}\n\
# HELP agentk_mcp_http_downstream_transport_error_responses_total Sanitized HTTP responses returned for downstream MCP spawn or transport failures.\n\
# TYPE agentk_mcp_http_downstream_transport_error_responses_total counter\n\
agentk_mcp_http_downstream_transport_error_responses_total {downstream_transport_error_responses}\n\
# HELP agentk_mcp_http_gateway_internal_error_responses_total Sanitized HTTP responses returned for AgentK MCP HTTP gateway internal failures.\n\
# TYPE agentk_mcp_http_gateway_internal_error_responses_total counter\n\
agentk_mcp_http_gateway_internal_error_responses_total {gateway_internal_error_responses}\n\
# HELP agentk_mcp_http_sessions_created_total Initialized MCP HTTP sessions created by this gateway.\n\
# TYPE agentk_mcp_http_sessions_created_total counter\n\
agentk_mcp_http_sessions_created_total {sessions_created}\n\
# HELP agentk_mcp_http_sessions_deleted_total MCP HTTP sessions closed by DELETE.\n\
# TYPE agentk_mcp_http_sessions_deleted_total counter\n\
agentk_mcp_http_sessions_deleted_total {sessions_deleted}\n\
# HELP agentk_mcp_http_sessions_expired_total MCP HTTP sessions reaped after idle timeout.\n\
# TYPE agentk_mcp_http_sessions_expired_total counter\n\
agentk_mcp_http_sessions_expired_total {sessions_expired}\n\
# HELP agentk_mcp_http_session_not_found_total MCP endpoint requests that referenced a missing session.\n\
# TYPE agentk_mcp_http_session_not_found_total counter\n\
agentk_mcp_http_session_not_found_total {session_not_found}\n",
        active_sessions = sse_buffer.active_sessions,
        max_active_sessions = state.max_active_sessions,
        max_concurrent_requests = state.max_concurrent_requests,
        max_body_bytes = state.max_body_bytes,
        max_header_bytes = state.max_header_bytes,
        session_idle_timeout_ms = state.session_idle_timeout.as_millis(),
        stream_timeout_ms = state.stream_timeout.as_millis(),
        configured_allowed_origins = state.allow_origins.len(),
        auth_required = usize::from(state.auth_token.is_some()),
        trusted_proxy_headers = usize::from(state.trust_proxy_headers),
        requests_total = metrics.requests_total,
        post_requests = metrics.post_requests,
        get_requests = metrics.get_requests,
        delete_requests = metrics.delete_requests,
        options_requests = metrics.options_requests,
        other_method_requests = metrics.other_method_requests,
        client_error_responses = metrics.client_error_responses,
        server_error_responses = metrics.server_error_responses,
        auth_rejections = metrics.auth_rejections,
        origin_rejections = metrics.origin_rejections,
        method_rejections = metrics.method_rejections,
        preflight_rejections = metrics.preflight_rejections,
        sse_stream_requests = metrics.sse_stream_requests,
        sse_resume_requests = metrics.sse_resume_requests,
        sse_invalid_resume_requests = metrics.sse_invalid_resume_requests,
        sse_evicted_resume_requests = metrics.sse_evicted_resume_requests,
        sse_events_returned = metrics.sse_events_returned,
        sse_retained_events_per_session = MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION,
        sse_sessions_with_buffered_events = sse_buffer.sessions_with_buffered_events,
        sse_buffered_events = sse_buffer.buffered_events,
        sse_buffer_capacity = sse_buffer.buffer_capacity,
        sse_event_buffer_evictions = metrics.sse_event_buffer_evictions,
        invalid_json_rpc_id_requests = metrics.invalid_json_rpc_id_requests,
        invalid_framing_responses = metrics.invalid_framing_responses,
        header_too_large_responses = metrics.header_too_large_responses,
        body_too_large_responses = metrics.body_too_large_responses,
        trusted_proxy_header_requests = metrics.trusted_proxy_header_requests,
        downstream_transport_error_responses = metrics.downstream_transport_error_responses,
        gateway_internal_error_responses = metrics.gateway_internal_error_responses,
        sessions_created = metrics.sessions_created,
        sessions_deleted = metrics.sessions_deleted,
        sessions_expired = metrics.sessions_expired,
        session_not_found = metrics.session_not_found
    )
}

fn mcp_http_gateway_error_response(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
    error: &AgentKError,
) -> DashboardHttpResponse {
    let downstream = mcp_http_error_is_downstream_transport(error);
    let status = if downstream {
        "502 Bad Gateway"
    } else {
        "500 Internal Server Error"
    };
    let message = if downstream {
        "Downstream MCP gateway error"
    } else {
        "AgentK MCP HTTP gateway error"
    };
    let detail = if downstream {
        "AgentK could not reach the configured downstream MCP server; raw command, environment, and payload values were not reflected"
    } else {
        "AgentK could not complete this MCP HTTP request; raw command, environment, and payload values were not reflected"
    };

    let mut response = if request.method == "POST"
        && request.target.split('?').next() == Some(state.endpoint.as_str())
    {
        DashboardHttpResponse {
            status,
            content_type: "application/json",
            headers: Vec::new(),
            body: serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": mcp_http_json_rpc_error_id(&request.body),
                "error": {
                    "code": if downstream { -32012 } else { -32603 },
                    "message": message,
                    "data": {
                        "detail": detail,
                        "agentk": {
                            "proxy": "streamable-http",
                            "mediated": false,
                            "downstream_forwarded": false,
                            "server_executed": false
                        }
                    }
                }
            }))
            .unwrap_or_else(|_| b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"AgentK MCP HTTP gateway error\"}}\n".to_vec()),
        }
    } else {
        dashboard_http_text(status, &format!("{message}\n"))
    };

    if request.target.split('?').next() == Some(state.endpoint.as_str())
        && let Some(origin) = mcp_http_cors_origin(request, &state.allow_origins)
    {
        mcp_http_apply_cors_headers(&mut response, &origin);
    }

    response
}

fn mcp_http_error_is_downstream_transport(error: &AgentKError) -> bool {
    match error {
        AgentKError::InvalidMcpRequest(message) => {
            message.contains("downstream MCP")
                || message.contains("failed to spawn downstream MCP server process")
        }
        _ => false,
    }
}

fn mcp_http_json_rpc_error_id(body: &[u8]) -> serde_json::Value {
    let Ok(message) = serde_json::from_slice::<serde_json::Value>(body) else {
        return serde_json::Value::Null;
    };
    let Some(id) = message.get("id") else {
        return serde_json::Value::Null;
    };
    match id {
        serde_json::Value::Null => serde_json::Value::Null,
        serde_json::Value::String(value) if value.len() <= MCP_HTTP_JSON_RPC_MAX_ID_BYTES => {
            id.clone()
        }
        serde_json::Value::Number(number)
            if number.as_i64().is_some() || number.as_u64().is_some() =>
        {
            id.clone()
        }
        _ => serde_json::Value::Null,
    }
}

fn mcp_http_protocol_version_error(
    request: &DashboardHttpRequest,
    negotiated_protocol_version: Option<&str>,
) -> Option<DashboardHttpResponse> {
    let protocol_version = request.header("mcp-protocol-version")?;
    if protocol_version == MCP_PROTOCOL_VERSION
        && negotiated_protocol_version.is_none_or(|negotiated| negotiated == protocol_version)
    {
        return None;
    }

    Some(dashboard_http_text(
        "400 Bad Request",
        &format!("MCP-Protocol-Version must be {MCP_PROTOCOL_VERSION}\n"),
    ))
}

fn mcp_http_validate_session_id(session_id: &str) -> Option<DashboardHttpResponse> {
    if session_id.len() == 32
        && session_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }

    Some(dashboard_http_text(
        "400 Bad Request",
        "Mcp-Session-Id must be a 32-character lowercase hex id\n",
    ))
}

fn mcp_http_control_header_error(request: &DashboardHttpRequest) -> Option<DashboardHttpResponse> {
    for name in [
        "accept",
        "access-control-request-headers",
        "access-control-request-method",
        "authorization",
        "content-type",
        "last-event-id",
        "mcp-protocol-version",
        "mcp-session-id",
        "origin",
        "x-agentk-mcp-token",
    ] {
        if request
            .headers
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .take(2)
            .count()
            > 1
        {
            return Some(dashboard_http_text(
                "400 Bad Request",
                "MCP HTTP control header must appear at most once\n",
            ));
        }
    }

    if request.header("authorization").is_some() && request.header("x-agentk-mcp-token").is_some() {
        return Some(dashboard_http_text(
            "400 Bad Request",
            "MCP HTTP token must use one auth header\n",
        ));
    }

    None
}

fn mcp_http_trusted_proxy_header_error(
    request: &DashboardHttpRequest,
    trust_proxy_headers: bool,
) -> Option<DashboardHttpResponse> {
    for (name, value) in &request.headers {
        if !is_forwarded_http_header(name) {
            continue;
        }
        if !trust_proxy_headers || !is_supported_trusted_forwarded_http_header(name) {
            return Some(dashboard_http_text(
                "400 Bad Request",
                "MCP HTTP forwarded headers require trusted proxy mode\n",
            ));
        }
        if request.header_count(name) > 1 || !is_clean_trusted_forwarded_header_value(name, value) {
            return Some(dashboard_http_text(
                "400 Bad Request",
                "MCP HTTP forwarded header is invalid\n",
            ));
        }
    }
    None
}

fn mcp_http_unexpected_body_error(
    request: &DashboardHttpRequest,
    path: &str,
    endpoint: &str,
) -> Option<DashboardHttpResponse> {
    if request.body.is_empty() || (path == endpoint && request.method == "POST") {
        return None;
    }

    Some(dashboard_http_text(
        "400 Bad Request",
        "MCP HTTP request bodies are only accepted on POST\n",
    ))
}

fn mcp_http_sse_response(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
) -> Result<DashboardHttpResponse, AgentKError> {
    if !mcp_http_accepts(request, "text/event-stream") {
        return Ok(dashboard_http_text(
            "406 Not Acceptable",
            "MCP HTTP GET requires Accept: text/event-stream\n",
        ));
    }
    let Some(session_id) = request.header("mcp-session-id") else {
        return Ok(dashboard_http_text(
            "400 Bad Request",
            "Mcp-Session-Id is required for SSE GET\n",
        ));
    };
    if let Some(response) = mcp_http_validate_session_id(session_id) {
        return Ok(response);
    }
    let session_id = session_id.to_string();
    let session = {
        let sessions = state.sessions.lock().map_err(|_| {
            AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
        })?;
        let Some(session) = sessions.get(&session_id) else {
            return Ok(dashboard_http_text(
                "404 Not Found",
                "MCP session not found\n",
            ));
        };
        Arc::clone(session)
    };
    let mut session = mcp_http_lock_session(&session)?;
    if let Some(response) =
        mcp_http_protocol_version_error(request, Some(session.protocol_version.as_str()))
    {
        return Ok(response);
    }
    let last_event_id = match mcp_http_last_event_id(request) {
        Ok(last_event_id) => last_event_id,
        Err(response) => {
            mcp_http_update_metrics(state, |metrics| {
                metrics.sse_invalid_resume_requests += 1;
            })?;
            return Ok(response);
        }
    };
    if mcp_http_sse_resume_evicted(&session, last_event_id) {
        mcp_http_update_metrics(state, |metrics| {
            metrics.sse_evicted_resume_requests += 1;
        })?;
        return Ok(dashboard_http_text(
            "410 Gone",
            "Last-Event-ID is older than the retained MCP HTTP SSE buffer\n",
        ));
    }
    let events = session
        .sse_events
        .iter()
        .filter(|event| last_event_id.is_none_or(|last_event_id| event.id > last_event_id))
        .cloned()
        .collect::<Vec<_>>();
    session.last_seen = Instant::now();
    drop(session);

    mcp_http_update_metrics(state, |metrics| {
        metrics.sse_stream_requests += 1;
        metrics.sse_events_returned += events.len();
        if last_event_id.is_some() {
            metrics.sse_resume_requests += 1;
        }
    })?;
    let mut headers = vec![("X-Accel-Buffering".to_string(), "no".to_string())];
    if let Some(last_event) = events.last().map(|event| event.id).or(last_event_id) {
        headers.push(("Last-Event-ID".to_string(), last_event.to_string()));
    }
    Ok(DashboardHttpResponse {
        status: "200 OK",
        content_type: "text/event-stream",
        headers,
        body: mcp_http_sse_body(&events),
    })
}

fn mcp_http_last_event_id(
    request: &DashboardHttpRequest,
) -> Result<Option<u64>, DashboardHttpResponse> {
    let Some(value) = request.header("last-event-id") else {
        return Ok(None);
    };
    if value.is_empty() || value.trim() != value || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(dashboard_http_text(
            "400 Bad Request",
            "Last-Event-ID must be an unsigned decimal event id\n",
        ));
    }
    value.parse::<u64>().map(Some).map_err(|_| {
        dashboard_http_text(
            "400 Bad Request",
            "Last-Event-ID must be an unsigned decimal event id\n",
        )
    })
}

fn mcp_http_sse_resume_evicted(session: &McpHttpSession, last_event_id: Option<u64>) -> bool {
    mcp_http_sse_resume_evicted_for_events(&session.sse_events, last_event_id)
}

fn mcp_http_sse_resume_evicted_for_events(
    events: &VecDeque<McpHttpSseEvent>,
    last_event_id: Option<u64>,
) -> bool {
    let Some(last_event_id) = last_event_id else {
        return false;
    };
    let Some(first_event_id) = events.front().map(|event| event.id) else {
        return false;
    };
    last_event_id.saturating_add(1) < first_event_id
}

fn mcp_http_sse_body(events: &[McpHttpSseEvent]) -> Vec<u8> {
    if events.is_empty() {
        return b": agentk no buffered events\n\n".to_vec();
    }

    let mut body = Vec::new();
    for event in events {
        body.extend_from_slice(format!("id: {}\nevent: message\n", event.id).as_bytes());
        let data = String::from_utf8_lossy(&event.data);
        if data.is_empty() {
            body.extend_from_slice(b"data:\n");
        } else {
            for line in data.lines() {
                body.extend_from_slice(b"data: ");
                body.extend_from_slice(line.as_bytes());
                body.extend_from_slice(b"\n");
            }
        }
        body.extend_from_slice(b"\n");
    }
    body
}

fn mcp_http_push_sse_event(
    events: &mut VecDeque<McpHttpSseEvent>,
    next_event_id: &mut u64,
    data: &[u8],
) -> usize {
    let id = *next_event_id;
    *next_event_id = (*next_event_id).saturating_add(1);
    events.push_back(McpHttpSseEvent {
        id,
        data: data.to_vec(),
    });
    let mut evictions = 0usize;
    while events.len() > MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION {
        events.pop_front();
        evictions += 1;
    }
    evictions
}

fn mcp_http_post_response(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
) -> Result<DashboardHttpResponse, AgentKError> {
    if !mcp_http_accepts(request, "application/json")
        || !mcp_http_accepts(request, "text/event-stream")
    {
        return Ok(dashboard_http_text(
            "406 Not Acceptable",
            "MCP HTTP POST requires Accept: application/json, text/event-stream\n",
        ));
    }
    if !request
        .header("content-type")
        .is_some_and(|value| http_media_type_matches(value, "application/json"))
    {
        return Ok(dashboard_http_text(
            "415 Unsupported Media Type",
            "MCP HTTP POST requires application/json\n",
        ));
    }
    if request.body.len() > state.max_body_bytes {
        return Ok(mcp_http_payload_too_large_response(state.max_body_bytes));
    }

    let message: serde_json::Value = match serde_json::from_slice(&request.body) {
        Ok(message) => message,
        Err(error) => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32700,
                    "message": "Parse error",
                    "data": { "detail": error.to_string() }
                }
            }))?;
            return Ok(DashboardHttpResponse {
                status: "400 Bad Request",
                content_type: "application/json",
                headers: Vec::new(),
                body,
            });
        }
    };
    if let Some(response) = mcp_http_json_rpc_shape_error(&message, &request.body, state)? {
        return Ok(response);
    }
    let method = message.get("method").and_then(|value| value.as_str());
    let is_initialize = method == Some("initialize");
    let is_notification_or_response = message.get("id").is_none();

    if is_initialize {
        if let Some(response) = mcp_http_protocol_version_error(request, None) {
            return Ok(response);
        }
        if state
            .sessions
            .lock()
            .map_err(|_| {
                AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
            })?
            .len()
            >= state.max_active_sessions
        {
            return Ok(mcp_http_too_many_sessions_response(
                state.max_active_sessions,
            ));
        }
        let session_id = mcp_http_new_session_id()?;
        let mut proxy = McpSubprocessProxy::spawn(state.proxy.clone())?;
        let response = proxy.handle_json_rpc_line(&request.body, false)?;
        let mut headers = Vec::new();
        if let Some(response) = response {
            let initialized = response.get("result").is_some();
            let protocol_version = response
                .get("result")
                .and_then(|result| result.get("protocolVersion"))
                .and_then(|value| value.as_str())
                .unwrap_or(MCP_PROTOCOL_VERSION)
                .to_string();
            let body = serde_json::to_vec(&response)?;
            if initialized {
                headers.push(("Mcp-Session-Id".to_string(), session_id.clone()));
                let mut sessions = state.sessions.lock().map_err(|_| {
                    AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
                })?;
                if sessions.len() >= state.max_active_sessions {
                    return Ok(mcp_http_too_many_sessions_response(
                        state.max_active_sessions,
                    ));
                }
                let mut session = McpHttpSession {
                    proxy,
                    protocol_version,
                    last_seen: Instant::now(),
                    next_sse_event_id: 1,
                    sse_events: VecDeque::new(),
                };
                {
                    let McpHttpSession {
                        sse_events,
                        next_sse_event_id,
                        ..
                    } = &mut session;
                    let sse_event_buffer_evictions =
                        mcp_http_push_sse_event(sse_events, next_sse_event_id, &body);
                    mcp_http_update_metrics(state, |metrics| {
                        metrics.sse_event_buffer_evictions += sse_event_buffer_evictions;
                    })?;
                }
                sessions.insert(session_id, Arc::new(Mutex::new(session)));
                mcp_http_update_metrics(state, |metrics| {
                    metrics.sessions_created += 1;
                })?;
            }
            return Ok(DashboardHttpResponse {
                status: "200 OK",
                content_type: "application/json",
                headers,
                body,
            });
        }
        return Ok(dashboard_http_text(
            "202 Accepted",
            "initialize notification accepted\n",
        ));
    }

    let Some(session_id) = request.header("mcp-session-id") else {
        return Ok(dashboard_http_text(
            "400 Bad Request",
            "Mcp-Session-Id is required after initialize\n",
        ));
    };
    if let Some(response) = mcp_http_validate_session_id(session_id) {
        return Ok(response);
    }
    let session_id = session_id.to_string();
    let session = {
        let sessions = state.sessions.lock().map_err(|_| {
            AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
        })?;
        let Some(session) = sessions.get(&session_id) else {
            return Ok(dashboard_http_text(
                "404 Not Found",
                "MCP session not found\n",
            ));
        };
        Arc::clone(session)
    };
    let mut session = mcp_http_lock_session(&session)?;
    if let Some(response) =
        mcp_http_protocol_version_error(request, Some(session.protocol_version.as_str()))
    {
        return Ok(response);
    }
    session.last_seen = Instant::now();
    let response = session.proxy.handle_json_rpc_line(&request.body, false)?;
    let response_body = response.as_ref().map(serde_json::to_vec).transpose()?;
    let mut sse_event_buffer_evictions = 0usize;
    if let Some(body) = response_body.as_deref() {
        let McpHttpSession {
            sse_events,
            next_sse_event_id,
            ..
        } = &mut *session;
        sse_event_buffer_evictions = mcp_http_push_sse_event(sse_events, next_sse_event_id, body);
    }
    mcp_http_write_session_outputs(&session_id, &session.proxy, state)?;
    drop(session);
    if sse_event_buffer_evictions > 0 {
        mcp_http_update_metrics(state, |metrics| {
            metrics.sse_event_buffer_evictions += sse_event_buffer_evictions;
        })?;
    }

    if let Some(body) = response_body {
        Ok(DashboardHttpResponse {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body,
        })
    } else if is_notification_or_response {
        Ok(DashboardHttpResponse {
            status: "202 Accepted",
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: Vec::new(),
        })
    } else {
        Ok(dashboard_http_text("202 Accepted", "accepted\n"))
    }
}

fn mcp_http_json_rpc_shape_error(
    message: &serde_json::Value,
    body: &[u8],
    state: &Arc<McpHttpGatewayState>,
) -> Result<Option<DashboardHttpResponse>, AgentKError> {
    let Some(object) = message.as_object() else {
        let detail = if message.is_array() {
            "batch requests are not supported"
        } else {
            "message must be a JSON object"
        };
        return Ok(Some(mcp_http_json_rpc_invalid_request_response(
            body, detail,
        )));
    };

    if object.get("jsonrpc") != Some(&serde_json::Value::String("2.0".to_string())) {
        return Ok(Some(mcp_http_json_rpc_invalid_request_response(
            body,
            "jsonrpc must be \"2.0\"",
        )));
    }

    if let Some(id) = object.get("id")
        && let Err(detail) = mcp_http_json_rpc_request_id(id)
    {
        mcp_http_update_metrics(state, |metrics| {
            metrics.invalid_json_rpc_id_requests += 1;
        })?;
        return Ok(Some(mcp_http_json_rpc_invalid_request_response(
            body, &detail,
        )));
    }

    if !object.get("method").is_some_and(|value| value.is_string()) {
        return Ok(Some(mcp_http_json_rpc_invalid_request_response(
            body,
            "method must be a string",
        )));
    }

    Ok(None)
}

fn mcp_http_json_rpc_request_id(id: &serde_json::Value) -> Result<serde_json::Value, String> {
    match id {
        serde_json::Value::Null => Ok(serde_json::Value::Null),
        serde_json::Value::String(value) if value.len() <= MCP_HTTP_JSON_RPC_MAX_ID_BYTES => {
            Ok(id.clone())
        }
        serde_json::Value::String(_) => Err(format!(
            "id string must be at most {MCP_HTTP_JSON_RPC_MAX_ID_BYTES} bytes"
        )),
        serde_json::Value::Number(number)
            if number.as_i64().is_some() || number.as_u64().is_some() =>
        {
            Ok(id.clone())
        }
        serde_json::Value::Number(_) => Err("id number must be an integer".to_string()),
        _ => Err("id must be a string, integer, or null".to_string()),
    }
}

fn mcp_http_json_rpc_invalid_request_response(body: &[u8], detail: &str) -> DashboardHttpResponse {
    DashboardHttpResponse {
        status: "400 Bad Request",
        content_type: "application/json",
        headers: Vec::new(),
        body: serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": mcp_http_json_rpc_error_id(body),
            "error": {
                "code": -32600,
                "message": "Invalid Request",
                "data": {
                    "detail": detail
                }
            }
        }))
        .unwrap_or_else(|_| {
            b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}\n"
                .to_vec()
        }),
    }
}

fn mcp_http_delete_response(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
) -> Result<DashboardHttpResponse, AgentKError> {
    let Some(session_id) = request.header("mcp-session-id") else {
        return Ok(dashboard_http_text(
            "400 Bad Request",
            "Mcp-Session-Id is required for DELETE\n",
        ));
    };
    if let Some(response) = mcp_http_validate_session_id(session_id) {
        return Ok(response);
    }
    let session_id = session_id.to_string();
    let Some(session) = ({
        let mut sessions = state.sessions.lock().map_err(|_| {
            AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
        })?;
        sessions.remove(&session_id)
    }) else {
        return Ok(dashboard_http_text(
            "404 Not Found",
            "MCP session not found\n",
        ));
    };
    let session_guard = mcp_http_lock_session(&session)?;
    if let Some(response) =
        mcp_http_protocol_version_error(request, Some(session_guard.protocol_version.as_str()))
    {
        drop(session_guard);
        let mut sessions = state.sessions.lock().map_err(|_| {
            AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
        })?;
        sessions.insert(session_id, session);
        return Ok(response);
    }
    mcp_http_write_session_outputs(&session_id, &session_guard.proxy, state)?;
    drop(session_guard);
    mcp_http_update_metrics(state, |metrics| {
        metrics.sessions_deleted += 1;
    })?;
    Ok(DashboardHttpResponse {
        status: "202 Accepted",
        content_type: "text/plain; charset=utf-8",
        headers: Vec::new(),
        body: Vec::new(),
    })
}

fn mcp_http_write_session_outputs(
    session_id: &str,
    proxy: &McpSubprocessProxy,
    state: &Arc<McpHttpGatewayState>,
) -> Result<(), AgentKError> {
    if let Some(path) = &state.trace_out {
        write_events_jsonl(
            proxy.events(),
            mcp_gateway_named_session_path(path, session_id),
        )?;
    }
    if let Some(path) = &state.session_report_out {
        write_mcp_session_report_json(
            &proxy.session_report(),
            mcp_gateway_named_session_path(path, session_id),
        )?;
    }
    Ok(())
}

fn mcp_gateway_named_session_path(path: &Path, session_id: &str) -> PathBuf {
    let suffix = session_id.chars().take(12).collect::<String>();
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.with_extension(format!("session-{suffix}"));
    };
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return path.with_file_name(format!("{file_name}.session-{suffix}"));
    };
    path.with_file_name(format!("{stem}.session-{suffix}.{extension}"))
}

fn mcp_http_new_session_id() -> Result<String, AgentKError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        AgentKError::InvalidMcpRequest(format!("failed to generate MCP session id: {error}"))
    })?;
    Ok(hex::encode(bytes))
}

fn mcp_http_allowed_origins_from_env(
    mut allow_origins: Vec<String>,
    allow_origin_env: &str,
) -> Result<Vec<String>, AgentKError> {
    if !is_safe_env_name(allow_origin_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "allow-origin-env must be a safe environment variable name".to_string(),
        ));
    }
    for origin in &allow_origins {
        mcp_http_validate_configured_origin(origin)?;
    }
    if let Ok(value) = env::var(allow_origin_env) {
        allow_origins.extend(mcp_http_parse_allow_origin_env(&value)?);
    }
    Ok(allow_origins)
}

fn mcp_http_parse_allow_origin_env(value: &str) -> Result<Vec<String>, AgentKError> {
    let mut origins = Vec::new();
    for origin in value
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
    {
        mcp_http_validate_configured_origin(origin)?;
        origins.push(origin.to_string());
    }
    Ok(origins)
}

fn mcp_http_validate_configured_origin(origin: &str) -> Result<(), AgentKError> {
    if !mcp_http_is_valid_configured_origin(origin) {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP allowed origins must be clean scheme://authority values or null".to_string(),
        ));
    }
    Ok(())
}

fn mcp_http_cors_origin(
    request: &DashboardHttpRequest,
    allow_origins: &[String],
) -> Option<String> {
    let origin = request.header("origin")?.trim();
    if allow_origins.iter().any(|allowed| allowed == origin)
        || (mcp_http_is_builtin_local_origin(origin)
            && mcp_http_request_host_allows_builtin_origin(request))
    {
        return Some(origin.to_string());
    }
    None
}

fn mcp_http_is_builtin_local_origin(origin: &str) -> bool {
    mcp_http_origin_matches_http_host(origin, "127.0.0.1")
        || mcp_http_origin_matches_http_host(origin, "localhost")
        || mcp_http_origin_matches_http_host(origin, "[::1]")
}

fn mcp_http_origin_matches_http_host(origin: &str, host: &str) -> bool {
    let prefix = format!("http://{host}");
    if origin == prefix {
        return true;
    }
    origin
        .strip_prefix(&format!("{prefix}:"))
        .is_some_and(mcp_http_is_valid_port)
}

fn mcp_http_request_host_allows_builtin_origin(request: &DashboardHttpRequest) -> bool {
    request
        .header("host")
        .is_none_or(mcp_http_is_local_authority)
}

fn mcp_http_is_local_authority(authority: &str) -> bool {
    if !is_valid_http_authority(authority) {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _suffix)) = rest.split_once(']') else {
            return false;
        };
        return host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback());
    }
    let host = authority
        .rsplit_once(':')
        .map(|(host, _port)| host)
        .unwrap_or(authority);
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback())
}

fn mcp_http_is_valid_configured_origin(origin: &str) -> bool {
    if origin == "null" {
        return true;
    }
    if origin.is_empty()
        || origin.trim() != origin
        || origin == "*"
        || origin
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b',')
    {
        return false;
    }
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    is_valid_origin_scheme(scheme) && is_valid_origin_authority(authority)
}

fn is_valid_origin_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn is_valid_origin_authority(authority: &str) -> bool {
    is_valid_http_authority(authority)
}

fn is_valid_http_authority(authority: &str) -> bool {
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return false;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        if !host
            .parse::<IpAddr>()
            .is_ok_and(|addr| matches!(addr, IpAddr::V6(_)))
        {
            return false;
        }
        return suffix.is_empty() || suffix.strip_prefix(':').is_some_and(mcp_http_is_valid_port);
    }

    if authority.contains('[') || authority.contains(']') {
        return false;
    }
    if authority.contains('*') || authority.bytes().filter(|byte| *byte == b':').count() > 1 {
        return false;
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        return mcp_http_is_valid_host_name(host) && mcp_http_is_valid_port(port);
    }
    mcp_http_is_valid_host_name(authority)
}

fn mcp_http_is_valid_host_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }

    host.split('.').all(mcp_http_is_valid_dns_label)
}

fn mcp_http_is_valid_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn mcp_http_is_valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn mcp_http_origin_allowed(request: &DashboardHttpRequest, allow_origins: &[String]) -> bool {
    if request.header("origin").is_none() {
        return true;
    }
    mcp_http_cors_origin(request, allow_origins).is_some()
}

fn mcp_http_auth_allowed(request: &DashboardHttpRequest, auth_token: Option<&str>) -> bool {
    let Some(auth_token) = auth_token else {
        return true;
    };
    if request.header("authorization").is_some() && request.header("x-agentk-mcp-token").is_some() {
        return false;
    }
    mcp_http_token_from_request(request)
        .is_some_and(|value| constant_time_token_eq(value, auth_token))
}

fn mcp_http_token_from_request(request: &DashboardHttpRequest) -> Option<&str> {
    if let Some(value) = request.header("authorization")
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return Some(token);
    }
    request.header("x-agentk-mcp-token")
}

fn mcp_http_accepts(request: &DashboardHttpRequest, expected: &str) -> bool {
    request.header("accept").is_some_and(|value| {
        value
            .split(',')
            .any(|part| http_media_type_matches(part, expected))
    })
}

fn http_media_type_matches(value: &str, expected: &str) -> bool {
    value
        .trim()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case(expected)
}

fn mcp_gateway_session_path(path: &std::path::Path, max_sessions: usize, index: usize) -> PathBuf {
    if max_sessions <= 1 {
        return path.to_path_buf();
    }

    let ordinal = index + 1;
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.with_extension(format!("session-{ordinal}"));
    };
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return path.with_file_name(format!("{file_name}.session-{ordinal}"));
    };
    path.with_file_name(format!("{stem}.session-{ordinal}.{extension}"))
}

fn mcp_proxy_stdio_with_io<R, W>(
    config: McpSubprocessProxyConfig,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
    reader: R,
    writer: W,
) -> Result<(), AgentKError>
where
    R: BufRead,
    W: Write,
{
    if trace_out.is_some() || session_report_out.is_some() {
        let mut proxy = McpSubprocessProxy::spawn(config)?;
        let stream_result = proxy.proxy_json_stream(reader, writer);
        let trace_result = match trace_out {
            Some(path) => write_events_jsonl(proxy.events(), path).map(|_| ()),
            None => Ok(()),
        };
        let session_report_result = match session_report_out {
            Some(path) => write_mcp_session_report_json(&proxy.session_report(), path),
            None => Ok(()),
        };

        stream_result?;
        trace_result?;
        session_report_result?;
        return Ok(());
    }

    mcp_subprocess_proxy_json_stream(reader, writer, config)
}

fn write_mcp_session_report_json(
    report: &agentk::McpSubprocessProxySessionReport,
    path: PathBuf,
) -> Result<(), AgentKError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(report)?)?;
    Ok(())
}

fn collect_mcp_proxy_allowed_env<F>(
    names: &[String],
    mut lookup: F,
) -> Result<BTreeMap<String, String>, AgentKError>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut env = BTreeMap::new();
    for name in names {
        if !is_safe_env_name(name) {
            return Err(AgentKError::InvalidMcpRequest(
                "allowed env names must match [A-Za-z_][A-Za-z0-9_]*".to_string(),
            ));
        }
        let value = lookup(name).ok_or_else(|| {
            AgentKError::InvalidMcpRequest(format!(
                "allowed env var {name} is not present or is not valid UTF-8"
            ))
        })?;
        env.insert(name.clone(), value);
    }

    Ok(env)
}

fn is_safe_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn sidecar_init(out: PathBuf, force: bool, json: bool) -> Result<(), AgentKError> {
    let report = init_sidecar_bundle(&out, force)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK team sidecar bundle created");
    println!("root      {}", report.root.display());
    println!("files     {}", report.files.len());
    for file in &report.files {
        println!("  {}", file.display());
    }
    println!();
    println!("next      edit clients/* and point your MCP client at AgentK");
    println!(
        "review    agentk trace-inspect {}",
        report
            .root
            .join(".agentk/runs/team-sidecar.jsonl")
            .display()
    );
    Ok(())
}

fn sidecar_check(root: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = check_sidecar_bundle(&root)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK team sidecar check");
        println!("root      {}", report.root.display());
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar bundle preflight failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_run(root: PathBuf) -> Result<(), AgentKError> {
    let config = sidecar_run_config(&root, |name| env::var(name).ok())?;
    let session_report_out = mcp_session_report_path(&config.trace_out);
    let stdin = io::stdin();
    let stdout = io::stdout();
    mcp_proxy_stdio_with_io(
        config.proxy,
        Some(config.trace_out),
        Some(session_report_out),
        BufReader::new(stdin.lock()),
        stdout.lock(),
    )
}

fn sidecar_serve_tcp(
    root: PathBuf,
    host: String,
    port: u16,
    max_sessions: usize,
    max_concurrent_sessions: usize,
) -> Result<(), AgentKError> {
    let config = sidecar_run_config(&root, |name| env::var(name).ok())?;
    let session_report_out = mcp_session_report_path(&config.trace_out);
    mcp_proxy_tcp_with_config(
        config.proxy,
        host,
        port,
        max_sessions,
        max_concurrent_sessions,
        Some(config.trace_out),
        Some(session_report_out),
    )
}

#[allow(clippy::too_many_arguments)]
fn sidecar_serve_http(
    root: PathBuf,
    host: String,
    port: u16,
    endpoint: String,
    max_requests: usize,
    max_concurrent_requests: usize,
    max_active_sessions: usize,
    session_idle_timeout_ms: u64,
    max_body_bytes: usize,
    max_header_bytes: usize,
    stream_timeout_ms: u64,
    allow_origins: Vec<String>,
    allow_origin_env: String,
    allow_non_local_bind: bool,
    trust_proxy_headers: bool,
    auth_token_env: String,
) -> Result<(), AgentKError> {
    if !is_safe_env_name(&auth_token_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "auth-token-env must be a safe environment variable name".to_string(),
        ));
    }
    let allow_origins = mcp_http_allowed_origins_from_env(allow_origins, &allow_origin_env)?;
    let config = sidecar_run_config(&root, |name| env::var(name).ok())?;
    let session_report_out = mcp_session_report_path(&config.trace_out);
    let auth_token = env::var(&auth_token_env)
        .ok()
        .filter(|value| !value.is_empty());
    mcp_proxy_http_with_config(McpHttpGatewayConfig {
        proxy: config.proxy,
        host,
        port,
        endpoint,
        max_requests,
        max_concurrent_requests,
        max_active_sessions,
        session_idle_timeout: Duration::from_millis(session_idle_timeout_ms),
        max_body_bytes,
        max_header_bytes,
        stream_timeout: Duration::from_millis(stream_timeout_ms),
        allow_origins,
        auth_token,
        allow_non_local_bind,
        trust_proxy_headers,
        trace_out: Some(config.trace_out),
        session_report_out: Some(session_report_out),
    })
}

fn mcp_session_report_path(trace_out: &std::path::Path) -> PathBuf {
    let Some(file_name) = trace_out.file_name().and_then(|name| name.to_str()) else {
        return trace_out.with_extension("session.json");
    };
    if let Some(stem) = file_name.strip_suffix(".jsonl") {
        return trace_out.with_file_name(format!("{stem}.session.json"));
    }
    trace_out.with_extension("session.json")
}

fn sidecar_package(
    root: PathBuf,
    out: PathBuf,
    archive_out: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = package_sidecar_bundle(&root, &out, force)?;
    let archive_report = archive_out
        .as_ref()
        .map(|archive| archive_sidecar_package(&report.package, archive, force))
        .transpose()?;

    if json {
        if let Some(archive) = &archive_report {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "package": report,
                    "archive": archive,
                }))?
            );
        } else {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        return Ok(());
    }

    println!("AgentK team sidecar package created");
    println!("root      {}", report.root.display());
    println!("package   {}", report.package.display());
    if let Some(archive) = &archive_report {
        println!("archive   {}", archive.archive.display());
        println!("checksum  {}", archive.checksum.display());
        println!("archive-sha {}", archive.sha256);
    }
    println!("files     {}", report.files.len());
    for file in &report.files {
        println!("  {}", file.display());
    }
    println!();
    println!(
        "client    {}",
        report
            .package
            .join("clients/claude-desktop.mcp.json")
            .display()
    );
    println!(
        "manifest  {}",
        report.package.join("manifest.json").display()
    );
    println!(
        "lock      {}",
        report.package.join("package.lock.json").display()
    );
    println!(
        "launch    {}",
        report.package.join("bin/agentk-sidecar").display()
    );
    println!(
        "tcp       {}",
        report.package.join("bin/agentk-sidecar-tcp").display()
    );
    println!(
        "http      {}",
        report.package.join("bin/agentk-sidecar-http").display()
    );
    println!(
        "dashboard {}",
        report.package.join("bin/agentk-dashboard").display()
    );
    println!(
        "serve     {}",
        report.package.join("bin/agentk-dashboard-server").display()
    );
    println!(
        "export    {}",
        report.package.join("bin/agentk-store-export").display()
    );
    println!(
        "check     {}",
        report.package.join("bin/agentk-store-check").display()
    );
    println!(
        "push      {}",
        report.package.join("bin/agentk-store-push").display()
    );
    println!(
        "slack     {}",
        report.package.join("bin/agentk-store-slack").display()
    );
    println!(
        "slack-send {}",
        report.package.join("bin/agentk-store-slack-send").display()
    );
    println!(
        "github    {}",
        report.package.join("bin/agentk-store-github").display()
    );
    println!(
        "github-send {}",
        report
            .package
            .join("bin/agentk-store-github-send")
            .display()
    );
    println!(
        "email     {}",
        report.package.join("bin/agentk-store-email").display()
    );
    println!(
        "email-send {}",
        report.package.join("bin/agentk-store-email-send").display()
    );
    Ok(())
}

fn sidecar_package_check(root: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = check_sidecar_package(&root)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK team sidecar package check");
        println!("root      {}", report.root.display());
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package preflight failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_http_handoff_check(root: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = check_sidecar_package_http_handoff(&root)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK team sidecar HTTP/SSE handoff check");
        println!("root      {}", report.root.display());
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package HTTP/SSE handoff check failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_team_handoff_check(root: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = check_sidecar_package_team_handoff(&root)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK team sidecar approval/audit handoff check");
        println!("root      {}", report.root.display());
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package team approval/audit handoff check failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_ops_handoff(
    root: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir = out.unwrap_or_else(|| {
        root.join("sidecar")
            .join(".agentk")
            .join("operator-handoff")
    });
    let report = write_sidecar_package_ops_handoff(&root, &output_dir)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK local/team operator handoff");
        println!("root      {}", report.root.display());
        println!("out       {}", report.output_dir.display());
        println!("json      {}", report.json_path.display());
        println!("markdown  {}", report.markdown_path.display());
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package operator handoff failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_doctor(
    root: PathBuf,
    out: Option<PathBuf>,
    release_manifest: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir = out.unwrap_or_else(|| root.join("sidecar").join(".agentk").join("doctor"));
    let report = write_sidecar_package_doctor(&root, &output_dir, release_manifest.as_deref())?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar doctor");
        println!("root      {}", report.root.display());
        println!("out       {}", report.output_dir.display());
        println!("json      {}", report.json_path.display());
        println!("markdown  {}", report.markdown_path.display());
        if let Some(release_manifest) = &report.release_manifest_path {
            println!("release   {}", release_manifest.display());
        }
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
        if !report.remediation_steps.is_empty() {
            println!("remediation");
            for step in &report.remediation_steps {
                println!("- {step}");
            }
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package doctor found blocking issues".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_support_bundle(
    root: PathBuf,
    out: Option<PathBuf>,
    release_manifest: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir =
        out.unwrap_or_else(|| root.join("sidecar").join(".agentk").join("support-bundle"));
    let report =
        write_sidecar_package_support_bundle(&root, &output_dir, release_manifest.as_deref())?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar support bundle");
        println!("root      {}", report.root.display());
        println!("out       {}", report.output_dir.display());
        println!("json      {}", report.json_path.display());
        println!("markdown  {}", report.markdown_path.display());
        if let Some(release_manifest) = &report.release_manifest_path {
            println!("release   {}", release_manifest.display());
        }
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
        println!("artifacts {}", report.artifacts.len());
        if !report.remediation_steps.is_empty() {
            println!("remediation");
            for step in &report.remediation_steps {
                println!("- {step}");
            }
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package support bundle found blocking issues".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_deploy_handoff(
    root: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir =
        out.unwrap_or_else(|| root.join("sidecar").join(".agentk").join("deploy-handoff"));
    let report = write_sidecar_package_deploy_handoff(&root, &output_dir)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar deploy handoff");
        println!("root      {}", report.root.display());
        println!("out       {}", report.output_dir.display());
        println!("json      {}", report.json_path.display());
        println!("markdown  {}", report.markdown_path.display());
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package deploy handoff failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_demo_handoff(
    root: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir =
        out.unwrap_or_else(|| root.join("sidecar").join(".agentk").join("demo-handoff"));
    let report = write_sidecar_package_demo_handoff(&root, &output_dir)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar demo handoff");
        println!("root      {}", report.root.display());
        println!("out       {}", report.output_dir.display());
        println!("json      {}", report.json_path.display());
        println!("markdown  {}", report.markdown_path.display());
        println!("trace     {}", report.trace_path.display());
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package demo handoff failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_quickstart(
    root: PathBuf,
    out: Option<PathBuf>,
    release_manifest: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir = out.unwrap_or_else(|| root.join("sidecar").join(".agentk").join("quickstart"));
    let report = write_sidecar_package_quickstart(&root, &output_dir, release_manifest.as_deref())?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar quickstart");
        println!("root      {}", report.root.display());
        println!("out       {}", report.output_dir.display());
        println!("json      {}", report.json_path.display());
        println!("markdown  {}", report.markdown_path.display());
        if let Some(release_manifest) = &report.release_manifest_path {
            println!("release   {}", release_manifest.display());
        }
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
        if !report.remediation_steps.is_empty() {
            println!("remediation");
            for step in &report.remediation_steps {
                println!("- {step}");
            }
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package quickstart failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_permissions_handoff(
    root: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir = out.unwrap_or_else(|| {
        root.join("sidecar")
            .join(".agentk")
            .join("permissions-handoff")
    });
    let report = write_sidecar_package_permissions_handoff(&root, &output_dir)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar permissions handoff");
        println!("root        {}", report.root.display());
        println!("out         {}", report.output_dir.display());
        println!("json        {}", report.json_path.display());
        println!("markdown    {}", report.markdown_path.display());
        println!("permissions {}", report.permissions_path.display());
        println!("identity    {}", report.identity_path.display());
        println!("reviewer    {}", report.authorized_reviewer);
        println!(
            "verdict     {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package permissions handoff failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_production_preflight(
    root: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir = out.unwrap_or_else(|| {
        root.join("sidecar")
            .join(".agentk")
            .join("production-preflight")
    });
    let report = write_sidecar_package_production_preflight(&root, &output_dir)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar production preflight");
        println!("root          {}", report.root.display());
        println!("out           {}", report.output_dir.display());
        println!("json          {}", report.json_path.display());
        println!("markdown      {}", report.markdown_path.display());
        println!("secrets       {}", report.secrets_path.display());
        println!("env templates {}", report.env_templates);
        println!("placeholders  {}", report.placeholder_assignments);
        println!(
            "verdict       {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package production preflight failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_client_handoff(
    root: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir =
        out.unwrap_or_else(|| root.join("sidecar").join(".agentk").join("client-handoff"));
    let report = write_sidecar_package_client_handoff(&root, &output_dir)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar client handoff");
        println!("root      {}", report.root.display());
        println!("out       {}", report.output_dir.display());
        println!("json      {}", report.json_path.display());
        println!("markdown  {}", report.markdown_path.display());
        println!("snippets  {}", report.client_snippets);
        println!("launchers {}", report.launchers);
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package client handoff failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_dashboard_handoff(
    root: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let output_dir = out.unwrap_or_else(|| {
        root.join("sidecar")
            .join(".agentk")
            .join("dashboard-handoff")
    });
    let report = write_sidecar_package_dashboard_handoff(&root, &output_dir)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK sidecar dashboard handoff");
        println!("root           {}", report.root.display());
        println!("out            {}", report.output_dir.display());
        println!("json           {}", report.json_path.display());
        println!("markdown       {}", report.markdown_path.display());
        println!("dashboard      {}", report.dashboard_path.display());
        println!("team-store     {}", report.team_store_root.display());
        println!("open approvals {}", report.dashboard.open);
        println!(
            "verdict        {}",
            if report.passed { "ready" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package dashboard handoff failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_archive_check(
    archive: PathBuf,
    checksum: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = check_sidecar_package_archive(&archive, checksum)?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK team sidecar archive check");
        println!("archive  {}", report.archive.display());
        println!("checksum {}", report.checksum.display());
        println!(
            "verdict  {}",
            if report.passed { "verified" } else { "blocked" }
        );
        if let Some(actual) = &report.actual_sha256 {
            println!("sha256   {actual}");
        }
        for check in &report.checks {
            println!(
                "[{}] {:<32} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package archive check failed".to_string(),
        ));
    }

    Ok(())
}

fn sidecar_package_install(
    archive: PathBuf,
    out: PathBuf,
    checksum: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = install_sidecar_package_archive(&archive, checksum, &out, force)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK team sidecar package installed");
    println!("archive  {}", report.archive.display());
    println!("checksum {}", report.checksum.display());
    println!("package  {}", report.package.display());
    println!("files    {}", report.files);
    println!("sha256   {}", report.archive_sha256);
    println!(
        "verdict  {}",
        if report.package_check.passed {
            "ready"
        } else {
            "blocked"
        }
    );
    Ok(())
}

fn sidecar_package_release_manifest(
    package: PathBuf,
    archive: PathBuf,
    checksum: Option<PathBuf>,
    install_receipt: Option<PathBuf>,
    out: PathBuf,
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = write_sidecar_package_release_manifest(
        &package,
        &archive,
        checksum,
        install_receipt,
        &out,
        force,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK team sidecar release manifest");
    println!("manifest {}", report.output.display());
    println!("package  {}", report.package_root.display());
    println!("archive  {}", report.archive.display());
    println!("checksum {}", report.checksum.display());
    println!("receipt  {}", report.install_receipt.display());
    println!("sha256   {}", report.archive_sha256);
    println!(
        "verdict  {}",
        if report.passed { "ready" } else { "blocked" }
    );
    Ok(())
}

fn sidecar_package_release_manifest_check(
    manifest: PathBuf,
    package: Option<PathBuf>,
    archive: Option<PathBuf>,
    checksum: Option<PathBuf>,
    install_receipt: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = check_sidecar_package_release_manifest(
        &manifest,
        package,
        archive,
        checksum,
        install_receipt,
    )?;
    let failed = !report.passed;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK team sidecar release manifest check");
        println!("manifest {}", report.manifest.display());
        if let Some(package) = &report.package {
            println!("package  {}", package.display());
        }
        if let Some(archive) = &report.archive {
            println!("archive  {}", archive.display());
        }
        if let Some(checksum) = &report.checksum {
            println!("checksum {}", checksum.display());
        }
        if let Some(receipt) = &report.install_receipt {
            println!("receipt  {}", receipt.display());
        }
        if let Some(sha256) = &report.archive_sha256 {
            println!("sha256   {sha256}");
        }
        println!(
            "verdict  {}",
            if report.passed { "verified" } else { "blocked" }
        );
        for check in &report.checks {
            println!(
                "[{}] {:<40} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if failed {
        return Err(AgentKError::InvalidMcpRequest(
            "sidecar package release manifest check failed".to_string(),
        ));
    }

    Ok(())
}

fn signing_key(json: bool) -> Result<(), AgentKError> {
    let status = signing_key_status();

    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("AgentK signing key");
    println!("algorithm {}", status.algorithm);
    println!("source    {}", status.source);
    println!("public    {}", status.public_key);
    println!("ready     {}", status.production_ready);
    if let Some(warning) = status.warning {
        println!("warning   {warning}");
    }
    Ok(())
}

fn keygen(path: PathBuf, force: bool, json: bool) -> Result<(), AgentKError> {
    let generated = generate_signing_key_file(&path, force)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&generated)?);
        return Ok(());
    }

    println!("AgentK signing key generated");
    println!("path      {}", generated.path.display());
    println!("mode      {}", generated.file_mode);
    println!("algorithm {}", generated.algorithm);
    println!("public    {}", generated.public_key);
    println!(
        "env       {}={}",
        generated.env_var,
        generated.path.display()
    );
    println!("warning   keep this file outside git and out of shell history");
    Ok(())
}

fn key_rotate(
    current: PathBuf,
    next_out: PathBuf,
    manifest: PathBuf,
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = rotate_signing_key_file(current, next_out, manifest, force)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK signing key rotated");
    println!("next key  {}", report.next_key_path.display());
    println!("mode      {}", report.next_key_file_mode);
    println!("manifest  {}", report.manifest_path.display());
    println!("algorithm {}", report.manifest.algorithm);
    println!("previous  {}", report.manifest.previous_public_key);
    println!("next      {}", report.manifest.next_public_key);
    println!("signature {}", report.manifest.signature);
    println!("warning   keep private key files outside git; manifest contains public data only");
    Ok(())
}

fn key_rotate_verify(manifest: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = verify_signing_key_rotation_manifest_file(manifest)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK key rotation manifest verification");
    println!("manifest  {}", report.manifest_path.display());
    println!("ok        {}", report.ok);
    println!("reason    {}", report.reason);
    println!("algorithm {}", report.algorithm);
    println!("previous  {}", report.previous_public_key);
    println!("next      {}", report.next_public_key);

    if !report.ok {
        std::process::exit(2);
    }

    Ok(())
}

fn policy_check(path: PathBuf) -> Result<(), AgentKError> {
    let policy = Policy::from_path(&path)?;
    println!("AgentK policy verified");
    println!("agent     {}", policy.agent.id);
    println!("rules     {}", policy.rules.len());
    println!("labels    {}", policy.labels.len());
    Ok(())
}

fn secret_refs_check(manifest: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = secret_reference_manifest_report_from_path(manifest)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK secret refs verified");
    println!("version   {}", report.version);
    println!("secrets   {}", report.secret_count);
    println!("providers {}", report.provider_count);
    println!(
        "external  {} production provider refs shape-checked",
        report.production_provider_ref_count
    );
    println!(
        "shapes    {} provider-specific refs shape-checked",
        report.shape_checked_ref_count
    );
    println!("redacted  provider refs were not printed");
    Ok(())
}

fn secret_refs_store_check(manifest: PathBuf, json: bool) -> Result<(), AgentKError> {
    let report = secret_reference_env_store_report_from_path(manifest)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK secret refs store check");
        println!("version     {}", report.version);
        println!("secrets     {}", report.secret_count);
        println!("stores      {}", report.store_count);
        println!("available   {}", report.available_count);
        println!("missing     {}", report.missing_count);
        println!("unsupported {}", report.unsupported_provider_count);
        println!("redacted    provider refs were not printed");
    }

    if !report.all_available() {
        std::process::exit(2);
    }

    Ok(())
}

fn readiness(json: bool) -> Result<(), AgentKError> {
    let report = readiness_report(".");

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK public-readiness gate");
    for check in &report.checks {
        println!("[{}] {:<24} {}", check.status, check.name, check.detail);
    }
    println!();
    println!(
        "verdict   {}",
        if report.ready {
            "no blocking failures"
        } else {
            "not ready"
        }
    );

    if !report.ready {
        std::process::exit(2);
    }

    if report
        .checks
        .iter()
        .any(|check| check.status == ReadinessStatus::Warn)
    {
        println!("note      warnings still need human review before release or merge");
    }

    Ok(())
}

fn release_audit(json: bool, strict: bool) -> Result<(), AgentKError> {
    let report = release_audit_report(".");
    let has_warnings = report
        .checks
        .iter()
        .any(|check| check.status == ReadinessStatus::Warn);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.passed || (strict && has_warnings) {
            std::process::exit(2);
        }
        return Ok(());
    }

    println!("AgentK release audit");
    println!("mode      {}", if strict { "strict" } else { "standard" });
    println!("root      {}", report.root.display());
    for check in &report.checks {
        println!("[{}] {:<30} {}", check.status, check.name, check.detail);
    }
    println!();
    println!(
        "verdict   {}",
        if report.passed && !(strict && has_warnings) {
            "no blocking failures"
        } else {
            "not ready"
        }
    );

    if has_warnings {
        println!("note      warnings still need human review before release or merge");
    }

    if strict && has_warnings {
        println!("strict    warnings are treated as blockers");
    }

    if !report.passed || (strict && has_warnings) {
        std::process::exit(2);
    }

    Ok(())
}

fn release_status(json: bool) -> Result<(), AgentKError> {
    let report = alpha_release_status_report(".");

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.ready_for_alpha_rc {
            std::process::exit(2);
        }
        return Ok(());
    }

    println!("AgentK v0.2 alpha release train status");
    println!("release   {}", report.release);
    println!(
        "verdict   {}",
        if report.ready_for_alpha_rc {
            "alpha RC surface ready"
        } else {
            "blocked"
        }
    );
    print_alpha_release_status_section("shipped", &report.shipped_surfaces);
    print_alpha_release_status_section("gates", &report.verification_gates);
    print_alpha_release_status_section("limits", &report.accepted_limits);
    print_alpha_release_status_section("final blockers", &report.final_release_blockers);

    if !report.ready_for_alpha_rc {
        std::process::exit(2);
    }

    Ok(())
}

fn print_alpha_release_status_section(title: &str, items: &[agentk::AlphaReleaseStatusItem]) {
    println!();
    println!("{title}");
    for item in items {
        println!("[{}] {:<42} {}", item.status, item.name, item.detail);
        if !item.evidence.is_empty() {
            println!("       evidence: {}", item.evidence.join("; "));
        }
    }
}

const RELEASE_CANDIDATE_SMOKE_REQUIRED_ARTIFACTS: &[&str] = &[
    "manifest",
    "package lock",
    "package archive",
    "package archive checksum",
    "release manifest",
    "install receipt",
    "package check json",
    "http handoff check json",
    "team handoff check json",
    "onboarding guide",
    "claude client",
    "codex cursor client",
    "http sse handoff",
    "team audit dashboard handoff",
    "operator handoff json",
    "operator handoff markdown",
    "sidecar doctor json",
    "sidecar doctor markdown",
    "support bundle json",
    "support bundle markdown",
    "deploy handoff json",
    "deploy handoff markdown",
    "demo handoff json",
    "demo handoff markdown",
    "quickstart json",
    "quickstart markdown",
    "permissions handoff json",
    "permissions handoff markdown",
    "production preflight json",
    "production preflight markdown",
    "client handoff json",
    "client handoff markdown",
    "dashboard handoff json",
    "dashboard handoff markdown",
    "trace",
    "dashboard",
    "store readme",
    "postgres load",
    "team approvals",
    "slack payloads",
    "github payloads",
    "email payloads",
    "systemd sidecar service",
    "systemd dashboard service",
    "launchd sidecar plist",
    "launchd dashboard plist",
    "dockerfile",
    "docker compose",
    "caddy reverse proxy",
    "nginx reverse proxy",
    "deploy readme",
    "sidecar http env example",
    "dashboard env example",
    "store postgres env example",
    "notifications env example",
];

const RELEASE_TICKET_SMOKE_INVENTORY_ARTIFACTS: &[&str] =
    RELEASE_CANDIDATE_SMOKE_REQUIRED_ARTIFACTS;

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseCandidateSmokeReport {
    root: PathBuf,
    package: PathBuf,
    package_archive: PathBuf,
    package_archive_checksum: PathBuf,
    package_release_manifest: PathBuf,
    evidence_report: Option<PathBuf>,
    installed_package: PathBuf,
    package_archive_sha256: String,
    trace_path: PathBuf,
    dashboard_path: PathBuf,
    store_export_root: PathBuf,
    team_store_root: PathBuf,
    slack_payload_root: PathBuf,
    github_payload_root: PathBuf,
    kept_root: bool,
    passed: bool,
    steps: Vec<ReleaseCandidateSmokeStep>,
    artifacts: Vec<ReleaseCandidateSmokeArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseCandidateSmokeStep {
    name: String,
    command: Vec<String>,
    passed: bool,
    exit_code: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseCandidateSmokeArtifact {
    name: String,
    path: PathBuf,
    present: bool,
    bytes: Option<u64>,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseEvidenceCheckReport {
    evidence: PathBuf,
    reported_root: PathBuf,
    checked_root: PathBuf,
    passed: bool,
    steps_passed: usize,
    steps_total: usize,
    artifacts_verified: usize,
    artifacts_total: usize,
    missing_artifacts: usize,
    changed_artifacts: usize,
    checks: Vec<ReleaseEvidenceCheckItem>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseEvidenceCheckItem {
    name: String,
    status: ReadinessStatus,
    detail: String,
}

const RELEASE_TICKET_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
struct ReleaseTicketReport {
    schema_version: u32,
    release: String,
    output: PathBuf,
    ready: bool,
    strict: bool,
    release_status: PathBuf,
    smoke_root: PathBuf,
    smoke_evidence: PathBuf,
    finalization: PathBuf,
    ticket: PathBuf,
    artifacts: Vec<ReleaseTicketArtifact>,
    checks: Vec<ReleaseTicketCheckItem>,
    accepted_limit_checks: Vec<ReleaseTicketCheckItem>,
    status: agentk::AlphaReleaseStatusReport,
    smoke: ReleaseCandidateSmokeReport,
    evidence_check: ReleaseEvidenceCheckReport,
    finalization_report: ReleaseFinalizeReport,
}

#[derive(Debug, Serialize)]
struct ReleaseTicketArtifact {
    name: String,
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ReleaseTicketCheckItem {
    name: String,
    status: ReadinessStatus,
    detail: String,
}

const RELEASE_FINALIZE_SCHEMA_VERSION: u32 = 1;
const RELEASE_FINALIZE_DRAFT_MARKERS: &[&str] = &[
    "<commit-sha>",
    "<sha256>",
    "<command and result>",
    "<hex-public-key>",
    "v0.2.0-alpha.N",
    "<git verify-tag result>",
    "<signer identity>",
];

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseFinalizeReport {
    schema_version: u32,
    release: String,
    generated_at_unix_seconds: u64,
    output: PathBuf,
    publish_state: String,
    strict: bool,
    ready: bool,
    commit: Option<String>,
    worktree_clean: bool,
    evidence: PathBuf,
    checked_root: PathBuf,
    package_archive: PathBuf,
    package_archive_sha256: String,
    package_release_manifest: PathBuf,
    release_notes: Option<ReleaseFinalizeArtifact>,
    signer: ReleaseFinalizeSigner,
    tag: ReleaseFinalizeTag,
    checks: Vec<ReleaseFinalizeCheckItem>,
    evidence_check: ReleaseEvidenceCheckReport,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseFinalizeArtifact {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseFinalizeSigner {
    algorithm: String,
    source: String,
    public_key: String,
    production_ready: bool,
    warning: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseFinalizeTag {
    tag: Option<String>,
    verified: bool,
    detail: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReleaseFinalizeCheckItem {
    name: String,
    status: ReadinessStatus,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ReleasePublicationCheckReport {
    finalization: PathBuf,
    notes: PathBuf,
    release: String,
    tag: Option<String>,
    package_archive: PathBuf,
    package_archive_sha256: String,
    package_release_manifest: PathBuf,
    publish_state: String,
    passed: bool,
    checks: Vec<ReleasePublicationCheckItem>,
}

#[derive(Debug, Serialize)]
struct ReleasePublicationCheckItem {
    name: String,
    status: ReadinessStatus,
    detail: String,
}

#[derive(Debug)]
struct ReleaseFinalizeGitOutput {
    ok: bool,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

fn release_candidate_smoke(
    root: Option<PathBuf>,
    force: bool,
    keep_root: bool,
    evidence_out: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_release_candidate_smoke(root, force, keep_root, evidence_out)?;
    if let Some(path) = &report.evidence_report {
        write_release_candidate_smoke_evidence(&report, path, force)?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK release candidate smoke");
    println!(
        "verdict   {}",
        if report.passed { "ready" } else { "blocked" }
    );
    println!("root      {}", report.root.display());
    println!("package   {}", report.package.display());
    println!("archive   {}", report.package_archive.display());
    println!("checksum  {}", report.package_archive_checksum.display());
    println!("handoff   {}", report.package_release_manifest.display());
    if let Some(path) = &report.evidence_report {
        println!("evidence  {}", path.display());
    }
    println!("installed {}", report.installed_package.display());
    println!("archive-sha {}", report.package_archive_sha256);
    println!("trace     {}", report.trace_path.display());
    println!("dashboard {}", report.dashboard_path.display());
    println!("store     {}", report.store_export_root.display());
    println!("team      {}", report.team_store_root.display());
    println!("slack     {}", report.slack_payload_root.display());
    println!("github    {}", report.github_payload_root.display());
    println!("kept-root {}", report.kept_root);
    println!();
    for step in &report.steps {
        println!(
            "[{}] {:<24} {}",
            if step.passed { "PASS" } else { "FAIL" },
            step.name,
            step.command.join(" ")
        );
    }
    println!();
    for artifact in &report.artifacts {
        println!(
            "[{}] {:<24} {}",
            if artifact.present { "PASS" } else { "FAIL" },
            artifact.name,
            artifact.path.display()
        );
        if let (Some(bytes), Some(sha256)) = (artifact.bytes, artifact.sha256.as_deref()) {
            println!("       bytes {:<14} sha256 {}", bytes, sha256);
        }
    }

    if !report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "release candidate smoke failed".to_string(),
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn release_homebrew_formula(
    source_url: String,
    sha256: Option<String>,
    source_archive: Option<PathBuf>,
    out: PathBuf,
    version: Option<String>,
    homepage: String,
    class_name: String,
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = write_homebrew_formula(
        &source_url,
        sha256.as_deref(),
        source_archive.as_deref(),
        &out,
        version.as_deref(),
        Some(&homepage),
        Some(&class_name),
        force,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK Homebrew formula written");
    println!("out        {}", report.output.display());
    println!("class      {}", report.class_name);
    println!("name       {}", report.formula_name);
    println!("version    {}", report.version);
    println!("homepage   {}", report.homepage);
    println!("source-url {}", report.source_url);
    if let Some(source_archive) = &report.source_archive {
        println!("archive    {}", source_archive.display());
    }
    println!("sha256     {}", report.sha256);
    println!("note       formula was written locally; AgentK did not publish a tap");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn release_homebrew_formula_check(
    formula: PathBuf,
    source_archive: Option<PathBuf>,
    source_url: Option<String>,
    sha256: Option<String>,
    version: Option<String>,
    homepage: Option<String>,
    class_name: Option<String>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = check_homebrew_formula(
        &formula,
        source_archive.as_deref(),
        source_url.as_deref(),
        sha256.as_deref(),
        version.as_deref(),
        homepage.as_deref(),
        class_name.as_deref(),
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK Homebrew formula check");
        println!("formula   {}", report.formula.display());
        if let Some(source_archive) = &report.source_archive {
            println!("archive   {}", source_archive.display());
        }
        if let Some(class_name) = &report.class_name {
            println!("class     {class_name}");
        }
        if let Some(version) = &report.version {
            println!("version   {version}");
        }
        if let Some(source_url) = &report.source_url {
            println!("source-url {source_url}");
        }
        if let Some(sha256) = &report.sha256 {
            println!("sha256    {sha256}");
        }
        println!(
            "verdict   {}",
            if report.passed { "verified" } else { "blocked" }
        );
        println!("note      formula was checked locally; AgentK did not publish a tap");
        for check in &report.checks {
            println!(
                "[{}] {:<36} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if !report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "Homebrew formula check failed".to_string(),
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn release_homebrew_tap_handoff_check(
    formula: PathBuf,
    tap_root: PathBuf,
    tap_formula_path: String,
    source_archive: Option<PathBuf>,
    source_url: Option<String>,
    sha256: Option<String>,
    version: Option<String>,
    homepage: Option<String>,
    class_name: Option<String>,
    tap: Option<String>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = check_homebrew_tap_handoff(
        &formula,
        &tap_root,
        &tap_formula_path,
        source_archive.as_deref(),
        source_url.as_deref(),
        sha256.as_deref(),
        version.as_deref(),
        homepage.as_deref(),
        class_name.as_deref(),
        tap.as_deref(),
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK Homebrew tap handoff check");
        println!("formula     {}", report.formula.display());
        println!("tap-root    {}", report.tap_root.display());
        println!("tap-formula {}", report.tap_formula.display());
        if let Some(tap) = &report.expected_tap {
            println!("tap         {tap}");
        }
        println!(
            "verdict     {}",
            if report.passed {
                "ready for maintainer review"
            } else {
                "blocked"
            }
        );
        println!("note        tap checkout was checked locally; AgentK did not publish a tap");
        if !report.dirty_paths.is_empty() {
            println!("dirty-paths {}", report.dirty_paths.join(", "));
        }
        for check in report
            .formula_check
            .checks
            .iter()
            .chain(report.checks.iter())
        {
            println!(
                "[{}] {:<40} {}",
                check.status.as_str().to_ascii_uppercase(),
                check.name,
                check.detail
            );
        }
    }

    if !report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "Homebrew tap handoff check failed".to_string(),
        ));
    }

    Ok(())
}

fn run_release_candidate_smoke(
    root: Option<PathBuf>,
    force: bool,
    keep_root: bool,
    evidence_out: Option<PathBuf>,
) -> Result<ReleaseCandidateSmokeReport, AgentKError> {
    let explicit_root = root.is_some();
    let root = root.unwrap_or_else(release_candidate_smoke_temp_root);
    let kept_root = explicit_root || keep_root;
    if let Some(path) = &evidence_out {
        if path.exists() && !force {
            return Err(AgentKError::FileExists(path.clone()));
        }
        if path.is_dir() {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "release candidate smoke evidence path is a directory: {}",
                path.display()
            )));
        }
        if path.starts_with(&root) && !kept_root {
            return Err(AgentKError::InvalidMcpRequest(
                "release candidate smoke evidence must be outside a temporary root unless --keep-root or explicit --root is used"
                    .to_string(),
            ));
        }
    }
    if root.exists() {
        if !root.is_dir() {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "release candidate smoke root {} exists but is not a directory",
                root.display()
            )));
        }
        if !force {
            return Err(AgentKError::FileExists(root));
        }
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(&root)?;

    let bundle = root.join("agentk-sidecar");
    let package = root.join("dist/agentk-sidecar");
    let package_archive = root.join("dist/agentk-sidecar.tar");
    let package_release_manifest = root.join("dist/agentk-sidecar-release-manifest.json");
    let installed_package = root.join("installed/agentk-sidecar");
    let install_receipt_path = installed_package.join("sidecar/.agentk/install-receipt.json");
    let trace_path = installed_package.join("sidecar/.agentk/runs/safe-agent-demo.jsonl");
    let decisions_path = installed_package.join("sidecar/.agentk/approvals.jsonl");
    let permissions_path = installed_package.join("sidecar/team-permissions.toml");
    let dashboard_path = installed_package.join("sidecar/.agentk/dashboard.html");
    let store_export_root = installed_package.join("sidecar/.agentk/store");
    let team_store_root = installed_package.join("sidecar/.agentk/team-store");
    let slack_payload_root = installed_package.join("sidecar/.agentk/slack");
    let github_payload_root = installed_package.join("sidecar/.agentk/github");
    let email_payload_root = installed_package.join("sidecar/.agentk/email");
    let operator_handoff_root = installed_package.join("sidecar/.agentk/operator-handoff");
    let operator_handoff_json = operator_handoff_root.join("operator-handoff.json");
    let operator_handoff_markdown = operator_handoff_root.join("operator-handoff.md");
    let doctor_root = installed_package.join("sidecar/.agentk/doctor");
    let doctor_json = doctor_root.join("sidecar-doctor.json");
    let doctor_markdown = doctor_root.join("sidecar-doctor.md");
    let support_bundle_root = installed_package.join("sidecar/.agentk/support-bundle");
    let support_bundle_json = support_bundle_root.join("support-bundle.json");
    let support_bundle_markdown = support_bundle_root.join("support-bundle.md");
    let deploy_handoff_root = installed_package.join("sidecar/.agentk/deploy-handoff");
    let deploy_handoff_json = deploy_handoff_root.join("deploy-handoff.json");
    let deploy_handoff_markdown = deploy_handoff_root.join("deploy-handoff.md");
    let demo_handoff_root = installed_package.join("sidecar/.agentk/demo-handoff");
    let demo_handoff_json = demo_handoff_root.join("demo-handoff.json");
    let demo_handoff_markdown = demo_handoff_root.join("demo-handoff.md");
    let quickstart_root = installed_package.join("sidecar/.agentk/quickstart");
    let quickstart_json = quickstart_root.join("quickstart.json");
    let quickstart_markdown = quickstart_root.join("quickstart.md");
    let permissions_handoff_root = installed_package.join("sidecar/.agentk/permissions-handoff");
    let permissions_handoff_json = permissions_handoff_root.join("permissions-handoff.json");
    let permissions_handoff_markdown = permissions_handoff_root.join("permissions-handoff.md");
    let production_preflight_root = installed_package.join("sidecar/.agentk/production-preflight");
    let production_preflight_json = production_preflight_root.join("production-preflight.json");
    let production_preflight_markdown = production_preflight_root.join("production-preflight.md");
    let client_handoff_root = installed_package.join("sidecar/.agentk/client-handoff");
    let client_handoff_json = client_handoff_root.join("client-handoff.json");
    let client_handoff_markdown = client_handoff_root.join("client-handoff.md");
    let dashboard_handoff_root = installed_package.join("sidecar/.agentk/dashboard-handoff");
    let dashboard_handoff_json = dashboard_handoff_root.join("dashboard-handoff.json");
    let dashboard_handoff_markdown = dashboard_handoff_root.join("dashboard-handoff.md");
    let release_evidence_root = installed_package.join("sidecar/.agentk/release");
    let package_check_json = release_evidence_root.join("package-check.json");
    let http_handoff_check_json = release_evidence_root.join("http-handoff-check.json");
    let team_handoff_check_json = release_evidence_root.join("team-handoff-check.json");

    init_sidecar_bundle(&bundle, false)?;
    package_sidecar_bundle(&bundle, &package, false)?;
    let package_archive_report = archive_sidecar_package(&package, &package_archive, false)?;

    let bin = installed_package.join("bin");
    let current_exe = env::current_exe()?;
    let agentk_bin = current_exe.display().to_string();
    let archive = package_archive.display().to_string();
    let archive_checksum = package_archive_report.checksum.display().to_string();
    let release_manifest = package_release_manifest.display().to_string();
    let installed = installed_package.display().to_string();
    let install_receipt = install_receipt_path.display().to_string();
    let trace = trace_path.display().to_string();
    let decisions = decisions_path.display().to_string();
    let permissions = permissions_path.display().to_string();
    let identity = installed_package
        .join("sidecar/team-identity.toml")
        .display()
        .to_string();
    let dashboard = dashboard_path.display().to_string();
    let store_export = store_export_root.display().to_string();
    let team_store = team_store_root.display().to_string();
    let slack_payloads = slack_payload_root.display().to_string();
    let github_payloads = github_payload_root.display().to_string();
    let email_payloads = email_payload_root.display().to_string();
    let operator_handoff = operator_handoff_root.display().to_string();
    let doctor = doctor_root.display().to_string();
    let support_bundle = support_bundle_root.display().to_string();
    let deploy_handoff = deploy_handoff_root.display().to_string();
    let demo_handoff = demo_handoff_root.display().to_string();
    let quickstart = quickstart_root.display().to_string();
    let permissions_handoff = permissions_handoff_root.display().to_string();
    let production_preflight = production_preflight_root.display().to_string();
    let client_handoff = client_handoff_root.display().to_string();
    let dashboard_handoff = dashboard_handoff_root.display().to_string();
    let common_env = [("AGENTK_BIN", agentk_bin.as_str())];
    let mut steps = Vec::new();

    release_candidate_smoke_step(
        &mut steps,
        "archive checksum",
        &current_exe,
        &[
            "sidecar-package-archive-check",
            "--archive",
            archive.as_str(),
            "--checksum",
            archive_checksum.as_str(),
            "--json",
        ],
        &[],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "package install",
        &current_exe,
        &[
            "sidecar-package-install",
            "--archive",
            archive.as_str(),
            "--checksum",
            archive_checksum.as_str(),
            "--out",
            installed.as_str(),
            "--json",
        ],
        &[],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "release manifest",
        &current_exe,
        &[
            "sidecar-package-release-manifest",
            "--package",
            installed.as_str(),
            "--archive",
            archive.as_str(),
            "--checksum",
            archive_checksum.as_str(),
            "--install-receipt",
            install_receipt.as_str(),
            "--out",
            release_manifest.as_str(),
            "--json",
        ],
        &[],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "release manifest check",
        &current_exe,
        &[
            "sidecar-package-release-manifest-check",
            "--manifest",
            release_manifest.as_str(),
            "--package",
            installed.as_str(),
            "--archive",
            archive.as_str(),
            "--checksum",
            archive_checksum.as_str(),
            "--install-receipt",
            install_receipt.as_str(),
            "--json",
        ],
        &[],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "package info",
        &bin.join("agentk-package-info"),
        &[],
        &[],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "package check",
        &bin.join("agentk-package-check"),
        &["--json"],
        &common_env,
    )?;
    fs::create_dir_all(&release_evidence_root)?;
    let package_check_report = check_sidecar_package(&installed_package)?;
    fs::write(
        &package_check_json,
        format!("{}\n", serde_json::to_string_pretty(&package_check_report)?),
    )?;
    if !package_check_report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "release candidate smoke package check report was blocked".to_string(),
        ));
    }
    let http_handoff_check_report = check_sidecar_package_http_handoff(&installed_package)?;
    fs::write(
        &http_handoff_check_json,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&http_handoff_check_report)?
        ),
    )?;
    if !http_handoff_check_report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "release candidate smoke HTTP handoff report was blocked".to_string(),
        ));
    }
    let team_handoff_check_report = check_sidecar_package_team_handoff(&installed_package)?;
    fs::write(
        &team_handoff_check_json,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&team_handoff_check_report)?
        ),
    )?;
    if !team_handoff_check_report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "release candidate smoke team handoff report was blocked".to_string(),
        ));
    }
    release_candidate_smoke_step(
        &mut steps,
        "HTTP handoff check",
        &bin.join("agentk-sidecar-http-handoff-check"),
        &["--json"],
        &common_env,
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "team handoff check",
        &bin.join("agentk-sidecar-team-handoff-check"),
        &["--json"],
        &common_env,
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "operator handoff",
        &bin.join("agentk-sidecar-ops-handoff"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_OPS_HANDOFF_OUT", operator_handoff.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "sidecar doctor",
        &bin.join("agentk-sidecar-doctor"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_SIDECAR_DOCTOR_OUT", doctor.as_str()),
            ("AGENTK_PACKAGE_RELEASE_MANIFEST", release_manifest.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "safe-agent demo",
        &bin.join("agentk-safe-agent-demo"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_SAFE_AGENT_DEMO_TRACE_OUT", trace.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "dashboard",
        &bin.join("agentk-dashboard"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_TRACE", trace.as_str()),
            ("AGENTK_DECISIONS", decisions.as_str()),
            ("AGENTK_PERMISSIONS", permissions.as_str()),
            ("AGENTK_DASHBOARD_OUT", dashboard.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "sidecar check",
        &bin.join("agentk-sidecar-check"),
        &["--json"],
        &common_env,
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "identity check",
        &bin.join("agentk-identity-check"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_IDENTITY", identity.as_str()),
            ("AGENTK_PERMISSIONS", permissions.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store export",
        &bin.join("agentk-store-export"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_TRACE", trace.as_str()),
            ("AGENTK_DECISIONS", decisions.as_str()),
            ("AGENTK_PERMISSIONS", permissions.as_str()),
            ("AGENTK_IDENTITY", identity.as_str()),
            ("AGENTK_STORE_EXPORT_ROOT", store_export.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store check",
        &bin.join("agentk-store-check"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_STORE_EXPORT_ROOT", store_export.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store sync",
        &bin.join("agentk-store-sync"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_TRACE", trace.as_str()),
            ("AGENTK_DECISIONS", decisions.as_str()),
            ("AGENTK_PERMISSIONS", permissions.as_str()),
            ("AGENTK_IDENTITY", identity.as_str()),
            ("AGENTK_STORE_ROOT", team_store.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store slack",
        &bin.join("agentk-store-slack"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_STORE_ROOT", team_store.as_str()),
            ("AGENTK_SLACK_OUT", slack_payloads.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store slack send dry-run",
        &bin.join("agentk-store-slack-send"),
        &["--dry-run", "--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_SLACK_OUT", slack_payloads.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store github",
        &bin.join("agentk-store-github"),
        &[
            "--repository",
            "agentk/safe-agent-demo",
            "--label",
            "agentk",
            "--label",
            "approval",
            "--json",
        ],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_STORE_ROOT", team_store.as_str()),
            ("AGENTK_GITHUB_OUT", github_payloads.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store github send dry-run",
        &bin.join("agentk-store-github-send"),
        &["--dry-run", "--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_GITHUB_OUT", github_payloads.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store email",
        &bin.join("agentk-store-email"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_STORE_ROOT", team_store.as_str()),
            ("AGENTK_EMAIL_OUT", email_payloads.as_str()),
            ("AGENTK_EMAIL_TO", "agentk-alerts@example.com"),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store email send dry-run",
        &bin.join("agentk-store-email-send"),
        &["--dry-run", "--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_EMAIL_OUT", email_payloads.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "store push dry-run",
        &bin.join("agentk-store-push"),
        &["--dry-run", "--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_STORE_EXPORT_ROOT", store_export.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "support bundle",
        &bin.join("agentk-sidecar-support-bundle"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_SUPPORT_BUNDLE_OUT", support_bundle.as_str()),
            ("AGENTK_PACKAGE_RELEASE_MANIFEST", release_manifest.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "deploy handoff",
        &bin.join("agentk-sidecar-deploy-handoff"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_DEPLOY_HANDOFF_OUT", deploy_handoff.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "demo handoff",
        &bin.join("agentk-sidecar-demo-handoff"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_DEMO_HANDOFF_OUT", demo_handoff.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "quickstart",
        &bin.join("agentk-sidecar-quickstart"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_QUICKSTART_OUT", quickstart.as_str()),
            ("AGENTK_PACKAGE_RELEASE_MANIFEST", release_manifest.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "permissions handoff",
        &bin.join("agentk-sidecar-permissions-handoff"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            (
                "AGENTK_PERMISSIONS_HANDOFF_OUT",
                permissions_handoff.as_str(),
            ),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "production preflight",
        &bin.join("agentk-sidecar-production-preflight"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            (
                "AGENTK_PRODUCTION_PREFLIGHT_OUT",
                production_preflight.as_str(),
            ),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "client handoff",
        &bin.join("agentk-sidecar-client-handoff"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_CLIENT_HANDOFF_OUT", client_handoff.as_str()),
        ],
    )?;
    release_candidate_smoke_step(
        &mut steps,
        "dashboard handoff",
        &bin.join("agentk-sidecar-dashboard-handoff"),
        &["--json"],
        &[
            ("AGENTK_BIN", agentk_bin.as_str()),
            ("AGENTK_DASHBOARD_HANDOFF_OUT", dashboard_handoff.as_str()),
        ],
    )?;

    let mut artifacts = Vec::new();
    release_candidate_smoke_artifact(
        &mut artifacts,
        "manifest",
        installed_package.join("manifest.json"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "package lock",
        installed_package.join("package.lock.json"),
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "package archive", package_archive.clone())?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "package archive checksum",
        package_archive_report.checksum.clone(),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "release manifest",
        package_release_manifest.clone(),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "install receipt",
        install_receipt_path.clone(),
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "package check json", package_check_json)?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "http handoff check json",
        http_handoff_check_json,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "team handoff check json",
        team_handoff_check_json,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "onboarding guide",
        installed_package.join("clients/onboarding.md"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "claude client",
        installed_package.join("clients/claude-desktop.mcp.json"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "codex cursor client",
        installed_package.join("clients/codex-cursor-command.txt"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "http sse handoff",
        installed_package.join("clients/http-sse-handoff.md"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "team audit dashboard handoff",
        installed_package.join("clients/team-audit-dashboard-handoff.md"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "operator handoff json",
        operator_handoff_json,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "operator handoff markdown",
        operator_handoff_markdown,
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "sidecar doctor json", doctor_json)?;
    release_candidate_smoke_artifact(&mut artifacts, "sidecar doctor markdown", doctor_markdown)?;
    release_candidate_smoke_artifact(&mut artifacts, "support bundle json", support_bundle_json)?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "support bundle markdown",
        support_bundle_markdown,
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "deploy handoff json", deploy_handoff_json)?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "deploy handoff markdown",
        deploy_handoff_markdown,
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "demo handoff json", demo_handoff_json)?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "demo handoff markdown",
        demo_handoff_markdown,
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "quickstart json", quickstart_json)?;
    release_candidate_smoke_artifact(&mut artifacts, "quickstart markdown", quickstart_markdown)?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "permissions handoff json",
        permissions_handoff_json,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "permissions handoff markdown",
        permissions_handoff_markdown,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "production preflight json",
        production_preflight_json,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "production preflight markdown",
        production_preflight_markdown,
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "client handoff json", client_handoff_json)?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "client handoff markdown",
        client_handoff_markdown,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "dashboard handoff json",
        dashboard_handoff_json,
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "dashboard handoff markdown",
        dashboard_handoff_markdown,
    )?;
    release_candidate_smoke_artifact(&mut artifacts, "trace", trace_path.clone())?;
    release_candidate_smoke_artifact(&mut artifacts, "dashboard", dashboard_path.clone())?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "store readme",
        store_export_root.join("README.md"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "postgres load",
        store_export_root.join("postgres/load.sql"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "team approvals",
        team_store_root.join("current/approvals.json"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "slack payloads",
        slack_payload_root.join("payloads.jsonl"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "github payloads",
        github_payload_root.join("payloads.jsonl"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "email payloads",
        email_payload_root.join("payloads.jsonl"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "systemd sidecar service",
        installed_package.join("deploy/systemd/agentk-sidecar-http.service"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "systemd dashboard service",
        installed_package.join("deploy/systemd/agentk-dashboard.service"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "launchd sidecar plist",
        installed_package.join("deploy/launchd/com.agentk.sidecar-http.plist"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "launchd dashboard plist",
        installed_package.join("deploy/launchd/com.agentk.dashboard.plist"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "dockerfile",
        installed_package.join("deploy/docker/Dockerfile"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "docker compose",
        installed_package.join("deploy/docker/compose.yml"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "caddy reverse proxy",
        installed_package.join("deploy/proxy/Caddyfile"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "nginx reverse proxy",
        installed_package.join("deploy/proxy/nginx.conf"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "deploy readme",
        installed_package.join("deploy/README.md"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "sidecar http env example",
        installed_package.join("deploy/env/sidecar-http.env.example"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "dashboard env example",
        installed_package.join("deploy/env/dashboard.env.example"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "store postgres env example",
        installed_package.join("deploy/env/store-postgres.env.example"),
    )?;
    release_candidate_smoke_artifact(
        &mut artifacts,
        "notifications env example",
        installed_package.join("deploy/env/notifications.env.example"),
    )?;

    if let Some(missing) = artifacts.iter().find(|artifact| !artifact.present) {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "release candidate smoke artifact is missing: {} ({})",
            missing.name,
            missing.path.display()
        )));
    }

    if !kept_root {
        fs::remove_dir_all(&root)?;
    }

    Ok(ReleaseCandidateSmokeReport {
        root,
        package,
        package_archive,
        package_archive_checksum: package_archive_report.checksum,
        package_release_manifest,
        evidence_report: evidence_out,
        installed_package,
        package_archive_sha256: package_archive_report.sha256,
        trace_path,
        dashboard_path,
        store_export_root,
        team_store_root,
        slack_payload_root,
        github_payload_root,
        kept_root,
        passed: true,
        steps,
        artifacts,
    })
}

fn release_candidate_smoke_step(
    steps: &mut Vec<ReleaseCandidateSmokeStep>,
    name: &str,
    program: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<(), AgentKError> {
    let command = std::iter::once(program.display().to_string())
        .chain(args.iter().map(|arg| (*arg).to_string()))
        .collect::<Vec<_>>();
    let mut process = std::process::Command::new(program);
    process.args(args);
    for (key, value) in envs {
        process.env(key, value);
    }
    let output = process.output()?;
    let passed = output.status.success();
    let exit_code = output.status.code();
    steps.push(ReleaseCandidateSmokeStep {
        name: name.to_string(),
        command,
        passed,
        exit_code,
    });
    if !passed {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "release candidate smoke step {name} failed: {}",
            release_candidate_smoke_output_detail(&output)
        )));
    }
    Ok(())
}

fn release_candidate_smoke_output_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no command output");
    let mut truncated = detail.chars().take(240).collect::<String>();
    if detail.chars().count() > 240 {
        truncated.push_str("...");
    }
    match output.status.code() {
        Some(code) => format!("exit {code}; {truncated}"),
        None => format!("terminated by signal; {truncated}"),
    }
}

fn release_candidate_smoke_artifact(
    artifacts: &mut Vec<ReleaseCandidateSmokeArtifact>,
    name: &str,
    path: PathBuf,
) -> Result<(), AgentKError> {
    let metadata = fs::metadata(&path)
        .ok()
        .filter(|metadata| metadata.is_file());
    let (present, bytes, sha256) = match metadata {
        Some(metadata) => (
            true,
            Some(metadata.len()),
            Some(release_candidate_smoke_file_sha256(&path)?),
        ),
        None => (false, None, None),
    };
    artifacts.push(ReleaseCandidateSmokeArtifact {
        name: name.to_string(),
        path,
        present,
        bytes,
        sha256,
    });
    Ok(())
}

fn release_candidate_smoke_file_sha256(path: &Path) -> Result<String, AgentKError> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn write_release_candidate_smoke_evidence(
    report: &ReleaseCandidateSmokeReport,
    path: &Path,
    force: bool,
) -> Result<(), AgentKError> {
    if path.exists() && !force {
        return Err(AgentKError::FileExists(path.to_path_buf()));
    }
    if path.is_dir() {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "release candidate smoke evidence path is a directory: {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(report)?)?;
    Ok(())
}

fn release_evidence_check(
    evidence: PathBuf,
    root: Option<PathBuf>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_release_evidence_check(&evidence, root)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK release evidence check");
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        println!("evidence  {}", report.evidence.display());
        println!("reported  {}", report.reported_root.display());
        println!("checked   {}", report.checked_root.display());
        println!(
            "steps     {}/{} passed",
            report.steps_passed, report.steps_total
        );
        println!(
            "artifacts {}/{} verified",
            report.artifacts_verified, report.artifacts_total
        );
        println!("missing   {}", report.missing_artifacts);
        println!("changed   {}", report.changed_artifacts);
        println!();
        for check in &report.checks {
            println!("[{}] {:<28} {}", check.status, check.name, check.detail);
        }
    }

    if !report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "release evidence check failed".to_string(),
        ));
    }

    Ok(())
}

fn release_ticket(
    release: String,
    out: PathBuf,
    notes: PathBuf,
    tag: Option<String>,
    strict: bool,
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_release_ticket(ReleaseTicketOptions {
        release,
        out,
        notes,
        tag,
        strict,
        force,
    })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK release ticket");
        println!(
            "verdict   {}",
            if report.ready {
                "ready for reviewer handoff"
            } else {
                "blocked"
            }
        );
        println!("release   {}", report.release);
        println!("out       {}", report.output.display());
        println!("status    {}", report.release_status.display());
        println!("smoke     {}", report.smoke_root.display());
        println!("evidence  {}", report.smoke_evidence.display());
        println!("finalize  {}", report.finalization.display());
        println!("ticket    {}", report.ticket.display());
        println!();
        for check in &report.checks {
            println!("[{}] {:<24} {}", check.status, check.name, check.detail);
        }
        println!();
        println!("Artifacts");
        for artifact in &report.artifacts {
            println!(
                "- {:<28} {} ({} bytes, sha256 {})",
                artifact.name,
                artifact.path.display(),
                artifact.bytes,
                artifact.sha256
            );
        }
    }

    if !report.ready {
        return Err(AgentKError::InvalidMcpRequest(
            "release ticket handoff failed".to_string(),
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn release_finalize(
    release: String,
    evidence: PathBuf,
    root: Option<PathBuf>,
    notes: PathBuf,
    tag: Option<String>,
    out: PathBuf,
    strict: bool,
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_release_finalize(ReleaseFinalizeOptions {
        release,
        evidence,
        root,
        notes,
        tag,
        out,
        strict,
        force,
    })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK release finalization handoff");
        println!(
            "verdict   {}",
            if report.ready {
                "ready for reviewer handoff"
            } else {
                "blocked"
            }
        );
        println!("release   {}", report.release);
        println!("out       {}", report.output.display());
        println!("publish   {}", report.publish_state);
        if let Some(commit) = &report.commit {
            println!("commit    {commit}");
        }
        println!("evidence  {}", report.evidence.display());
        println!("checked   {}", report.checked_root.display());
        println!("archive   {}", report.package_archive.display());
        println!("archive-sha {}", report.package_archive_sha256);
        println!("manifest  {}", report.package_release_manifest.display());
        if let Some(notes) = &report.release_notes {
            println!("notes     {}", notes.path.display());
            println!("notes-sha {}", notes.sha256);
        }
        println!(
            "signer    {} ({})",
            report.signer.source, report.signer.algorithm
        );
        if let Some(tag) = &report.tag.tag {
            println!("tag       {tag}");
        }
        println!();
        for check in &report.checks {
            println!("[{}] {:<28} {}", check.status, check.name, check.detail);
        }
    }

    if !report.ready {
        return Err(AgentKError::InvalidMcpRequest(
            "release finalization handoff failed".to_string(),
        ));
    }

    Ok(())
}

fn release_publication_check(
    finalization: &Path,
    notes: Option<&Path>,
    json: bool,
) -> Result<(), AgentKError> {
    let report = run_release_publication_check(finalization, notes)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("AgentK release publication check");
        println!(
            "verdict   {}",
            if report.passed { "ready" } else { "blocked" }
        );
        println!("release   {}", report.release);
        if let Some(tag) = &report.tag {
            println!("tag       {tag}");
        }
        println!("finalize  {}", report.finalization.display());
        println!("notes     {}", report.notes.display());
        println!("archive   {}", report.package_archive.display());
        println!("sha256    {}", report.package_archive_sha256);
        println!();
        for check in &report.checks {
            println!("[{}] {:<30} {}", check.status, check.name, check.detail);
        }
    }

    if !report.passed {
        return Err(AgentKError::InvalidMcpRequest(
            "release publication check failed".to_string(),
        ));
    }

    Ok(())
}

struct ReleaseTicketOptions {
    release: String,
    out: PathBuf,
    notes: PathBuf,
    tag: Option<String>,
    strict: bool,
    force: bool,
}

fn run_release_ticket(options: ReleaseTicketOptions) -> Result<ReleaseTicketReport, AgentKError> {
    let ReleaseTicketOptions {
        release,
        out,
        notes,
        tag,
        strict,
        force,
    } = options;

    if out.exists() {
        if !out.is_dir() {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "release ticket output path exists but is not a directory: {}",
                out.display()
            )));
        }
        if !force {
            return Err(AgentKError::FileExists(out));
        }
        fs::remove_dir_all(&out)?;
    }
    fs::create_dir_all(&out)?;

    let release_status_path = out.join("release-status.json");
    let smoke_root = out.join("release-candidate-smoke");
    let smoke_evidence = out.join("release-candidate-smoke.json");
    let finalization = out.join("release-finalization.json");
    let ticket = out.join("release-ticket.json");

    let status = alpha_release_status_report(".");
    fs::write(
        &release_status_path,
        format!("{}\n", serde_json::to_string_pretty(&status)?),
    )?;

    let smoke = run_release_candidate_smoke(
        Some(smoke_root.clone()),
        true,
        true,
        Some(smoke_evidence.clone()),
    )?;
    write_release_candidate_smoke_evidence(&smoke, &smoke_evidence, true)?;

    let evidence_check = run_release_evidence_check(&smoke_evidence, Some(smoke_root.clone()))?;
    let finalization_report = run_release_finalize(ReleaseFinalizeOptions {
        release: release.clone(),
        evidence: smoke_evidence.clone(),
        root: Some(smoke_root.clone()),
        notes,
        tag,
        out: finalization.clone(),
        strict,
        force: true,
    })?;
    let dashboard_handoff_artifacts = ["dashboard handoff json", "dashboard handoff markdown"];
    let dashboard_handoff_missing = dashboard_handoff_artifacts
        .iter()
        .filter(|name| !release_ticket_smoke_artifact_present(&smoke, name))
        .copied()
        .collect::<Vec<_>>();
    let objective_checks = release_ticket_objective_checks(&smoke);
    let install_package_check = release_ticket_install_package_provenance_check(&smoke);
    let store_notification_check = release_ticket_store_notification_handoff_check(&smoke);
    let served_dashboard_runtime_check = release_ticket_served_dashboard_runtime_check(&smoke);
    let homebrew_handoff = release_ticket_homebrew_handoff_check(&out, &release, &smoke)?;
    let quickstart_check = release_ticket_quickstart_handoff_check(&smoke);
    let support_handoff_check = release_ticket_support_doctor_handoff_check(&smoke);
    let deploy_preflight_check = release_ticket_deploy_preflight_check(&smoke);
    let accepted_limit_checks = release_ticket_accepted_limit_checks(&status);
    let accepted_limits_ready = !accepted_limit_checks.is_empty()
        && accepted_limit_checks
            .iter()
            .all(|check| check.status == ReadinessStatus::Warn);

    let mut checks = vec![
        release_ticket_check_item(
            "release status",
            if status.ready_for_alpha_rc {
                ReadinessStatus::Pass
            } else {
                ReadinessStatus::Fail
            },
            if status.ready_for_alpha_rc {
                "release-status reports alpha RC readiness"
            } else {
                "release-status reports alpha RC blockers"
            },
        ),
        release_ticket_check_item(
            "smoke evidence",
            if smoke.passed {
                ReadinessStatus::Pass
            } else {
                ReadinessStatus::Fail
            },
            format!("{} artifacts recorded", smoke.artifacts.len()),
        ),
        release_ticket_check_item(
            "evidence check",
            if evidence_check.passed {
                ReadinessStatus::Pass
            } else {
                ReadinessStatus::Fail
            },
            format!(
                "{}/{} artifacts verified",
                evidence_check.artifacts_verified, evidence_check.artifacts_total
            ),
        ),
        release_ticket_check_item(
            "dashboard handoff",
            if dashboard_handoff_missing.is_empty() {
                ReadinessStatus::Pass
            } else {
                ReadinessStatus::Fail
            },
            if dashboard_handoff_missing.is_empty() {
                "dashboard-handoff JSON/Markdown are present in release-ticket smoke evidence"
                    .to_string()
            } else {
                format!(
                    "missing dashboard handoff artifacts: {}",
                    dashboard_handoff_missing.join(", ")
                )
            },
        ),
        release_ticket_check_item(
            "finalization",
            if finalization_report.ready {
                ReadinessStatus::Pass
            } else {
                ReadinessStatus::Fail
            },
            if finalization_report.ready {
                "release-finalize wrote reviewer handoff evidence".to_string()
            } else {
                "release-finalize reported blockers".to_string()
            },
        ),
        release_ticket_check_item(
            "publish action",
            ReadinessStatus::Pass,
            "release-ticket writes local evidence only; it does not tag, push, upload, or publish",
        ),
        release_ticket_check_item(
            "accepted alpha limits",
            if accepted_limits_ready {
                ReadinessStatus::Pass
            } else {
                ReadinessStatus::Fail
            },
            if accepted_limits_ready {
                format!(
                    "{} explicit deferred-scope limits are present in release-status",
                    accepted_limit_checks.len()
                )
            } else {
                "accepted alpha limits are missing or no longer marked as explicit warnings"
                    .to_string()
            },
        ),
        install_package_check,
        store_notification_check,
        served_dashboard_runtime_check,
        homebrew_handoff.check,
        quickstart_check,
        support_handoff_check,
        deploy_preflight_check,
    ];
    checks.extend(objective_checks);
    let ready = checks
        .iter()
        .all(|check| check.status != ReadinessStatus::Fail);

    let mut artifacts = vec![
        release_ticket_artifact("release status", &release_status_path)?,
        release_ticket_artifact("smoke evidence", &smoke_evidence)?,
        release_ticket_artifact("finalization", &finalization)?,
    ];
    artifacts.extend(release_ticket_smoke_inventory_artifacts(&smoke)?);
    artifacts.extend(homebrew_handoff.artifacts);

    let report = ReleaseTicketReport {
        schema_version: RELEASE_TICKET_SCHEMA_VERSION,
        release,
        output: out,
        ready,
        strict,
        release_status: release_status_path,
        smoke_root,
        smoke_evidence,
        finalization,
        ticket: ticket.clone(),
        artifacts,
        checks,
        accepted_limit_checks,
        status,
        smoke,
        evidence_check,
        finalization_report,
    };
    fs::write(
        &ticket,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )?;

    Ok(report)
}

struct ReleaseTicketHomebrewHandoff {
    check: ReleaseTicketCheckItem,
    artifacts: Vec<ReleaseTicketArtifact>,
}

fn release_ticket_homebrew_handoff_check(
    out: &Path,
    release: &str,
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<ReleaseTicketHomebrewHandoff, AgentKError> {
    let evidence = release_ticket_homebrew_handoff_evidence(out, release, smoke)?;
    let status = if evidence
        .report
        .get("passed")
        .and_then(|value| value.as_bool())
        .unwrap_or_default()
    {
        ReadinessStatus::Pass
    } else {
        ReadinessStatus::Fail
    };
    Ok(ReleaseTicketHomebrewHandoff {
        check: release_ticket_check_item(
            "Homebrew handoff",
            status,
            "Homebrew handoff evidence proves local formula generation, archive SHA verification, tap checkout byte match, dirty-path hygiene, and no tap publication artifacts",
        ),
        artifacts: evidence.artifacts,
    })
}

struct ReleaseTicketHomebrewEvidence {
    report: serde_json::Value,
    artifacts: Vec<ReleaseTicketArtifact>,
}

fn release_ticket_homebrew_handoff_evidence(
    out: &Path,
    release: &str,
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<ReleaseTicketHomebrewEvidence, AgentKError> {
    let homebrew_root = out.join("homebrew-handoff");
    let tap_root = homebrew_root.join("homebrew-agentk");
    let tap_formula = tap_root.join("Formula/agentk.rb");
    let formula = homebrew_root.join("agentk.rb");
    fs::create_dir_all(tap_formula.parent().unwrap_or(&tap_root))?;
    release_ticket_git_init(&tap_root)?;

    let source_url =
        format!("https://github.com/Atomics-hub/agentk/archive/refs/tags/{release}.tar.gz");
    let version = release.trim_start_matches('v');
    let homepage = "https://github.com/Atomics-hub/agentk";
    let class_name = "Agentk";

    let formula_report = write_homebrew_formula(
        &source_url,
        None,
        Some(&smoke.package_archive),
        &formula,
        Some(version),
        Some(homepage),
        Some(class_name),
        true,
    )?;
    let formula_json = homebrew_root.join("formula.json");
    fs::write(
        &formula_json,
        format!("{}\n", serde_json::to_string_pretty(&formula_report)?),
    )?;

    let formula_check = check_homebrew_formula(
        &formula,
        Some(&smoke.package_archive),
        Some(&source_url),
        Some(&formula_report.sha256),
        Some(version),
        Some(homepage),
        Some(class_name),
    )?;
    let formula_check_json = homebrew_root.join("formula-check.json");
    fs::write(
        &formula_check_json,
        format!("{}\n", serde_json::to_string_pretty(&formula_check)?),
    )?;

    fs::copy(&formula, &tap_formula)?;
    let tap_check = check_homebrew_tap_handoff(
        &formula,
        &tap_root,
        "Formula/agentk.rb",
        Some(&smoke.package_archive),
        Some(&source_url),
        Some(&formula_report.sha256),
        Some(version),
        Some(homepage),
        Some(class_name),
        Some("Atomics-hub/agentk"),
    )?;
    let tap_check_json = homebrew_root.join("tap-handoff-check.json");
    fs::write(
        &tap_check_json,
        format!("{}\n", serde_json::to_string_pretty(&tap_check)?),
    )?;

    let formula_content = fs::read_to_string(&formula)?;
    for fragment in [
        "class Agentk < Formula",
        "depends_on \"rust\" => :build",
        "cargo\", \"install\"",
        "#{bin}/agentk",
    ] {
        if !formula_content.contains(fragment) {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "Homebrew formula does not prove {fragment}"
            )));
        }
    }

    let passed = formula_check.passed
        && tap_check.passed
        && tap_check
            .dirty_paths
            .iter()
            .all(|path| path == "Formula/agentk.rb");
    let dirty_paths = tap_check.dirty_paths.clone();
    let report = serde_json::json!({
        "passed": passed,
        "published_tap": false,
        "source_url": source_url,
        "source_archive": smoke.package_archive.display().to_string(),
        "package_archive_sha256": smoke.package_archive_sha256,
        "formula": formula.display().to_string(),
        "formula_report": formula_json.display().to_string(),
        "formula_check": formula_check_json.display().to_string(),
        "tap_root": tap_root.display().to_string(),
        "tap_formula": tap_formula.display().to_string(),
        "tap_handoff_check": tap_check_json.display().to_string(),
        "dirty_paths": dirty_paths,
        "formula_checks": formula_check.checks,
        "tap_checks": tap_check.checks,
    });
    let report_path = homebrew_root.join("homebrew-handoff.json");
    fs::write(
        &report_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )?;
    let artifacts = vec![
        release_ticket_artifact("Homebrew formula", &formula)?,
        release_ticket_artifact("Homebrew formula report", &formula_json)?,
        release_ticket_artifact("Homebrew formula check", &formula_check_json)?,
        release_ticket_artifact("Homebrew tap formula", &tap_formula)?,
        release_ticket_artifact("Homebrew tap handoff check", &tap_check_json)?,
        release_ticket_artifact("Homebrew handoff report", &report_path)?,
    ];
    Ok(ReleaseTicketHomebrewEvidence { report, artifacts })
}

fn release_ticket_git_init(path: &Path) -> Result<(), AgentKError> {
    fs::create_dir_all(path)?;
    let output = ProcessCommand::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(path)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AgentKError::InvalidMcpRequest(format!(
            "could not initialize local Homebrew tap checkout at {}",
            path.display()
        )))
    }
}

fn release_ticket_artifact(
    name: impl Into<String>,
    path: impl AsRef<Path>,
) -> Result<ReleaseTicketArtifact, AgentKError> {
    let path = path.as_ref();
    let metadata = fs::metadata(path)?;
    Ok(ReleaseTicketArtifact {
        name: name.into(),
        path: path.to_path_buf(),
        bytes: metadata.len(),
        sha256: release_candidate_smoke_file_sha256(path)?,
    })
}

fn release_ticket_smoke_inventory_artifacts(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<Vec<ReleaseTicketArtifact>, AgentKError> {
    release_ticket_named_smoke_inventory_artifacts(smoke, RELEASE_TICKET_SMOKE_INVENTORY_ARTIFACTS)
}

fn release_ticket_named_smoke_inventory_artifacts(
    smoke: &ReleaseCandidateSmokeReport,
    names: &[&str],
) -> Result<Vec<ReleaseTicketArtifact>, AgentKError> {
    names
        .iter()
        .map(|name| {
            let artifact = release_ticket_smoke_artifact(smoke, name).ok_or_else(|| {
                AgentKError::InvalidMcpRequest(format!(
                    "release ticket smoke artifact inventory is missing {name}"
                ))
            })?;
            Ok(ReleaseTicketArtifact {
                name: format!("smoke: {}", artifact.name),
                path: artifact.path.clone(),
                bytes: artifact.bytes.ok_or_else(|| {
                    AgentKError::InvalidMcpRequest(format!(
                        "release ticket smoke artifact inventory is missing byte count for {name}"
                    ))
                })?,
                sha256: artifact.sha256.clone().ok_or_else(|| {
                    AgentKError::InvalidMcpRequest(format!(
                        "release ticket smoke artifact inventory is missing SHA-256 for {name}"
                    ))
                })?,
            })
        })
        .collect()
}

fn release_ticket_served_dashboard_runtime_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let missing_artifacts = [
        "dashboard handoff json",
        "dashboard handoff markdown",
        "dashboard",
        "team audit dashboard handoff",
        "systemd dashboard service",
        "launchd dashboard plist",
        "dashboard env example",
    ]
    .iter()
    .filter(|name| !release_ticket_smoke_artifact_present(smoke, name))
    .copied()
    .collect::<Vec<_>>();
    if !missing_artifacts.is_empty() {
        return release_ticket_check_item(
            "served dashboard runtime",
            ReadinessStatus::Fail,
            format!(
                "missing served dashboard artifacts: {}",
                missing_artifacts.join(", ")
            ),
        );
    }

    match release_ticket_served_dashboard_runtime_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "served dashboard runtime",
            ReadinessStatus::Pass,
            "served dashboard evidence proves launcher package preflight, loopback/admin-token defaults, bounded request caps, supervisor hardening, redacted probes, and permission-checked review APIs",
        ),
        Err(detail) => {
            release_ticket_check_item("served dashboard runtime", ReadinessStatus::Fail, detail)
        }
    }
}

fn release_ticket_served_dashboard_runtime_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let report = release_ticket_json_artifact(smoke, "dashboard handoff json")?;
    release_ticket_require_bool(&report, "passed", true, "dashboard handoff json")?;
    release_ticket_require_bool(
        &report,
        "local_team_sidecar_alpha",
        true,
        "dashboard handoff json",
    )?;
    release_ticket_require_bool(&report, "hosted_saas", false, "dashboard handoff json")?;
    release_ticket_require_checks(
        &report,
        "dashboard handoff json",
        &[
            ("static dashboard artifact", "open approvals"),
            ("durable team store", "notifications"),
            ("package team handoff env", "loopback defaults"),
            ("package team handoff env", "dummy admin token"),
            ("package team handoff env", "bounded request caps"),
            ("alpha scope", "hosted SaaS is false"),
        ],
    )?;
    release_ticket_require_artifacts(
        &report,
        "dashboard handoff json",
        &[
            "dashboard server launcher",
            "dashboard env example",
            "team dashboard handoff doc",
        ],
    )?;

    let launcher = release_ticket_report_artifact_text(
        &report,
        "dashboard handoff json",
        "dashboard server launcher",
    )?;
    for fragment in [
        "agentk-package-check\" --json",
        "dashboard-serve",
        "AGENTK_DASHBOARD_HOST:-127.0.0.1",
        "AGENTK_DASHBOARD_ALLOW_NON_LOCAL_BIND",
        "--admin-token-env",
        "--stream-timeout-ms",
        "--max-body-bytes",
        "--max-header-bytes",
        "--store-root",
    ] {
        if !launcher.contains(fragment) {
            return Err(format!(
                "dashboard server launcher does not prove {fragment}"
            ));
        }
    }

    let env = release_ticket_text_artifact(smoke, "dashboard env example")?;
    for fragment in [
        "AGENTK_DASHBOARD_HOST=127.0.0.1",
        "AGENTK_DASHBOARD_ALLOW_NON_LOCAL_BIND=0",
        "AGENTK_DASHBOARD_ADMIN_TOKEN",
        "CHANGE_ME",
        "AGENTK_DASHBOARD_STREAM_TIMEOUT_MS=",
        "AGENTK_DASHBOARD_MAX_BODY_BYTES=",
        "AGENTK_DASHBOARD_MAX_HEADER_BYTES=",
        "AGENTK_STORE_ROOT=",
    ] {
        if !env.contains(fragment) {
            return Err(format!("dashboard env example does not prove {fragment}"));
        }
    }

    let systemd = release_ticket_text_artifact(smoke, "systemd dashboard service")?;
    for fragment in [
        "AgentK team dashboard server",
        "EnvironmentFile=-%h/.config/agentk/dashboard.env",
        "agentk-dashboard-server",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "UMask=0077",
    ] {
        if !systemd.contains(fragment) {
            return Err(format!(
                "systemd dashboard service does not prove {fragment}"
            ));
        }
    }

    let launchd = release_ticket_text_artifact(smoke, "launchd dashboard plist")?;
    for fragment in [
        "com.agentk.dashboard",
        "agentk-dashboard-server",
        "WorkingDirectory",
        "dashboard-server.out.log",
        "dashboard-server.err.log",
    ] {
        if !launchd.contains(fragment) {
            return Err(format!("launchd dashboard plist does not prove {fragment}"));
        }
    }

    let handoff = release_ticket_text_artifact(smoke, "team audit dashboard handoff")?;
    for fragment in [
        "/api/review",
        "/api/approve",
        "/api/deny",
        "/healthz",
        "/readyz",
        "/metrics",
        "admin token",
        "not hosted SaaS",
    ] {
        if !handoff.contains(fragment) {
            return Err(format!(
                "team audit dashboard handoff does not document {fragment}"
            ));
        }
    }

    Ok(())
}

fn release_ticket_store_notification_handoff_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let missing_artifacts = [
        "store readme",
        "postgres load",
        "team approvals",
        "slack payloads",
        "github payloads",
        "email payloads",
        "store postgres env example",
        "notifications env example",
    ]
    .iter()
    .filter(|name| !release_ticket_smoke_artifact_present(smoke, name))
    .copied()
    .collect::<Vec<_>>();
    if !missing_artifacts.is_empty() {
        return release_ticket_check_item(
            "store/notification handoff",
            ReadinessStatus::Fail,
            format!(
                "missing store/notification artifacts: {}",
                missing_artifacts.join(", ")
            ),
        );
    }

    match release_ticket_store_notification_handoff_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "store/notification handoff",
            ReadinessStatus::Pass,
            "store/notification evidence proves durable approvals, Postgres load coverage, Slack/GitHub/email redacted payloads, and local env-held bridge configuration",
        ),
        Err(detail) => {
            release_ticket_check_item("store/notification handoff", ReadinessStatus::Fail, detail)
        }
    }
}

fn release_ticket_store_notification_handoff_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let approvals = release_ticket_json_artifact(smoke, "team approvals")?;
    release_ticket_require_bool(&approvals, "signatures_ok", true, "team approvals")?;
    if approvals
        .get("events_checked")
        .and_then(|value| value.as_u64())
        .unwrap_or_default()
        < 10
    {
        return Err("team approvals does not prove trace event coverage".to_string());
    }
    if approvals
        .get("open_approvals")
        .and_then(|value| value.as_array())
        .map(|values| values.len())
        .unwrap_or_default()
        < 5
    {
        return Err("team approvals does not prove open approval inventory".to_string());
    }
    let blocked_rules = approvals
        .get("blocked_rules")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "team approvals is missing blocked_rules".to_string())?;
    for rule in [
        "tool-invoke-capability-missing",
        "tool-sensitive-input",
        "tool-tainted-input",
        "taint-sensitive-egress",
    ] {
        if blocked_rules
            .get(rule)
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
            == 0
        {
            return Err(format!("team approvals does not prove blocked rule {rule}"));
        }
    }

    let store_readme = release_ticket_text_artifact(smoke, "store readme")?;
    for fragment in [
        "Postgres",
        "redacted evidence and hashes",
        "raw tool payloads",
        "secret values",
    ] {
        if !store_readme.contains(fragment) {
            return Err(format!("store readme does not document {fragment}"));
        }
    }
    let postgres_load = release_ticket_text_artifact(smoke, "postgres load")?;
    for table in [
        "agentk_traces",
        "agentk_audit_events",
        "agentk_approval_decisions",
        "agentk_blocked_rules",
        "agentk_syscall_summary",
        "agentk_evidence_summary",
        "agentk_team_users",
        "agentk_team_roles",
        "agentk_team_user_roles",
        "agentk_team_role_scopes",
        "agentk_team_identity_mappings",
    ] {
        if !postgres_load.contains(table) {
            return Err(format!("postgres load does not cover {table}"));
        }
    }
    for name in ["store postgres env example", "notifications env example"] {
        let env = release_ticket_text_artifact(smoke, name)?;
        if !env.contains("CHANGE_ME") && !env.contains("OWNER/REPO") {
            return Err(format!(
                "{name} does not prove placeholder-only bridge config"
            ));
        }
    }

    let slack = release_ticket_jsonl_artifact(smoke, "slack payloads")?;
    release_ticket_require_jsonl_len_at_least(&slack, "slack payloads", 5)?;
    for payload in &slack {
        release_ticket_require_nested_string(
            payload,
            &["metadata", "event_type"],
            "agentk_approval_requested",
            "slack payloads",
        )?;
        release_ticket_require_nested_string(
            payload,
            &["metadata", "event_payload", "status"],
            "pending",
            "slack payloads",
        )?;
    }

    let github = release_ticket_jsonl_artifact(smoke, "github payloads")?;
    release_ticket_require_jsonl_len_at_least(&github, "github payloads", 5)?;
    for payload in &github {
        release_ticket_require_string(payload, "operation", "upsert_issue", "github payloads")?;
        release_ticket_require_string(
            payload,
            "repository",
            "agentk/safe-agent-demo",
            "github payloads",
        )?;
        release_ticket_require_nested_string(
            payload,
            &["metadata", "status"],
            "pending",
            "github payloads",
        )?;
        let body = payload
            .get("issue")
            .and_then(|issue| issue.get("body"))
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !body.contains("no raw tool payloads or secret values") {
            return Err("github payloads do not prove redacted payload disclaimer".to_string());
        }
    }

    let email = release_ticket_jsonl_artifact(smoke, "email payloads")?;
    release_ticket_require_jsonl_len_at_least(&email, "email payloads", 5)?;
    for payload in &email {
        release_ticket_require_nested_string(
            payload,
            &["metadata", "status"],
            "pending",
            "email payloads",
        )?;
        let recipients = payload
            .get("to")
            .and_then(|value| value.as_array())
            .ok_or_else(|| "email payloads are missing to recipients".to_string())?;
        if !recipients
            .iter()
            .any(|value| value.as_str() == Some("agentk-alerts@example.com"))
        {
            return Err("email payloads do not prove dummy recipient handoff".to_string());
        }
        let body = payload
            .get("body")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !body.contains("no raw tool payloads or secret values") {
            return Err("email payloads do not prove redacted payload disclaimer".to_string());
        }
    }
    Ok(())
}

fn release_ticket_install_package_provenance_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let missing_artifacts = [
        "manifest",
        "package lock",
        "package archive",
        "package archive checksum",
        "release manifest",
        "install receipt",
        "package check json",
    ]
    .iter()
    .filter(|name| !release_ticket_smoke_artifact_present(smoke, name))
    .copied()
    .collect::<Vec<_>>();
    if !missing_artifacts.is_empty() {
        return release_ticket_check_item(
            "install/package provenance",
            ReadinessStatus::Fail,
            format!(
                "missing install/package artifacts: {}",
                missing_artifacts.join(", ")
            ),
        );
    }

    match release_ticket_install_package_provenance_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "install/package provenance",
            ReadinessStatus::Pass,
            "install/package evidence proves archive checksum, release manifest binding, install receipt, package lock, launchers, client snippets, deploy templates, and package self-check",
        ),
        Err(detail) => {
            release_ticket_check_item("install/package provenance", ReadinessStatus::Fail, detail)
        }
    }
}

fn release_ticket_install_package_provenance_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let manifest = release_ticket_json_artifact(smoke, "manifest")?;
    let package_lock = release_ticket_json_artifact(smoke, "package lock")?;
    let release_manifest = release_ticket_json_artifact(smoke, "release manifest")?;
    let install_receipt = release_ticket_json_artifact(smoke, "install receipt")?;
    let package_check = release_ticket_json_artifact(smoke, "package check json")?;

    release_ticket_require_string(&manifest, "package", "agentk-team-sidecar", "manifest")?;
    release_ticket_require_array_len_at_least(&manifest, "launchers", 30, "manifest")?;
    release_ticket_require_array_len_at_least(&manifest, "client_snippets", 5, "manifest")?;
    release_ticket_require_array_len_at_least(&manifest, "deploy_templates", 8, "manifest")?;
    release_ticket_require_array_len_at_least(&manifest, "deploy_env_examples", 4, "manifest")?;
    release_ticket_require_array_len_at_least(&manifest, "storage_contracts", 1, "manifest")?;
    release_ticket_require_nested_bool(
        &manifest,
        &[
            "default_transports",
            "2",
            "sse_alpha",
            "hosted_control_plane",
        ],
        false,
        "manifest",
    )?;

    release_ticket_require_u64(&package_lock, "schema_version", 1, "package lock")?;
    release_ticket_require_array_len_at_least(&package_lock, "files", 60, "package lock")?;

    release_ticket_require_bool(&release_manifest, "passed", true, "release manifest")?;
    release_ticket_require_string(
        &release_manifest,
        "package_name",
        "agentk-team-sidecar",
        "release manifest",
    )?;
    release_ticket_require_string(
        &release_manifest,
        "hash_algorithm",
        "sha256",
        "release manifest",
    )?;
    release_ticket_require_hex_sha256(&release_manifest, "archive_sha256", "release manifest")?;
    release_ticket_require_hex_sha256(
        &release_manifest,
        "package_manifest_sha256",
        "release manifest",
    )?;
    release_ticket_require_hex_sha256(
        &release_manifest,
        "package_lock_sha256",
        "release manifest",
    )?;
    release_ticket_require_hex_sha256(
        &release_manifest,
        "install_receipt_sha256",
        "release manifest",
    )?;
    if release_manifest
        .get("installed_files")
        .and_then(|value| value.as_u64())
        .unwrap_or_default()
        < 60
    {
        return Err("release manifest does not prove installed file coverage".to_string());
    }

    release_ticket_require_string(
        &install_receipt,
        "package",
        "agentk-team-sidecar",
        "install receipt",
    )?;
    release_ticket_require_string(
        &install_receipt,
        "hash_algorithm",
        "sha256",
        "install receipt",
    )?;
    release_ticket_require_hex_sha256(&install_receipt, "archive_sha256", "install receipt")?;
    if install_receipt
        .get("archive_sha256")
        .and_then(|value| value.as_str())
        != release_manifest
            .get("archive_sha256")
            .and_then(|value| value.as_str())
    {
        return Err(
            "install receipt archive_sha256 does not match release manifest archive_sha256"
                .to_string(),
        );
    }
    if install_receipt
        .get("installed_files")
        .and_then(|value| value.as_u64())
        != release_manifest
            .get("installed_files")
            .and_then(|value| value.as_u64())
    {
        return Err(
            "install receipt installed_files does not match release manifest installed_files"
                .to_string(),
        );
    }
    let checksum = release_ticket_text_artifact(smoke, "package archive checksum")?;
    let archive_sha256 = release_manifest
        .get("archive_sha256")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "release manifest is missing archive_sha256".to_string())?;
    if !checksum.contains(archive_sha256) {
        return Err(
            "package archive checksum file does not contain release manifest archive_sha256"
                .to_string(),
        );
    }

    release_ticket_require_bool(&package_check, "passed", true, "package check json")?;
    release_ticket_require_checks(
        &package_check,
        "package check json",
        &[
            ("manifest.json", "present"),
            ("package.lock.json", "present"),
            ("bin/agentk-sidecar-quickstart", "present"),
            ("clients/onboarding.md", "present"),
            ("package manifest identity", "AgentK"),
            ("package manifest inventory", "expected launchers"),
            ("package manifest transports", "stdio, TCP JSONL"),
            ("package manifest team handoff", "local alpha contract"),
            ("package launcher modes", "executable launchers"),
            ("package launcher preflights", "runtime launchers"),
            ("package lock", "files match"),
            ("package sidecar bundle", "sidecar checks passed"),
        ],
    )?;
    Ok(())
}

fn release_ticket_quickstart_handoff_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let missing_artifacts = ["quickstart json", "quickstart markdown"]
        .iter()
        .filter(|name| !release_ticket_smoke_artifact_present(smoke, name))
        .copied()
        .collect::<Vec<_>>();
    if !missing_artifacts.is_empty() {
        return release_ticket_check_item(
            "quickstart handoff",
            ReadinessStatus::Fail,
            format!(
                "missing quickstart artifacts: {}",
                missing_artifacts.join(", ")
            ),
        );
    }

    match release_ticket_quickstart_handoff_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "quickstart handoff",
            ReadinessStatus::Pass,
            "quickstart evidence proves first-run package health, HTTP/team handoff, demo, deploy, support, permissions, preflight, client, dashboard, artifact inventory, and local non-hosted scope",
        ),
        Err(detail) => {
            release_ticket_check_item("quickstart handoff", ReadinessStatus::Fail, detail)
        }
    }
}

fn release_ticket_quickstart_handoff_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let quickstart = release_ticket_json_artifact(smoke, "quickstart json")?;

    release_ticket_require_bool(&quickstart, "passed", true, "quickstart json")?;
    release_ticket_require_bool(
        &quickstart,
        "local_team_sidecar_alpha",
        true,
        "quickstart json",
    )?;
    release_ticket_require_bool(&quickstart, "hosted_saas", false, "quickstart json")?;
    release_ticket_require_empty_array(&quickstart, "remediation_steps", "quickstart json")?;
    release_ticket_require_checks(
        &quickstart,
        "quickstart json",
        &[
            ("package preflight", "package readiness checks"),
            ("HTTP gateway handoff", "HTTP/SSE readiness checks"),
            (
                "team dashboard/store handoff",
                "dashboard/store readiness checks",
            ),
            ("safe-agent demo handoff", "demo artifacts"),
            ("deploy handoff", "deploy artifacts"),
            ("support bundle", "support artifacts"),
            ("permissions handoff", "permission artifacts"),
            ("production preflight", "production-preflight artifacts"),
            ("client handoff", "client artifacts"),
            ("dashboard handoff", "dashboard handoff artifacts"),
            (
                "quickstart artifact inventory",
                "quickstart artifacts inspected",
            ),
            ("alpha scope", "hosted SaaS is false"),
        ],
    )?;
    release_ticket_require_artifacts(
        &quickstart,
        "quickstart json",
        &[
            "demo handoff json",
            "demo handoff markdown",
            "deploy handoff json",
            "deploy handoff markdown",
            "support bundle json",
            "support bundle markdown",
            "permissions handoff json",
            "permissions handoff markdown",
            "production preflight json",
            "production preflight markdown",
            "client handoff json",
            "client handoff markdown",
            "dashboard handoff json",
            "dashboard handoff markdown",
            "operator handoff json",
            "sidecar doctor json",
            "safe-agent trace",
            "dashboard html",
            "durable approvals",
            "slack payloads",
            "github payloads",
            "email payloads",
        ],
    )?;
    for path in [
        &["package_check", "passed"][..],
        &["http_handoff_check", "passed"],
        &["team_handoff_check", "passed"],
        &["demo_handoff", "passed"],
        &["deploy_handoff", "passed"],
        &["support_bundle", "passed"],
        &["permissions_handoff", "passed"],
        &["production_preflight", "passed"],
        &["client_handoff", "passed"],
        &["dashboard_handoff", "passed"],
    ] {
        release_ticket_require_nested_bool(&quickstart, path, true, "quickstart json")?;
    }
    Ok(())
}

fn release_ticket_support_doctor_handoff_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let missing_artifacts = [
        "operator handoff json",
        "operator handoff markdown",
        "sidecar doctor json",
        "sidecar doctor markdown",
        "support bundle json",
        "support bundle markdown",
    ]
    .iter()
    .filter(|name| !release_ticket_smoke_artifact_present(smoke, name))
    .copied()
    .collect::<Vec<_>>();
    if !missing_artifacts.is_empty() {
        return release_ticket_check_item(
            "support/doctor handoff",
            ReadinessStatus::Fail,
            format!(
                "missing support/doctor artifacts: {}",
                missing_artifacts.join(", ")
            ),
        );
    }

    match release_ticket_support_doctor_handoff_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "support/doctor handoff",
            ReadinessStatus::Pass,
            "support evidence proves operator handoff refresh, sidecar doctor remediation, release-manifest binding, hashed support inventory, and local non-hosted scope",
        ),
        Err(detail) => {
            release_ticket_check_item("support/doctor handoff", ReadinessStatus::Fail, detail)
        }
    }
}

fn release_ticket_support_doctor_handoff_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let operator = release_ticket_json_artifact(smoke, "operator handoff json")?;
    let doctor = release_ticket_json_artifact(smoke, "sidecar doctor json")?;
    let support = release_ticket_json_artifact(smoke, "support bundle json")?;

    release_ticket_require_bool(&operator, "passed", true, "operator handoff json")?;
    release_ticket_require_bool(
        &operator,
        "local_team_sidecar_alpha",
        true,
        "operator handoff json",
    )?;
    release_ticket_require_bool(&operator, "hosted_saas", false, "operator handoff json")?;
    release_ticket_require_checks(
        &operator,
        "operator handoff json",
        &[
            ("safe-agent demo", "checks improved"),
            ("dashboard artifact", "open approvals"),
            ("team permissions", "reviewers"),
            ("team identity", "mappings"),
            ("durable team store", "notifications"),
            ("notification payload exports", "payloads"),
            ("alpha scope", "hosted SaaS is false"),
        ],
    )?;

    release_ticket_require_bool(&doctor, "passed", true, "sidecar doctor json")?;
    release_ticket_require_bool(
        &doctor,
        "local_team_sidecar_alpha",
        true,
        "sidecar doctor json",
    )?;
    release_ticket_require_bool(&doctor, "hosted_saas", false, "sidecar doctor json")?;
    release_ticket_require_empty_array(&doctor, "remediation_steps", "sidecar doctor json")?;
    release_ticket_require_checks(
        &doctor,
        "sidecar doctor json",
        &[
            ("package self-check", "package readiness checks"),
            ("install receipt", "installed files"),
            ("env template sanity", "no detected secrets"),
            ("MCP gateway handoff readiness", "HTTP/SSE checks"),
            ("team dashboard/store readiness", "team handoff checks"),
            (
                "operator handoff artifacts",
                "operator handoff JSON/Markdown",
            ),
            ("audit evidence retention", "notification rows"),
            ("release manifest binding", "binds archive sha256"),
            ("filesystem/demo package integrity", "trace evidence"),
            ("alpha scope", "hosted SaaS is false"),
        ],
    )?;

    release_ticket_require_bool(&support, "passed", true, "support bundle json")?;
    release_ticket_require_bool(
        &support,
        "local_team_sidecar_alpha",
        true,
        "support bundle json",
    )?;
    release_ticket_require_bool(&support, "hosted_saas", false, "support bundle json")?;
    release_ticket_require_empty_array(&support, "remediation_steps", "support bundle json")?;
    release_ticket_require_checks(
        &support,
        "support bundle json",
        &[
            ("package preflight", "package readiness checks"),
            ("operator handoff refresh", "handoff checks"),
            ("sidecar doctor", "0 remediation steps"),
            ("support artifact inventory", "support artifacts inspected"),
            ("alpha scope", "hosted SaaS is false"),
        ],
    )?;
    release_ticket_require_artifacts(
        &support,
        "support bundle json",
        &[
            "package manifest",
            "package lock",
            "release manifest",
            "operator handoff json",
            "operator handoff markdown",
            "sidecar doctor json",
            "sidecar doctor markdown",
            "safe-agent trace",
            "dashboard html",
            "store export audit",
            "durable approvals",
            "slack payloads",
            "github payloads",
            "email payloads",
        ],
    )?;
    release_ticket_require_nested_bool(
        &support,
        &["operator_handoff", "passed"],
        true,
        "support bundle json",
    )?;
    release_ticket_require_nested_bool(
        &support,
        &["doctor", "passed"],
        true,
        "support bundle json",
    )?;
    Ok(())
}

fn release_ticket_deploy_preflight_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let missing_artifacts = [
        "deploy handoff json",
        "deploy handoff markdown",
        "production preflight json",
        "production preflight markdown",
    ]
    .iter()
    .filter(|name| !release_ticket_smoke_artifact_present(smoke, name))
    .copied()
    .collect::<Vec<_>>();
    if !missing_artifacts.is_empty() {
        return release_ticket_check_item(
            "deploy/preflight handoff",
            ReadinessStatus::Fail,
            format!(
                "missing deploy/preflight artifacts: {}",
                missing_artifacts.join(", ")
            ),
        );
    }

    match release_ticket_deploy_preflight_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "deploy/preflight handoff",
            ReadinessStatus::Pass,
            "deploy/preflight evidence proves deploy templates, supervisor env examples, secret-reference placeholders, non-local bind defaults, no live secret retrieval, and local non-hosted scope",
        ),
        Err(detail) => {
            release_ticket_check_item("deploy/preflight handoff", ReadinessStatus::Fail, detail)
        }
    }
}

fn release_ticket_deploy_preflight_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let deploy = release_ticket_json_artifact(smoke, "deploy handoff json")?;
    let preflight = release_ticket_json_artifact(smoke, "production preflight json")?;

    release_ticket_require_bool(&deploy, "passed", true, "deploy handoff json")?;
    release_ticket_require_bool(
        &deploy,
        "local_team_sidecar_alpha",
        true,
        "deploy handoff json",
    )?;
    release_ticket_require_bool(&deploy, "hosted_saas", false, "deploy handoff json")?;
    release_ticket_require_checks(
        &deploy,
        "deploy handoff json",
        &[
            ("package deploy templates", "baseline hardening markers"),
            ("package deploy env examples", "required dummy values"),
            (
                "package HTTP/SSE handoff",
                "bounded HTTP/SSE alpha contract",
            ),
            ("dashboard deploy env handoff", "loopback defaults"),
            ("deploy scope", "TLS, external identity, and network policy"),
        ],
    )?;
    release_ticket_require_artifacts(
        &deploy,
        "deploy handoff json",
        &[
            "deploy/systemd/agentk-sidecar-http.service",
            "deploy/systemd/agentk-dashboard.service",
            "deploy/docker/Dockerfile",
            "deploy/docker/compose.yml",
            "deploy/proxy/Caddyfile",
            "deploy/proxy/nginx.conf",
            "deploy/env/sidecar-http.env.example",
            "deploy/env/dashboard.env.example",
            "deploy/env/store-postgres.env.example",
            "deploy/env/notifications.env.example",
        ],
    )?;

    release_ticket_require_bool(&preflight, "passed", true, "production preflight json")?;
    release_ticket_require_bool(
        &preflight,
        "local_team_sidecar_alpha",
        true,
        "production preflight json",
    )?;
    release_ticket_require_bool(
        &preflight,
        "hosted_saas",
        false,
        "production preflight json",
    )?;
    release_ticket_require_bool(
        &preflight,
        "live_secret_retrieval",
        false,
        "production preflight json",
    )?;
    release_ticket_require_bool(
        &preflight,
        "non_local_bind_defaults_disabled",
        true,
        "production preflight json",
    )?;
    if preflight
        .get("placeholder_assignments")
        .and_then(|value| value.as_u64())
        .unwrap_or_default()
        < 4
    {
        return Err("production preflight json does not prove placeholder coverage".to_string());
    }
    let secret_refs = preflight
        .get("secret_refs")
        .ok_or_else(|| "production preflight json is missing secret_refs".to_string())?;
    if secret_refs
        .get("secret_count")
        .and_then(|value| value.as_u64())
        .unwrap_or_default()
        == 0
    {
        return Err(
            "production preflight json does not prove secret-reference coverage".to_string(),
        );
    }
    release_ticket_require_checks(
        &preflight,
        "production preflight json",
        &[
            ("secret reference manifest", "values are references"),
            ("package deploy env examples", "required dummy values"),
            ("placeholder coverage", "placeholders"),
            ("non-local bind defaults", "non-local binds disabled"),
            ("live secret retrieval", "without reading secret values"),
            ("alpha scope", "hosted SaaS is false"),
        ],
    )?;
    release_ticket_require_artifacts(
        &preflight,
        "production preflight json",
        &[
            "secret reference manifest",
            "deploy/env/sidecar-http.env.example",
            "deploy/env/dashboard.env.example",
            "deploy/env/store-postgres.env.example",
            "deploy/env/notifications.env.example",
        ],
    )?;
    Ok(())
}

fn release_ticket_accepted_limit_checks(
    status: &agentk::AlphaReleaseStatusReport,
) -> Vec<ReleaseTicketCheckItem> {
    status
        .accepted_limits
        .iter()
        .map(|limit| {
            release_ticket_check_item(
                format!("accepted limit: {}", limit.name),
                limit.status,
                limit.detail.clone(),
            )
        })
        .collect()
}

fn release_ticket_objective_checks(
    smoke: &ReleaseCandidateSmokeReport,
) -> Vec<ReleaseTicketCheckItem> {
    [
        release_ticket_production_mcp_gateway_check(smoke),
        release_ticket_approvals_audit_dashboard_check(smoke),
        release_ticket_multi_user_permissions_check(smoke),
        release_ticket_claude_codex_cursor_sidecar_check(smoke),
        release_ticket_safe_agent_demo_check(smoke),
    ]
    .into_iter()
    .collect()
}

fn release_ticket_json_artifact(
    smoke: &ReleaseCandidateSmokeReport,
    name: &str,
) -> Result<serde_json::Value, String> {
    let artifact = release_ticket_smoke_artifact(smoke, name)
        .ok_or_else(|| format!("{name} artifact is missing"))?;
    let bytes = fs::read(&artifact.path).map_err(|err| {
        format!(
            "{name} could not be read at {}: {err}",
            artifact.path.display()
        )
    })?;
    serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|err| {
        format!(
            "{name} could not be parsed at {}: {err}",
            artifact.path.display()
        )
    })
}

fn release_ticket_jsonl_artifact(
    smoke: &ReleaseCandidateSmokeReport,
    name: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let artifact = release_ticket_smoke_artifact(smoke, name)
        .ok_or_else(|| format!("{name} artifact is missing"))?;
    let content = fs::read_to_string(&artifact.path).map_err(|err| {
        format!(
            "{name} could not be read as UTF-8 at {}: {err}",
            artifact.path.display()
        )
    })?;
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<serde_json::Value>(line).map_err(|err| {
                format!(
                    "{name} line {} could not be parsed at {}: {err}",
                    index + 1,
                    artifact.path.display()
                )
            })
        })
        .collect()
}

fn release_ticket_text_artifact(
    smoke: &ReleaseCandidateSmokeReport,
    name: &str,
) -> Result<String, String> {
    let artifact = release_ticket_smoke_artifact(smoke, name)
        .ok_or_else(|| format!("{name} artifact is missing"))?;
    fs::read_to_string(&artifact.path).map_err(|err| {
        format!(
            "{name} could not be read as UTF-8 at {}: {err}",
            artifact.path.display()
        )
    })
}

fn release_ticket_report_artifact_text(
    report: &serde_json::Value,
    report_label: &str,
    artifact_name: &str,
) -> Result<String, String> {
    let artifacts = report
        .get("artifacts")
        .and_then(|value| value.as_array())
        .ok_or_else(|| format!("{report_label} is missing artifacts"))?;
    let artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact.get("name").and_then(|value| value.as_str()) == Some(artifact_name)
                && artifact.get("present").and_then(|value| value.as_bool()) == Some(true)
        })
        .ok_or_else(|| {
            format!("{report_label} does not prove required artifact {artifact_name}")
        })?;
    let path = artifact
        .get("path")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("{artifact_name} is missing artifact path"))?;
    fs::read_to_string(path)
        .map_err(|err| format!("{artifact_name} could not be read as UTF-8 at {path}: {err}"))
}

fn release_ticket_require_bool(
    report: &serde_json::Value,
    field: &str,
    expected: bool,
    label: &str,
) -> Result<(), String> {
    if report.get(field).and_then(|value| value.as_bool()) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{label} does not prove {field} == {expected}"))
    }
}

fn release_ticket_require_string(
    report: &serde_json::Value,
    field: &str,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    if report.get(field).and_then(|value| value.as_str()) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{label} does not prove {field} == {expected}"))
    }
}

fn release_ticket_require_nested_string(
    report: &serde_json::Value,
    path: &[&str],
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let mut value = report;
    for field in path {
        value = if let Ok(index) = field.parse::<usize>() {
            value
                .as_array()
                .and_then(|values| values.get(index))
                .ok_or_else(|| format!("{label} is missing {}", path.join(".")))?
        } else {
            value
                .get(*field)
                .ok_or_else(|| format!("{label} is missing {}", path.join(".")))?
        };
    }
    if value.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(format!(
            "{label} does not prove {} == {expected}",
            path.join(".")
        ))
    }
}

fn release_ticket_require_u64(
    report: &serde_json::Value,
    field: &str,
    expected: u64,
    label: &str,
) -> Result<(), String> {
    if report.get(field).and_then(|value| value.as_u64()) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{label} does not prove {field} == {expected}"))
    }
}

fn release_ticket_require_array_len_at_least(
    report: &serde_json::Value,
    field: &str,
    min_len: usize,
    label: &str,
) -> Result<(), String> {
    match report.get(field).and_then(|value| value.as_array()) {
        Some(values) if values.len() >= min_len => Ok(()),
        Some(values) => Err(format!(
            "{label} reports {} entries in {field}, expected at least {min_len}",
            values.len()
        )),
        None => Err(format!("{label} is missing array {field}")),
    }
}

fn release_ticket_require_jsonl_len_at_least(
    values: &[serde_json::Value],
    label: &str,
    min_len: usize,
) -> Result<(), String> {
    if values.len() >= min_len {
        Ok(())
    } else {
        Err(format!(
            "{label} reports {} JSONL entries, expected at least {min_len}",
            values.len()
        ))
    }
}

fn release_ticket_require_hex_sha256(
    report: &serde_json::Value,
    field: &str,
    label: &str,
) -> Result<(), String> {
    let value = report
        .get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("{label} is missing {field}"))?;
    if value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "{label} does not prove {field} is a SHA-256 hex digest"
        ))
    }
}

fn release_ticket_require_nested_bool(
    report: &serde_json::Value,
    path: &[&str],
    expected: bool,
    label: &str,
) -> Result<(), String> {
    let mut value = report;
    for field in path {
        value = if let Ok(index) = field.parse::<usize>() {
            value
                .as_array()
                .and_then(|values| values.get(index))
                .ok_or_else(|| format!("{label} is missing {}", path.join(".")))?
        } else {
            value
                .get(*field)
                .ok_or_else(|| format!("{label} is missing {}", path.join(".")))?
        };
    }
    if value.as_bool() == Some(expected) {
        Ok(())
    } else {
        Err(format!(
            "{label} does not prove {} == {expected}",
            path.join(".")
        ))
    }
}

fn release_ticket_require_empty_array(
    report: &serde_json::Value,
    field: &str,
    label: &str,
) -> Result<(), String> {
    match report.get(field).and_then(|value| value.as_array()) {
        Some(values) if values.is_empty() => Ok(()),
        Some(values) => Err(format!(
            "{label} reports {} non-empty entries in {field}",
            values.len()
        )),
        None => Err(format!("{label} is missing array {field}")),
    }
}

fn release_ticket_require_checks(
    report: &serde_json::Value,
    label: &str,
    required: &[(&str, &str)],
) -> Result<(), String> {
    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .ok_or_else(|| format!("{label} is missing checks"))?;
    for (name, detail_fragment) in required {
        let passed = checks.iter().any(|check| {
            check.get("name").and_then(|value| value.as_str()) == Some(*name)
                && matches!(
                    check.get("status").and_then(|value| value.as_str()),
                    Some("pass" | "warn")
                )
                && check
                    .get("detail")
                    .and_then(|value| value.as_str())
                    .is_some_and(|detail| detail.contains(detail_fragment))
        });
        if !passed {
            return Err(format!("{label} does not prove {name}: {detail_fragment}"));
        }
    }
    Ok(())
}

fn release_ticket_require_artifacts(
    report: &serde_json::Value,
    label: &str,
    required: &[&str],
) -> Result<(), String> {
    let artifacts = report
        .get("artifacts")
        .and_then(|value| value.as_array())
        .ok_or_else(|| format!("{label} is missing artifacts"))?;
    for name in required {
        let present = artifacts.iter().any(|artifact| {
            artifact.get("name").and_then(|value| value.as_str()) == Some(*name)
                && artifact.get("present").and_then(|value| value.as_bool()) == Some(true)
        });
        if !present {
            return Err(format!("{label} does not prove required artifact {name}"));
        }
    }
    Ok(())
}

fn release_ticket_claude_codex_cursor_sidecar_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let base_check = release_ticket_objective_check(
        smoke,
        "objective: Claude/Codex/Cursor sidecar",
        &["client handoff", "package check"],
        &[
            "claude client",
            "codex cursor client",
            "client handoff json",
            "client handoff markdown",
            "http sse handoff",
        ],
        "client snippets, package check, and client handoff are release-ticket evidence",
    );
    if base_check.status != ReadinessStatus::Pass {
        return base_check;
    }

    match release_ticket_claude_codex_cursor_sidecar_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "objective: Claude/Codex/Cursor sidecar",
            ReadinessStatus::Pass,
            "Claude/Codex/Cursor sidecar evidence proves packaged Claude JSON, Codex/Cursor command, stdio/TCP/HTTP launchers, Streamable HTTP handoff, client artifact inventory, and local non-hosted scope",
        ),
        Err(detail) => release_ticket_check_item(
            "objective: Claude/Codex/Cursor sidecar",
            ReadinessStatus::Fail,
            detail,
        ),
    }
}

fn release_ticket_claude_codex_cursor_sidecar_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let client_handoff = release_ticket_smoke_artifact(smoke, "client handoff json")
        .ok_or_else(|| "client handoff json artifact is missing".to_string())?;
    let bytes = fs::read(&client_handoff.path).map_err(|err| {
        format!(
            "client handoff json could not be read at {}: {err}",
            client_handoff.path.display()
        )
    })?;
    let report = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|err| {
        format!(
            "client handoff json could not be parsed at {}: {err}",
            client_handoff.path.display()
        )
    })?;
    if report.get("passed").and_then(|value| value.as_bool()) != Some(true) {
        return Err("client handoff json does not report passed".into());
    }
    if report
        .get("local_team_sidecar_alpha")
        .and_then(|value| value.as_bool())
        != Some(true)
        || report.get("hosted_saas").and_then(|value| value.as_bool()) != Some(false)
    {
        return Err("client handoff json does not prove local/team non-hosted scope".into());
    }
    if report
        .get("client_snippets")
        .and_then(|value| value.as_u64())
        .unwrap_or_default()
        < 5
        || report
            .get("launchers")
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
            < 3
        || report
            .get("http_handoff_check")
            .and_then(|value| value.get("passed"))
            .and_then(|value| value.as_bool())
            != Some(true)
    {
        return Err("client handoff json does not prove client snippets, launchers, and HTTP handoff readiness".into());
    }

    let artifact_names = report
        .get("artifacts")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "client handoff json is missing artifacts".to_string())?;
    for artifact_name in [
        "clients/onboarding.md",
        "clients/claude-desktop.mcp.json",
        "clients/codex-cursor-command.txt",
        "clients/http-sse-handoff.md",
        "clients/team-audit-dashboard-handoff.md",
        "bin/agentk-sidecar",
        "bin/agentk-sidecar-tcp",
        "bin/agentk-sidecar-http",
    ] {
        let present = artifact_names.iter().any(|artifact| {
            artifact.get("name").and_then(|value| value.as_str()) == Some(artifact_name)
                && artifact.get("present").and_then(|value| value.as_bool()) == Some(true)
        });
        if !present {
            return Err(format!(
                "client handoff json does not prove required artifact {artifact_name}"
            ));
        }
    }

    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "client handoff json is missing checks".to_string())?;
    for (name, detail_fragment) in [
        ("Claude Desktop MCP client", "bin/agentk-sidecar"),
        ("Codex/Cursor MCP command", "review commands"),
        (
            "package HTTP/SSE handoff",
            "bounded HTTP/SSE alpha contract",
        ),
        ("Streamable HTTP handoff", "HTTP/SSE handoff checks"),
        ("stdio launcher", "Claude, Codex, and Cursor stdio launcher"),
        (
            "TCP and HTTP launchers",
            "Streamable HTTP launchers are packaged",
        ),
        ("alpha scope", "hosted SaaS is false"),
    ] {
        let passed = checks.iter().any(|check| {
            check.get("name").and_then(|value| value.as_str()) == Some(name)
                && check.get("status").and_then(|value| value.as_str()) == Some("pass")
                && check
                    .get("detail")
                    .and_then(|value| value.as_str())
                    .is_some_and(|detail| detail.contains(detail_fragment))
        });
        if !passed {
            return Err(format!(
                "client handoff json does not prove {name}: {detail_fragment}"
            ));
        }
    }
    Ok(())
}

fn release_ticket_multi_user_permissions_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let base_check = release_ticket_objective_check(
        smoke,
        "objective: multi-user permissions",
        &["identity check", "permissions handoff"],
        &[
            "permissions handoff json",
            "permissions handoff markdown",
            "team audit dashboard handoff",
        ],
        "identity check, permissions handoff, and team audit handoff are release-ticket evidence",
    );
    if base_check.status != ReadinessStatus::Pass {
        return base_check;
    }

    match release_ticket_multi_user_permissions_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "objective: multi-user permissions",
            ReadinessStatus::Pass,
            "multi-user permissions evidence proves reviewer roles, identity mapping coverage, reviewer-scoped reads, authorized approval recording, unauthorized reviewer rejection, and local non-hosted scope",
        ),
        Err(detail) => release_ticket_check_item(
            "objective: multi-user permissions",
            ReadinessStatus::Fail,
            detail,
        ),
    }
}

fn release_ticket_multi_user_permissions_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let permissions_handoff = release_ticket_smoke_artifact(smoke, "permissions handoff json")
        .ok_or_else(|| "permissions handoff json artifact is missing".to_string())?;
    let bytes = fs::read(&permissions_handoff.path).map_err(|err| {
        format!(
            "permissions handoff json could not be read at {}: {err}",
            permissions_handoff.path.display()
        )
    })?;
    let report = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|err| {
        format!(
            "permissions handoff json could not be parsed at {}: {err}",
            permissions_handoff.path.display()
        )
    })?;
    if report.get("passed").and_then(|value| value.as_bool()) != Some(true) {
        return Err("permissions handoff json does not report passed".into());
    }
    if report
        .get("local_team_sidecar_alpha")
        .and_then(|value| value.as_bool())
        != Some(true)
        || report.get("hosted_saas").and_then(|value| value.as_bool()) != Some(false)
    {
        return Err("permissions handoff json does not prove local/team non-hosted scope".into());
    }
    if report
        .get("authorized_decision_recorded")
        .and_then(|value| value.as_bool())
        != Some(true)
        || report
            .get("unauthorized_reviewer_rejected")
            .and_then(|value| value.as_bool())
            != Some(true)
    {
        return Err(
            "permissions handoff json does not prove authorized allow and unauthorized deny paths"
                .into(),
        );
    }
    let open = report
        .get("open_approvals")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let scoped = report
        .get("scoped_open_approvals")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    if open == 0 || scoped != open {
        return Err(
            "permissions handoff json does not prove reviewer-scoped approval reads".into(),
        );
    }

    let permissions = report
        .get("permissions")
        .ok_or_else(|| "permissions handoff json is missing permissions summary".to_string())?;
    if permissions
        .get("users")
        .and_then(|value| value.as_u64())
        .unwrap_or_default()
        == 0
        || permissions
            .get("roles")
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
            == 0
        || permissions
            .get("reviewers")
            .and_then(|value| value.as_array())
            .is_none_or(|reviewers| reviewers.is_empty())
    {
        return Err("permissions handoff json does not prove users, roles, and reviewers".into());
    }
    let identity = report
        .get("identity")
        .ok_or_else(|| "permissions handoff json is missing identity summary".to_string())?;
    let permission_reviewers = identity
        .get("permission_reviewers")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let covered_reviewers = identity
        .get("covered_permission_reviewers")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    if permission_reviewers == 0 || covered_reviewers != permission_reviewers {
        return Err(
            "permissions handoff json does not prove identity coverage for permission reviewers"
                .into(),
        );
    }

    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "permissions handoff json is missing checks".to_string())?;
    for (name, detail_fragment) in [
        ("reviewer roles", "reviewers"),
        ("identity mapping coverage", "mapped reviewers"),
        ("reviewer-scoped read", "approvals visible"),
        ("authorized approve path", "recorded an approval decision"),
        (
            "unauthorized reviewer rejection",
            "rejected before appending",
        ),
        ("alpha scope", "live IdP auth are false"),
    ] {
        let passed = checks.iter().any(|check| {
            check.get("name").and_then(|value| value.as_str()) == Some(name)
                && check.get("status").and_then(|value| value.as_str()) == Some("pass")
                && check
                    .get("detail")
                    .and_then(|value| value.as_str())
                    .is_some_and(|detail| detail.contains(detail_fragment))
        });
        if !passed {
            return Err(format!(
                "permissions handoff json does not prove {name}: {detail_fragment}"
            ));
        }
    }
    Ok(())
}

fn release_ticket_approvals_audit_dashboard_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let base_check = release_ticket_objective_check(
        smoke,
        "objective: approvals/audit dashboard",
        &["dashboard", "dashboard handoff"],
        &[
            "dashboard",
            "dashboard handoff json",
            "dashboard handoff markdown",
            "team approvals",
            "systemd dashboard service",
            "dashboard env example",
        ],
        "dashboard render, dashboard handoff, service template, and env example are release-ticket evidence",
    );
    if base_check.status != ReadinessStatus::Pass {
        return base_check;
    }

    match release_ticket_approvals_audit_dashboard_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "objective: approvals/audit dashboard",
            ReadinessStatus::Pass,
            "approvals/audit dashboard evidence proves static dashboard readiness, reviewer-scoped team store, open approval inventory, dashboard env handoff, and local non-hosted scope",
        ),
        Err(detail) => release_ticket_check_item(
            "objective: approvals/audit dashboard",
            ReadinessStatus::Fail,
            detail,
        ),
    }
}

fn release_ticket_approvals_audit_dashboard_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let dashboard_handoff = release_ticket_smoke_artifact(smoke, "dashboard handoff json")
        .ok_or_else(|| "dashboard handoff json artifact is missing".to_string())?;
    let bytes = fs::read(&dashboard_handoff.path).map_err(|err| {
        format!(
            "dashboard handoff json could not be read at {}: {err}",
            dashboard_handoff.path.display()
        )
    })?;
    let report = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|err| {
        format!(
            "dashboard handoff json could not be parsed at {}: {err}",
            dashboard_handoff.path.display()
        )
    })?;
    if report.get("passed").and_then(|value| value.as_bool()) != Some(true) {
        return Err("dashboard handoff json does not report passed".into());
    }
    if report
        .get("local_team_sidecar_alpha")
        .and_then(|value| value.as_bool())
        != Some(true)
        || report.get("hosted_saas").and_then(|value| value.as_bool()) != Some(false)
    {
        return Err("dashboard handoff json does not prove local/team non-hosted scope".into());
    }

    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "dashboard handoff json is missing checks".to_string())?;
    for (name, detail_fragment) in [
        ("team dashboard/store readiness", "team handoff checks"),
        ("safe-agent demo trace", "checks improved"),
        ("static dashboard artifact", "open approvals"),
        ("durable team store", "notifications"),
        ("package team handoff env", "dashboard env example"),
        ("alpha scope", "hosted SaaS is false"),
    ] {
        let passed = checks.iter().any(|check| {
            check.get("name").and_then(|value| value.as_str()) == Some(name)
                && check.get("status").and_then(|value| value.as_str()) == Some("pass")
                && check
                    .get("detail")
                    .and_then(|value| value.as_str())
                    .is_some_and(|detail| detail.contains(detail_fragment))
        });
        if !passed {
            return Err(format!(
                "dashboard handoff json does not prove {name}: {detail_fragment}"
            ));
        }
    }

    let dashboard = report
        .get("dashboard")
        .ok_or_else(|| "dashboard handoff json is missing dashboard summary".to_string())?;
    let open = dashboard
        .get("open")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let evidence_refs = dashboard
        .get("evidence_refs")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let reviewers = dashboard
        .get("reviewers")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    if open == 0 || evidence_refs == 0 || reviewers == 0 {
        return Err(
            "dashboard handoff json does not prove open approvals, evidence refs, and reviewers"
                .into(),
        );
    }
    let store_sync = report
        .get("store_sync")
        .ok_or_else(|| "dashboard handoff json is missing store_sync".to_string())?;
    if store_sync
        .get("open")
        .and_then(|value| value.as_u64())
        .unwrap_or_default()
        == 0
        || store_sync
            .get("notifications")
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
            == 0
    {
        return Err(
            "dashboard handoff json does not prove durable team store approvals and notifications"
                .into(),
        );
    }
    Ok(())
}

fn release_ticket_production_mcp_gateway_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let base_check = release_ticket_objective_check(
        smoke,
        "objective: production MCP gateway",
        &[
            "HTTP handoff check",
            "production preflight",
            "deploy handoff",
        ],
        &[
            "http handoff check json",
            "http sse handoff",
            "sidecar http env example",
            "systemd sidecar service",
            "docker compose",
            "caddy reverse proxy",
            "nginx reverse proxy",
        ],
        "MCP HTTP gateway handoff, deploy templates, env example, and reverse-proxy artifacts are release-ticket evidence",
    );
    if base_check.status != ReadinessStatus::Pass {
        return base_check;
    }

    match release_ticket_production_mcp_gateway_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "objective: production MCP gateway",
            ReadinessStatus::Pass,
            "production MCP gateway evidence proves loopback defaults, auth-token env handoff, bounded Streamable HTTP/SSE replay, Last-Event-ID resume, no hosted control plane, and client docs",
        ),
        Err(detail) => release_ticket_check_item(
            "objective: production MCP gateway",
            ReadinessStatus::Fail,
            detail,
        ),
    }
}

fn release_ticket_production_mcp_gateway_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let http_handoff = release_ticket_smoke_artifact(smoke, "http handoff check json")
        .ok_or_else(|| "http handoff check json artifact is missing".to_string())?;
    let bytes = fs::read(&http_handoff.path).map_err(|err| {
        format!(
            "http handoff check json could not be read at {}: {err}",
            http_handoff.path.display()
        )
    })?;
    let report = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|err| {
        format!(
            "http handoff check json could not be parsed at {}: {err}",
            http_handoff.path.display()
        )
    })?;
    if report.get("passed").and_then(|value| value.as_bool()) != Some(true) {
        return Err("http handoff check json does not report passed".into());
    }

    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "http handoff check json is missing checks".to_string())?;
    for (name, detail_fragment) in [
        ("package HTTP/SSE manifest", "bounded SSE alpha contract"),
        ("package HTTP/SSE launcher", "bounded local env controls"),
        ("package HTTP/SSE env", "loopback defaults"),
        (
            "package HTTP/SSE handoff",
            "bounded HTTP/SSE alpha contract",
        ),
        ("package HTTP/SSE README", "bounded HTTP/SSE handoff"),
    ] {
        let passed = checks.iter().any(|check| {
            check.get("name").and_then(|value| value.as_str()) == Some(name)
                && check.get("status").and_then(|value| value.as_str()) == Some("pass")
                && check
                    .get("detail")
                    .and_then(|value| value.as_str())
                    .is_some_and(|detail| detail.contains(detail_fragment))
        });
        if !passed {
            return Err(format!(
                "http handoff check json does not prove {name}: {detail_fragment}"
            ));
        }
    }
    Ok(())
}

fn release_ticket_safe_agent_demo_check(
    smoke: &ReleaseCandidateSmokeReport,
) -> ReleaseTicketCheckItem {
    let base_check = release_ticket_objective_check(
        smoke,
        "objective: safe-agent demo",
        &["safe-agent demo", "demo handoff", "store sync"],
        &[
            "trace",
            "demo handoff json",
            "demo handoff markdown",
            "team approvals",
            "slack payloads",
            "github payloads",
            "postgres load",
        ],
        "safe-agent demo filesystem evidence, trace, handoff, store, notification, and Postgres artifacts are release-ticket evidence",
    );
    if base_check.status != ReadinessStatus::Pass {
        return base_check;
    }

    match release_ticket_safe_agent_demo_filesystem_evidence(smoke) {
        Ok(()) => release_ticket_check_item(
            "objective: safe-agent demo",
            ReadinessStatus::Pass,
            "safe-agent demo proves GitHub/Postgres/Slack/filesystem evidence, including allowed filesystem read and blocked filesystem patch",
        ),
        Err(detail) => {
            release_ticket_check_item("objective: safe-agent demo", ReadinessStatus::Fail, detail)
        }
    }
}

fn release_ticket_safe_agent_demo_filesystem_evidence(
    smoke: &ReleaseCandidateSmokeReport,
) -> Result<(), String> {
    let demo_handoff = release_ticket_smoke_artifact(smoke, "demo handoff json")
        .ok_or_else(|| "demo handoff json artifact is missing".to_string())?;
    let bytes = fs::read(&demo_handoff.path).map_err(|err| {
        format!(
            "demo handoff json could not be read at {}: {err}",
            demo_handoff.path.display()
        )
    })?;
    let report = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|err| {
        format!(
            "demo handoff json could not be parsed at {}: {err}",
            demo_handoff.path.display()
        )
    })?;
    let demo = report
        .get("safe_agent_demo")
        .or_else(|| {
            report
                .get("operator_handoff")
                .and_then(|handoff| handoff.get("safe_agent_demo"))
        })
        .ok_or_else(|| "demo handoff json is missing safe_agent_demo".to_string())?;
    let scenario = demo
        .get("scenario")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if !scenario.contains("GitHub/Postgres/Slack/filesystem") {
        return Err(
            "safe-agent demo scenario does not name GitHub/Postgres/Slack/filesystem".into(),
        );
    }
    let agentk = demo
        .get("agentk")
        .ok_or_else(|| "safe-agent demo is missing agentk mode evidence".to_string())?;
    let patch_executed = agentk
        .get("filesystem_patch_executed")
        .and_then(|value| value.as_bool());
    if patch_executed != Some(false) {
        return Err("safe-agent demo does not prove AgentK blocked filesystem patch".into());
    }
    let allowed_actions = agentk
        .get("allowed_read_or_draft_actions")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    if allowed_actions < 4 {
        return Err("safe-agent demo does not prove filesystem read plus GitHub/Postgres/Slack draft/read actions".into());
    }
    let scorecard_blocks_patch = demo
        .get("scorecard")
        .and_then(|value| value.as_array())
        .is_some_and(|checks| {
            checks.iter().any(|check| {
                check.get("check").and_then(|value| value.as_str())
                    == Some("Filesystem patch is blocked")
                    && check.get("improved").and_then(|value| value.as_bool()) == Some(true)
            })
        });
    if !scorecard_blocks_patch {
        return Err(
            "safe-agent demo scorecard does not prove filesystem patch blocking improved".into(),
        );
    }
    Ok(())
}

fn release_ticket_objective_check(
    smoke: &ReleaseCandidateSmokeReport,
    name: &str,
    steps: &[&str],
    artifacts: &[&str],
    pass_detail: &str,
) -> ReleaseTicketCheckItem {
    let missing_steps = steps
        .iter()
        .filter(|name| !release_ticket_smoke_step_passed(smoke, name))
        .copied()
        .collect::<Vec<_>>();
    let missing_artifacts = artifacts
        .iter()
        .filter(|name| !release_ticket_smoke_artifact_present(smoke, name))
        .copied()
        .collect::<Vec<_>>();
    let status = if missing_steps.is_empty() && missing_artifacts.is_empty() {
        ReadinessStatus::Pass
    } else {
        ReadinessStatus::Fail
    };
    let detail = if status == ReadinessStatus::Pass {
        pass_detail.to_string()
    } else {
        let mut missing = Vec::new();
        if !missing_steps.is_empty() {
            missing.push(format!("missing steps: {}", missing_steps.join(", ")));
        }
        if !missing_artifacts.is_empty() {
            missing.push(format!(
                "missing artifacts: {}",
                missing_artifacts.join(", ")
            ));
        }
        missing.join("; ")
    };
    release_ticket_check_item(name, status, detail)
}

fn release_ticket_smoke_step_passed(smoke: &ReleaseCandidateSmokeReport, name: &str) -> bool {
    smoke
        .steps
        .iter()
        .any(|step| step.name == name && step.passed)
}

fn release_ticket_smoke_artifact_present(smoke: &ReleaseCandidateSmokeReport, name: &str) -> bool {
    release_ticket_smoke_artifact(smoke, name).is_some()
}

fn release_ticket_smoke_artifact<'a>(
    smoke: &'a ReleaseCandidateSmokeReport,
    name: &str,
) -> Option<&'a ReleaseCandidateSmokeArtifact> {
    smoke
        .artifacts
        .iter()
        .find(|artifact| artifact.name == name && artifact.present)
}

fn release_ticket_check_item(
    name: impl Into<String>,
    status: ReadinessStatus,
    detail: impl Into<String>,
) -> ReleaseTicketCheckItem {
    ReleaseTicketCheckItem {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

struct ReleaseFinalizeOptions {
    release: String,
    evidence: PathBuf,
    root: Option<PathBuf>,
    notes: PathBuf,
    tag: Option<String>,
    out: PathBuf,
    strict: bool,
    force: bool,
}

fn run_release_finalize(
    options: ReleaseFinalizeOptions,
) -> Result<ReleaseFinalizeReport, AgentKError> {
    run_release_finalize_with(options, signing_key_status(), |args| {
        release_finalize_git(args)
    })
}

fn run_release_finalize_with<F>(
    options: ReleaseFinalizeOptions,
    signer_status: agentk::SigningKeyStatus,
    mut git: F,
) -> Result<ReleaseFinalizeReport, AgentKError>
where
    F: FnMut(&[&str]) -> Result<ReleaseFinalizeGitOutput, AgentKError>,
{
    let ReleaseFinalizeOptions {
        release,
        evidence,
        root,
        notes,
        tag,
        out,
        strict,
        force,
    } = options;

    if out.exists() {
        if out.is_dir() {
            return Err(AgentKError::InvalidMcpRequest(format!(
                "release finalization output path is a directory: {}",
                out.display()
            )));
        }
        if !force {
            return Err(AgentKError::FileExists(out));
        }
    }

    let evidence_check = run_release_evidence_check(&evidence, root)?;
    let smoke = read_release_candidate_smoke_report(&evidence)?;
    let checked_root = evidence_check.checked_root.clone();
    let package_archive =
        release_evidence_rebased_path(&smoke.package_archive, &smoke.root, &checked_root);
    let package_release_manifest =
        release_evidence_rebased_path(&smoke.package_release_manifest, &smoke.root, &checked_root);
    let release_notes = release_finalize_artifact(&notes).transpose()?;
    let notes_content = fs::read_to_string(&notes).ok();
    let notes_draft_markers = notes_content
        .as_deref()
        .map(release_finalize_draft_markers)
        .unwrap_or_default();
    let notes_required_markers_ok = notes_content.as_deref().is_some_and(|content| {
        content.contains("Final Release Evidence")
            && content.contains("Package archive SHA-256")
            && content.contains("Signed tag verification")
            && content.contains("AgentK evidence signing public key")
    });

    let commit_output = git(&["rev-parse", "HEAD"])?;
    let commit = commit_output
        .ok
        .then(|| commit_output.stdout.trim().to_string())
        .filter(|value| release_finalize_valid_commit(value));

    let status_output = git(&["status", "--short"])?;
    let worktree_clean = status_output.ok && status_output.stdout.trim().is_empty();

    let tag_report = match tag.as_deref() {
        Some(tag_name) => {
            let verify = git(&["verify-tag", tag_name])?;
            ReleaseFinalizeTag {
                tag: Some(tag_name.to_string()),
                verified: verify.ok,
                detail: if verify.ok {
                    release_finalize_command_detail(&verify, "signed tag verified")
                } else {
                    release_finalize_command_detail(&verify, "signed tag verification failed")
                },
            }
        }
        None => ReleaseFinalizeTag {
            tag: None,
            verified: false,
            detail: "no tag supplied; pass --tag after creating the signed release tag".to_string(),
        },
    };

    let signer = ReleaseFinalizeSigner {
        algorithm: signer_status.algorithm,
        source: signer_status.source.to_string(),
        public_key: signer_status.public_key,
        production_ready: signer_status.production_ready,
        warning: signer_status.warning,
    };

    let mut checks = Vec::new();
    checks.push(release_finalize_check_item(
        "evidence check",
        if evidence_check.passed {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        format!(
            "{}/{} artifacts verified, {}/{} smoke steps passed",
            evidence_check.artifacts_verified,
            evidence_check.artifacts_total,
            evidence_check.steps_passed,
            evidence_check.steps_total
        ),
    ));
    checks.push(release_finalize_check_item(
        "package archive hash",
        if release_evidence_valid_sha256(&smoke.package_archive_sha256) {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        format!("archive sha256 {}", smoke.package_archive_sha256),
    ));
    checks.push(release_finalize_check_item(
        "release notes file",
        if release_notes.is_some() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        release_notes
            .as_ref()
            .map(|artifact| format!("{} bytes, sha256 {}", artifact.bytes, artifact.sha256))
            .unwrap_or_else(|| format!("{} could not be read", notes.display())),
    ));
    checks.push(release_finalize_check_item(
        "release notes markers",
        if notes_required_markers_ok {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        "release notes include final evidence fields for archive hash, signer, and signed tag",
    ));
    checks.push(release_finalize_check_item(
        "release notes final values",
        if notes_draft_markers.is_empty() {
            ReadinessStatus::Pass
        } else {
            release_finalize_review_status(strict)
        },
        if notes_draft_markers.is_empty() {
            "release notes do not contain final-evidence placeholders".to_string()
        } else {
            format!(
                "release notes still contain draft markers: {}",
                notes_draft_markers.join(", ")
            )
        },
    ));
    checks.push(release_finalize_check_item(
        "git commit",
        if commit.is_some() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        commit
            .as_deref()
            .unwrap_or("git rev-parse HEAD did not return a full commit"),
    ));
    checks.push(release_finalize_check_item(
        "git worktree",
        if worktree_clean {
            ReadinessStatus::Pass
        } else {
            release_finalize_review_status(strict)
        },
        if worktree_clean {
            "tracked worktree is clean".to_string()
        } else if status_output.ok {
            release_evidence_truncated_detail(status_output.stdout.trim(), 360)
        } else {
            release_finalize_command_detail(&status_output, "git status failed")
        },
    ));
    checks.push(release_finalize_check_item(
        "signing key",
        if signer.production_ready {
            ReadinessStatus::Pass
        } else {
            release_finalize_review_status(strict)
        },
        signer
            .warning
            .clone()
            .unwrap_or_else(|| format!("{} signer active", signer.source)),
    ));
    checks.push(release_finalize_check_item(
        "signed tag",
        if tag_report.verified {
            ReadinessStatus::Pass
        } else {
            release_finalize_review_status(strict)
        },
        tag_report.detail.clone(),
    ));
    checks.push(release_finalize_check_item(
        "publish action",
        ReadinessStatus::Pass,
        "release-finalize only writes local handoff evidence; it does not tag, push, or publish",
    ));

    let ready = checks
        .iter()
        .all(|check| check.status != ReadinessStatus::Fail);
    let report = ReleaseFinalizeReport {
        schema_version: RELEASE_FINALIZE_SCHEMA_VERSION,
        release,
        generated_at_unix_seconds: release_finalize_unix_seconds(),
        output: out.clone(),
        publish_state: "not-published".to_string(),
        strict,
        ready,
        commit,
        worktree_clean,
        evidence,
        checked_root,
        package_archive,
        package_archive_sha256: smoke.package_archive_sha256,
        package_release_manifest,
        release_notes,
        signer,
        tag: tag_report,
        checks,
        evidence_check,
    };

    if let Some(parent) = out.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &out,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )?;

    Ok(report)
}

fn run_release_publication_check(
    finalization_path: &Path,
    notes_override: Option<&Path>,
) -> Result<ReleasePublicationCheckReport, AgentKError> {
    let finalization_content = fs::read_to_string(finalization_path)?;
    let finalization: ReleaseFinalizeReport = serde_json::from_str(&finalization_content)?;
    let notes_path = notes_override
        .map(Path::to_path_buf)
        .or_else(|| {
            finalization
                .release_notes
                .as_ref()
                .map(|artifact| artifact.path.clone())
        })
        .ok_or_else(|| {
            AgentKError::InvalidMcpRequest(
                "release publication check requires release notes from finalization or --notes"
                    .to_string(),
            )
        })?;
    let notes_content = fs::read_to_string(&notes_path).ok();
    let notes_values = notes_content
        .as_deref()
        .map(release_publication_final_evidence_values)
        .unwrap_or_default();
    let notes_draft_markers = notes_content
        .as_deref()
        .map(release_finalize_draft_markers)
        .unwrap_or_default();
    let package_archive_display = finalization.package_archive.display().to_string();
    let package_release_manifest_display =
        finalization.package_release_manifest.display().to_string();

    let mut checks = Vec::new();
    checks.push(release_publication_check_item(
        "finalization schema",
        if finalization.schema_version == RELEASE_FINALIZE_SCHEMA_VERSION {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        format!("schema_version {}", finalization.schema_version),
    ));
    checks.push(release_publication_check_item(
        "finalization ready",
        if finalization.ready {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if finalization.ready {
            "release-finalize reported ready"
        } else {
            "release-finalize reported blocked"
        },
    ));
    checks.push(release_publication_check_item(
        "strict finalization",
        if finalization.strict {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if finalization.strict {
            "release-finalize was run with --strict"
        } else {
            "rerun release-finalize with --strict before publication"
        },
    ));
    checks.push(release_publication_check_item(
        "publish state",
        if finalization.publish_state == "not-published" {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        format!("publish_state {}", finalization.publish_state),
    ));
    checks.push(release_publication_check_item(
        "evidence check",
        if finalization.evidence_check.passed {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        format!(
            "{}/{} artifacts verified, {}/{} smoke steps passed",
            finalization.evidence_check.artifacts_verified,
            finalization.evidence_check.artifacts_total,
            finalization.evidence_check.steps_passed,
            finalization.evidence_check.steps_total
        ),
    ));
    checks.push(release_publication_notes_artifact_check(
        &notes_path,
        finalization.release_notes.as_ref(),
    ));
    checks.push(release_publication_check_item(
        "release notes placeholders",
        if notes_draft_markers.is_empty() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if notes_draft_markers.is_empty() {
            "release notes contain no final-evidence placeholders".to_string()
        } else {
            format!(
                "release notes still contain draft markers: {}",
                notes_draft_markers.join(", ")
            )
        },
    ));
    checks.push(release_publication_note_match_check(
        &notes_values,
        "Release commit",
        finalization.commit.as_deref(),
    ));
    checks.push(release_publication_note_match_check(
        &notes_values,
        "Package archive",
        Some(&package_archive_display),
    ));
    checks.push(release_publication_note_match_check(
        &notes_values,
        "Package archive SHA-256",
        Some(&finalization.package_archive_sha256),
    ));
    checks.push(release_publication_note_match_check(
        &notes_values,
        "Package release manifest",
        Some(&package_release_manifest_display),
    ));
    checks.push(release_publication_note_match_check(
        &notes_values,
        "AgentK evidence signing public key",
        Some(&finalization.signer.public_key),
    ));
    checks.push(release_publication_note_match_check(
        &notes_values,
        "Signed tag",
        finalization.tag.tag.as_deref(),
    ));
    checks.push(release_publication_required_note_check(
        &notes_values,
        "Strict release-audit result",
        None,
    ));
    checks.push(release_publication_required_note_check(
        &notes_values,
        "Signed tag verification",
        finalization.tag.tag.as_deref(),
    ));
    checks.push(release_publication_required_note_check(
        &notes_values,
        "Git tag signer",
        None,
    ));
    checks.push(release_publication_package_archive_check(
        &finalization.package_archive,
        &finalization.package_archive_sha256,
    ));
    checks.push(release_publication_check_item(
        "package release manifest",
        if finalization.package_release_manifest.is_file() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if finalization.package_release_manifest.is_file() {
            format!("{} exists", finalization.package_release_manifest.display())
        } else {
            format!(
                "{} is missing or not a file",
                finalization.package_release_manifest.display()
            )
        },
    ));
    checks.push(release_publication_check_item(
        "signing key",
        if finalization.signer.production_ready {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        finalization
            .signer
            .warning
            .clone()
            .unwrap_or_else(|| format!("{} signer active", finalization.signer.source)),
    ));
    checks.push(release_publication_check_item(
        "signed tag",
        if finalization.tag.tag.is_some() && finalization.tag.verified {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        finalization.tag.detail.clone(),
    ));
    checks.push(release_publication_check_item(
        "git worktree",
        if finalization.worktree_clean {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if finalization.worktree_clean {
            "release-finalize recorded a clean worktree".to_string()
        } else {
            "release-finalize recorded a dirty worktree".to_string()
        },
    ));

    let passed = checks
        .iter()
        .all(|check| check.status != ReadinessStatus::Fail);
    Ok(ReleasePublicationCheckReport {
        finalization: finalization_path.to_path_buf(),
        notes: notes_path,
        release: finalization.release,
        tag: finalization.tag.tag,
        package_archive: finalization.package_archive,
        package_archive_sha256: finalization.package_archive_sha256,
        package_release_manifest: finalization.package_release_manifest,
        publish_state: finalization.publish_state,
        passed,
        checks,
    })
}

fn release_finalize_git(args: &[&str]) -> Result<ReleaseFinalizeGitOutput, AgentKError> {
    let output = ProcessCommand::new("git").args(args).output()?;
    Ok(ReleaseFinalizeGitOutput {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        exit_code: output.status.code(),
    })
}

fn release_finalize_artifact(path: &Path) -> Option<Result<ReleaseFinalizeArtifact, AgentKError>> {
    let metadata = fs::metadata(path)
        .ok()?
        .is_file()
        .then(|| fs::metadata(path));
    let metadata = match metadata? {
        Ok(metadata) => metadata,
        Err(error) => return Some(Err(AgentKError::Io(error))),
    };
    Some(
        release_candidate_smoke_file_sha256(path).map(|sha256| ReleaseFinalizeArtifact {
            path: path.to_path_buf(),
            bytes: metadata.len(),
            sha256,
        }),
    )
}

fn release_finalize_draft_markers(content: &str) -> Vec<String> {
    RELEASE_FINALIZE_DRAFT_MARKERS
        .iter()
        .copied()
        .filter(|marker| content.contains(marker))
        .map(str::to_string)
        .collect()
}

fn release_publication_final_evidence_values(content: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            in_section = trimmed == "## Final Release Evidence";
            continue;
        }
        if !in_section {
            continue;
        }
        let Some(entry) = trimmed.strip_prefix("- ") else {
            continue;
        };
        let Some((label, raw_value)) = entry.split_once(':') else {
            continue;
        };
        let value = raw_value.trim();
        let value = value
            .strip_prefix('`')
            .and_then(|inner| inner.strip_suffix('`'))
            .unwrap_or(value)
            .trim()
            .to_string();
        values.insert(label.trim().to_string(), value);
    }
    values
}

fn release_publication_notes_artifact_check(
    notes_path: &Path,
    finalized: Option<&ReleaseFinalizeArtifact>,
) -> ReleasePublicationCheckItem {
    match (release_candidate_smoke_file_sha256(notes_path), finalized) {
        (Ok(current_sha256), Some(finalized)) if current_sha256 == finalized.sha256 => {
            release_publication_check_item(
                "release notes artifact",
                ReadinessStatus::Pass,
                format!("{} matches finalization sha256", notes_path.display()),
            )
        }
        (Ok(current_sha256), Some(finalized)) => release_publication_check_item(
            "release notes artifact",
            ReadinessStatus::Fail,
            format!(
                "{} sha256 {} does not match finalized {}",
                notes_path.display(),
                current_sha256,
                finalized.sha256
            ),
        ),
        (Ok(_), None) => release_publication_check_item(
            "release notes artifact",
            ReadinessStatus::Fail,
            "finalization report did not record release notes".to_string(),
        ),
        (Err(error), _) => release_publication_check_item(
            "release notes artifact",
            ReadinessStatus::Fail,
            format!("{} could not be hashed: {error}", notes_path.display()),
        ),
    }
}

fn release_publication_note_match_check(
    notes_values: &BTreeMap<String, String>,
    label: &str,
    expected: Option<&str>,
) -> ReleasePublicationCheckItem {
    let Some(expected) = expected else {
        return release_publication_check_item(
            format!("notes {label}"),
            ReadinessStatus::Fail,
            format!("finalization report did not record {label}"),
        );
    };
    match notes_values.get(label) {
        Some(actual) if actual == expected => release_publication_check_item(
            format!("notes {label}"),
            ReadinessStatus::Pass,
            "release notes match finalization evidence".to_string(),
        ),
        Some(actual) => release_publication_check_item(
            format!("notes {label}"),
            ReadinessStatus::Fail,
            format!("expected `{expected}`, found `{actual}`"),
        ),
        None => release_publication_check_item(
            format!("notes {label}"),
            ReadinessStatus::Fail,
            "missing from Final Release Evidence".to_string(),
        ),
    }
}

fn release_publication_required_note_check(
    notes_values: &BTreeMap<String, String>,
    label: &str,
    must_contain: Option<&str>,
) -> ReleasePublicationCheckItem {
    let (status, detail) = match notes_values.get(label) {
        Some(value)
            if !value.is_empty()
                && !RELEASE_FINALIZE_DRAFT_MARKERS
                    .iter()
                    .any(|marker| value.contains(marker))
                && must_contain.is_none_or(|needle| value.contains(needle)) =>
        {
            (
                ReadinessStatus::Pass,
                "release notes contain reviewed final evidence".to_string(),
            )
        }
        Some(value) if must_contain.is_some_and(|needle| !value.contains(needle)) => (
            ReadinessStatus::Fail,
            format!(
                "release notes value `{value}` does not mention `{}`",
                must_contain.unwrap_or_default()
            ),
        ),
        Some(value) => (
            ReadinessStatus::Fail,
            format!("release notes value `{value}` is still a placeholder"),
        ),
        None => (
            ReadinessStatus::Fail,
            "missing from Final Release Evidence".to_string(),
        ),
    };
    release_publication_check_item(format!("notes {label}"), status, detail)
}

fn release_publication_package_archive_check(
    package_archive: &Path,
    expected_sha256: &str,
) -> ReleasePublicationCheckItem {
    match release_candidate_smoke_file_sha256(package_archive) {
        Ok(actual_sha256) if actual_sha256 == expected_sha256 => release_publication_check_item(
            "package archive artifact",
            ReadinessStatus::Pass,
            format!("{} matches finalized SHA-256", package_archive.display()),
        ),
        Ok(actual_sha256) => release_publication_check_item(
            "package archive artifact",
            ReadinessStatus::Fail,
            format!(
                "{} sha256 {} does not match finalized {}",
                package_archive.display(),
                actual_sha256,
                expected_sha256
            ),
        ),
        Err(error) => release_publication_check_item(
            "package archive artifact",
            ReadinessStatus::Fail,
            format!("{} could not be hashed: {error}", package_archive.display()),
        ),
    }
}

fn release_publication_check_item(
    name: impl Into<String>,
    status: ReadinessStatus,
    detail: impl Into<String>,
) -> ReleasePublicationCheckItem {
    ReleasePublicationCheckItem {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

fn release_finalize_valid_commit(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn release_finalize_review_status(strict: bool) -> ReadinessStatus {
    if strict {
        ReadinessStatus::Fail
    } else {
        ReadinessStatus::Warn
    }
}

fn release_finalize_command_detail(output: &ReleaseFinalizeGitOutput, fallback: &str) -> String {
    let detail = [output.stderr.trim(), output.stdout.trim()]
        .into_iter()
        .find(|value| !value.is_empty())
        .unwrap_or(fallback);
    let detail = match output.exit_code {
        Some(code) if !output.ok => format!("exit {code}; {detail}"),
        None if !output.ok => format!("terminated by signal; {detail}"),
        _ => detail.to_string(),
    };
    release_evidence_truncated_detail(&detail, 360)
}

fn release_finalize_check_item(
    name: &str,
    status: ReadinessStatus,
    detail: impl Into<String>,
) -> ReleaseFinalizeCheckItem {
    ReleaseFinalizeCheckItem {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

fn release_finalize_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn run_release_evidence_check(
    evidence: &Path,
    root_override: Option<PathBuf>,
) -> Result<ReleaseEvidenceCheckReport, AgentKError> {
    let smoke = read_release_candidate_smoke_report(evidence)?;
    let checked_root = root_override.unwrap_or_else(|| smoke.root.clone());
    let mut checks = Vec::new();

    checks.push(release_evidence_check_item(
        "smoke verdict",
        if smoke.passed {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if smoke.passed {
            "release-candidate-smoke reported ready"
        } else {
            "release-candidate-smoke reported blocked"
        },
    ));

    let steps_total = smoke.steps.len();
    let failed_steps = smoke
        .steps
        .iter()
        .filter(|step| !step.passed)
        .map(|step| step.name.as_str())
        .collect::<Vec<_>>();
    let steps_passed = steps_total.saturating_sub(failed_steps.len());
    checks.push(release_evidence_check_item(
        "step results",
        if steps_total > 0 && failed_steps.is_empty() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if steps_total == 0 {
            "no smoke steps were recorded".to_string()
        } else if failed_steps.is_empty() {
            format!("{steps_passed}/{steps_total} smoke steps passed")
        } else {
            format!(
                "{}/{} smoke steps passed; failed: {}",
                steps_passed,
                steps_total,
                failed_steps.join(", ")
            )
        },
    ));

    let artifact_names = smoke
        .artifacts
        .iter()
        .map(|artifact| artifact.name.as_str())
        .collect::<BTreeSet<_>>();
    let missing_required = RELEASE_CANDIDATE_SMOKE_REQUIRED_ARTIFACTS
        .iter()
        .copied()
        .filter(|name| !artifact_names.contains(name))
        .collect::<Vec<_>>();
    let unknown_artifacts = artifact_names
        .iter()
        .copied()
        .filter(|name| !RELEASE_CANDIDATE_SMOKE_REQUIRED_ARTIFACTS.contains(name))
        .collect::<Vec<_>>();
    checks.push(release_evidence_check_item(
        "artifact inventory",
        if smoke.artifacts.is_empty() || !missing_required.is_empty() {
            ReadinessStatus::Fail
        } else if unknown_artifacts.is_empty() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Warn
        },
        if smoke.artifacts.is_empty() {
            "no artifacts were recorded".to_string()
        } else if !missing_required.is_empty() {
            format!(
                "missing required artifacts: {}",
                missing_required.join(", ")
            )
        } else if unknown_artifacts.is_empty() {
            format!(
                "{} required artifacts recorded",
                RELEASE_CANDIDATE_SMOKE_REQUIRED_ARTIFACTS.len()
            )
        } else {
            format!("unknown extra artifacts: {}", unknown_artifacts.join(", "))
        },
    ));

    let artifact_bindings = [
        ("package archive", smoke.package_archive.as_path()),
        (
            "package archive checksum",
            smoke.package_archive_checksum.as_path(),
        ),
        ("release manifest", smoke.package_release_manifest.as_path()),
        ("trace", smoke.trace_path.as_path()),
        ("dashboard", smoke.dashboard_path.as_path()),
    ];
    let binding_mismatches = artifact_bindings
        .iter()
        .filter_map(|(name, expected_path)| {
            match smoke
                .artifacts
                .iter()
                .find(|artifact| artifact.name == *name)
            {
                Some(artifact) if artifact.path.as_path() == *expected_path => None,
                Some(artifact) => Some(format!(
                    "{} artifact path {} does not match report field {}",
                    name,
                    artifact.path.display(),
                    expected_path.display()
                )),
                None => Some(format!("{name} artifact is missing")),
            }
        })
        .collect::<Vec<_>>();
    checks.push(release_evidence_check_item(
        "artifact bindings",
        if binding_mismatches.is_empty() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if binding_mismatches.is_empty() {
            "report fields match named handoff artifacts".to_string()
        } else {
            release_evidence_truncated_detail(&binding_mismatches.join("; "), 360)
        },
    ));

    let mut artifacts_verified = 0;
    let mut missing_artifacts = 0;
    let mut changed_artifacts = 0;
    let mut artifact_failures = Vec::new();
    let mut package_archive_sha = None;

    for artifact in &smoke.artifacts {
        let path = release_evidence_rebased_path(&artifact.path, &smoke.root, &checked_root);
        if !artifact.present {
            missing_artifacts += 1;
            artifact_failures.push(format!("{} was recorded absent", artifact.name));
            continue;
        }
        let Some(expected_bytes) = artifact.bytes else {
            changed_artifacts += 1;
            artifact_failures.push(format!("{} is missing recorded byte count", artifact.name));
            continue;
        };
        let Some(expected_sha256) = artifact.sha256.as_deref() else {
            changed_artifacts += 1;
            artifact_failures.push(format!("{} is missing recorded SHA-256", artifact.name));
            continue;
        };
        if !release_evidence_valid_sha256(expected_sha256) {
            changed_artifacts += 1;
            artifact_failures.push(format!("{} has invalid recorded SHA-256", artifact.name));
            continue;
        }
        let metadata = match fs::metadata(&path)
            .ok()
            .filter(|metadata| metadata.is_file())
        {
            Some(metadata) => metadata,
            None => {
                missing_artifacts += 1;
                artifact_failures.push(format!("{} is missing on disk", artifact.name));
                continue;
            }
        };
        let actual_sha256 = release_candidate_smoke_file_sha256(&path)?;
        let bytes_match = metadata.len() == expected_bytes;
        let sha_matches = actual_sha256 == expected_sha256;
        if bytes_match && sha_matches {
            artifacts_verified += 1;
        } else {
            changed_artifacts += 1;
            artifact_failures.push(format!("{} hash or size changed", artifact.name));
        }
        if artifact.name == "package archive" {
            package_archive_sha = Some(actual_sha256);
        }
    }

    let artifacts_total = smoke.artifacts.len();
    checks.push(release_evidence_check_item(
        "artifact hashes",
        if artifacts_total > 0 && artifacts_verified == artifacts_total {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        if artifact_failures.is_empty() {
            format!("{artifacts_verified}/{artifacts_total} artifacts match recorded SHA-256")
        } else {
            let detail = format!(
                "{artifacts_verified}/{artifacts_total} artifacts verified; {}",
                artifact_failures.join("; ")
            );
            release_evidence_truncated_detail(&detail, 360)
        },
    ));

    checks.push(release_evidence_check_item(
        "package archive hash",
        match package_archive_sha.as_deref() {
            Some(sha) if sha == smoke.package_archive_sha256 => ReadinessStatus::Pass,
            Some(_) => ReadinessStatus::Fail,
            None => ReadinessStatus::Fail,
        },
        match package_archive_sha {
            Some(sha) if sha == smoke.package_archive_sha256 => {
                "package archive matches report-level SHA-256".to_string()
            }
            Some(_) => "package archive does not match report-level SHA-256".to_string(),
            None => "package archive artifact was not verified".to_string(),
        },
    ));

    checks.push(release_evidence_check_item(
        "evidence binding",
        match smoke.evidence_report.as_ref() {
            Some(path) if path == evidence => ReadinessStatus::Pass,
            Some(_) | None => ReadinessStatus::Warn,
        },
        match smoke.evidence_report.as_ref() {
            Some(path) if path == evidence => "evidence path matches recorded report".to_string(),
            Some(path) => format!(
                "evidence was recorded as {}; current check used {}",
                path.display(),
                evidence.display()
            ),
            None => "smoke report was not written with --evidence-out".to_string(),
        },
    ));

    let passed = checks
        .iter()
        .all(|check| check.status != ReadinessStatus::Fail);

    Ok(ReleaseEvidenceCheckReport {
        evidence: evidence.to_path_buf(),
        reported_root: smoke.root,
        checked_root,
        passed,
        steps_passed,
        steps_total,
        artifacts_verified,
        artifacts_total,
        missing_artifacts,
        changed_artifacts,
        checks,
    })
}

fn read_release_candidate_smoke_report(
    evidence: &Path,
) -> Result<ReleaseCandidateSmokeReport, AgentKError> {
    let content = fs::read_to_string(evidence)?;
    Ok(serde_json::from_str(&content)?)
}

fn release_evidence_rebased_path(
    path: &Path,
    reported_root: &Path,
    checked_root: &Path,
) -> PathBuf {
    if reported_root != checked_root
        && let Ok(relative) = path.strip_prefix(reported_root)
    {
        return checked_root.join(relative);
    }
    path.to_path_buf()
}

fn release_evidence_valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn release_evidence_truncated_detail(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let keep = max_chars.saturating_sub(3);
    let mut truncated = value.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn release_evidence_check_item(
    name: &str,
    status: ReadinessStatus,
    detail: impl Into<String>,
) -> ReleaseEvidenceCheckItem {
    ReleaseEvidenceCheckItem {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

fn release_candidate_smoke_temp_root() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    env::temp_dir().join(format!(
        "agentk-release-candidate-smoke-{}-{nanos}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mcp_proxy_trace_out_test_path(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "agentk-mcp-proxy-stdio-{label}-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        ))
    }

    fn test_temp_path(prefix: &str, extension: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{prefix}-{}-{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos(),
            extension
        ))
    }

    fn synthetic_release_smoke_report(root: &Path, evidence: &Path) -> ReleaseCandidateSmokeReport {
        let artifact_root = root.join("artifacts");
        fs::create_dir_all(&artifact_root).expect("artifact root should create");
        let mut artifacts = Vec::new();
        let mut paths = BTreeMap::new();
        for name in RELEASE_CANDIDATE_SMOKE_REQUIRED_ARTIFACTS {
            let filename = format!("{}.txt", name.replace(' ', "-"));
            let path = artifact_root.join(filename);
            fs::write(&path, format!("agentk release evidence {name}\n"))
                .expect("artifact should write");
            release_candidate_smoke_artifact(&mut artifacts, name, path.clone())
                .expect("artifact should record");
            paths.insert((*name).to_string(), path);
        }
        let package_archive_sha256 = artifacts
            .iter()
            .find(|artifact| artifact.name == "package archive")
            .and_then(|artifact| artifact.sha256.clone())
            .expect("package archive artifact should have sha");

        ReleaseCandidateSmokeReport {
            root: root.to_path_buf(),
            package: root.join("dist/agentk-sidecar"),
            package_archive: paths["package archive"].clone(),
            package_archive_checksum: paths["package archive checksum"].clone(),
            package_release_manifest: paths["release manifest"].clone(),
            evidence_report: Some(evidence.to_path_buf()),
            installed_package: root.join("installed/agentk-sidecar"),
            package_archive_sha256,
            trace_path: paths["trace"].clone(),
            dashboard_path: paths["dashboard"].clone(),
            store_export_root: root.join("installed/agentk-sidecar/sidecar/.agentk/store"),
            team_store_root: root.join("installed/agentk-sidecar/sidecar/.agentk/team-store"),
            slack_payload_root: root.join("installed/agentk-sidecar/sidecar/.agentk/slack"),
            github_payload_root: root.join("installed/agentk-sidecar/sidecar/.agentk/github"),
            kept_root: true,
            passed: true,
            steps: vec![
                ReleaseCandidateSmokeStep {
                    name: "package install".to_string(),
                    command: vec!["agentk".to_string(), "sidecar-package-install".to_string()],
                    passed: true,
                    exit_code: Some(0),
                },
                ReleaseCandidateSmokeStep {
                    name: "release manifest check".to_string(),
                    command: vec![
                        "agentk".to_string(),
                        "sidecar-package-release-manifest-check".to_string(),
                    ],
                    passed: true,
                    exit_code: Some(0),
                },
            ],
            artifacts,
        }
    }

    fn release_finalize_test_git_output(
        ok: bool,
        stdout: &str,
        stderr: &str,
    ) -> ReleaseFinalizeGitOutput {
        ReleaseFinalizeGitOutput {
            ok,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            exit_code: Some(if ok { 0 } else { 1 }),
        }
    }

    fn release_finalize_test_signer(
        source: agentk::SigningKeySource,
        production_ready: bool,
    ) -> agentk::SigningKeyStatus {
        agentk::SigningKeyStatus {
            algorithm: "ed25519".to_string(),
            source,
            public_key: "abababababababababababababababababababababababababababababababab"
                .to_string(),
            production_ready,
            warning: (!production_ready).then(|| "test signer is not release ready".to_string()),
        }
    }

    fn dashboard_test_request(
        method: &str,
        target: &str,
        body: impl Into<Vec<u8>>,
    ) -> DashboardHttpRequest {
        dashboard_test_request_with_headers(method, target, [], body)
    }

    fn dashboard_test_request_with_headers<const N: usize>(
        method: &str,
        target: &str,
        headers: [(&str, &str); N],
        body: impl Into<Vec<u8>>,
    ) -> DashboardHttpRequest {
        DashboardHttpRequest {
            method: method.to_string(),
            target: target.to_string(),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
                .collect(),
            body: body.into(),
        }
    }

    fn response_header<'a>(response: &'a DashboardHttpResponse, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn http_response_writer_emits_security_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("test client should connect");
            let response = dashboard_http_text("200 OK", "ok\n");
            write_dashboard_http_response(&mut stream, &response)
                .expect("test response should write");
        });
        let mut client = TcpStream::connect(addr).expect("test client should connect");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("test client should read response");
        writer.join().expect("writer thread should finish");
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(response.contains("Referrer-Policy: no-referrer\r\n"));
        assert!(response.contains("X-Frame-Options: DENY\r\n"));
        assert!(response.contains("Content-Security-Policy:"));
        assert!(response.contains("frame-ancestors 'none'"));
    }

    #[cfg(unix)]
    fn mcp_proxy_trace_out_probe_server() -> String {
        r#"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"trace-out-probe","version":"test"}}}'
      ;;
    *'"method":"notifications/initialized"'*)
      ;;
    *'"method":"tools/list"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"demo.echo","description":"Echo public payloads.","inputSchema":{"type":"object"}}]}}'
      ;;
    *)
      printf '%s\n' '{"jsonrpc":"2.0","id":999,"error":{"code":-32601,"message":"unknown fake request"}}'
      ;;
  esac
done
"#
        .to_string()
    }

    #[cfg(unix)]
    fn mcp_proxy_trace_out_probe_input() -> &'static str {
        r#"
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
"#
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct FailOnSecondNewlineWriter {
        bytes: Vec<u8>,
        newline_count: usize,
    }

    #[cfg(unix)]
    impl std::io::Write for FailOnSecondNewlineWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for byte in buf {
                if *byte == b'\n' {
                    self.newline_count += 1;
                    if self.newline_count == 2 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "test writer failure after mediated event",
                        ));
                    }
                }
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn mcp_proxy_stdio_accepts_hyphen_prefixed_child_args() {
        std::thread::Builder::new()
            .name("agentk-cli-stdio-args-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(mcp_proxy_stdio_accepts_hyphen_prefixed_child_args_inner)
            .expect("stdio args parser smoke thread should spawn")
            .join()
            .expect("stdio args parser smoke thread should not panic");
    }

    fn mcp_proxy_stdio_accepts_hyphen_prefixed_child_args_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "mcp-proxy-stdio",
            "--command",
            "sh",
            "--arg",
            "-c",
            "--arg",
            "printf ok",
        ])
        .expect("hyphen-prefixed child args should parse");

        let Some(Command::McpProxyStdio {
            args,
            max_client_messages,
            ..
        }) = cli.command
        else {
            panic!("expected mcp-proxy-stdio command");
        };
        assert_eq!(args, vec!["-c".to_string(), "printf ok".to_string()]);
        assert_eq!(max_client_messages, 10000);
    }

    #[test]
    fn mcp_proxy_stdio_accepts_session_report_out() {
        std::thread::Builder::new()
            .name("agentk-cli-stdio-session-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(mcp_proxy_stdio_accepts_session_report_out_inner)
            .expect("stdio session parser smoke thread should spawn")
            .join()
            .expect("stdio session parser smoke thread should not panic");
    }

    fn mcp_proxy_stdio_accepts_session_report_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "mcp-proxy-stdio",
            "--command",
            "sh",
            "--session-report-out",
            ".agentk/runs/proxy.session.json",
        ])
        .expect("session report path should parse");

        let Some(Command::McpProxyStdio {
            session_report_out, ..
        }) = cli.command
        else {
            panic!("expected mcp-proxy-stdio command");
        };
        assert_eq!(
            session_report_out,
            Some(PathBuf::from(".agentk/runs/proxy.session.json"))
        );
    }

    #[test]
    fn mcp_proxy_tcp_accepts_transport_args() {
        std::thread::Builder::new()
            .name("agentk-cli-tcp-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(mcp_proxy_tcp_accepts_transport_args_inner)
            .expect("TCP parser smoke thread should spawn")
            .join()
            .expect("TCP parser smoke thread should not panic");
    }

    fn mcp_proxy_tcp_accepts_transport_args_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "mcp-proxy-tcp",
            "--host",
            "127.0.0.1",
            "--port",
            "9798",
            "--max-sessions",
            "2",
            "--max-concurrent-sessions",
            "2",
            "--command",
            "sh",
            "--arg",
            "-c",
            "--arg",
            "printf ok",
            "--trace-out",
            ".agentk/runs/tcp.jsonl",
            "--session-report-out",
            ".agentk/runs/tcp.session.json",
        ])
        .expect("tcp proxy args should parse");

        let Some(Command::McpProxyTcp {
            host,
            port,
            max_sessions,
            max_concurrent_sessions,
            args,
            trace_out,
            session_report_out,
            ..
        }) = cli.command
        else {
            panic!("expected mcp-proxy-tcp command");
        };
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9798);
        assert_eq!(max_sessions, 2);
        assert_eq!(max_concurrent_sessions, 2);
        assert_eq!(args, vec!["-c".to_string(), "printf ok".to_string()]);
        assert_eq!(trace_out, Some(PathBuf::from(".agentk/runs/tcp.jsonl")));
        assert_eq!(
            session_report_out,
            Some(PathBuf::from(".agentk/runs/tcp.session.json"))
        );
    }

    #[test]
    fn mcp_proxy_http_accepts_streamable_http_args() {
        std::thread::Builder::new()
            .name("agentk-cli-http-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(mcp_proxy_http_accepts_streamable_http_args_inner)
            .expect("HTTP parser smoke thread should spawn")
            .join()
            .expect("HTTP parser smoke thread should not panic");
    }

    fn mcp_proxy_http_accepts_streamable_http_args_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "mcp-proxy-http",
            "--host",
            "127.0.0.1",
            "--port",
            "9798",
            "--endpoint",
            "/mcp",
            "--max-requests",
            "3",
            "--max-concurrent-requests",
            "2",
            "--max-active-sessions",
            "5",
            "--session-idle-timeout-ms",
            "60000",
            "--max-body-bytes",
            "32768",
            "--max-header-bytes",
            "8192",
            "--stream-timeout-ms",
            "12000",
            "--allow-origin",
            "http://localhost:3000",
            "--allow-origin-env",
            "AGENTK_TEST_HTTP_ALLOW_ORIGINS",
            "--allow-non-local-bind",
            "--trust-proxy-headers",
            "--auth-token-env",
            "AGENTK_TEST_HTTP_TOKEN",
            "--command",
            "sh",
            "--arg",
            "-c",
            "--arg",
            "printf ok",
            "--trace-out",
            ".agentk/runs/http.jsonl",
            "--session-report-out",
            ".agentk/runs/http.session.json",
        ])
        .expect("http proxy args should parse");

        let Some(Command::McpProxyHttp {
            host,
            port,
            endpoint,
            max_requests,
            max_concurrent_requests,
            max_active_sessions,
            session_idle_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            stream_timeout_ms,
            allow_origins,
            allow_origin_env,
            allow_non_local_bind,
            trust_proxy_headers,
            auth_token_env,
            args,
            trace_out,
            session_report_out,
            ..
        }) = cli.command
        else {
            panic!("expected mcp-proxy-http command");
        };
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9798);
        assert_eq!(endpoint, "/mcp");
        assert_eq!(max_requests, 3);
        assert_eq!(max_concurrent_requests, 2);
        assert_eq!(max_active_sessions, 5);
        assert_eq!(session_idle_timeout_ms, 60000);
        assert_eq!(max_body_bytes, 32768);
        assert_eq!(max_header_bytes, 8192);
        assert_eq!(stream_timeout_ms, 12000);
        assert_eq!(allow_origins, vec!["http://localhost:3000".to_string()]);
        assert_eq!(allow_origin_env, "AGENTK_TEST_HTTP_ALLOW_ORIGINS");
        assert!(allow_non_local_bind);
        assert!(trust_proxy_headers);
        assert_eq!(auth_token_env, "AGENTK_TEST_HTTP_TOKEN");
        assert_eq!(args, vec!["-c".to_string(), "printf ok".to_string()]);
        assert_eq!(trace_out, Some(PathBuf::from(".agentk/runs/http.jsonl")));
        assert_eq!(
            session_report_out,
            Some(PathBuf::from(".agentk/runs/http.session.json"))
        );
    }

    #[test]
    fn mcp_http_endpoint_validation_accepts_origin_form_paths() {
        for endpoint in ["/", "/mcp", "/mcp/v1", "/agentk_mcp", "/mcp%20path"] {
            validate_mcp_http_endpoint(endpoint).expect("endpoint path should be accepted");
        }
    }

    #[test]
    fn mcp_http_endpoint_validation_rejects_unsafe_paths() {
        let cases = [
            ("", "origin-form path"),
            ("mcp", "origin-form path"),
            ("http://127.0.0.1/mcp", "origin-form path"),
            ("/mcp?value=QUERY_SHOULD_NOT_REFLECT", "query strings"),
            ("/mcp#FRAGMENT_SHOULD_NOT_REFLECT", "fragments"),
            ("/m cp", "whitespace"),
            ("/mcp\nCONTROL_SHOULD_NOT_REFLECT", "control characters"),
            ("/healthz", "operational probe paths"),
            ("/readyz", "operational probe paths"),
            ("/metrics", "operational probe paths"),
        ];

        for (endpoint, expected_message) in cases {
            let error =
                validate_mcp_http_endpoint(endpoint).expect_err("endpoint path should be rejected");
            let error = error.to_string();
            assert!(
                error.contains(expected_message),
                "expected {error:?} to contain {expected_message:?}"
            );
            assert!(!error.contains("QUERY_SHOULD_NOT_REFLECT"));
            assert!(!error.contains("FRAGMENT_SHOULD_NOT_REFLECT"));
            assert!(!error.contains("CONTROL_SHOULD_NOT_REFLECT"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_response_handles_stateful_streamable_http_posts() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let common_headers = [
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
            ("Origin", "http://127.0.0.1:3000"),
        ];

        let initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            common_headers,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let initialize_response =
            mcp_http_response(&initialize, &state).expect("initialize should produce response");
        assert_eq!(initialize_response.status, "200 OK");
        assert_eq!(
            response_header(&initialize_response, "Access-Control-Allow-Origin"),
            Some("http://127.0.0.1:3000")
        );
        assert_eq!(
            response_header(&initialize_response, "Access-Control-Expose-Headers"),
            Some("Mcp-Session-Id, Last-Event-ID, WWW-Authenticate")
        );
        let session_id = response_header(&initialize_response, "Mcp-Session-Id")
            .expect("initialize should return session id")
            .to_string();
        let initialize_json: serde_json::Value = serde_json::from_slice(&initialize_response.body)
            .expect("initialize response should be json");
        assert_eq!(
            initialize_json["result"]["protocolVersion"],
            serde_json::json!("2025-11-25")
        );

        let initialized = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        );
        let initialized_response =
            mcp_http_response(&initialized, &state).expect("notification should be accepted");
        assert_eq!(initialized_response.status, "202 Accepted");
        assert!(initialized_response.body.is_empty());

        let bad_resume = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                ("Last-Event-ID", "BAD_RESUME_SHOULD_NOT_REFLECT"),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            Vec::new(),
        );
        let bad_resume_response =
            mcp_http_response(&bad_resume, &state).expect("bad SSE resume should fail closed");
        assert_eq!(bad_resume_response.status, "400 Bad Request");
        assert!(
            !String::from_utf8_lossy(&bad_resume_response.body)
                .contains("BAD_RESUME_SHOULD_NOT_REFLECT")
        );

        let overflow_resume = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                ("Last-Event-ID", "999999999999999999999999999999999999999"),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            Vec::new(),
        );
        let overflow_resume_response =
            mcp_http_response(&overflow_resume, &state).expect("overflow resume should fail");
        assert_eq!(overflow_resume_response.status, "400 Bad Request");
        assert!(
            String::from_utf8_lossy(&overflow_resume_response.body)
                .contains("Last-Event-ID must be an unsigned decimal event id")
        );
        assert!(
            !String::from_utf8_lossy(&overflow_resume_response.body)
                .contains("999999999999999999999999999999999999999")
        );

        let initial_sse = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            Vec::new(),
        );
        let initial_sse_response =
            mcp_http_response(&initial_sse, &state).expect("SSE should return buffered events");
        assert_eq!(initial_sse_response.status, "200 OK");
        assert_eq!(initial_sse_response.content_type, "text/event-stream");
        assert_eq!(
            response_header(&initial_sse_response, "Last-Event-ID"),
            Some("1")
        );
        assert_eq!(
            response_header(&initial_sse_response, "Access-Control-Allow-Origin"),
            Some("http://127.0.0.1:3000")
        );
        let initial_sse_body = String::from_utf8_lossy(&initial_sse_response.body);
        assert!(initial_sse_body.contains("id: 1\n"));
        assert!(initial_sse_body.contains("event: message\n"));
        assert!(initial_sse_body.contains("data: {"));
        assert!(initial_sse_body.contains("\"jsonrpc\":\"2.0\""));
        assert!(initial_sse_body.contains("\"protocolVersion\":\"2025-11-25\""));
        assert_eq!(
            state.sessions.lock().expect("sessions should lock").len(),
            1
        );

        let invalid_protocol = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session_id.as_str()),
                (
                    "MCP-Protocol-Version",
                    "UNSUPPORTED_HTTP_VERSION_SHOULD_NOT_REFLECT",
                ),
            ],
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        );
        let invalid_protocol_response =
            mcp_http_response(&invalid_protocol, &state).expect("bad protocol should be rejected");
        assert_eq!(invalid_protocol_response.status, "400 Bad Request");
        assert!(
            !String::from_utf8_lossy(&invalid_protocol_response.body)
                .contains("UNSUPPORTED_HTTP_VERSION_SHOULD_NOT_REFLECT")
        );
        let client_messages_seen = state
            .sessions
            .lock()
            .expect("session lock should not be poisoned")
            .get(&session_id)
            .expect("session should still exist")
            .lock()
            .expect("session lock should not be poisoned")
            .proxy
            .session_report()
            .client_messages_seen;
        assert_eq!(client_messages_seen, 2);

        let tools = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        );
        let tools_response =
            mcp_http_response(&tools, &state).expect("tools/list should produce response");
        assert_eq!(tools_response.status, "200 OK");
        let tools_json: serde_json::Value =
            serde_json::from_slice(&tools_response.body).expect("tools response should be json");
        assert!(tools_json["result"]["tools"].is_array());

        let resumed_sse = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                ("Last-Event-ID", "1"),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            Vec::new(),
        );
        let resumed_sse_response =
            mcp_http_response(&resumed_sse, &state).expect("SSE resume should return new events");
        assert_eq!(resumed_sse_response.status, "200 OK");
        assert_eq!(
            response_header(&resumed_sse_response, "Last-Event-ID"),
            Some("2")
        );
        let resumed_sse_body = String::from_utf8_lossy(&resumed_sse_response.body);
        assert!(!resumed_sse_body.contains("id: 1\n"));
        assert!(resumed_sse_body.contains("id: 2\n"));
        assert!(resumed_sse_body.contains("\"tools\""));

        let current_sse = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                ("Last-Event-ID", "2"),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            Vec::new(),
        );
        let current_sse_response =
            mcp_http_response(&current_sse, &state).expect("current SSE resume should heartbeat");
        assert_eq!(current_sse_response.status, "200 OK");
        assert_eq!(
            response_header(&current_sse_response, "Last-Event-ID"),
            Some("2")
        );
        assert_eq!(
            String::from_utf8_lossy(&current_sse_response.body),
            ": agentk no buffered events\n\n"
        );

        {
            let session = Arc::clone(
                state
                    .sessions
                    .lock()
                    .expect("sessions should lock")
                    .get(&session_id)
                    .expect("session should still exist"),
            );
            let mut session = session.lock().expect("session should lock");
            while session.sse_events.front().is_some_and(|event| event.id < 2) {
                session.sse_events.pop_front();
            }
        }
        let evicted_sse = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                ("Last-Event-ID", "0"),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            Vec::new(),
        );
        let evicted_sse_response =
            mcp_http_response(&evicted_sse, &state).expect("evicted SSE resume should fail");
        assert_eq!(evicted_sse_response.status, "410 Gone");
        assert!(
            String::from_utf8_lossy(&evicted_sse_response.body)
                .contains("older than the retained MCP HTTP SSE buffer")
        );

        let delete = dashboard_test_request_with_headers(
            "DELETE",
            "/mcp",
            [
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            Vec::new(),
        );
        let delete_response =
            mcp_http_response(&delete, &state).expect("delete should be accepted");
        assert_eq!(delete_response.status, "202 Accepted");

        let post_delete_sse = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            Vec::new(),
        );
        let post_delete_sse_response = mcp_http_response(&post_delete_sse, &state)
            .expect("deleted session SSE should be gone");
        assert_eq!(post_delete_sse_response.status, "404 Not Found");

        let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
        assert_eq!(metrics.requests_total, 12);
        assert_eq!(metrics.post_requests, 4);
        assert_eq!(metrics.get_requests, 7);
        assert_eq!(metrics.delete_requests, 1);
        assert_eq!(metrics.client_error_responses, 5);
        assert_eq!(metrics.server_error_responses, 0);
        assert_eq!(metrics.sse_stream_requests, 3);
        assert_eq!(metrics.sse_resume_requests, 2);
        assert_eq!(metrics.sse_invalid_resume_requests, 2);
        assert_eq!(metrics.sse_evicted_resume_requests, 1);
        assert_eq!(metrics.sse_events_returned, 2);
        assert_eq!(metrics.session_not_found, 1);
        assert_eq!(metrics.sessions_created, 1);
        assert_eq!(metrics.sessions_deleted, 1);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_response_reports_sse_buffer_pressure_and_evictions() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-buffer-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });

        let initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let initialize_response =
            mcp_http_response(&initialize, &state).expect("initialize should produce response");
        assert_eq!(initialize_response.status, "200 OK");
        let session_id = response_header(&initialize_response, "Mcp-Session-Id")
            .expect("initialize should return session id")
            .to_string();

        {
            let session = Arc::clone(
                state
                    .sessions
                    .lock()
                    .expect("sessions should lock")
                    .get(&session_id)
                    .expect("session should exist"),
            );
            let mut session = session.lock().expect("session should lock");
            while session.sse_events.len() < MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION {
                let McpHttpSession {
                    sse_events,
                    next_sse_event_id,
                    ..
                } = &mut *session;
                assert_eq!(
                    mcp_http_push_sse_event(sse_events, next_sse_event_id, b"{}"),
                    0
                );
            }
            assert_eq!(
                session.sse_events.len(),
                MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION
            );
            assert_eq!(session.sse_events.front().map(|event| event.id), Some(1));
            assert_eq!(
                session.sse_events.back().map(|event| event.id),
                Some(MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION as u64)
            );
        }

        let tools = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        );
        let tools_response =
            mcp_http_response(&tools, &state).expect("tools/list should produce response");
        assert_eq!(tools_response.status, "200 OK");

        let snapshot = mcp_http_sse_buffer_snapshot(&state).expect("snapshot should be available");
        assert_eq!(snapshot.active_sessions, 1);
        assert_eq!(snapshot.sessions_with_buffered_events, 1);
        assert_eq!(
            snapshot.buffered_events,
            MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION
        );
        assert_eq!(
            snapshot.buffer_capacity,
            MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION
        );
        assert_eq!(
            mcp_http_metrics_snapshot(&state)
                .expect("metrics should snapshot")
                .sse_event_buffer_evictions,
            1
        );

        let ready = mcp_http_response(
            &dashboard_test_request("GET", "/readyz", Vec::new()),
            &state,
        )
        .expect("readyz should respond");
        assert_eq!(ready.status, "200 OK");
        let ready_json: serde_json::Value =
            serde_json::from_slice(&ready.body).expect("readyz should be JSON");
        assert_eq!(ready_json["active_sessions"], serde_json::json!(1));
        assert_eq!(
            ready_json["sse_sessions_with_buffered_events"],
            serde_json::json!(1)
        );
        assert_eq!(
            ready_json["sse_buffered_events"],
            serde_json::json!(MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION)
        );
        assert_eq!(
            ready_json["sse_buffer_capacity"],
            serde_json::json!(MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION)
        );
        assert_eq!(
            ready_json["sse_event_buffer_evictions"],
            serde_json::json!(1)
        );

        let metrics = mcp_http_response(
            &dashboard_test_request("GET", "/metrics", Vec::new()),
            &state,
        )
        .expect("metrics should respond");
        assert_eq!(metrics.status, "200 OK");
        let metrics_body = String::from_utf8(metrics.body).expect("metrics should be utf8");
        assert!(metrics_body.contains("agentk_mcp_http_active_sessions 1\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_sessions_with_buffered_events 1\n"));
        assert!(metrics_body.contains(&format!(
            "agentk_mcp_http_sse_buffered_events {}\n",
            MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION
        )));
        assert!(metrics_body.contains(&format!(
            "agentk_mcp_http_sse_buffer_capacity {}\n",
            MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION
        )));
        assert!(metrics_body.contains("agentk_mcp_http_sse_event_buffer_evictions_total 1\n"));

        let evicted_resume = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("Last-Event-ID", "0"),
            ],
            Vec::new(),
        );
        let evicted_resume_response =
            mcp_http_response(&evicted_resume, &state).expect("evicted resume should fail closed");
        assert_eq!(evicted_resume_response.status, "410 Gone");
        assert_eq!(
            mcp_http_metrics_snapshot(&state)
                .expect("metrics should snapshot")
                .sse_evicted_resume_requests,
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_response_sanitizes_downstream_spawn_failures() {
        let missing_command = "agentk-missing-downstream-command-9f8d7c6b";
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new(
                "agent://test",
                "http-missing-probe",
                missing_command,
            )
            .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Origin", "http://127.0.0.1:3000"),
            ],
            r#"{"jsonrpc":"2.0","id":"spawn-check","method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"CLIENT_SECRET_SHOULD_NOT_REFLECT","version":"0"}}}"#,
        );

        let response =
            mcp_http_response(&initialize, &state).expect("spawn failure should return response");

        assert_eq!(response.status, "502 Bad Gateway");
        assert_eq!(response.content_type, "application/json");
        assert_eq!(
            response_header(&response, "Access-Control-Allow-Origin"),
            Some("http://127.0.0.1:3000")
        );
        let body = String::from_utf8(response.body.clone()).expect("body should be utf8");
        assert!(!body.contains(missing_command));
        assert!(!body.contains("CLIENT_SECRET_SHOULD_NOT_REFLECT"));
        let json: serde_json::Value =
            serde_json::from_slice(&response.body).expect("response should be JSON-RPC");
        assert_eq!(json["id"], serde_json::json!("spawn-check"));
        assert_eq!(
            json["error"]["message"],
            serde_json::json!("Downstream MCP gateway error")
        );
        assert_eq!(
            json["error"]["data"]["agentk"]["downstream_forwarded"],
            serde_json::json!(false)
        );
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
        let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.post_requests, 1);
        assert_eq!(metrics.server_error_responses, 1);
        assert_eq!(metrics.downstream_transport_error_responses, 1);
        assert_eq!(metrics.gateway_internal_error_responses, 0);
        assert_eq!(metrics.sessions_created, 0);
    }

    #[test]
    fn mcp_http_response_handles_browser_cors_preflight_without_auth() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: vec!["https://console.example".to_string()],
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let preflight = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Origin", "http://localhost:5173"),
                ("Access-Control-Request-Method", "POST"),
                (
                    "Access-Control-Request-Headers",
                    "authorization, mcp-session-id, mcp-protocol-version",
                ),
            ],
            Vec::new(),
        );

        let response = mcp_http_response(&preflight, &state).expect("preflight should be handled");
        assert_eq!(response.status, "204 No Content");
        assert!(response.body.is_empty());
        assert_eq!(
            response_header(&response, "Access-Control-Allow-Origin"),
            Some("http://localhost:5173")
        );
        assert_eq!(response_header(&response, "Vary"), Some("Origin"));
        assert_eq!(
            response_header(&response, "Access-Control-Allow-Methods"),
            Some("POST, GET, DELETE, OPTIONS")
        );
        assert!(
            response_header(&response, "Access-Control-Allow-Headers")
                .expect("preflight should list allowed headers")
                .contains("MCP-Protocol-Version")
        );
        assert!(
            response_header(&response, "Access-Control-Allow-Headers")
                .expect("preflight should list allowed headers")
                .contains("Last-Event-ID")
        );
        assert_eq!(response_header(&response, "WWW-Authenticate"), None);

        let configured_origin = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Origin", "https://console.example"),
                ("Access-Control-Request-Method", "DELETE"),
            ],
            Vec::new(),
        );
        let configured_response = mcp_http_response(&configured_origin, &state)
            .expect("configured origin preflight should be handled");
        assert_eq!(configured_response.status, "204 No Content");
        assert_eq!(
            response_header(&configured_response, "Access-Control-Allow-Origin"),
            Some("https://console.example")
        );

        let ipv6_local_origin = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Origin", "http://[::1]:5173"),
                ("Access-Control-Request-Method", "POST"),
            ],
            Vec::new(),
        );
        let ipv6_local_response = mcp_http_response(&ipv6_local_origin, &state)
            .expect("IPv6 loopback origin preflight should be handled");
        assert_eq!(ipv6_local_response.status, "204 No Content");
        assert_eq!(
            response_header(&ipv6_local_response, "Access-Control-Allow-Origin"),
            Some("http://[::1]:5173")
        );

        let missing_origin = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [("Access-Control-Request-Method", "POST")],
            Vec::new(),
        );
        let missing_origin_response = mcp_http_response(&missing_origin, &state)
            .expect("preflight without origin should be rejected");
        assert_eq!(missing_origin_response.status, "400 Bad Request");
        assert_eq!(
            response_header(&missing_origin_response, "Access-Control-Allow-Origin"),
            None
        );
        assert_eq!(
            response_header(&missing_origin_response, "Access-Control-Allow-Methods"),
            None
        );
        assert!(
            String::from_utf8_lossy(&missing_origin_response.body)
                .contains("preflight requires an allowed Origin")
        );

        let unauthorized_post = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Origin", "http://localhost:5173"),
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let unauthorized_response = mcp_http_response(&unauthorized_post, &state)
            .expect("unauthorized request should still get CORS headers");
        assert_eq!(unauthorized_response.status, "401 Unauthorized");
        assert_eq!(
            response_header(&unauthorized_response, "Access-Control-Allow-Origin"),
            Some("http://localhost:5173")
        );
        assert_eq!(
            response_header(&unauthorized_response, "WWW-Authenticate"),
            Some("Bearer realm=\"agentk-mcp\"")
        );

        let bad_origin = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [("Origin", "http://localhost.evil.example.invalid")],
            Vec::new(),
        );
        let bad_origin_response =
            mcp_http_response(&bad_origin, &state).expect("bad origin should be rejected");
        assert_eq!(bad_origin_response.status, "403 Forbidden");
        assert_eq!(
            response_header(&bad_origin_response, "Access-Control-Allow-Origin"),
            None
        );
        let localhost_suffix = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [("Origin", "http://localhost.evil.example")],
            Vec::new(),
        );
        let localhost_suffix_response = mcp_http_response(&localhost_suffix, &state)
            .expect("localhost suffix origin should be rejected");
        assert_eq!(localhost_suffix_response.status, "403 Forbidden");
        for malformed_origin in [
            "http://localhost:",
            "http://localhost:abc",
            "http://localhost:5173/path",
            "http://127.0.0.1:",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:5173/path",
            "http://[::1]:abc",
            "http://[::1]:5173/path",
        ] {
            let malformed_origin_request = dashboard_test_request_with_headers(
                "OPTIONS",
                "/mcp",
                [("Origin", malformed_origin)],
                Vec::new(),
            );
            let malformed_origin_response = mcp_http_response(&malformed_origin_request, &state)
                .expect("malformed local origin should be rejected");
            assert_eq!(
                malformed_origin_response.status, "403 Forbidden",
                "{malformed_origin} should be rejected"
            );
            assert_eq!(
                response_header(&malformed_origin_response, "Access-Control-Allow-Origin"),
                None
            );
        }
        let missing_preflight_method = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [("Origin", "http://localhost:5173")],
            Vec::new(),
        );
        let missing_preflight_method_response =
            mcp_http_response(&missing_preflight_method, &state)
                .expect("missing preflight method should be rejected");
        assert_eq!(missing_preflight_method_response.status, "400 Bad Request");
        assert_eq!(
            response_header(
                &missing_preflight_method_response,
                "Access-Control-Allow-Origin"
            ),
            Some("http://localhost:5173")
        );
        assert!(
            String::from_utf8_lossy(&missing_preflight_method_response.body)
                .contains("preflight method is required")
        );

        let unsupported_preflight_method = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Origin", "http://localhost:5173"),
                ("Access-Control-Request-Method", "PATCH"),
            ],
            Vec::new(),
        );
        let unsupported_preflight_method_response =
            mcp_http_response(&unsupported_preflight_method, &state)
                .expect("unsupported preflight method should be rejected");
        assert_eq!(
            unsupported_preflight_method_response.status,
            "400 Bad Request"
        );
        assert_eq!(
            response_header(
                &unsupported_preflight_method_response,
                "Access-Control-Allow-Origin"
            ),
            Some("http://localhost:5173")
        );

        let unsupported_preflight_header = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Origin", "http://localhost:5173"),
                ("Access-Control-Request-Method", "POST"),
                (
                    "Access-Control-Request-Headers",
                    "authorization, x-unsafe-header",
                ),
            ],
            Vec::new(),
        );
        let unsupported_preflight_header_response =
            mcp_http_response(&unsupported_preflight_header, &state)
                .expect("unsupported preflight header should be rejected");
        assert_eq!(
            unsupported_preflight_header_response.status,
            "400 Bad Request"
        );
        assert!(
            String::from_utf8_lossy(&unsupported_preflight_header_response.body)
                .contains("preflight header is not allowed")
        );
        assert_eq!(
            response_header(
                &unsupported_preflight_header_response,
                "Access-Control-Allow-Origin"
            ),
            Some("http://localhost:5173")
        );
        let private_network_preflight = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Origin", "http://localhost:5173"),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Private-Network", "true"),
            ],
            Vec::new(),
        );
        let private_network_preflight_response =
            mcp_http_response(&private_network_preflight, &state)
                .expect("private-network preflight should be rejected");
        assert_eq!(private_network_preflight_response.status, "400 Bad Request");
        assert!(
            String::from_utf8_lossy(&private_network_preflight_response.body)
                .contains("private-network")
        );
        assert_eq!(
            response_header(
                &private_network_preflight_response,
                "Access-Control-Allow-Origin"
            ),
            Some("http://localhost:5173")
        );
        assert_eq!(
            response_header(
                &private_network_preflight_response,
                "Access-Control-Allow-Private-Network"
            ),
            None
        );
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
        let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
        assert_eq!(metrics.preflight_rejections, 5);
    }

    #[test]
    fn mcp_http_response_requires_explicit_null_origin_opt_in() {
        let default_state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let null_preflight = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Origin", "null"),
                ("Access-Control-Request-Method", "POST"),
            ],
            Vec::new(),
        );
        let rejected = mcp_http_response(&null_preflight, &default_state)
            .expect("default null origin should be rejected");
        assert_eq!(rejected.status, "403 Forbidden");
        assert_eq!(
            response_header(&rejected, "Access-Control-Allow-Origin"),
            None
        );
        assert_eq!(
            mcp_http_metrics_snapshot(&default_state)
                .expect("metrics should snapshot")
                .origin_rejections,
            1
        );

        let opt_in_state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: vec!["null".to_string()],
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let allowed = mcp_http_response(&null_preflight, &opt_in_state)
            .expect("explicit null origin should be allowed");
        assert_eq!(allowed.status, "204 No Content");
        assert_eq!(
            response_header(&allowed, "Access-Control-Allow-Origin"),
            Some("null")
        );
    }

    #[test]
    fn mcp_http_response_requires_local_host_for_builtin_origin() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: vec!["https://console.example".to_string()],
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let local_origin_nonlocal_host = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Host", "agentk.example.invalid"),
                ("Origin", "http://localhost:5173"),
                ("Access-Control-Request-Method", "POST"),
            ],
            Vec::new(),
        );
        let rejected = mcp_http_response(&local_origin_nonlocal_host, &state)
            .expect("built-in local origin should require local Host");
        assert_eq!(rejected.status, "403 Forbidden");
        assert_eq!(
            response_header(&rejected, "Access-Control-Allow-Origin"),
            None
        );
        assert_eq!(
            mcp_http_metrics_snapshot(&state)
                .expect("metrics should snapshot")
                .origin_rejections,
            1
        );

        let configured_origin_nonlocal_host = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Host", "agentk.example.invalid"),
                ("Origin", "https://console.example"),
                ("Access-Control-Request-Method", "DELETE"),
            ],
            Vec::new(),
        );
        let configured = mcp_http_response(&configured_origin_nonlocal_host, &state)
            .expect("configured origin should not require local Host");
        assert_eq!(configured.status, "204 No Content");
        assert_eq!(
            response_header(&configured, "Access-Control-Allow-Origin"),
            Some("https://console.example")
        );

        let local_origin_local_host = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Host", "127.0.0.1:9798"),
                ("Origin", "http://localhost:5173"),
                ("Access-Control-Request-Method", "POST"),
            ],
            Vec::new(),
        );
        let local = mcp_http_response(&local_origin_local_host, &state)
            .expect("built-in local origin should allow local Host");
        assert_eq!(local.status, "204 No Content");
        assert_eq!(
            response_header(&local, "Access-Control-Allow-Origin"),
            Some("http://localhost:5173")
        );

        let ipv6_local = dashboard_test_request_with_headers(
            "OPTIONS",
            "/mcp",
            [
                ("Host", "[::1]:9798"),
                ("Origin", "http://[::1]:5173"),
                ("Access-Control-Request-Method", "POST"),
            ],
            Vec::new(),
        );
        let ipv6 = mcp_http_response(&ipv6_local, &state)
            .expect("built-in IPv6 local origin should allow IPv6 local Host");
        assert_eq!(ipv6.status, "204 No Content");
        assert_eq!(
            response_header(&ipv6, "Access-Control-Allow-Origin"),
            Some("http://[::1]:5173")
        );
    }

    #[test]
    fn mcp_http_response_rejects_sse_gets_without_spawning() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });

        let unauthorized = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Origin", "http://localhost:5173"),
            ],
            Vec::new(),
        );
        let unauthorized_response =
            mcp_http_response(&unauthorized, &state).expect("unauthorized SSE should fail");
        assert_eq!(unauthorized_response.status, "401 Unauthorized");
        assert_eq!(
            response_header(&unauthorized_response, "Access-Control-Allow-Origin"),
            Some("http://localhost:5173")
        );

        let missing_accept = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [("Authorization", "Bearer secret")],
            Vec::new(),
        );
        let missing_accept_response =
            mcp_http_response(&missing_accept, &state).expect("missing Accept should fail");
        assert_eq!(missing_accept_response.status, "406 Not Acceptable");
        assert!(
            String::from_utf8_lossy(&missing_accept_response.body)
                .contains("Accept: text/event-stream")
        );

        let bad_session = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Authorization", "Bearer secret"),
                ("Mcp-Session-Id", "BAD_SESSION_SHOULD_NOT_REFLECT"),
            ],
            Vec::new(),
        );
        let bad_session_response =
            mcp_http_response(&bad_session, &state).expect("bad session should fail");
        assert_eq!(bad_session_response.status, "400 Bad Request");
        assert!(
            !String::from_utf8_lossy(&bad_session_response.body)
                .contains("BAD_SESSION_SHOULD_NOT_REFLECT")
        );

        let missing_session = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Authorization", "Bearer secret"),
                ("Origin", "http://127.0.0.1:5173"),
            ],
            Vec::new(),
        );
        let missing_session_response =
            mcp_http_response(&missing_session, &state).expect("missing session should fail");
        assert_eq!(missing_session_response.status, "400 Bad Request");
        assert!(
            String::from_utf8_lossy(&missing_session_response.body)
                .contains("Mcp-Session-Id is required")
        );

        let unknown_session = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Authorization", "Bearer secret"),
                ("Origin", "http://127.0.0.1:5173"),
                ("Mcp-Session-Id", "0123456789abcdef0123456789abcdef"),
            ],
            Vec::new(),
        );
        let unknown_session_response =
            mcp_http_response(&unknown_session, &state).expect("unknown session should fail");
        assert_eq!(unknown_session_response.status, "404 Not Found");
        assert_eq!(
            response_header(&unknown_session_response, "Access-Control-Allow-Origin"),
            Some("http://127.0.0.1:5173")
        );
        assert!(
            String::from_utf8_lossy(&unknown_session_response.body)
                .contains("MCP session not found")
        );

        let duplicate_resume = dashboard_test_request_with_headers(
            "GET",
            "/mcp",
            [
                ("Accept", "text/event-stream"),
                ("Authorization", "Bearer secret"),
                ("Mcp-Session-Id", "0123456789abcdef0123456789abcdef"),
                ("Last-Event-ID", "1"),
                ("Last-Event-ID", "2"),
            ],
            Vec::new(),
        );
        let duplicate_resume_response =
            mcp_http_response(&duplicate_resume, &state).expect("duplicate resume should fail");
        assert_eq!(duplicate_resume_response.status, "400 Bad Request");
        assert!(
            String::from_utf8_lossy(&duplicate_resume_response.body).contains("control header")
        );
        assert!(!String::from_utf8_lossy(&duplicate_resume_response.body).contains("2"));

        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
        let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
        assert_eq!(metrics.requests_total, 6);
        assert_eq!(metrics.get_requests, 6);
        assert_eq!(metrics.auth_rejections, 1);
        assert_eq!(metrics.session_not_found, 1);
        assert_eq!(metrics.sessions_created, 0);
    }

    #[test]
    fn mcp_http_sse_buffer_bounds_events_and_detects_evicted_resume() {
        let mut events = VecDeque::new();
        let mut next_event_id = 1;
        for index in 0..(MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION + 2) {
            mcp_http_push_sse_event(
                &mut events,
                &mut next_event_id,
                format!("event-{index}").as_bytes(),
            );
        }

        assert_eq!(events.len(), MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION);
        assert_eq!(events.front().expect("front event").id, 3);
        assert_eq!(events.back().expect("back event").id, 130);
        assert_eq!(next_event_id, 131);
        let ids = events.iter().map(|event| event.id).collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), events.len());
        assert!(mcp_http_sse_resume_evicted_for_events(&events, Some(0)));
        assert!(mcp_http_sse_resume_evicted_for_events(&events, Some(1)));
        assert!(!mcp_http_sse_resume_evicted_for_events(&events, Some(2)));
        assert!(!mcp_http_sse_resume_evicted_for_events(&events, Some(129)));
        assert!(!mcp_http_sse_resume_evicted_for_events(&events, Some(130)));
    }

    #[test]
    fn mcp_http_auth_accepts_supported_token_headers() {
        let bearer = dashboard_test_request_with_headers(
            "GET",
            "/readyz",
            [("Authorization", "Bearer secret")],
            Vec::new(),
        );
        assert!(mcp_http_auth_allowed(&bearer, Some("secret")));

        let explicit_header = dashboard_test_request_with_headers(
            "GET",
            "/readyz",
            [("X-AgentK-MCP-Token", "secret")],
            Vec::new(),
        );
        assert!(mcp_http_auth_allowed(&explicit_header, Some("secret")));

        let dual_carrier = dashboard_test_request_with_headers(
            "GET",
            "/readyz",
            [
                ("Authorization", "Bearer secret"),
                ("X-AgentK-MCP-Token", "secret"),
            ],
            Vec::new(),
        );
        assert!(!mcp_http_auth_allowed(&dual_carrier, Some("secret")));

        let wrong = dashboard_test_request_with_headers(
            "GET",
            "/readyz",
            [("Authorization", "Bearer wrong")],
            Vec::new(),
        );
        assert!(!mcp_http_auth_allowed(&wrong, Some("secret")));

        let missing = dashboard_test_request("GET", "/readyz", Vec::new());
        assert!(!mcp_http_auth_allowed(&missing, Some("secret")));
        assert!(mcp_http_auth_allowed(&missing, None));
    }

    #[test]
    fn mcp_http_response_rejects_ambiguous_control_headers() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#;
        let cases = vec![
            dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json"),
                    ("Accept", "text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Authorization", "Bearer secret"),
                ],
                body,
            ),
            dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Content-Type", "text/plain"),
                    ("Authorization", "Bearer secret"),
                ],
                body,
            ),
            dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", "session-a"),
                    ("Mcp-Session-Id", "SESSION_SHOULD_NOT_REFLECT"),
                    ("Authorization", "Bearer secret"),
                ],
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            ),
            dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
                    (
                        "MCP-Protocol-Version",
                        "UNSUPPORTED_HTTP_VERSION_SHOULD_NOT_REFLECT",
                    ),
                    ("Authorization", "Bearer secret"),
                ],
                body,
            ),
            dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Origin", "http://localhost:5173"),
                    ("Origin", "https://origin-should-not-reflect.example"),
                    ("Authorization", "Bearer secret"),
                ],
                body,
            ),
            dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Authorization", "Bearer secret"),
                    ("Authorization", "Bearer TOKEN_SHOULD_NOT_REFLECT"),
                ],
                body,
            ),
            dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Authorization", "Bearer secret"),
                    ("X-AgentK-MCP-Token", "TOKEN_SHOULD_NOT_REFLECT"),
                ],
                body,
            ),
            dashboard_test_request_with_headers(
                "OPTIONS",
                "/mcp",
                [
                    ("Origin", "http://localhost:5173"),
                    ("Access-Control-Request-Method", "POST"),
                    ("Access-Control-Request-Method", "DELETE"),
                ],
                Vec::new(),
            ),
        ];

        for request in cases {
            let response =
                mcp_http_response(&request, &state).expect("ambiguous control header should fail");
            assert_eq!(response.status, "400 Bad Request");
            let response_body = String::from_utf8_lossy(&response.body);
            assert!(response_body.contains("MCP HTTP"));
            assert!(!response_body.contains("TOKEN_SHOULD_NOT_REFLECT"));
            assert!(!response_body.contains("SESSION_SHOULD_NOT_REFLECT"));
            assert!(!response_body.contains("UNSUPPORTED_HTTP_VERSION_SHOULD_NOT_REFLECT"));
            assert!(!response_body.contains("origin-should-not-reflect"));
        }

        let ready = dashboard_test_request_with_headers(
            "GET",
            "/readyz",
            [
                ("Authorization", "Bearer secret"),
                ("X-AgentK-MCP-Token", "secret"),
            ],
            Vec::new(),
        );
        let ready_response =
            mcp_http_response(&ready, &state).expect("ambiguous readyz auth should fail");
        assert_eq!(ready_response.status, "400 Bad Request");
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
    }

    #[test]
    fn mcp_http_response_rejects_invalid_json_media_type() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let request = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json-patch"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );

        let response = mcp_http_response(&request, &state).expect("invalid media type should fail");
        assert_eq!(response.status, "415 Unsupported Media Type");
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_response_rejects_invalid_json_rpc_shapes_before_session_forwarding() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-shape-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let initialize_response =
            mcp_http_response(&initialize, &state).expect("initialize should create session");
        assert_eq!(initialize_response.status, "200 OK");
        let session_id = response_header(&initialize_response, "Mcp-Session-Id")
            .expect("initialize should return session")
            .to_string();

        let cases = [
            (
                r#"[{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"secret":"SHAPE_SECRET_BATCH"}}]"#,
                "batch requests are not supported",
            ),
            (
                r#""SHAPE_SECRET_PRIMITIVE""#,
                "message must be a JSON object",
            ),
            (
                r#"{"jsonrpc":"2.0","id":"shape-response","result":{"secret":"SHAPE_SECRET_RESPONSE"}}"#,
                "method must be a string",
            ),
            (
                r#"{"id":"shape-jsonrpc","method":"tools/list","params":{"secret":"SHAPE_SECRET_JSONRPC"}}"#,
                "jsonrpc must be \"2.0\"",
            ),
            (
                r#"{"jsonrpc":"2.0","id":"shape-method","method":{"secret":"SHAPE_SECRET_METHOD"}}"#,
                "method must be a string",
            ),
        ];

        for (body, detail) in cases {
            let request = dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", session_id.as_str()),
                    ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
                ],
                body,
            );
            let response =
                mcp_http_response(&request, &state).expect("invalid shape should fail closed");
            assert_eq!(response.status, "400 Bad Request");
            assert_eq!(response.content_type, "application/json");
            let response_body = String::from_utf8_lossy(&response.body);
            assert!(!response_body.contains("SHAPE_SECRET"));
            let response_json: serde_json::Value =
                serde_json::from_slice(&response.body).expect("response should be JSON-RPC");
            assert_eq!(response_json["error"]["code"], serde_json::json!(-32600));
            assert_eq!(
                response_json["error"]["message"],
                serde_json::json!("Invalid Request")
            );
            assert_eq!(
                response_json["error"]["data"]["detail"],
                serde_json::json!(detail)
            );
        }

        let session = Arc::clone(
            state
                .sessions
                .lock()
                .expect("sessions should lock")
                .get(&session_id)
                .expect("session should still exist"),
        );
        let session = session.lock().expect("session should lock");
        assert_eq!(session.proxy.session_report().client_messages_seen, 1);
        assert_eq!(session.sse_events.len(), 1);
        drop(session);

        let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
        assert_eq!(metrics.requests_total, 6);
        assert_eq!(metrics.post_requests, 6);
        assert_eq!(metrics.client_error_responses, 5);
        assert_eq!(metrics.sessions_created, 1);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_response_rejects_invalid_json_rpc_ids_before_session_forwarding() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-id-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let initialize_response =
            mcp_http_response(&initialize, &state).expect("initialize should create session");
        assert_eq!(initialize_response.status, "200 OK");
        let session_id = response_header(&initialize_response, "Mcp-Session-Id")
            .expect("initialize should return session")
            .to_string();
        let long_id = format!(
            "ID_SECRET_LONG_{}",
            "x".repeat(MCP_HTTP_JSON_RPC_MAX_ID_BYTES)
        );
        let cases = [
            (
                r#"{"jsonrpc":"2.0","id":{"secret":"ID_SECRET_OBJECT"},"method":"tools/list","params":{}}"#.to_string(),
                "id must be a string, integer, or null".to_string(),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1.5,"method":"tools/list","params":{}}"#.to_string(),
                "id number must be an integer".to_string(),
            ),
            (
                format!(
                    r#"{{"jsonrpc":"2.0","id":"{long_id}","method":"tools/list","params":{{}}}}"#
                ),
                format!("id string must be at most {MCP_HTTP_JSON_RPC_MAX_ID_BYTES} bytes"),
            ),
            (
                r#"{"jsonrpc":"2.0","id":true,"method":"tools/list","params":{}}"#.to_string(),
                "id must be a string, integer, or null".to_string(),
            ),
        ];

        for (body, detail) in &cases {
            let request = dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", session_id.as_str()),
                    ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
                ],
                body.as_str(),
            );
            let response =
                mcp_http_response(&request, &state).expect("invalid id should fail closed");
            assert_eq!(response.status, "400 Bad Request");
            assert_eq!(response.content_type, "application/json");
            let response_body = String::from_utf8_lossy(&response.body);
            assert!(!response_body.contains("ID_SECRET"));
            let response_json: serde_json::Value =
                serde_json::from_slice(&response.body).expect("response should be JSON-RPC");
            assert_eq!(response_json["id"], serde_json::Value::Null);
            assert_eq!(response_json["error"]["code"], serde_json::json!(-32600));
            assert_eq!(
                response_json["error"]["message"],
                serde_json::json!("Invalid Request")
            );
            assert_eq!(
                response_json["error"]["data"]["detail"],
                serde_json::json!(detail)
            );
        }

        let bad_initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":{"secret":"ID_SECRET_PRESESSION"},"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let bad_initialize_response =
            mcp_http_response(&bad_initialize, &state).expect("invalid initialize id should fail");
        assert_eq!(bad_initialize_response.status, "400 Bad Request");
        assert!(
            !String::from_utf8_lossy(&bad_initialize_response.body)
                .contains("ID_SECRET_PRESESSION")
        );

        let session = Arc::clone(
            state
                .sessions
                .lock()
                .expect("sessions should lock")
                .get(&session_id)
                .expect("session should still exist"),
        );
        let session = session.lock().expect("session should lock");
        assert_eq!(session.proxy.session_report().client_messages_seen, 1);
        assert_eq!(session.sse_events.len(), 1);
        drop(session);

        let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
        assert_eq!(metrics.requests_total, 6);
        assert_eq!(metrics.post_requests, 6);
        assert_eq!(metrics.client_error_responses, 5);
        assert_eq!(metrics.invalid_json_rpc_id_requests, 5);
        assert_eq!(metrics.sessions_created, 1);
    }

    #[test]
    fn mcp_http_response_rejects_unexpected_request_bodies() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let cases = vec![
            dashboard_test_request("GET", "/mcp", "BODY_SHOULD_NOT_REFLECT"),
            dashboard_test_request_with_headers(
                "OPTIONS",
                "/mcp",
                [("Origin", "http://localhost:5173")],
                "BODY_SHOULD_NOT_REFLECT",
            ),
            dashboard_test_request_with_headers(
                "DELETE",
                "/mcp",
                [
                    ("Mcp-Session-Id", "session-a"),
                    ("Authorization", "Bearer secret"),
                ],
                "BODY_SHOULD_NOT_REFLECT",
            ),
            dashboard_test_request("GET", "/healthz", "BODY_SHOULD_NOT_REFLECT"),
            dashboard_test_request_with_headers(
                "GET",
                "/metrics",
                [("Authorization", "Bearer secret")],
                "BODY_SHOULD_NOT_REFLECT",
            ),
            dashboard_test_request("POST", "/missing", "BODY_SHOULD_NOT_REFLECT"),
        ];

        for request in cases {
            let response =
                mcp_http_response(&request, &state).expect("unexpected body should fail closed");
            assert_eq!(response.status, "400 Bad Request");
            let response_body = String::from_utf8_lossy(&response.body);
            assert!(response_body.contains("MCP HTTP request bodies"));
            assert!(!response_body.contains("BODY_SHOULD_NOT_REFLECT"));
        }
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );

        let head_with_body = dashboard_test_request_with_headers(
            "HEAD",
            "/readyz",
            [("Authorization", "Bearer secret")],
            "BODY_SHOULD_NOT_REFLECT",
        );
        let head_response =
            mcp_http_response(&head_with_body, &state).expect("HEAD body should fail closed");
        assert_eq!(head_response.status, "400 Bad Request");
        assert!(head_response.body.is_empty());
    }

    #[test]
    fn mcp_http_response_rejects_endpoint_and_probe_query_strings() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let cases = vec![
            dashboard_test_request_with_headers(
                "POST",
                "/mcp?session=QUERY_SHOULD_NOT_REFLECT",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                ],
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
            ),
            dashboard_test_request_with_headers(
                "OPTIONS",
                "/mcp?origin=QUERY_SHOULD_NOT_REFLECT",
                [
                    ("Origin", "http://localhost:5173"),
                    ("Access-Control-Request-Method", "POST"),
                ],
                Vec::new(),
            ),
            dashboard_test_request_with_headers(
                "DELETE",
                "/mcp?session=QUERY_SHOULD_NOT_REFLECT",
                [
                    ("Authorization", "Bearer secret"),
                    ("Mcp-Session-Id", "session-a"),
                ],
                Vec::new(),
            ),
            dashboard_test_request("GET", "/healthz?probe=QUERY_SHOULD_NOT_REFLECT", Vec::new()),
            dashboard_test_request_with_headers(
                "GET",
                "/readyz?probe=QUERY_SHOULD_NOT_REFLECT",
                [("Authorization", "Bearer secret")],
                Vec::new(),
            ),
            dashboard_test_request_with_headers(
                "GET",
                "/metrics?probe=QUERY_SHOULD_NOT_REFLECT",
                [("Authorization", "Bearer secret")],
                Vec::new(),
            ),
        ];

        for request in cases {
            let response =
                mcp_http_response(&request, &state).expect("query target should fail closed");
            assert_eq!(response.status, "400 Bad Request");
            let response_body = String::from_utf8_lossy(&response.body);
            assert!(response_body.contains("query strings"));
            assert!(!response_body.contains("QUERY_SHOULD_NOT_REFLECT"));
        }
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
    }

    #[test]
    fn mcp_http_allow_origin_env_parses_comma_separated_origins() {
        let origins = mcp_http_parse_allow_origin_env(
            " https://console.example, http://localhost:5173 , null, vscode-webview://agentk, http://[::1]:5173 ",
        )
        .expect("allow-origin env should parse");
        assert_eq!(
            origins,
            vec![
                "https://console.example".to_string(),
                "http://localhost:5173".to_string(),
                "null".to_string(),
                "vscode-webview://agentk".to_string(),
                "http://[::1]:5173".to_string(),
            ]
        );
        assert!(mcp_http_parse_allow_origin_env("https://bad.exa\nmple").is_err());
        for bad_origin in [
            "",
            "*",
            " https://console.example",
            "https://console.example ",
            "https://console.example/path",
            "https://console.example?debug=1",
            "https://console.example#fragment",
            "https://user@console.example",
            "https://*",
            "https://*.example",
            "https://bad;host",
            "https://bad_host.example",
            "https://bad%20host.example",
            "https://-console.example",
            "https://console-.example",
            "https://console..example",
            "https://console.example:",
            "https://console.example:99999",
            "https://2001:db8::1",
            "http://[::1",
            "http://[not-ip]",
            "http://[127.0.0.1]",
            "http://[::1]:bad",
            "console.example",
            "1bad://console.example",
        ] {
            assert!(
                mcp_http_validate_configured_origin(bad_origin).is_err(),
                "{bad_origin:?} should be rejected"
            );
        }
    }

    #[test]
    fn mcp_http_response_rejects_bad_origin_and_missing_session() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let bad_origin = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Origin", "https://evil.example.invalid"),
            ],
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        );
        let bad_origin_response =
            mcp_http_response(&bad_origin, &state).expect("bad origin should be handled");
        assert_eq!(bad_origin_response.status, "403 Forbidden");

        let missing_session = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
            ],
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        );
        let missing_session_response =
            mcp_http_response(&missing_session, &state).expect("missing session should be handled");
        assert_eq!(missing_session_response.status, "400 Bad Request");

        let bad_protocol = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                (
                    "MCP-Protocol-Version",
                    "UNSUPPORTED_HTTP_VERSION_SHOULD_NOT_REFLECT",
                ),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let bad_protocol_response =
            mcp_http_response(&bad_protocol, &state).expect("bad protocol should be handled");
        assert_eq!(bad_protocol_response.status, "400 Bad Request");
        assert!(
            !String::from_utf8_lossy(&bad_protocol_response.body)
                .contains("UNSUPPORTED_HTTP_VERSION_SHOULD_NOT_REFLECT")
        );
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
    }

    #[test]
    fn mcp_http_response_rejects_malformed_session_ids_without_reflection() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        for bad_session_id in [
            "",
            "SESSION_SHOULD_NOT_REFLECT",
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcdef00",
        ] {
            let post = dashboard_test_request_with_headers(
                "POST",
                "/mcp",
                [
                    ("Accept", "application/json, text/event-stream"),
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", bad_session_id),
                ],
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            );
            let post_response =
                mcp_http_response(&post, &state).expect("malformed POST session id should fail");
            assert_eq!(post_response.status, "400 Bad Request");
            let post_body = String::from_utf8_lossy(&post_response.body);
            assert!(post_body.contains("Mcp-Session-Id"));
            if !bad_session_id.is_empty() {
                assert!(!post_body.contains(bad_session_id));
            }

            let delete = dashboard_test_request_with_headers(
                "DELETE",
                "/mcp",
                [("Mcp-Session-Id", bad_session_id)],
                Vec::new(),
            );
            let delete_response = mcp_http_response(&delete, &state)
                .expect("malformed DELETE session id should fail");
            assert_eq!(delete_response.status, "400 Bad Request");
            let delete_body = String::from_utf8_lossy(&delete_response.body);
            assert!(delete_body.contains("Mcp-Session-Id"));
            if !bad_session_id.is_empty() {
                assert!(!delete_body.contains(bad_session_id));
            }
        }

        let valid_unknown_session_id = "0123456789abcdef0123456789abcdef";
        let valid_unknown = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", valid_unknown_session_id),
            ],
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        );
        let valid_unknown_response =
            mcp_http_response(&valid_unknown, &state).expect("unknown session should be handled");
        assert_eq!(valid_unknown_response.status, "404 Not Found");
        assert!(
            !String::from_utf8_lossy(&valid_unknown_response.body)
                .contains(valid_unknown_session_id)
        );
        assert_eq!(
            mcp_http_metrics_snapshot(&state)
                .expect("metrics should snapshot")
                .session_not_found,
            1
        );
    }

    #[test]
    fn mcp_http_response_rejects_protocol_version_mismatches() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });

        let bad_initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Protocol-Version", "1900-01-01"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0.0.0"}}}"#,
        );
        let bad_initialize_response =
            mcp_http_response(&bad_initialize, &state).expect("bad protocol should be handled");
        assert_eq!(bad_initialize_response.status, "400 Bad Request");
        assert!(
            String::from_utf8_lossy(&bad_initialize_response.body)
                .contains("MCP-Protocol-Version must be 2025-11-25")
        );
        assert_eq!(
            state.sessions.lock().expect("sessions should lock").len(),
            0
        );

        let good_initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0.0.0"}}}"#,
        );
        let good_initialize_response = mcp_http_response(&good_initialize, &state)
            .expect("supported protocol should initialize");
        assert_eq!(good_initialize_response.status, "200 OK");
        let session_id = response_header(&good_initialize_response, "Mcp-Session-Id")
            .expect("initialize should return session")
            .to_string();

        let bad_followup = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("Mcp-Protocol-Version", "1900-01-01"),
            ],
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        );
        let bad_followup_response =
            mcp_http_response(&bad_followup, &state).expect("bad followup should be handled");
        assert_eq!(bad_followup_response.status, "400 Bad Request");
        assert_eq!(
            state.sessions.lock().expect("sessions should lock").len(),
            1
        );

        let bad_delete = dashboard_test_request_with_headers(
            "DELETE",
            "/mcp",
            [
                ("Mcp-Session-Id", session_id.as_str()),
                ("Mcp-Protocol-Version", "1900-01-01"),
            ],
            Vec::new(),
        );
        let bad_delete_response =
            mcp_http_response(&bad_delete, &state).expect("bad delete should be handled");
        assert_eq!(bad_delete_response.status, "400 Bad Request");
        assert_eq!(
            state.sessions.lock().expect("sessions should lock").len(),
            1
        );

        let good_delete = dashboard_test_request_with_headers(
            "DELETE",
            "/mcp",
            [
                ("Mcp-Session-Id", session_id.as_str()),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            Vec::new(),
        );
        let good_delete_response =
            mcp_http_response(&good_delete, &state).expect("good delete should be accepted");
        assert_eq!(good_delete_response.status, "202 Accepted");
        assert_eq!(
            state.sessions.lock().expect("sessions should lock").len(),
            0
        );
    }

    #[test]
    fn mcp_http_response_rejects_oversized_bodies() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: 16,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let oversized = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );

        let response =
            mcp_http_response(&oversized, &state).expect("oversized body should be handled");
        assert_eq!(response.status, "413 Payload Too Large");
        assert!(
            String::from_utf8_lossy(&response.body)
                .contains("MCP HTTP request body must be at most 16 bytes")
        );
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_response_enforces_active_session_limit() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: 1,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let headers = [
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
            ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
        ];
        let first_initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            headers,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let first_response =
            mcp_http_response(&first_initialize, &state).expect("first initialize should run");
        assert_eq!(first_response.status, "200 OK");
        let session_id = response_header(&first_response, "Mcp-Session-Id")
            .expect("first initialize should return session")
            .to_string();

        let second_initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            headers,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let second_response =
            mcp_http_response(&second_initialize, &state).expect("session cap should be handled");
        assert_eq!(second_response.status, "429 Too Many Requests");
        assert!(
            String::from_utf8_lossy(&second_response.body)
                .contains("MCP HTTP active session limit reached: 1")
        );
        assert_eq!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .len(),
            1
        );

        let delete = dashboard_test_request_with_headers(
            "DELETE",
            "/mcp",
            [
                ("Mcp-Session-Id", session_id.as_str()),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            Vec::new(),
        );
        let delete_response =
            mcp_http_response(&delete, &state).expect("delete should release session");
        assert_eq!(delete_response.status, "202 Accepted");

        let third_response =
            mcp_http_response(&second_initialize, &state).expect("new initialize should fit");
        assert_eq!(third_response.status, "200 OK");
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_session_map_stays_available_while_one_session_is_busy() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-busy-session-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: 2,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let headers = [
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
            ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
        ];
        let first_initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            headers,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let first_response =
            mcp_http_response(&first_initialize, &state).expect("first initialize should run");
        assert_eq!(first_response.status, "200 OK");
        let first_session_id = response_header(&first_response, "Mcp-Session-Id")
            .expect("first initialize should return session")
            .to_string();
        let busy_session = Arc::clone(
            state
                .sessions
                .lock()
                .expect("sessions should lock")
                .get(&first_session_id)
                .expect("first session should exist"),
        );
        let busy_guard = busy_session
            .lock()
            .expect("session lock should not be poisoned");

        let second_initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            headers,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let second_response = mcp_http_response(&second_initialize, &state)
            .expect("second initialize should not wait on busy first session");
        assert_eq!(second_response.status, "200 OK");
        let second_session_id = response_header(&second_response, "Mcp-Session-Id")
            .expect("second initialize should return session");
        assert_ne!(second_session_id, first_session_id);
        assert_eq!(
            state.sessions.lock().expect("sessions should lock").len(),
            2
        );
        drop(busy_guard);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_response_reaps_idle_sessions() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: 1,
            session_idle_timeout: Duration::from_millis(250),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        );
        let first_response =
            mcp_http_response(&initialize, &state).expect("initialize should create session");
        assert_eq!(first_response.status, "200 OK");
        let session_id = response_header(&first_response, "Mcp-Session-Id")
            .expect("session should be returned")
            .to_string();
        {
            let session = Arc::clone(
                state
                    .sessions
                    .lock()
                    .expect("sessions should lock")
                    .get(&session_id)
                    .expect("session should exist"),
            );
            session
                .lock()
                .expect("session lock should not be poisoned")
                .last_seen = Instant::now() - Duration::from_secs(1);
        }

        let ready = mcp_http_response(
            &dashboard_test_request("GET", "/readyz", Vec::new()),
            &state,
        )
        .expect("readyz should prune expired session");
        assert_eq!(ready.status, "200 OK");
        let ready_json: serde_json::Value =
            serde_json::from_slice(&ready.body).expect("readyz should be JSON");
        assert_eq!(ready_json["active_sessions"], serde_json::json!(0));
        assert_eq!(ready_json["expired_sessions_reaped"], serde_json::json!(1));

        let second_response =
            mcp_http_response(&initialize, &state).expect("new initialize should fit after prune");
        assert_eq!(second_response.status, "200 OK");
    }

    #[cfg(unix)]
    #[test]
    fn mcp_http_drain_active_sessions_writes_session_outputs() {
        let trace_path = mcp_proxy_trace_out_test_path("http-drain");
        let session_report_path = mcp_session_report_path(&trace_path);
        let _ = fs::remove_file(&trace_path);
        let _ = fs::remove_file(&session_report_path);
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-drain-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: 1,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: Some(trace_path.clone()),
            session_report_out: Some(session_report_path.clone()),
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let initialize = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0.0.0"}}}"#,
        );
        let initialize_response =
            mcp_http_response(&initialize, &state).expect("initialize should succeed");
        assert_eq!(initialize_response.status, "200 OK");
        let session_id = response_header(&initialize_response, "Mcp-Session-Id")
            .expect("initialize should return session id")
            .to_string();
        let initialized = dashboard_test_request_with_headers(
            "POST",
            "/mcp",
            [
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", session_id.as_str()),
                ("Mcp-Protocol-Version", MCP_PROTOCOL_VERSION),
            ],
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        );
        let initialized_response =
            mcp_http_response(&initialized, &state).expect("initialized notification should run");
        assert_eq!(initialized_response.status, "202 Accepted");
        assert_eq!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .len(),
            1
        );

        let drained = mcp_http_drain_active_sessions(&state).expect("drain should write outputs");
        assert_eq!(drained, 1);
        assert!(
            state
                .sessions
                .lock()
                .expect("session lock should not be poisoned")
                .is_empty()
        );
        let drained_trace_path = mcp_gateway_named_session_path(&trace_path, &session_id);
        let drained_report_path = mcp_gateway_named_session_path(&session_report_path, &session_id);
        assert!(drained_trace_path.exists());
        assert!(drained_report_path.exists());
        let session_report: agentk::McpSubprocessProxySessionReport = serde_json::from_str(
            &fs::read_to_string(&drained_report_path).expect("drained report should read"),
        )
        .expect("drained report should be valid JSON");
        assert_eq!(session_report.server_id, "http-drain-probe");
        assert!(session_report.initialized);
        assert!(session_report.ready);

        let _ = fs::remove_file(drained_trace_path);
        let _ = fs::remove_file(drained_report_path);
        let _ = fs::remove_file(trace_path);
        let _ = fs::remove_file(session_report_path);
    }

    #[test]
    fn mcp_http_response_reports_operational_health_and_readiness() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: vec![
                "https://console.example".to_string(),
                "vscode-webview://agentk".to_string(),
            ],
            auth_token: Some("secret".to_string()),
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });

        let health = mcp_http_response(
            &dashboard_test_request("GET", "/healthz", Vec::new()),
            &state,
        )
        .expect("healthz should respond");
        assert_eq!(health.status, "200 OK");
        assert_eq!(health.content_type, "application/json");
        assert_eq!(health.body, br#"{"ok":true}"#);

        let unauthorized_ready = mcp_http_response(
            &dashboard_test_request("GET", "/readyz", Vec::new()),
            &state,
        )
        .expect("readyz auth failure should respond");
        assert_eq!(unauthorized_ready.status, "401 Unauthorized");
        assert_eq!(
            response_header(&unauthorized_ready, "WWW-Authenticate"),
            Some("Bearer realm=\"agentk-mcp\"")
        );

        let ready = mcp_http_response(
            &dashboard_test_request_with_headers(
                "GET",
                "/readyz",
                [("Authorization", "Bearer secret")],
                Vec::new(),
            ),
            &state,
        )
        .expect("readyz should respond");
        assert_eq!(ready.status, "200 OK");
        let ready_json: serde_json::Value =
            serde_json::from_slice(&ready.body).expect("readyz should be JSON");
        assert_eq!(ready_json["ready"], serde_json::json!(true));
        assert_eq!(ready_json["endpoint"], serde_json::json!("/mcp"));
        assert_eq!(
            ready_json["protocol_version"],
            serde_json::json!(MCP_PROTOCOL_VERSION)
        );
        assert_eq!(ready_json["active_sessions"], serde_json::json!(0));
        assert_eq!(
            ready_json["max_active_sessions"],
            serde_json::json!(MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS)
        );
        assert_eq!(ready_json["max_concurrent_requests"], serde_json::json!(8));
        assert_eq!(
            ready_json["session_idle_timeout_ms"],
            serde_json::json!(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS)
        );
        assert_eq!(ready_json["expired_sessions_reaped"], serde_json::json!(0));
        assert_eq!(
            ready_json["max_body_bytes"],
            serde_json::json!(MCP_HTTP_DEFAULT_MAX_BODY_BYTES)
        );
        assert_eq!(
            ready_json["max_header_bytes"],
            serde_json::json!(MCP_HTTP_DEFAULT_MAX_HEADER_BYTES)
        );
        assert_eq!(
            ready_json["stream_timeout_ms"],
            serde_json::json!(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS)
        );
        assert_eq!(
            ready_json["configured_allowed_origins"],
            serde_json::json!(2)
        );
        assert!(
            !String::from_utf8_lossy(&ready.body).contains("https://console.example"),
            "readyz should report allowed-origin counts without raw origin values"
        );
        assert_eq!(ready_json["auth_required"], serde_json::json!(true));
        assert_eq!(ready_json["requests_total"], serde_json::json!(2));
        assert_eq!(ready_json["get_requests"], serde_json::json!(2));
        assert_eq!(ready_json["auth_rejections"], serde_json::json!(1));
        assert_eq!(ready_json["client_error_responses"], serde_json::json!(1));
        assert_eq!(ready_json["preflight_rejections"], serde_json::json!(0));
        assert_eq!(ready_json["sse_stream_requests"], serde_json::json!(0));
        assert_eq!(ready_json["sse_resume_requests"], serde_json::json!(0));
        assert_eq!(
            ready_json["sse_invalid_resume_requests"],
            serde_json::json!(0)
        );
        assert_eq!(
            ready_json["sse_evicted_resume_requests"],
            serde_json::json!(0)
        );
        assert_eq!(ready_json["sse_events_returned"], serde_json::json!(0));
        assert_eq!(
            ready_json["sse_retained_events_per_session"],
            serde_json::json!(MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION)
        );
        assert_eq!(
            ready_json["sse_sessions_with_buffered_events"],
            serde_json::json!(0)
        );
        assert_eq!(ready_json["sse_buffered_events"], serde_json::json!(0));
        assert_eq!(ready_json["sse_buffer_capacity"], serde_json::json!(0));
        assert_eq!(
            ready_json["sse_event_buffer_evictions"],
            serde_json::json!(0)
        );
        assert_eq!(
            ready_json["invalid_json_rpc_id_requests"],
            serde_json::json!(0)
        );
        assert_eq!(
            ready_json["invalid_framing_responses"],
            serde_json::json!(0)
        );
        assert_eq!(
            ready_json["header_too_large_responses"],
            serde_json::json!(0)
        );
        assert_eq!(ready_json["body_too_large_responses"], serde_json::json!(0));
        assert_eq!(
            ready_json["downstream_transport_error_responses"],
            serde_json::json!(0)
        );
        assert_eq!(
            ready_json["gateway_internal_error_responses"],
            serde_json::json!(0)
        );
        assert_eq!(ready_json["sessions_created"], serde_json::json!(0));
        assert_eq!(ready_json["session_not_found"], serde_json::json!(0));

        let rejected_preflight = mcp_http_response(
            &dashboard_test_request_with_headers(
                "OPTIONS",
                "/mcp",
                [("Origin", "https://console.example")],
                Vec::new(),
            ),
            &state,
        )
        .expect("preflight validation failure should respond");
        assert_eq!(rejected_preflight.status, "400 Bad Request");

        let unauthorized_metrics = mcp_http_response(
            &dashboard_test_request("GET", "/metrics", Vec::new()),
            &state,
        )
        .expect("metrics auth failure should respond");
        assert_eq!(unauthorized_metrics.status, "401 Unauthorized");

        let metrics = mcp_http_response(
            &dashboard_test_request_with_headers(
                "GET",
                "/metrics",
                [("X-AgentK-MCP-Token", "secret")],
                Vec::new(),
            ),
            &state,
        )
        .expect("metrics should respond");
        assert_eq!(metrics.status, "200 OK");
        assert_eq!(
            metrics.content_type,
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let metrics_body = String::from_utf8(metrics.body).expect("metrics should be utf8");
        assert!(metrics_body.contains("agentk_mcp_http_ready 1\n"));
        assert!(metrics_body.contains("agentk_mcp_http_active_sessions 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_max_concurrent_requests 8\n"));
        assert!(metrics_body.contains("agentk_mcp_http_configured_allowed_origins 2\n"));
        assert!(metrics_body.contains("agentk_mcp_http_auth_required 1\n"));
        assert!(metrics_body.contains("agentk_mcp_http_requests_total 5\n"));
        assert!(metrics_body.contains("agentk_mcp_http_get_requests_total 4\n"));
        assert!(metrics_body.contains("agentk_mcp_http_options_requests_total 1\n"));
        assert!(metrics_body.contains("agentk_mcp_http_client_error_responses_total 3\n"));
        assert!(metrics_body.contains("agentk_mcp_http_auth_rejections_total 2\n"));
        assert!(metrics_body.contains("agentk_mcp_http_preflight_rejections_total 1\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_stream_requests_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_resume_requests_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_invalid_resume_requests_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_evicted_resume_requests_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_events_returned_total 0\n"));
        assert!(metrics_body.contains(&format!(
            "agentk_mcp_http_sse_retained_events_per_session {}\n",
            MCP_HTTP_MAX_SSE_EVENTS_PER_SESSION
        )));
        assert!(metrics_body.contains("agentk_mcp_http_sse_sessions_with_buffered_events 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_buffered_events 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_buffer_capacity 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_sse_event_buffer_evictions_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_invalid_json_rpc_id_requests_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_invalid_framing_responses_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_header_too_large_responses_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_body_too_large_responses_total 0\n"));
        assert!(
            metrics_body.contains("agentk_mcp_http_downstream_transport_error_responses_total 0\n")
        );
        assert!(
            metrics_body.contains("agentk_mcp_http_gateway_internal_error_responses_total 0\n")
        );
        assert!(metrics_body.contains("agentk_mcp_http_sessions_created_total 0\n"));
        assert!(metrics_body.contains("agentk_mcp_http_session_not_found_total 0\n"));
        assert!(
            !metrics_body.contains("https://console.example"),
            "metrics should report allowed-origin counts without raw origin values"
        );

        let metrics_head = mcp_http_response(
            &dashboard_test_request_with_headers(
                "HEAD",
                "/metrics",
                [("Authorization", "Bearer secret")],
                Vec::new(),
            ),
            &state,
        )
        .expect("metrics HEAD should respond");
        assert_eq!(metrics_head.status, "200 OK");
        assert!(metrics_head.body.is_empty());

        let ready_head = mcp_http_response(
            &dashboard_test_request_with_headers(
                "HEAD",
                "/readyz",
                [("Authorization", "Bearer secret")],
                Vec::new(),
            ),
            &state,
        )
        .expect("readyz HEAD should respond");
        assert_eq!(ready_head.status, "200 OK");
        assert!(ready_head.body.is_empty());

        let unsupported_endpoint_head = mcp_http_response(
            &dashboard_test_request_with_headers(
                "HEAD",
                "/mcp",
                [("Authorization", "Bearer secret")],
                Vec::new(),
            ),
            &state,
        )
        .expect("endpoint HEAD should be handled");
        assert_eq!(unsupported_endpoint_head.status, "405 Method Not Allowed");
        assert_eq!(
            response_header(&unsupported_endpoint_head, "Allow"),
            Some("POST, GET, DELETE, OPTIONS")
        );
        assert!(unsupported_endpoint_head.body.is_empty());

        let unsupported = mcp_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/readyz",
                [("Authorization", "Bearer secret")],
                Vec::new(),
            ),
            &state,
        )
        .expect("unsupported operational method should be handled");
        assert_eq!(unsupported.status, "405 Method Not Allowed");
        assert_eq!(response_header(&unsupported, "Allow"), Some("GET, HEAD"));
    }

    #[test]
    fn mcp_session_report_path_uses_trace_stem() {
        assert_eq!(
            mcp_session_report_path(std::path::Path::new(
                "agentk-sidecar/.agentk/runs/team-sidecar.jsonl"
            )),
            PathBuf::from("agentk-sidecar/.agentk/runs/team-sidecar.session.json")
        );
    }

    #[test]
    fn mcp_gateway_session_path_suffixes_multi_session_outputs() {
        assert_eq!(
            mcp_gateway_session_path(std::path::Path::new(".agentk/runs/tcp.jsonl"), 1, 0),
            PathBuf::from(".agentk/runs/tcp.jsonl")
        );
        assert_eq!(
            mcp_gateway_session_path(std::path::Path::new(".agentk/runs/tcp.jsonl"), 2, 1),
            PathBuf::from(".agentk/runs/tcp.session-2.jsonl")
        );
        assert_eq!(
            mcp_gateway_session_path(std::path::Path::new(".agentk/runs/tcp"), 3, 0),
            PathBuf::from(".agentk/runs/tcp.session-1")
        );
    }

    #[cfg(unix)]
    #[test]
    fn mcp_proxy_tcp_accept_loop_proxies_one_bounded_session() {
        let trace_path = mcp_proxy_trace_out_test_path("tcp-trace");
        let session_report_path = mcp_session_report_path(&trace_path);
        let _ = fs::remove_file(&trace_path);
        let _ = fs::remove_file(&session_report_path);

        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener address should be available");
        let config = McpSubprocessProxyConfig::new("agent://test", "tcp-probe", "sh")
            .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
            .with_max_client_messages(10);
        let trace_for_thread = trace_path.clone();
        let report_for_thread = session_report_path.clone();

        let server = std::thread::spawn(move || {
            mcp_proxy_tcp_accept_loop(
                config,
                listener,
                1,
                1,
                Some(trace_for_thread),
                Some(report_for_thread),
            )
        });

        let mut client = TcpStream::connect(addr).expect("test client should connect");
        client
            .write_all(mcp_proxy_trace_out_probe_input().as_bytes())
            .expect("test client should write MCP input");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("test client should close write side");
        let mut responses = String::new();
        client
            .read_to_string(&mut responses)
            .expect("test client should read MCP responses");

        server
            .join()
            .expect("tcp proxy thread should not panic")
            .expect("tcp proxy session should complete");

        assert!(responses.contains("\"tools\""));
        let verify = verify_jsonl(&trace_path).expect("tcp trace-out should be verifiable");
        assert_eq!(verify.events_checked, 1);
        let session_report: agentk::McpSubprocessProxySessionReport = serde_json::from_str(
            &fs::read_to_string(&session_report_path).expect("tcp session report should read"),
        )
        .expect("tcp session report should be valid json");
        assert_eq!(session_report.agent_id, "agent://test");
        assert_eq!(session_report.server_id, "tcp-probe");
        assert!(session_report.ready);
        assert_eq!(session_report.client_messages_seen, 3);
        assert_eq!(session_report.allowed_events, 1);

        let _ = fs::remove_file(trace_path);
        let _ = fs::remove_file(session_report_path);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_proxy_tcp_accept_loop_allows_bounded_concurrent_sessions() {
        let trace_path = mcp_proxy_trace_out_test_path("tcp-concurrent");
        let session_report_path = mcp_session_report_path(&trace_path);
        let trace_session_1 = mcp_gateway_session_path(&trace_path, 2, 0);
        let trace_session_2 = mcp_gateway_session_path(&trace_path, 2, 1);
        let report_session_1 = mcp_gateway_session_path(&session_report_path, 2, 0);
        let report_session_2 = mcp_gateway_session_path(&session_report_path, 2, 1);
        for path in [
            &trace_path,
            &session_report_path,
            &trace_session_1,
            &trace_session_2,
            &report_session_1,
            &report_session_2,
        ] {
            let _ = fs::remove_file(path);
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener address should be available");
        let config = McpSubprocessProxyConfig::new("agent://test", "tcp-concurrent", "sh")
            .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
            .with_max_client_messages(10);
        let trace_for_thread = trace_path.clone();
        let report_for_thread = session_report_path.clone();

        let server = std::thread::spawn(move || {
            mcp_proxy_tcp_accept_loop(
                config,
                listener,
                2,
                2,
                Some(trace_for_thread),
                Some(report_for_thread),
            )
        });

        let idle_client = TcpStream::connect(addr).expect("idle client should connect");
        let mut active_client = TcpStream::connect(addr).expect("active client should connect");
        active_client
            .write_all(mcp_proxy_trace_out_probe_input().as_bytes())
            .expect("active client should write MCP input");
        active_client
            .shutdown(std::net::Shutdown::Write)
            .expect("active client should close write side");
        let mut responses = String::new();
        active_client
            .read_to_string(&mut responses)
            .expect("active client should read MCP responses");
        assert!(responses.contains("\"tools\""));

        drop(idle_client);
        server
            .join()
            .expect("tcp proxy thread should not panic")
            .expect("tcp proxy sessions should complete");

        let verifiable_traces = [&trace_session_1, &trace_session_2]
            .into_iter()
            .filter(|path| verify_jsonl(path).is_ok_and(|report| report.events_checked == 1))
            .count();
        assert_eq!(verifiable_traces, 1);
        assert!(report_session_1.exists());
        assert!(report_session_2.exists());

        for path in [
            trace_session_1,
            trace_session_2,
            report_session_1,
            report_session_2,
        ] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn sidecar_run_accepts_bundle_root() {
        std::thread::Builder::new()
            .name("agentk-cli-sidecar-run-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_run_accepts_bundle_root_inner)
            .expect("sidecar-run parser smoke thread should spawn")
            .join()
            .expect("sidecar-run parser smoke thread should not panic");
    }

    fn sidecar_run_accepts_bundle_root_inner() {
        let cli = Cli::try_parse_from(["agentk", "sidecar-run", "--root", "agentk-sidecar"])
            .expect("sidecar-run should parse");

        let Some(Command::SidecarRun { root }) = cli.command else {
            panic!("expected sidecar-run command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar"));
    }

    #[test]
    fn sidecar_serve_tcp_accepts_bundle_and_bind_args() {
        std::thread::Builder::new()
            .name("agentk-cli-sidecar-tcp-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_serve_tcp_accepts_bundle_and_bind_args_inner)
            .expect("sidecar TCP parser smoke thread should spawn")
            .join()
            .expect("sidecar TCP parser smoke thread should not panic");
    }

    fn sidecar_serve_tcp_accepts_bundle_and_bind_args_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-serve-tcp",
            "--root",
            "agentk-sidecar",
            "--host",
            "127.0.0.1",
            "--port",
            "9797",
            "--max-sessions",
            "2",
            "--max-concurrent-sessions",
            "2",
        ])
        .expect("sidecar tcp command should parse");

        let Some(Command::SidecarServeTcp {
            root,
            host,
            port,
            max_sessions,
            max_concurrent_sessions,
        }) = cli.command
        else {
            panic!("expected sidecar-serve-tcp command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar"));
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9797);
        assert_eq!(max_sessions, 2);
        assert_eq!(max_concurrent_sessions, 2);
    }

    #[test]
    fn sidecar_serve_http_accepts_bundle_and_streamable_http_args() {
        std::thread::Builder::new()
            .name("agentk-cli-sidecar-http-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_serve_http_accepts_bundle_and_streamable_http_args_inner)
            .expect("sidecar HTTP parser smoke thread should spawn")
            .join()
            .expect("sidecar HTTP parser smoke thread should not panic");
    }

    fn sidecar_serve_http_accepts_bundle_and_streamable_http_args_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-serve-http",
            "--root",
            "agentk-sidecar",
            "--host",
            "127.0.0.1",
            "--port",
            "9798",
            "--endpoint",
            "/mcp",
            "--max-requests",
            "3",
            "--max-concurrent-requests",
            "2",
            "--max-active-sessions",
            "5",
            "--session-idle-timeout-ms",
            "60000",
            "--max-body-bytes",
            "32768",
            "--max-header-bytes",
            "8192",
            "--stream-timeout-ms",
            "12000",
            "--allow-origin",
            "http://localhost:3000",
            "--allow-origin-env",
            "AGENTK_TEST_HTTP_ALLOW_ORIGINS",
            "--allow-non-local-bind",
            "--trust-proxy-headers",
            "--auth-token-env",
            "AGENTK_TEST_HTTP_TOKEN",
        ])
        .expect("sidecar http command should parse");

        let Some(Command::SidecarServeHttp {
            root,
            host,
            port,
            endpoint,
            max_requests,
            max_concurrent_requests,
            max_active_sessions,
            session_idle_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            stream_timeout_ms,
            allow_origins,
            allow_origin_env,
            allow_non_local_bind,
            trust_proxy_headers,
            auth_token_env,
        }) = cli.command
        else {
            panic!("expected sidecar-serve-http command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar"));
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9798);
        assert_eq!(endpoint, "/mcp");
        assert_eq!(max_requests, 3);
        assert_eq!(max_concurrent_requests, 2);
        assert_eq!(max_active_sessions, 5);
        assert_eq!(session_idle_timeout_ms, 60000);
        assert_eq!(max_body_bytes, 32768);
        assert_eq!(max_header_bytes, 8192);
        assert_eq!(stream_timeout_ms, 12000);
        assert_eq!(allow_origins, vec!["http://localhost:3000".to_string()]);
        assert_eq!(allow_origin_env, "AGENTK_TEST_HTTP_ALLOW_ORIGINS");
        assert!(allow_non_local_bind);
        assert!(trust_proxy_headers);
        assert_eq!(auth_token_env, "AGENTK_TEST_HTTP_TOKEN");
    }

    #[test]
    fn mcp_http_bind_host_requires_loopback_unless_explicitly_allowed() {
        validate_mcp_http_bind_security("localhost", false, false)
            .expect("localhost should be local");
        validate_mcp_http_bind_security("127.8.9.10", false, false).expect("127/8 should be local");
        validate_mcp_http_bind_security("[::1]", false, false)
            .expect("IPv6 loopback should be local");
        let wildcard = validate_mcp_http_bind_security("0.0.0.0", false, false)
            .expect_err("wildcard host should require explicit opt-in")
            .to_string();
        assert!(wildcard.contains("--allow-non-local-bind"));
        let missing_auth = validate_mcp_http_bind_security("0.0.0.0", true, false)
            .expect_err("non-loopback opt-in should still require auth")
            .to_string();
        assert!(missing_auth.contains("auth token"));
        validate_mcp_http_bind_security("0.0.0.0", true, true)
            .expect("explicit opt-in plus auth should allow wildcard host");
    }

    #[test]
    fn mcp_http_stream_timeouts_are_applied_to_accepted_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");
        let client = TcpStream::connect(addr).expect("test client should connect");
        let (stream, _) = listener.accept().expect("test server should accept");
        let timeout = Duration::from_millis(1234);
        configure_mcp_http_stream(&stream, timeout).expect("stream should configure");
        assert_eq!(
            stream.read_timeout().expect("read timeout should inspect"),
            Some(timeout)
        );
        assert_eq!(
            stream
                .write_timeout()
                .expect("write timeout should inspect"),
            Some(timeout)
        );
        drop(client);
    }

    #[test]
    fn dashboard_http_stream_timeouts_are_applied_to_accepted_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");
        let client = TcpStream::connect(addr).expect("test client should connect");
        let (stream, _) = listener.accept().expect("test server should accept");
        let timeout = Duration::from_millis(1234);
        configure_dashboard_http_stream(&stream, timeout).expect("stream should configure");
        assert_eq!(
            stream.read_timeout().expect("read timeout should inspect"),
            Some(timeout)
        );
        assert_eq!(
            stream
                .write_timeout()
                .expect("write timeout should inspect"),
            Some(timeout)
        );
        drop(client);
    }

    fn dashboard_http_stream_response_for(
        raw_request: &[u8],
        max_body_bytes: usize,
        max_header_bytes: usize,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");
        let server = thread::spawn(move || {
            let trace_path = PathBuf::from("dashboard-stream-trace.jsonl");
            let decisions_path = PathBuf::from("dashboard-stream-approvals.jsonl");
            let (mut stream, _) = listener.accept().expect("test client should connect");
            let context = DashboardHttpContext {
                trace_path: &trace_path,
                decisions_path: &decisions_path,
                permissions_path: None,
                identity_path: None,
                admin_token: None,
                admin_read_required: false,
                max_body_bytes,
                max_header_bytes,
                store_root: None,
            };
            handle_dashboard_http_stream(&mut stream, &context)
                .expect("dashboard stream response should write");
        });
        let mut client = TcpStream::connect(addr).expect("test client should connect");
        client
            .write_all(raw_request)
            .expect("test request should write");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("test response should read");
        server.join().expect("server thread should finish");
        response
    }

    #[test]
    fn dashboard_http_stream_returns_431_for_oversized_headers() {
        for raw_request in [
            b"GET /readyz HTTP/1.1\r\nX-Long: 123456789012345678901234567890\r\n\r\n".as_slice(),
            b"GET /readyz?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n\r\n"
                .as_slice(),
        ] {
            let response = dashboard_http_stream_response_for(raw_request, 1024, 32);
            assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large"));
            assert!(response.contains("dashboard HTTP request headers must be at most 32 bytes"));
        }
    }

    #[test]
    fn dashboard_http_stream_returns_413_for_declared_oversized_body() {
        let response = dashboard_http_stream_response_for(
            b"POST /api/approve HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\n",
            8,
            DASHBOARD_HTTP_MAX_HEADER_BYTES,
        );
        assert!(response.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(response.contains("dashboard HTTP request body must be at most 8 bytes"));
    }

    #[test]
    fn dashboard_http_stream_rejects_missing_host_for_all_versions() {
        for raw_request in [
            b"GET /healthz HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.0\r\n\r\n".as_slice(),
        ] {
            let response = dashboard_http_stream_response_for(
                raw_request,
                DASHBOARD_HTTP_MAX_BODY_BYTES,
                DASHBOARD_HTTP_MAX_HEADER_BYTES,
            );
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid dashboard HTTP request"));
        }

        let valid_http10 = dashboard_http_stream_response_for(
            b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n",
            DASHBOARD_HTTP_MAX_BODY_BYTES,
            DASHBOARD_HTTP_MAX_HEADER_BYTES,
        );
        assert!(valid_http10.starts_with("HTTP/1.1 200 OK"));
        assert!(valid_http10.ends_with("{\"ok\":true}"));
    }

    #[test]
    fn dashboard_http_stream_rejects_untrusted_forwarded_headers() {
        for raw_request in [
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nForwarded: for=SPOOFED_FOR;host=SPOOFED_HOST\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Host: SPOOFED_HOST\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: SPOOFED_IP\r\n\r\n".as_slice(),
        ] {
            let response = dashboard_http_stream_response_for(
                raw_request,
                DASHBOARD_HTTP_MAX_BODY_BYTES,
                DASHBOARD_HTTP_MAX_HEADER_BYTES,
            );
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid dashboard HTTP request"));
            assert!(!response.contains("SPOOFED"));
        }
    }

    #[test]
    fn dashboard_http_stream_rejects_method_override_headers() {
        for raw_request in [
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-HTTP-Method-Override: POST\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Method-Override: DELETE\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-HTTP-Method: PATCH_SHOULD_NOT_REFLECT\r\n\r\n".as_slice(),
        ] {
            let response = dashboard_http_stream_response_for(
                raw_request,
                DASHBOARD_HTTP_MAX_BODY_BYTES,
                DASHBOARD_HTTP_MAX_HEADER_BYTES,
            );
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid dashboard HTTP request"));
            assert!(!response.contains("PATCH_SHOULD_NOT_REFLECT"));
        }
    }

    #[test]
    fn dashboard_http_stream_rejects_proxy_and_trace_methods() {
        for raw_request in [
            b"CONNECT /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"TRACE /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"TRACK /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
        ] {
            let response = dashboard_http_stream_response_for(
                raw_request,
                DASHBOARD_HTTP_MAX_BODY_BYTES,
                DASHBOARD_HTTP_MAX_HEADER_BYTES,
            );
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid dashboard HTTP request"));
        }
    }

    #[test]
    fn dashboard_http_stream_rejects_ambient_cookie_headers() {
        for raw_request in [
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nCookie: COOKIE_SECRET_SHOULD_NOT_REFLECT=1\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nSet-Cookie: COOKIE_SECRET_SHOULD_NOT_REFLECT=1\r\n\r\n".as_slice(),
        ] {
            let response = dashboard_http_stream_response_for(
                raw_request,
                DASHBOARD_HTTP_MAX_BODY_BYTES,
                DASHBOARD_HTTP_MAX_HEADER_BYTES,
            );
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid dashboard HTTP request"));
            assert!(!response.contains("COOKIE_SECRET_SHOULD_NOT_REFLECT"));
        }
    }

    #[test]
    fn dashboard_http_stream_rejects_encoded_request_bodies() {
        let response = dashboard_http_stream_response_for(
            b"POST /api/approve HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\nContent-Length: 42\r\n\r\nCONTENT_ENCODING_SECRET_SHOULD_NOT_REFLECT",
            DASHBOARD_HTTP_MAX_BODY_BYTES,
            DASHBOARD_HTTP_MAX_HEADER_BYTES,
        );
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("invalid dashboard HTTP request"));
        assert!(!response.contains("CONTENT_ENCODING_SECRET_SHOULD_NOT_REFLECT"));
    }

    #[test]
    fn dashboard_http_stream_rejects_websocket_handshake_headers() {
        for raw_request in [
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Key: WEBSOCKET_SECRET_SHOULD_NOT_REFLECT\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Protocol: mcp\r\n\r\n".as_slice(),
        ] {
            let response = dashboard_http_stream_response_for(
                raw_request,
                DASHBOARD_HTTP_MAX_BODY_BYTES,
                DASHBOARD_HTTP_MAX_HEADER_BYTES,
            );
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid dashboard HTTP request"));
            assert!(!response.contains("WEBSOCKET_SECRET_SHOULD_NOT_REFLECT"));
        }
    }

    #[test]
    fn mcp_http_stream_returns_431_for_oversized_headers() {
        fn response_for(raw_request: &[u8]) -> (String, McpHttpGatewayMetrics) {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
            let addr = listener
                .local_addr()
                .expect("test listener should have addr");
            let state = Arc::new(McpHttpGatewayState {
                proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
                endpoint: "/mcp".to_string(),
                max_concurrent_requests: 8,
                max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
                session_idle_timeout: Duration::from_millis(
                    MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS,
                ),
                max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
                max_header_bytes: 32,
                stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
                allow_origins: Vec::new(),
                auth_token: None,
                trust_proxy_headers: false,
                trace_out: None,
                session_report_out: None,
                metrics: Mutex::new(McpHttpGatewayMetrics::default()),
                sessions: Mutex::new(BTreeMap::new()),
            });
            let server_state = Arc::clone(&state);
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("test client should connect");
                handle_mcp_http_stream(&mut stream, &server_state)
                    .expect("oversized header response should write");
            });
            let mut client = TcpStream::connect(addr).expect("test client should connect");
            client
                .write_all(raw_request)
                .expect("test request should write");
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .expect("test response should read");
            server.join().expect("server thread should finish");
            assert!(
                state
                    .sessions
                    .lock()
                    .expect("session lock should not be poisoned")
                    .is_empty()
            );
            let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
            (response, metrics)
        }

        for raw_request in [
            b"GET /mcp HTTP/1.1\r\nX-Long: 123456789012345678901234567890\r\n\r\n".as_slice(),
            b"GET /mcp?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
        ] {
            let (response, metrics) = response_for(raw_request);
            assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large"));
            assert!(response.contains("MCP HTTP request headers must be at most 32 bytes"));
            assert_eq!(metrics.client_error_responses, 1);
            assert_eq!(metrics.header_too_large_responses, 1);
            assert_eq!(metrics.invalid_framing_responses, 0);
            assert_eq!(metrics.body_too_large_responses, 0);
        }
    }

    #[test]
    fn mcp_http_stream_returns_413_for_declared_oversized_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS),
            max_body_bytes: 8,
            max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
            stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
            allow_origins: Vec::new(),
            auth_token: None,
            trust_proxy_headers: false,
            trace_out: None,
            session_report_out: None,
            metrics: Mutex::new(McpHttpGatewayMetrics::default()),
            sessions: Mutex::new(BTreeMap::new()),
        });
        let server_state = Arc::clone(&state);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("test client should connect");
            handle_mcp_http_stream(&mut stream, &server_state)
                .expect("oversized body response should write");
        });
        let mut client = TcpStream::connect(addr).expect("test client should connect");
        client
            .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\n")
            .expect("test request should write");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("test response should read");
        server.join().expect("server thread should finish");
        assert!(response.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(response.contains("MCP HTTP request body must be at most 8 bytes"));
        let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
        assert_eq!(metrics.client_error_responses, 1);
        assert_eq!(metrics.body_too_large_responses, 1);
        assert_eq!(metrics.header_too_large_responses, 0);
        assert_eq!(metrics.invalid_framing_responses, 0);
    }

    #[test]
    fn mcp_http_stream_returns_400_for_invalid_framing() {
        fn response_for(raw_request: &[u8]) -> (String, McpHttpGatewayMetrics) {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
            let addr = listener
                .local_addr()
                .expect("test listener should have addr");
            let state = Arc::new(McpHttpGatewayState {
                proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
                endpoint: "/mcp".to_string(),
                max_concurrent_requests: 8,
                max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
                session_idle_timeout: Duration::from_millis(
                    MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS,
                ),
                max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
                max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
                stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
                allow_origins: Vec::new(),
                auth_token: None,
                trust_proxy_headers: false,
                trace_out: None,
                session_report_out: None,
                metrics: Mutex::new(McpHttpGatewayMetrics::default()),
                sessions: Mutex::new(BTreeMap::new()),
            });
            let server_state = Arc::clone(&state);
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("test client should connect");
                handle_mcp_http_stream(&mut stream, &server_state)
                    .expect("invalid framing response should write");
            });
            let mut client = TcpStream::connect(addr).expect("test client should connect");
            client
                .write_all(raw_request)
                .expect("test request should write");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("test request should close write side");
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .expect("test response should read");
            server.join().expect("server thread should finish");
            let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
            (response, metrics)
        }

        for raw_request in [
            b"GET /mcp\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\n\n".as_slice(),
            b"GET /mcp HTTP/2.0\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\xff\r\n\r\n".as_slice(),
            b"GET\t/mcp HTTP/1.1\r\n\r\n".as_slice(),
            b"GET  /mcp HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /mcp\tHTTP/1.1\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1 \r\n\r\n".as_slice(),
            b"GET /\tmcp HTTP/1.1\r\n\r\n".as_slice(),
            b"GET http://example.invalid/mcp HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.0\r\n\r\n".as_slice(),
            b"GET //example.invalid/mcp HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"GET /mcp#FRAGMENT_SHOULD_NOT_REFLECT HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1 extra\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\n\r\n".as_slice(),
            b"CONNECT /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"TRACE /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"TRACK /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: \r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nHost: 127.0.0.1\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: bad host\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: http://localhost\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: user@localhost\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: *.example\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: bad;host\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: bad_host.example\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: bad%20host.example\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: -bad.example\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: bad-.example\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: bad..example\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost:\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost:99999\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: [not-ip]\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: [127.0.0.1]\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: [::1]:bad\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nBadHeader\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\n\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\n Folded: nope\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\n: nope\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nBad Name: nope\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost : localhost\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nContent-Length : 0\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: +0\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: LENGTH_SHOULD_NOT_REFLECT\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-Bad: \xff\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-Bad: value\0\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-Bad: value\rbad\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nTransfer-Encoding:\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\nContent-Length: 42\r\n\r\nCONTENT_ENCODING_SECRET_SHOULD_NOT_REFLECT"
                .as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Key: WEBSOCKET_SECRET_SHOULD_NOT_REFLECT\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Protocol: mcp\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Version: 13\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close, upgrade\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nProxy-Connection: keep-alive\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nKeep-Alive: timeout=5\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nTE: trailers\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nTrailer: X-Later\r\n\r\n".as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic PROXY_SECRET_SHOULD_NOT_REFLECT\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nProxy-Authenticate: Basic realm=\"PROXY_REALM_SHOULD_NOT_REFLECT\"\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nForwarded: for=SPOOFED_FOR;host=SPOOFED_HOST\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Host: SPOOFED_HOST\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: SPOOFED_IP\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nX-HTTP-Method-Override: POST\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nX-Method-Override: DELETE\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nX-HTTP-Method: PATCH_SHOULD_NOT_REFLECT\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nCookie: COOKIE_SECRET_SHOULD_NOT_REFLECT=1\r\n\r\n"
                .as_slice(),
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nSet-Cookie: COOKIE_SECRET_SHOULD_NOT_REFLECT=1\r\n\r\n"
                .as_slice(),
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nabc".as_slice(),
        ] {
            let (response, metrics) = response_for(raw_request);
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid MCP HTTP request"));
            assert!(!response.contains("FRAGMENT_SHOULD_NOT_REFLECT"));
            assert!(!response.contains("LENGTH_SHOULD_NOT_REFLECT"));
            assert!(!response.contains("PROXY_SECRET_SHOULD_NOT_REFLECT"));
            assert!(!response.contains("PROXY_REALM_SHOULD_NOT_REFLECT"));
            assert!(!response.contains("SPOOFED"));
            assert!(!response.contains("PATCH_SHOULD_NOT_REFLECT"));
            assert!(!response.contains("COOKIE_SECRET_SHOULD_NOT_REFLECT"));
            assert!(!response.contains("CONTENT_ENCODING_SECRET_SHOULD_NOT_REFLECT"));
            assert!(!response.contains("WEBSOCKET_SECRET_SHOULD_NOT_REFLECT"));
            let body = response
                .split("\r\n\r\n")
                .nth(1)
                .expect("response should include body");
            assert_eq!(body, "invalid MCP HTTP request\n");
            assert_eq!(metrics.client_error_responses, 1);
            assert_eq!(metrics.invalid_framing_responses, 1);
            assert_eq!(metrics.header_too_large_responses, 0);
            assert_eq!(metrics.body_too_large_responses, 0);
        }

        let (close_response, close_metrics) =
            response_for(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(close_response.starts_with("HTTP/1.1 200 OK"));
        assert!(close_response.ends_with("{\"ok\":true}"));
        assert_eq!(close_metrics.client_error_responses, 0);
        assert_eq!(close_metrics.invalid_framing_responses, 0);

        let (http10_response, http10_metrics) =
            response_for(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n");
        assert!(http10_response.starts_with("HTTP/1.1 200 OK"));
        assert!(http10_response.ends_with("{\"ok\":true}"));
        assert_eq!(http10_metrics.client_error_responses, 0);
        assert_eq!(http10_metrics.invalid_framing_responses, 0);
    }

    #[test]
    fn mcp_http_stream_accepts_clean_forwarded_headers_only_when_trusted() {
        fn response_for(
            raw_request: &[u8],
            trust_proxy_headers: bool,
        ) -> (String, McpHttpGatewayMetrics) {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
            let addr = listener
                .local_addr()
                .expect("test listener should have addr");
            let state = Arc::new(McpHttpGatewayState {
                proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
                endpoint: "/mcp".to_string(),
                max_concurrent_requests: 8,
                max_active_sessions: MCP_HTTP_DEFAULT_MAX_ACTIVE_SESSIONS,
                session_idle_timeout: Duration::from_millis(
                    MCP_HTTP_DEFAULT_SESSION_IDLE_TIMEOUT_MS,
                ),
                max_body_bytes: MCP_HTTP_DEFAULT_MAX_BODY_BYTES,
                max_header_bytes: MCP_HTTP_DEFAULT_MAX_HEADER_BYTES,
                stream_timeout: Duration::from_millis(MCP_HTTP_DEFAULT_STREAM_TIMEOUT_MS),
                allow_origins: Vec::new(),
                auth_token: None,
                trust_proxy_headers,
                trace_out: None,
                session_report_out: None,
                metrics: Mutex::new(McpHttpGatewayMetrics::default()),
                sessions: Mutex::new(BTreeMap::new()),
            });
            let server_state = Arc::clone(&state);
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("test client should connect");
                handle_mcp_http_stream(&mut stream, &server_state)
                    .expect("trusted proxy response should write");
            });
            let mut client = TcpStream::connect(addr).expect("test client should connect");
            client
                .write_all(raw_request)
                .expect("test request should write");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("test request should close write side");
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .expect("test response should read");
            server.join().expect("server thread should finish");
            let metrics = mcp_http_metrics_snapshot(&state).expect("metrics should snapshot");
            (response, metrics)
        }

        let clean_forwarded = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nForwarded: for=127.0.0.1;host=localhost;proto=https\r\nX-Forwarded-For: 127.0.0.1\r\nX-Forwarded-Host: localhost\r\nX-Forwarded-Proto: https\r\nX-Real-IP: 127.0.0.1\r\n\r\n";
        let (rejected_response, rejected_metrics) = response_for(clean_forwarded, false);
        assert!(rejected_response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(rejected_response.contains("invalid MCP HTTP request"));
        assert_eq!(rejected_metrics.invalid_framing_responses, 1);

        let (trusted_response, trusted_metrics) = response_for(clean_forwarded, true);
        assert!(trusted_response.starts_with("HTTP/1.1 200 OK"));
        assert!(trusted_response.ends_with("{\"ok\":true}"));
        assert!(!trusted_response.contains("127.0.0.1"));
        assert_eq!(trusted_metrics.invalid_framing_responses, 0);
        assert_eq!(trusted_metrics.trusted_proxy_header_requests, 1);

        for dirty_forwarded in [
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 127.0.0.1, 10.0.0.1\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Server: SPOOFED_PROXY\r\n\r\n".as_slice(),
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nForwarded: for=SPOOFED_FOR;host=SPOOFED_HOST\r\n\r\n".as_slice(),
        ] {
            let (response, metrics) = response_for(dirty_forwarded, true);
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
            assert!(response.contains("invalid MCP HTTP request"));
            assert!(!response.contains("SPOOFED"));
            assert_eq!(metrics.invalid_framing_responses, 1);
        }

        let duplicate_forwarded = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 127.0.0.1\r\nX-Real-IP: 127.0.0.1\r\n\r\n";
        let (duplicate_response, duplicate_metrics) = response_for(duplicate_forwarded, true);
        assert!(duplicate_response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(duplicate_response.contains("MCP HTTP forwarded header is invalid"));
        assert_eq!(duplicate_metrics.invalid_framing_responses, 0);
    }

    #[test]
    fn sidecar_package_accepts_root_out_and_force() {
        std::thread::Builder::new()
            .name("agentk-cli-package-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_accepts_root_out_and_force_inner)
            .expect("sidecar-package parser smoke thread should spawn")
            .join()
            .expect("sidecar-package parser smoke thread should not panic");
    }

    fn sidecar_package_accepts_root_out_and_force_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package",
            "--root",
            "agentk-sidecar",
            "--out",
            "dist/agentk-sidecar",
            "--archive-out",
            "dist/agentk-sidecar.tar",
            "--force",
        ])
        .expect("sidecar-package should parse");

        let Some(Command::SidecarPackage {
            root,
            out,
            archive_out,
            force,
            ..
        }) = cli.command
        else {
            panic!("expected sidecar-package command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar"));
        assert_eq!(out, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(archive_out, Some(PathBuf::from("dist/agentk-sidecar.tar")));
        assert!(force);
    }

    #[test]
    fn sidecar_package_check_accepts_root() {
        std::thread::Builder::new()
            .name("agentk-cli-package-check-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_check_accepts_root_inner)
            .expect("sidecar-package-check parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-check parser smoke thread should not panic");
    }

    fn sidecar_package_check_accepts_root_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-check",
            "--root",
            "dist/agentk-sidecar",
            "--json",
        ])
        .expect("sidecar-package-check should parse");

        let Some(Command::SidecarPackageCheck { root, json }) = cli.command else {
            panic!("expected sidecar-package-check command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert!(json);
    }

    #[test]
    fn sidecar_package_http_handoff_check_accepts_root() {
        std::thread::Builder::new()
            .name("agentk-cli-package-http-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_http_handoff_check_accepts_root_inner)
            .expect("sidecar-package-http-handoff-check parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-http-handoff-check parser smoke thread should not panic");
    }

    fn sidecar_package_http_handoff_check_accepts_root_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-http-handoff-check",
            "--root",
            "dist/agentk-sidecar",
            "--json",
        ])
        .expect("sidecar-package-http-handoff-check should parse");

        let Some(Command::SidecarPackageHttpHandoffCheck { root, json }) = cli.command else {
            panic!("expected sidecar-package-http-handoff-check command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert!(json);
    }

    #[test]
    fn sidecar_package_team_handoff_check_accepts_root() {
        std::thread::Builder::new()
            .name("agentk-cli-package-team-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_team_handoff_check_accepts_root_inner)
            .expect("sidecar-package-team-handoff-check parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-team-handoff-check parser smoke thread should not panic");
    }

    fn sidecar_package_team_handoff_check_accepts_root_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-team-handoff-check",
            "--root",
            "dist/agentk-sidecar",
            "--json",
        ])
        .expect("sidecar-package-team-handoff-check should parse");

        let Some(Command::SidecarPackageTeamHandoffCheck { root, json }) = cli.command else {
            panic!("expected sidecar-package-team-handoff-check command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert!(json);
    }

    #[test]
    fn sidecar_package_ops_handoff_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-ops-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_ops_handoff_accepts_root_and_out_inner)
            .expect("sidecar-package-ops-handoff parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-ops-handoff parser smoke thread should not panic");
    }

    fn sidecar_package_ops_handoff_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-ops-handoff",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/operator-handoff",
            "--json",
        ])
        .expect("sidecar-package-ops-handoff should parse");

        let Some(Command::SidecarPackageOpsHandoff { root, out, json }) = cli.command else {
            panic!("expected sidecar-package-ops-handoff command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/operator-handoff"
            ))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_doctor_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-doctor-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_doctor_accepts_root_and_out_inner)
            .expect("sidecar-package-doctor parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-doctor parser smoke thread should not panic");
    }

    fn sidecar_package_doctor_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-doctor",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/doctor",
            "--release-manifest",
            "dist/agentk-sidecar-release-manifest.json",
            "--json",
        ])
        .expect("sidecar-package-doctor should parse");

        let Some(Command::SidecarPackageDoctor {
            root,
            out,
            release_manifest,
            json,
        }) = cli.command
        else {
            panic!("expected sidecar-package-doctor command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from("dist/agentk-sidecar/sidecar/.agentk/doctor"))
        );
        assert_eq!(
            release_manifest,
            Some(PathBuf::from("dist/agentk-sidecar-release-manifest.json"))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_support_bundle_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-support-bundle-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_support_bundle_accepts_root_and_out_inner)
            .expect("sidecar-package-support-bundle parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-support-bundle parser smoke thread should not panic");
    }

    fn sidecar_package_support_bundle_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-support-bundle",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/support-bundle",
            "--release-manifest",
            "dist/agentk-sidecar-release-manifest.json",
            "--json",
        ])
        .expect("sidecar-package-support-bundle should parse");

        let Some(Command::SidecarPackageSupportBundle {
            root,
            out,
            release_manifest,
            json,
        }) = cli.command
        else {
            panic!("expected sidecar-package-support-bundle command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/support-bundle"
            ))
        );
        assert_eq!(
            release_manifest,
            Some(PathBuf::from("dist/agentk-sidecar-release-manifest.json"))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_deploy_handoff_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-deploy-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_deploy_handoff_accepts_root_and_out_inner)
            .expect("sidecar-package-deploy-handoff parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-deploy-handoff parser smoke thread should not panic");
    }

    fn sidecar_package_deploy_handoff_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-deploy-handoff",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/deploy-handoff",
            "--json",
        ])
        .expect("sidecar-package-deploy-handoff should parse");

        let Some(Command::SidecarPackageDeployHandoff { root, out, json }) = cli.command else {
            panic!("expected sidecar-package-deploy-handoff command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/deploy-handoff"
            ))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_demo_handoff_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-demo-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_demo_handoff_accepts_root_and_out_inner)
            .expect("sidecar-package-demo-handoff parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-demo-handoff parser smoke thread should not panic");
    }

    fn sidecar_package_demo_handoff_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-demo-handoff",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/demo-handoff",
            "--json",
        ])
        .expect("sidecar-package-demo-handoff should parse");

        let Some(Command::SidecarPackageDemoHandoff { root, out, json }) = cli.command else {
            panic!("expected sidecar-package-demo-handoff command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/demo-handoff"
            ))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_quickstart_accepts_root_out_and_release_manifest() {
        std::thread::Builder::new()
            .name("agentk-cli-package-quickstart-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_quickstart_accepts_root_out_and_release_manifest_inner)
            .expect("sidecar-package-quickstart parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-quickstart parser smoke thread should not panic");
    }

    fn sidecar_package_quickstart_accepts_root_out_and_release_manifest_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-quickstart",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/quickstart",
            "--release-manifest",
            "dist/agentk-sidecar-release-manifest.json",
            "--json",
        ])
        .expect("sidecar-package-quickstart should parse");

        let Some(Command::SidecarPackageQuickstart {
            root,
            out,
            release_manifest,
            json,
        }) = cli.command
        else {
            panic!("expected sidecar-package-quickstart command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/quickstart"
            ))
        );
        assert_eq!(
            release_manifest,
            Some(PathBuf::from("dist/agentk-sidecar-release-manifest.json"))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_permissions_handoff_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-permissions-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_permissions_handoff_accepts_root_and_out_inner)
            .expect("sidecar-package-permissions-handoff parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-permissions-handoff parser smoke thread should not panic");
    }

    fn sidecar_package_permissions_handoff_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-permissions-handoff",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/permissions-handoff",
            "--json",
        ])
        .expect("sidecar-package-permissions-handoff should parse");

        let Some(Command::SidecarPackagePermissionsHandoff { root, out, json }) = cli.command
        else {
            panic!("expected sidecar-package-permissions-handoff command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/permissions-handoff"
            ))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_production_preflight_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-production-preflight-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_production_preflight_accepts_root_and_out_inner)
            .expect("sidecar-package-production-preflight parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-production-preflight parser smoke thread should not panic");
    }

    fn sidecar_package_production_preflight_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-production-preflight",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/production-preflight",
            "--json",
        ])
        .expect("sidecar-package-production-preflight should parse");

        let Some(Command::SidecarPackageProductionPreflight { root, out, json }) = cli.command
        else {
            panic!("expected sidecar-package-production-preflight command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/production-preflight"
            ))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_client_handoff_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-client-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_client_handoff_accepts_root_and_out_inner)
            .expect("sidecar-package-client-handoff parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-client-handoff parser smoke thread should not panic");
    }

    fn sidecar_package_client_handoff_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-client-handoff",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/client-handoff",
            "--json",
        ])
        .expect("sidecar-package-client-handoff should parse");

        let Some(Command::SidecarPackageClientHandoff { root, out, json }) = cli.command else {
            panic!("expected sidecar-package-client-handoff command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/client-handoff"
            ))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_dashboard_handoff_accepts_root_and_out() {
        std::thread::Builder::new()
            .name("agentk-cli-package-dashboard-handoff-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_dashboard_handoff_accepts_root_and_out_inner)
            .expect("sidecar-package-dashboard-handoff parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-dashboard-handoff parser smoke thread should not panic");
    }

    fn sidecar_package_dashboard_handoff_accepts_root_and_out_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-dashboard-handoff",
            "--root",
            "dist/agentk-sidecar",
            "--out",
            "dist/agentk-sidecar/sidecar/.agentk/dashboard-handoff",
            "--json",
        ])
        .expect("sidecar-package-dashboard-handoff should parse");

        let Some(Command::SidecarPackageDashboardHandoff { root, out, json }) = cli.command else {
            panic!("expected sidecar-package-dashboard-handoff command");
        };
        assert_eq!(root, PathBuf::from("dist/agentk-sidecar"));
        assert_eq!(
            out,
            Some(PathBuf::from(
                "dist/agentk-sidecar/sidecar/.agentk/dashboard-handoff"
            ))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_archive_check_accepts_archive_and_checksum() {
        std::thread::Builder::new()
            .name("agentk-cli-archive-check-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_archive_check_accepts_archive_and_checksum_inner)
            .expect("sidecar-package-archive-check parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-archive-check parser smoke thread should not panic");
    }

    fn sidecar_package_archive_check_accepts_archive_and_checksum_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-archive-check",
            "--archive",
            "dist/agentk-sidecar.tar",
            "--checksum",
            "dist/agentk-sidecar.tar.sha256",
            "--json",
        ])
        .expect("sidecar-package-archive-check should parse");

        let Some(Command::SidecarPackageArchiveCheck {
            archive,
            checksum,
            json,
        }) = cli.command
        else {
            panic!("expected sidecar-package-archive-check command");
        };
        assert_eq!(archive, PathBuf::from("dist/agentk-sidecar.tar"));
        assert_eq!(
            checksum,
            Some(PathBuf::from("dist/agentk-sidecar.tar.sha256"))
        );
        assert!(json);
    }

    #[test]
    fn sidecar_package_install_accepts_archive_out_checksum_and_force() {
        std::thread::Builder::new()
            .name("agentk-cli-package-install-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_install_accepts_archive_out_checksum_and_force_inner)
            .expect("sidecar-package-install parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-install parser smoke thread should not panic");
    }

    fn sidecar_package_install_accepts_archive_out_checksum_and_force_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-install",
            "--archive",
            "dist/agentk-sidecar.tar",
            "--out",
            "installed/agentk-sidecar",
            "--checksum",
            "dist/agentk-sidecar.tar.sha256",
            "--force",
            "--json",
        ])
        .expect("sidecar-package-install should parse");

        let Some(Command::SidecarPackageInstall {
            archive,
            out,
            checksum,
            force,
            json,
        }) = cli.command
        else {
            panic!("expected sidecar-package-install command");
        };
        assert_eq!(archive, PathBuf::from("dist/agentk-sidecar.tar"));
        assert_eq!(out, PathBuf::from("installed/agentk-sidecar"));
        assert_eq!(
            checksum,
            Some(PathBuf::from("dist/agentk-sidecar.tar.sha256"))
        );
        assert!(force);
        assert!(json);
    }

    #[test]
    fn sidecar_package_release_manifest_accepts_package_archive_and_receipt() {
        std::thread::Builder::new()
            .name("agentk-cli-release-manifest-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_release_manifest_accepts_package_archive_and_receipt_inner)
            .expect("sidecar-package-release-manifest parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-release-manifest parser smoke thread should not panic");
    }

    fn sidecar_package_release_manifest_accepts_package_archive_and_receipt_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-release-manifest",
            "--package",
            "installed/agentk-sidecar",
            "--archive",
            "dist/agentk-sidecar.tar",
            "--checksum",
            "dist/agentk-sidecar.tar.sha256",
            "--install-receipt",
            "installed/agentk-sidecar/sidecar/.agentk/install-receipt.json",
            "--out",
            "dist/agentk-sidecar-release-manifest.json",
            "--force",
            "--json",
        ])
        .expect("sidecar-package-release-manifest should parse");

        let Some(Command::SidecarPackageReleaseManifest {
            package,
            archive,
            checksum,
            install_receipt,
            out,
            force,
            json,
        }) = cli.command
        else {
            panic!("expected sidecar-package-release-manifest command");
        };
        assert_eq!(package, PathBuf::from("installed/agentk-sidecar"));
        assert_eq!(archive, PathBuf::from("dist/agentk-sidecar.tar"));
        assert_eq!(
            checksum,
            Some(PathBuf::from("dist/agentk-sidecar.tar.sha256"))
        );
        assert_eq!(
            install_receipt,
            Some(PathBuf::from(
                "installed/agentk-sidecar/sidecar/.agentk/install-receipt.json"
            ))
        );
        assert_eq!(
            out,
            PathBuf::from("dist/agentk-sidecar-release-manifest.json")
        );
        assert!(force);
        assert!(json);
    }

    #[test]
    fn sidecar_package_release_manifest_check_accepts_manifest_and_overrides() {
        std::thread::Builder::new()
            .name("agentk-cli-release-manifest-check-parser-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(sidecar_package_release_manifest_check_accepts_manifest_and_overrides_inner)
            .expect("sidecar-package-release-manifest-check parser smoke thread should spawn")
            .join()
            .expect("sidecar-package-release-manifest-check parser smoke thread should not panic");
    }

    fn sidecar_package_release_manifest_check_accepts_manifest_and_overrides_inner() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package-release-manifest-check",
            "--manifest",
            "dist/agentk-sidecar-release-manifest.json",
            "--package",
            "installed/agentk-sidecar",
            "--archive",
            "dist/agentk-sidecar.tar",
            "--checksum",
            "dist/agentk-sidecar.tar.sha256",
            "--install-receipt",
            "installed/agentk-sidecar/sidecar/.agentk/install-receipt.json",
            "--json",
        ])
        .expect("sidecar-package-release-manifest-check should parse");

        let Some(Command::SidecarPackageReleaseManifestCheck {
            manifest,
            package,
            archive,
            checksum,
            install_receipt,
            json,
        }) = cli.command
        else {
            panic!("expected sidecar-package-release-manifest-check command");
        };
        assert_eq!(
            manifest,
            PathBuf::from("dist/agentk-sidecar-release-manifest.json")
        );
        assert_eq!(package, Some(PathBuf::from("installed/agentk-sidecar")));
        assert_eq!(archive, Some(PathBuf::from("dist/agentk-sidecar.tar")));
        assert_eq!(
            checksum,
            Some(PathBuf::from("dist/agentk-sidecar.tar.sha256"))
        );
        assert_eq!(
            install_receipt,
            Some(PathBuf::from(
                "installed/agentk-sidecar/sidecar/.agentk/install-receipt.json"
            ))
        );
        assert!(json);
    }

    #[test]
    fn approvals_and_decisions_accept_review_metadata() {
        std::thread::Builder::new()
            .name("agentk-cli-parser-smoke".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(approvals_and_decisions_accept_review_metadata_inner)
            .expect("parser smoke thread should spawn")
            .join()
            .expect("parser smoke thread should not panic");
    }

    fn approvals_and_decisions_accept_review_metadata_inner() {
        let approvals = Cli::try_parse_from([
            "agentk",
            "approvals",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
        ])
        .expect("approvals should parse");
        let Some(Command::Approvals {
            path, decisions, ..
        }) = approvals.command
        else {
            panic!("expected approvals command");
        };
        assert_eq!(
            approval_decisions_path(&path, decisions),
            PathBuf::from("agentk-sidecar/.agentk/approvals.jsonl")
        );

        let approve = Cli::try_parse_from([
            "agentk",
            "approve",
            "trace.jsonl",
            "appr_demo",
            "--reviewer",
            "tom",
            "--reason",
            "one-shot approval",
            "--permissions",
            "team-permissions.toml",
        ])
        .expect("approve should parse");
        let Some(Command::Approve {
            id,
            reviewer,
            reason,
            permissions,
            ..
        }) = approve.command
        else {
            panic!("expected approve command");
        };
        assert_eq!(id, "appr_demo");
        assert_eq!(reviewer, "tom");
        assert_eq!(reason, "one-shot approval");
        assert_eq!(permissions, Some(PathBuf::from("team-permissions.toml")));

        let permissions = Cli::try_parse_from([
            "agentk",
            "permissions",
            "--path",
            "agentk-sidecar/team-permissions.toml",
        ])
        .expect("permissions should parse");
        let Some(Command::Permissions { path, .. }) = permissions.command else {
            panic!("expected permissions command");
        };
        assert_eq!(path, PathBuf::from("agentk-sidecar/team-permissions.toml"));

        let identity = Cli::try_parse_from([
            "agentk",
            "identity-check",
            "--identity",
            "agentk-sidecar/team-identity.toml",
            "--permissions",
            "agentk-sidecar/team-permissions.toml",
            "--json",
        ])
        .expect("identity-check should parse");
        let Some(Command::IdentityCheck {
            identity,
            permissions,
            json,
        }) = identity.command
        else {
            panic!("expected identity-check command");
        };
        assert_eq!(identity, PathBuf::from("agentk-sidecar/team-identity.toml"));
        assert_eq!(
            permissions,
            Some(PathBuf::from("agentk-sidecar/team-permissions.toml"))
        );
        assert!(json);

        let dashboard = Cli::try_parse_from([
            "agentk",
            "dashboard",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
            "--permissions",
            "agentk-sidecar/team-permissions.toml",
            "--out",
            "agentk-sidecar/.agentk/dashboard.html",
        ])
        .expect("dashboard should parse");
        let Some(Command::Dashboard {
            path,
            decisions,
            permissions,
            out,
            ..
        }) = dashboard.command
        else {
            panic!("expected dashboard command");
        };
        assert_eq!(
            approval_decisions_path(&path, decisions),
            PathBuf::from("agentk-sidecar/.agentk/approvals.jsonl")
        );
        assert_eq!(
            permissions,
            Some(PathBuf::from("agentk-sidecar/team-permissions.toml"))
        );
        assert_eq!(out, PathBuf::from("agentk-sidecar/.agentk/dashboard.html"));

        let dashboard_serve = Cli::try_parse_from([
            "agentk",
            "dashboard-serve",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
            "--permissions",
            "agentk-sidecar/team-permissions.toml",
            "--identity",
            "agentk-sidecar/team-identity.toml",
            "--host",
            "127.0.0.1",
            "--port",
            "8787",
            "--stream-timeout-ms",
            "12000",
            "--max-body-bytes",
            "1234",
            "--max-header-bytes",
            "4321",
            "--store-root",
            "agentk-sidecar/.agentk/team-store",
        ])
        .expect("dashboard server should parse");
        let Some(Command::DashboardServe {
            path,
            decisions,
            permissions,
            identity,
            host,
            port,
            admin_token_env,
            stream_timeout_ms,
            max_body_bytes,
            max_header_bytes,
            allow_non_local_bind,
            store_root,
        }) = dashboard_serve.command
        else {
            panic!("expected dashboard-serve command");
        };
        assert_eq!(
            approval_decisions_path(&path, decisions),
            PathBuf::from("agentk-sidecar/.agentk/approvals.jsonl")
        );
        assert_eq!(
            permissions,
            Some(PathBuf::from("agentk-sidecar/team-permissions.toml"))
        );
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8787);
        assert_eq!(admin_token_env, "AGENTK_DASHBOARD_ADMIN_TOKEN");
        assert_eq!(stream_timeout_ms, 12000);
        assert_eq!(max_body_bytes, 1234);
        assert_eq!(max_header_bytes, 4321);
        assert!(!allow_non_local_bind);
        assert_eq!(
            store_root,
            Some(PathBuf::from("agentk-sidecar/.agentk/team-store"))
        );
        assert_eq!(
            identity,
            Some(PathBuf::from("agentk-sidecar/team-identity.toml"))
        );

        let dashboard_serve_non_local = Cli::try_parse_from([
            "agentk",
            "dashboard-serve",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
            "--host",
            "0.0.0.0",
            "--allow-non-local-bind",
        ])
        .expect("dashboard server non-local opt-in should parse");
        let Some(Command::DashboardServe {
            allow_non_local_bind,
            ..
        }) = dashboard_serve_non_local.command
        else {
            panic!("expected dashboard-serve command");
        };
        assert!(allow_non_local_bind);

        validate_dashboard_http_size_limits(1, 1)
            .expect("positive dashboard HTTP bounds should pass");
        let missing_body_limit = validate_dashboard_http_size_limits(0, 1)
            .expect_err("zero body limit should fail")
            .to_string();
        assert!(missing_body_limit.contains("max-body-bytes"));
        let missing_header_limit = validate_dashboard_http_size_limits(1, 0)
            .expect_err("zero header limit should fail")
            .to_string();
        assert!(missing_header_limit.contains("max-header-bytes"));

        validate_dashboard_bind_security("127.0.0.1", false, false)
            .expect("loopback dashboard bind should not require auth");
        validate_dashboard_bind_security("localhost", false, false)
            .expect("localhost dashboard bind should not require auth");
        let missing_opt_in = validate_dashboard_bind_security("0.0.0.0", false, true)
            .expect_err("non-loopback dashboard bind should require opt-in")
            .to_string();
        assert!(missing_opt_in.contains("--allow-non-local-bind"));
        let missing_admin = validate_dashboard_bind_security("0.0.0.0", true, false)
            .expect_err("non-loopback dashboard bind should require admin auth")
            .to_string();
        assert!(missing_admin.contains("non-empty admin token"));
        validate_dashboard_bind_security("0.0.0.0", true, true)
            .expect("non-loopback dashboard bind should allow explicit authenticated opt-in");
        validate_dashboard_stream_timeout(Duration::from_millis(1))
            .expect("positive dashboard stream timeout should be allowed");
        let zero_timeout = validate_dashboard_stream_timeout(Duration::ZERO)
            .expect_err("zero dashboard stream timeout should fail")
            .to_string();
        assert!(zero_timeout.contains("stream-timeout-ms"));

        let store_export = Cli::try_parse_from([
            "agentk",
            "store-export",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
            "--permissions",
            "agentk-sidecar/team-permissions.toml",
            "--identity",
            "agentk-sidecar/team-identity.toml",
            "--out",
            "agentk-sidecar/.agentk/store",
        ])
        .expect("store export should parse");
        let Some(Command::StoreExport {
            path,
            decisions,
            permissions,
            identity,
            out,
            ..
        }) = store_export.command
        else {
            panic!("expected store-export command");
        };
        assert_eq!(
            approval_decisions_path(&path, decisions),
            PathBuf::from("agentk-sidecar/.agentk/approvals.jsonl")
        );
        assert_eq!(
            permissions,
            Some(PathBuf::from("agentk-sidecar/team-permissions.toml"))
        );
        assert_eq!(
            identity,
            Some(PathBuf::from("agentk-sidecar/team-identity.toml"))
        );
        assert_eq!(out, PathBuf::from("agentk-sidecar/.agentk/store"));

        let store_sync = Cli::try_parse_from([
            "agentk",
            "store-sync",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
            "--permissions",
            "agentk-sidecar/team-permissions.toml",
            "--identity",
            "agentk-sidecar/team-identity.toml",
            "--root",
            "agentk-sidecar/.agentk/team-store",
        ])
        .expect("store sync should parse");
        let Some(Command::StoreSync {
            path,
            decisions,
            permissions,
            identity,
            root,
            ..
        }) = store_sync.command
        else {
            panic!("expected store-sync command");
        };
        assert_eq!(
            approval_decisions_path(&path, decisions),
            PathBuf::from("agentk-sidecar/.agentk/approvals.jsonl")
        );
        assert_eq!(
            permissions,
            Some(PathBuf::from("agentk-sidecar/team-permissions.toml"))
        );
        assert_eq!(
            identity,
            Some(PathBuf::from("agentk-sidecar/team-identity.toml"))
        );
        assert_eq!(root, PathBuf::from("agentk-sidecar/.agentk/team-store"));

        let store_check = Cli::try_parse_from([
            "agentk",
            "store-check",
            "--root",
            "agentk-sidecar/.agentk/store",
        ])
        .expect("store check should parse");
        let Some(Command::StoreCheck { root, .. }) = store_check.command else {
            panic!("expected store-check command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar/.agentk/store"));

        let store_push = Cli::try_parse_from([
            "agentk",
            "store-push",
            "--root",
            "agentk-sidecar/.agentk/store",
            "--database-url-env",
            "AGENTK_TEST_DATABASE_URL",
            "--psql",
            "custom-psql",
            "--dry-run",
        ])
        .expect("store push should parse");
        let Some(Command::StorePush {
            root,
            database_url_env,
            psql,
            dry_run,
            ..
        }) = store_push.command
        else {
            panic!("expected store-push command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar/.agentk/store"));
        assert_eq!(database_url_env, "AGENTK_TEST_DATABASE_URL");
        assert_eq!(psql, "custom-psql");
        assert!(dry_run);

        let store_slack = Cli::try_parse_from([
            "agentk",
            "store-slack",
            "--root",
            "agentk-sidecar/.agentk/team-store",
            "--out",
            "agentk-sidecar/.agentk/slack",
            "--channel",
            "#agentk-approvals",
            "--json",
        ])
        .expect("store slack should parse");
        let Some(Command::StoreSlack {
            root,
            out,
            channel,
            json,
        }) = store_slack.command
        else {
            panic!("expected store-slack command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar/.agentk/team-store"));
        assert_eq!(out, PathBuf::from("agentk-sidecar/.agentk/slack"));
        assert_eq!(channel, Some("#agentk-approvals".to_string()));
        assert!(json);

        let store_slack_send = Cli::try_parse_from([
            "agentk",
            "store-slack-send",
            "--payload-root",
            "agentk-sidecar/.agentk/slack",
            "--webhook-url-env",
            "AGENTK_TEST_SLACK_WEBHOOK_URL",
            "--curl",
            "custom-curl",
            "--dry-run",
            "--json",
        ])
        .expect("store slack send should parse");
        let Some(Command::StoreSlackSend {
            payload_root,
            webhook_url_env,
            curl,
            dry_run,
            json,
        }) = store_slack_send.command
        else {
            panic!("expected store-slack-send command");
        };
        assert_eq!(payload_root, PathBuf::from("agentk-sidecar/.agentk/slack"));
        assert_eq!(webhook_url_env, "AGENTK_TEST_SLACK_WEBHOOK_URL");
        assert_eq!(curl, "custom-curl");
        assert!(dry_run);
        assert!(json);

        let store_github = Cli::try_parse_from([
            "agentk",
            "store-github",
            "--root",
            "agentk-sidecar/.agentk/team-store",
            "--out",
            "agentk-sidecar/.agentk/github",
            "--repository",
            "owner/repo",
            "--label",
            "agentk",
            "--label",
            "approvals",
            "--json",
        ])
        .expect("store github should parse");
        let Some(Command::StoreGithub {
            root,
            out,
            repository,
            label,
            json,
        }) = store_github.command
        else {
            panic!("expected store-github command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar/.agentk/team-store"));
        assert_eq!(out, PathBuf::from("agentk-sidecar/.agentk/github"));
        assert_eq!(repository, Some("owner/repo".to_string()));
        assert_eq!(label, vec!["agentk".to_string(), "approvals".to_string()]);
        assert!(json);

        let store_github_send = Cli::try_parse_from([
            "agentk",
            "store-github-send",
            "--payload-root",
            "agentk-sidecar/.agentk/github",
            "--github-token-env",
            "AGENTK_TEST_GITHUB_TOKEN",
            "--gh",
            "custom-gh",
            "--dry-run",
            "--json",
        ])
        .expect("store github send should parse");
        let Some(Command::StoreGithubSend {
            payload_root,
            github_token_env,
            gh,
            dry_run,
            json,
        }) = store_github_send.command
        else {
            panic!("expected store-github-send command");
        };
        assert_eq!(payload_root, PathBuf::from("agentk-sidecar/.agentk/github"));
        assert_eq!(github_token_env, "AGENTK_TEST_GITHUB_TOKEN");
        assert_eq!(gh, "custom-gh");
        assert!(dry_run);
        assert!(json);

        let store_email = Cli::try_parse_from([
            "agentk",
            "store-email",
            "--root",
            "agentk-sidecar/.agentk/team-store",
            "--out",
            "agentk-sidecar/.agentk/email",
            "--to",
            "agentk-alerts@example.com",
            "--json",
        ])
        .expect("store email should parse");
        let Some(Command::StoreEmail {
            root,
            out,
            to,
            json,
        }) = store_email.command
        else {
            panic!("expected store-email command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar/.agentk/team-store"));
        assert_eq!(out, PathBuf::from("agentk-sidecar/.agentk/email"));
        assert_eq!(to, vec!["agentk-alerts@example.com".to_string()]);
        assert!(json);

        let store_email_send = Cli::try_parse_from([
            "agentk",
            "store-email-send",
            "--payload-root",
            "agentk-sidecar/.agentk/email",
            "--sendmail",
            "custom-sendmail",
            "--dry-run",
            "--json",
        ])
        .expect("store email send should parse");
        let Some(Command::StoreEmailSend {
            payload_root,
            sendmail,
            dry_run,
            json,
        }) = store_email_send.command
        else {
            panic!("expected store-email-send command");
        };
        assert_eq!(payload_root, PathBuf::from("agentk-sidecar/.agentk/email"));
        assert_eq!(sendmail, "custom-sendmail");
        assert!(dry_run);
        assert!(json);

        let release_candidate_smoke = Cli::try_parse_from([
            "agentk",
            "release-candidate-smoke",
            "--root",
            "agentk-rc-smoke",
            "--evidence-out",
            "dist/release-candidate-smoke.json",
            "--force",
            "--keep-root",
        ])
        .expect("release candidate smoke should parse");
        let Some(Command::ReleaseCandidateSmoke {
            root,
            force,
            keep_root,
            evidence_out,
            ..
        }) = release_candidate_smoke.command
        else {
            panic!("expected release-candidate-smoke command");
        };
        assert_eq!(root, Some(PathBuf::from("agentk-rc-smoke")));
        assert_eq!(
            evidence_out,
            Some(PathBuf::from("dist/release-candidate-smoke.json"))
        );
        assert!(force);
        assert!(keep_root);

        let release_evidence_check = Cli::try_parse_from([
            "agentk",
            "release-evidence-check",
            "--evidence",
            "dist/release-candidate-smoke.json",
            "--root",
            "dist/release-candidate-smoke",
            "--json",
        ])
        .expect("release evidence check should parse");
        let Some(Command::ReleaseEvidenceCheck {
            evidence,
            root,
            json,
        }) = release_evidence_check.command
        else {
            panic!("expected release-evidence-check command");
        };
        assert_eq!(evidence, PathBuf::from("dist/release-candidate-smoke.json"));
        assert_eq!(root, Some(PathBuf::from("dist/release-candidate-smoke")));
        assert!(json);

        let release_ticket = Cli::try_parse_from([
            "agentk",
            "release-ticket",
            "--release",
            "v0.2-alpha",
            "--out",
            "dist/release-ticket",
            "--notes",
            "docs/v0.2-alpha-release-notes.md",
            "--tag",
            "v0.2.0-alpha.1",
            "--strict",
            "--force",
            "--json",
        ])
        .expect("release ticket should parse");
        let Some(Command::ReleaseTicket {
            release,
            out,
            notes,
            tag,
            strict,
            force,
            json,
        }) = release_ticket.command
        else {
            panic!("expected release-ticket command");
        };
        assert_eq!(release, "v0.2-alpha");
        assert_eq!(out, PathBuf::from("dist/release-ticket"));
        assert_eq!(notes, PathBuf::from("docs/v0.2-alpha-release-notes.md"));
        assert_eq!(tag, Some("v0.2.0-alpha.1".to_string()));
        assert!(strict);
        assert!(force);
        assert!(json);

        let release_status = Cli::try_parse_from(["agentk", "release-status", "--json"])
            .expect("release status should parse");
        let Some(Command::ReleaseStatus { json }) = release_status.command else {
            panic!("expected release-status command");
        };
        assert!(json);

        let release_publication_check = Cli::try_parse_from([
            "agentk",
            "release-publication-check",
            "--finalization",
            "dist/release-finalization.json",
            "--notes",
            "docs/v0.2-alpha-release-notes.md",
            "--json",
        ])
        .expect("release publication check should parse");
        let Some(Command::ReleasePublicationCheck {
            finalization,
            notes,
            json,
        }) = release_publication_check.command
        else {
            panic!("expected release-publication-check command");
        };
        assert_eq!(
            finalization,
            PathBuf::from("dist/release-finalization.json")
        );
        assert_eq!(
            notes,
            Some(PathBuf::from("docs/v0.2-alpha-release-notes.md"))
        );
        assert!(json);

        let release_homebrew_formula = Cli::try_parse_from([
            "agentk",
            "release-homebrew-formula",
            "--source-url",
            "https://github.com/agentk/agentk/archive/refs/tags/v0.1.0.tar.gz",
            "--sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--source-archive",
            "dist/agentk-v0.1.0.tar.gz",
            "--out",
            "dist/homebrew/agentk.rb",
            "--version",
            "0.1.0",
            "--homepage",
            "https://github.com/agentk/agentk",
            "--class-name",
            "Agentk",
            "--force",
            "--json",
        ])
        .expect("release homebrew formula should parse");
        let Some(Command::ReleaseHomebrewFormula {
            source_url,
            sha256,
            source_archive,
            out,
            version,
            homepage,
            class_name,
            force,
            json,
        }) = release_homebrew_formula.command
        else {
            panic!("expected release-homebrew-formula command");
        };
        assert_eq!(
            source_url,
            "https://github.com/agentk/agentk/archive/refs/tags/v0.1.0.tar.gz"
        );
        assert_eq!(
            sha256,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
        assert_eq!(
            source_archive,
            Some(PathBuf::from("dist/agentk-v0.1.0.tar.gz"))
        );
        assert_eq!(out, PathBuf::from("dist/homebrew/agentk.rb"));
        assert_eq!(version, Some("0.1.0".to_string()));
        assert_eq!(homepage, "https://github.com/agentk/agentk");
        assert_eq!(class_name, "Agentk");
        assert!(force);
        assert!(json);

        let release_homebrew_formula_check = Cli::try_parse_from([
            "agentk",
            "release-homebrew-formula-check",
            "--formula",
            "dist/homebrew/agentk.rb",
            "--source-archive",
            "dist/agentk-v0.1.0.tar.gz",
            "--source-url",
            "https://github.com/agentk/agentk/archive/refs/tags/v0.1.0.tar.gz",
            "--sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--version",
            "0.1.0",
            "--homepage",
            "https://github.com/agentk/agentk",
            "--class-name",
            "Agentk",
            "--json",
        ])
        .expect("release homebrew formula check should parse");
        let Some(Command::ReleaseHomebrewFormulaCheck {
            formula,
            source_archive,
            source_url,
            sha256,
            version,
            homepage,
            class_name,
            json,
        }) = release_homebrew_formula_check.command
        else {
            panic!("expected release-homebrew-formula-check command");
        };
        assert_eq!(formula, PathBuf::from("dist/homebrew/agentk.rb"));
        assert_eq!(
            source_archive,
            Some(PathBuf::from("dist/agentk-v0.1.0.tar.gz"))
        );
        assert_eq!(
            source_url,
            Some("https://github.com/agentk/agentk/archive/refs/tags/v0.1.0.tar.gz".to_string())
        );
        assert_eq!(
            sha256,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
        assert_eq!(version, Some("0.1.0".to_string()));
        assert_eq!(
            homepage,
            Some("https://github.com/agentk/agentk".to_string())
        );
        assert_eq!(class_name, Some("Agentk".to_string()));
        assert!(json);

        let release_homebrew_tap_handoff_check = Cli::try_parse_from([
            "agentk",
            "release-homebrew-tap-handoff-check",
            "--formula",
            "dist/homebrew/agentk.rb",
            "--tap-root",
            "dist/homebrew-tap",
            "--tap-formula-path",
            "Formula/agentk.rb",
            "--source-archive",
            "dist/agentk-v0.1.0.tar.gz",
            "--source-url",
            "https://github.com/agentk/agentk/archive/refs/tags/v0.1.0.tar.gz",
            "--sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--version",
            "0.1.0",
            "--homepage",
            "https://github.com/agentk/agentk",
            "--class-name",
            "Agentk",
            "--tap",
            "atomics-hub/agentk",
            "--json",
        ])
        .expect("release homebrew tap handoff check should parse");
        let Some(Command::ReleaseHomebrewTapHandoffCheck {
            formula,
            tap_root,
            tap_formula_path,
            source_archive,
            source_url,
            sha256,
            version,
            homepage,
            class_name,
            tap,
            json,
        }) = release_homebrew_tap_handoff_check.command
        else {
            panic!("expected release-homebrew-tap-handoff-check command");
        };
        assert_eq!(formula, PathBuf::from("dist/homebrew/agentk.rb"));
        assert_eq!(tap_root, PathBuf::from("dist/homebrew-tap"));
        assert_eq!(tap_formula_path, "Formula/agentk.rb");
        assert_eq!(
            source_archive,
            Some(PathBuf::from("dist/agentk-v0.1.0.tar.gz"))
        );
        assert_eq!(
            source_url,
            Some("https://github.com/agentk/agentk/archive/refs/tags/v0.1.0.tar.gz".to_string())
        );
        assert_eq!(
            sha256,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
        assert_eq!(version, Some("0.1.0".to_string()));
        assert_eq!(
            homepage,
            Some("https://github.com/agentk/agentk".to_string())
        );
        assert_eq!(class_name, Some("Agentk".to_string()));
        assert_eq!(tap, Some("atomics-hub/agentk".to_string()));
        assert!(json);
    }

    #[test]
    fn store_push_dry_run_preflights_without_exposing_database_url() {
        let trace_path = test_temp_path("agentk-store-push-trace", "jsonl");
        let decisions_path = test_temp_path("agentk-store-push-decisions", "jsonl");
        let output_dir = test_temp_path("agentk-store-push-export", "dir");
        run_safe_agent_demo(&trace_path).expect("safe agent demo should write a trace");
        export_audit_store(&trace_path, &decisions_path, None, None, &output_dir)
            .expect("store export should write");

        let report = run_store_push(
            output_dir.clone(),
            "AGENTK_TEST_DATABASE_URL".to_string(),
            "psql".to_string(),
            true,
        )
        .expect("dry-run push should pass preflight");

        assert!(report.preflight_passed);
        assert!(report.dry_run);
        assert!(!report.pushed);
        assert_eq!(report.command[1], "$AGENTK_TEST_DATABASE_URL");
        assert!(report.load_sql.ends_with("postgres/load.sql"));

        let unsafe_env = run_store_push(
            output_dir.clone(),
            "BAD-NAME".to_string(),
            "psql".to_string(),
            true,
        )
        .expect_err("unsafe env name should fail")
        .to_string();
        assert!(unsafe_env.contains("safe environment variable name"));

        fs::remove_file(output_dir.join("postgres/load.sql")).expect("load script should remove");
        let broken = run_store_push(
            output_dir.clone(),
            "AGENTK_TEST_DATABASE_URL".to_string(),
            "psql".to_string(),
            true,
        )
        .expect_err("broken store should fail preflight")
        .to_string();
        assert!(broken.contains("audit store preflight failed"));

        let _ = fs::remove_file(trace_path);
        let _ = fs::remove_file(decisions_path);
        fs::remove_dir_all(output_dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn store_slack_send_delivers_with_fake_curl_without_reporting_webhook() {
        use std::os::unix::fs::PermissionsExt;

        let payload_root = test_temp_path("agentk-slack-payload-root", "dir");
        let fake_curl = test_temp_path("agentk-fake-curl", "sh");
        let args_path = test_temp_path("agentk-fake-curl-args", "txt");
        let config_path = test_temp_path("agentk-fake-curl-config", "txt");
        let webhook_env = format!("AGENTK_TEST_SLACK_WEBHOOK_{}", std::process::id());
        fs::create_dir_all(&payload_root).expect("payload root should create");
        fs::write(
            payload_root.join("manifest.json"),
            serde_json::json!({
                "schema": "agentk.slack_notification_payloads",
                "version": 1,
                "payloads": "payloads.jsonl"
            })
            .to_string(),
        )
        .expect("manifest should write");
        fs::write(
            payload_root.join("payloads.jsonl"),
            serde_json::json!({
                "text": "AgentK approval requested",
                "blocks": []
            })
            .to_string()
                + "\n",
        )
        .expect("payloads should write");
        fs::write(
            &fake_curl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\ncase \"$*\" in *SECRET*) exit 23;; esac\nexit 0\n",
                args_path.display(),
                config_path.display()
            ),
        )
        .expect("fake curl should write");
        fs::set_permissions(&fake_curl, fs::Permissions::from_mode(0o700))
            .expect("fake curl should be executable");

        let dry_run = run_store_slack_send(
            payload_root.clone(),
            webhook_env.clone(),
            fake_curl.display().to_string(),
            true,
        )
        .expect("dry-run should parse payload export without a webhook");
        assert_eq!(dry_run.payloads, 1);
        assert_eq!(dry_run.delivered, 0);
        assert!(!dry_run.webhook_url_present);

        unsafe {
            env::set_var(&webhook_env, "https://hooks.slack.test/services/SECRET");
        }
        let report = run_store_slack_send(
            payload_root.clone(),
            webhook_env.clone(),
            fake_curl.display().to_string(),
            false,
        )
        .expect("fake curl delivery should succeed");
        let report_json = serde_json::to_string(&report).expect("report should serialize");
        assert_eq!(report.payloads, 1);
        assert_eq!(report.delivered, 1);
        assert_eq!(report.failed, 0);
        assert!(report.webhook_url_present);
        assert!(!report_json.contains("SECRET"));
        assert!(!report.command.iter().any(|arg| arg.contains("SECRET")));
        let args = fs::read_to_string(&args_path).expect("fake curl args should read");
        assert!(!args.contains("SECRET"));
        let config = fs::read_to_string(&config_path).expect("fake curl config should read");
        assert!(config.contains("https://hooks.slack.test/services/SECRET"));
        assert!(config.contains("data-binary = \"@"));

        unsafe {
            env::remove_var(&webhook_env);
        }
        fs::remove_dir_all(payload_root).ok();
        let _ = fs::remove_file(fake_curl);
        let _ = fs::remove_file(args_path);
        let _ = fs::remove_file(config_path);
    }

    #[cfg(unix)]
    #[test]
    fn store_github_send_delivers_with_fake_gh_without_reporting_token() {
        use std::os::unix::fs::PermissionsExt;

        let payload_root = test_temp_path("agentk-github-payload-root", "dir");
        let fake_gh = test_temp_path("agentk-fake-gh", "sh");
        let args_path = test_temp_path("agentk-fake-gh-args", "txt");
        let token_env = format!("AGENTK_TEST_GITHUB_TOKEN_{}", std::process::id());
        fs::create_dir_all(&payload_root).expect("payload root should create");
        fs::write(
            payload_root.join("manifest.json"),
            serde_json::json!({
                "schema": "agentk.github_notification_payloads",
                "version": 1,
                "payloads": "payloads.jsonl"
            })
            .to_string(),
        )
        .expect("manifest should write");
        fs::write(
            payload_root.join("payloads.jsonl"),
            serde_json::json!({
                "operation": "upsert_issue",
                "dedupe_key": "agentk:test-trace:appr_test:approval_requested",
                "repository": "owner/repo",
                "issue": {
                    "title": "AgentK approval requested: appr_test",
                    "body": "Review approval appr_test.",
                    "labels": ["agentk", "approval"],
                    "desired_state": "open"
                },
                "metadata": {
                    "notification_id": "notif_requested_appr_test"
                }
            })
            .to_string()
                + "\n",
        )
        .expect("payloads should write");
        fs::write(
            &fake_gh,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\ncase \"$*\" in *SECRET*) exit 23;; esac\ncase \"$*\" in *search/issues*) exit 0;; *repos/owner/repo/issues*) printf '{{\"number\":456}}\\n'; exit 0;; *) exit 0;; esac\n",
                args_path.display()
            ),
        )
        .expect("fake gh should write");
        fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o700))
            .expect("fake gh should be executable");

        let dry_run = run_store_github_send(
            payload_root.clone(),
            token_env.clone(),
            fake_gh.display().to_string(),
            true,
        )
        .expect("dry-run should parse payload export without a token");
        assert_eq!(dry_run.payloads, 1);
        assert_eq!(dry_run.delivered, 0);
        assert!(!dry_run.github_token_present);

        unsafe {
            env::set_var(&token_env, "SECRET_GITHUB_TOKEN");
        }
        let report = run_store_github_send(
            payload_root.clone(),
            token_env.clone(),
            fake_gh.display().to_string(),
            false,
        )
        .expect("fake gh delivery should succeed");
        let report_json = serde_json::to_string(&report).expect("report should serialize");
        assert_eq!(report.payloads, 1);
        assert_eq!(report.delivered, 1);
        assert_eq!(report.failed, 0);
        assert!(report.github_token_present);
        assert_eq!(report.attempts[0].operation, "created");
        assert_eq!(report.attempts[0].issue_number, Some(456));
        assert!(!report_json.contains("SECRET_GITHUB_TOKEN"));
        assert!(
            !report
                .command
                .iter()
                .any(|arg| arg.contains("SECRET_GITHUB_TOKEN"))
        );
        let args = fs::read_to_string(&args_path).expect("fake gh args should read");
        assert!(!args.contains("SECRET_GITHUB_TOKEN"));
        assert!(args.contains("search/issues"));
        assert!(args.contains("repos/owner/repo/issues"));

        unsafe {
            env::remove_var(&token_env);
        }
        fs::remove_dir_all(payload_root).ok();
        let _ = fs::remove_file(fake_gh);
        let _ = fs::remove_file(args_path);
    }

    #[cfg(unix)]
    #[test]
    fn store_email_send_delivers_with_fake_sendmail() {
        use std::os::unix::fs::PermissionsExt;

        let payload_root = test_temp_path("agentk-email-payload-root", "dir");
        let fake_sendmail = test_temp_path("agentk-fake-sendmail", "sh");
        let args_path = test_temp_path("agentk-fake-sendmail-args", "txt");
        let message_path = test_temp_path("agentk-fake-sendmail-message", "txt");
        fs::create_dir_all(&payload_root).expect("payload root should create");
        fs::write(
            payload_root.join("manifest.json"),
            serde_json::json!({
                "schema": "agentk.email_notification_payloads",
                "version": 1,
                "payloads": "payloads.jsonl"
            })
            .to_string(),
        )
        .expect("manifest should write");
        fs::write(
            payload_root.join("payloads.jsonl"),
            serde_json::json!({
                "to": ["agentk-alerts@example.com"],
                "subject": "AgentK approval requested: appr_test",
                "message": "To: agentk-alerts@example.com\nSubject: AgentK approval requested: appr_test\n\nReview approval appr_test."
            })
            .to_string()
                + "\n",
        )
        .expect("payloads should write");
        fs::write(
            &fake_sendmail,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\ncase \"$*\" in *SECRET*) exit 23;; esac\nexit 0\n",
                args_path.display(),
                message_path.display()
            ),
        )
        .expect("fake sendmail should write");
        fs::set_permissions(&fake_sendmail, fs::Permissions::from_mode(0o700))
            .expect("fake sendmail should be executable");

        let dry_run = run_store_email_send(
            payload_root.clone(),
            fake_sendmail.display().to_string(),
            true,
        )
        .expect("dry-run should parse payload export");
        assert_eq!(dry_run.payloads, 1);
        assert_eq!(dry_run.delivered, 0);
        assert_eq!(
            dry_run.command,
            vec![
                fake_sendmail.display().to_string(),
                "-t".to_string(),
                "-oi".to_string()
            ]
        );

        let report = run_store_email_send(
            payload_root.clone(),
            fake_sendmail.display().to_string(),
            false,
        )
        .expect("fake sendmail delivery should succeed");
        let report_json = serde_json::to_string(&report).expect("report should serialize");
        assert_eq!(report.payloads, 1);
        assert_eq!(report.delivered, 1);
        assert_eq!(report.failed, 0);
        assert!(!report_json.contains("SECRET"));
        let args = fs::read_to_string(&args_path).expect("fake sendmail args should read");
        assert!(args.contains("-t"));
        assert!(args.contains("-oi"));
        let message = fs::read_to_string(&message_path).expect("fake sendmail message should read");
        assert!(message.contains("To: agentk-alerts@example.com"));
        assert!(message.contains("Subject: AgentK approval requested"));
        assert!(message.contains("Review approval appr_test."));
        assert!(!message.contains("SECRET"));

        fs::remove_dir_all(payload_root).ok();
        let _ = fs::remove_file(fake_sendmail);
        let _ = fs::remove_file(args_path);
        let _ = fs::remove_file(message_path);
    }

    #[test]
    fn release_candidate_smoke_requires_force_for_existing_root() {
        let root = test_temp_path("agentk-rc-smoke-existing", "dir");
        fs::create_dir_all(&root).expect("root should create");

        let error = run_release_candidate_smoke(Some(root.clone()), false, true, None)
            .expect_err("existing root should require force")
            .to_string();
        assert!(error.contains("already exists"));

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn release_candidate_smoke_artifacts_record_file_size_and_hash() {
        let path = test_temp_path("agentk-rc-smoke-artifact", "txt");
        fs::write(&path, b"agentk\n").expect("artifact should write");

        let mut artifacts = Vec::new();
        release_candidate_smoke_artifact(&mut artifacts, "sample", path.clone())
            .expect("artifact should hash");

        assert_eq!(artifacts.len(), 1);
        assert!(artifacts[0].present);
        assert_eq!(artifacts[0].bytes, Some(7));
        assert_eq!(
            artifacts[0].sha256,
            Some(release_candidate_smoke_file_sha256(&path).expect("hash should compute"))
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn release_ticket_smoke_inventory_lifts_named_artifacts() {
        let path = test_temp_path("agentk-ticket-smoke-artifact", "json");
        fs::write(&path, b"{\"ready\":true}\n").expect("artifact should write");
        let sha256 = release_candidate_smoke_file_sha256(&path).expect("hash should compute");
        let smoke = ReleaseCandidateSmokeReport {
            root: PathBuf::from("root"),
            package: PathBuf::from("root/dist/agentk-sidecar"),
            package_archive: PathBuf::from("root/dist/agentk-sidecar.tar"),
            package_archive_checksum: PathBuf::from("root/dist/agentk-sidecar.tar.sha256"),
            package_release_manifest: PathBuf::from(
                "root/dist/agentk-sidecar-release-manifest.json",
            ),
            evidence_report: None,
            installed_package: PathBuf::from("root/installed/agentk-sidecar"),
            package_archive_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            trace_path: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/runs/safe-agent-demo.jsonl",
            ),
            dashboard_path: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/dashboard.html",
            ),
            store_export_root: PathBuf::from("root/installed/agentk-sidecar/sidecar/.agentk/store"),
            team_store_root: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/team-store",
            ),
            slack_payload_root: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/slack",
            ),
            github_payload_root: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/github",
            ),
            kept_root: true,
            passed: true,
            steps: Vec::new(),
            artifacts: vec![ReleaseCandidateSmokeArtifact {
                name: "quickstart json".to_string(),
                path: path.clone(),
                present: true,
                bytes: Some(15),
                sha256: Some(sha256.clone()),
            }],
        };

        let artifacts =
            release_ticket_named_smoke_inventory_artifacts(&smoke, &["quickstart json"])
                .expect("named smoke artifact should lift into ticket inventory");

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "smoke: quickstart json");
        assert_eq!(artifacts[0].path, path);
        assert_eq!(artifacts[0].bytes, 15);
        assert_eq!(artifacts[0].sha256, sha256);

        let _ = fs::remove_file(artifacts[0].path.clone());
    }

    #[test]
    fn release_candidate_smoke_evidence_requires_force_to_overwrite() {
        let out = test_temp_path("agentk-rc-smoke-evidence", "json");
        let report = ReleaseCandidateSmokeReport {
            root: PathBuf::from("root"),
            package: PathBuf::from("root/dist/agentk-sidecar"),
            package_archive: PathBuf::from("root/dist/agentk-sidecar.tar"),
            package_archive_checksum: PathBuf::from("root/dist/agentk-sidecar.tar.sha256"),
            package_release_manifest: PathBuf::from(
                "root/dist/agentk-sidecar-release-manifest.json",
            ),
            evidence_report: Some(out.clone()),
            installed_package: PathBuf::from("root/installed/agentk-sidecar"),
            package_archive_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            trace_path: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/runs/safe-agent-demo.jsonl",
            ),
            dashboard_path: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/dashboard.html",
            ),
            store_export_root: PathBuf::from("root/installed/agentk-sidecar/sidecar/.agentk/store"),
            team_store_root: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/team-store",
            ),
            slack_payload_root: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/slack",
            ),
            github_payload_root: PathBuf::from(
                "root/installed/agentk-sidecar/sidecar/.agentk/github",
            ),
            kept_root: true,
            passed: true,
            steps: Vec::new(),
            artifacts: Vec::new(),
        };

        write_release_candidate_smoke_evidence(&report, &out, false)
            .expect("first evidence write should pass");
        let error = write_release_candidate_smoke_evidence(&report, &out, false)
            .expect_err("second evidence write should require force")
            .to_string();
        assert!(error.contains("already exists"));
        write_release_candidate_smoke_evidence(&report, &out, true)
            .expect("force should overwrite evidence");
        let content = fs::read_to_string(&out).expect("evidence should read");
        assert!(content.contains("package_archive_sha256"));
        assert!(content.contains("evidence_report"));

        let _ = fs::remove_file(out);
    }

    #[test]
    fn release_evidence_check_verifies_and_detects_changed_artifacts() {
        let root = test_temp_path("agentk-release-evidence-root", "dir");
        let evidence = test_temp_path("agentk-release-evidence", "json");
        let report = synthetic_release_smoke_report(&root, &evidence);
        write_release_candidate_smoke_evidence(&report, &evidence, false)
            .expect("evidence should write");

        let clean = run_release_evidence_check(&evidence, None).expect("evidence should check");

        assert!(clean.passed);
        assert_eq!(clean.steps_passed, clean.steps_total);
        assert_eq!(
            clean.artifacts_total,
            RELEASE_CANDIDATE_SMOKE_REQUIRED_ARTIFACTS.len()
        );
        assert_eq!(clean.artifacts_verified, clean.artifacts_total);
        assert_eq!(clean.missing_artifacts, 0);
        assert_eq!(clean.changed_artifacts, 0);

        let package_lock = report
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "package lock")
            .expect("package lock artifact should exist")
            .path
            .clone();
        fs::write(&package_lock, "tampered package lock\n").expect("artifact should tamper");

        let tampered =
            run_release_evidence_check(&evidence, None).expect("tampered evidence should parse");

        assert!(!tampered.passed);
        assert_eq!(tampered.changed_artifacts, 1);
        assert!(
            tampered
                .checks
                .iter()
                .any(|check| check.name == "artifact hashes"
                    && check.status == ReadinessStatus::Fail)
        );

        fs::remove_dir_all(root).ok();
        let _ = fs::remove_file(evidence);
    }

    #[test]
    fn release_evidence_check_rebases_relocated_smoke_root() {
        let original_root = test_temp_path("agentk-release-evidence-original", "dir");
        let relocated_root = test_temp_path("agentk-release-evidence-relocated", "dir");
        let evidence = test_temp_path("agentk-release-evidence-rebased", "json");
        let report = synthetic_release_smoke_report(&original_root, &evidence);
        for artifact in &report.artifacts {
            let relative = artifact
                .path
                .strip_prefix(&original_root)
                .expect("artifact should live under original root");
            let relocated = relocated_root.join(relative);
            if let Some(parent) = relocated.parent() {
                fs::create_dir_all(parent).expect("relocated parent should create");
            }
            fs::copy(&artifact.path, &relocated).expect("artifact should copy");
        }
        write_release_candidate_smoke_evidence(&report, &evidence, false)
            .expect("evidence should write");
        fs::remove_dir_all(&original_root).expect("original root should remove");

        let check = run_release_evidence_check(&evidence, Some(relocated_root.clone()))
            .expect("relocated evidence should check");

        assert!(check.passed);
        assert_eq!(check.reported_root, original_root);
        assert_eq!(check.checked_root, relocated_root);
        assert_eq!(check.artifacts_verified, check.artifacts_total);

        fs::remove_dir_all(check.checked_root).ok();
        let _ = fs::remove_file(evidence);
    }

    #[test]
    fn release_finalize_writes_strict_handoff_without_publishing() {
        let root = test_temp_path("agentk-release-finalize-root", "dir");
        let evidence = test_temp_path("agentk-release-finalize-evidence", "json");
        let notes = test_temp_path("agentk-release-finalize-notes", "md");
        let out = test_temp_path("agentk-release-finalize", "json");
        let report = synthetic_release_smoke_report(&root, &evidence);
        write_release_candidate_smoke_evidence(&report, &evidence, false)
            .expect("evidence should write");
        fs::write(
            &notes,
            format!(
                "# AgentK v0.2 Alpha Release Notes\n\n## Final Release Evidence\n\n\
                 - Release commit: `1111111111111111111111111111111111111111`\n\
                 - Package archive: `{}`\n\
                 - Package archive SHA-256: `{}`\n\
                 - Package release manifest: `{}`\n\
                 - Strict release-audit result: `passed`\n\
                 - AgentK evidence signing public key: `abababababababababababababababababababababababababababababababab`\n\
                 - Signed tag: `v0.2.0-alpha.1`\n\
                 - Signed tag verification: `git verify-tag v0.2.0-alpha.1 passed`\n\
                 - Git tag signer: `AgentK Release Maintainer`\n",
                report.package_archive.display(),
                report.package_archive_sha256,
                report.package_release_manifest.display()
            ),
        )
        .expect("notes should write");

        let finalized = run_release_finalize_with(
            ReleaseFinalizeOptions {
                release: "v0.2-alpha".to_string(),
                evidence: evidence.clone(),
                root: None,
                notes: notes.clone(),
                tag: Some("v0.2.0-alpha.1".to_string()),
                out: out.clone(),
                strict: true,
                force: false,
            },
            release_finalize_test_signer(agentk::SigningKeySource::File, true),
            |args| match args {
                ["rev-parse", "HEAD"] => Ok(release_finalize_test_git_output(
                    true,
                    "1111111111111111111111111111111111111111",
                    "",
                )),
                ["status", "--short"] => Ok(release_finalize_test_git_output(true, "", "")),
                ["verify-tag", "v0.2.0-alpha.1"] => Ok(release_finalize_test_git_output(
                    true,
                    "",
                    "gpg: Good signature from AgentK Release Maintainer",
                )),
                _ => panic!("unexpected git args: {args:?}"),
            },
        )
        .expect("finalization should run");

        assert!(finalized.ready);
        assert!(finalized.strict);
        assert_eq!(finalized.publish_state, "not-published");
        assert_eq!(
            finalized.commit.as_deref(),
            Some("1111111111111111111111111111111111111111")
        );
        assert!(finalized.worktree_clean);
        assert!(finalized.tag.verified);
        assert!(
            finalized
                .checks
                .iter()
                .all(|check| check.status == ReadinessStatus::Pass)
        );
        let output = fs::read_to_string(&out).expect("handoff report should write");
        assert!(output.contains("\"publish_state\": \"not-published\""));
        assert!(output.contains("\"package_archive_sha256\""));
        assert!(!output.contains("private"));

        fs::remove_dir_all(root).ok();
        let _ = fs::remove_file(evidence);
        let _ = fs::remove_file(notes);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn release_publication_check_accepts_matching_strict_finalization_and_notes() {
        let root = test_temp_path("agentk-release-publication-root", "dir");
        let evidence = test_temp_path("agentk-release-publication-evidence", "json");
        let notes = test_temp_path("agentk-release-publication-notes", "md");
        let out = test_temp_path("agentk-release-publication", "json");
        let report = synthetic_release_smoke_report(&root, &evidence);
        write_release_candidate_smoke_evidence(&report, &evidence, false)
            .expect("evidence should write");
        fs::write(
            &notes,
            format!(
                "# AgentK v0.2 Alpha Release Notes\n\n## Final Release Evidence\n\n\
                 - Release commit: `3333333333333333333333333333333333333333`\n\
                 - Package archive: `{}`\n\
                 - Package archive SHA-256: `{}`\n\
                 - Package release manifest: `{}`\n\
                 - Strict release-audit result: `AGENTK_REQUIRE_SIGNING_KEY=1 cargo run --locked -- release-audit --strict passed`\n\
                 - AgentK evidence signing public key: `abababababababababababababababababababababababababababababababab`\n\
                 - Signed tag: `v0.2.0-alpha.2`\n\
                 - Signed tag verification: `git verify-tag v0.2.0-alpha.2 passed`\n\
                 - Git tag signer: `AgentK Release Maintainer`\n",
                report.package_archive.display(),
                report.package_archive_sha256,
                report.package_release_manifest.display()
            ),
        )
        .expect("notes should write");

        run_release_finalize_with(
            ReleaseFinalizeOptions {
                release: "v0.2-alpha".to_string(),
                evidence: evidence.clone(),
                root: None,
                notes: notes.clone(),
                tag: Some("v0.2.0-alpha.2".to_string()),
                out: out.clone(),
                strict: true,
                force: false,
            },
            release_finalize_test_signer(agentk::SigningKeySource::File, true),
            |args| match args {
                ["rev-parse", "HEAD"] => Ok(release_finalize_test_git_output(
                    true,
                    "3333333333333333333333333333333333333333",
                    "",
                )),
                ["status", "--short"] => Ok(release_finalize_test_git_output(true, "", "")),
                ["verify-tag", "v0.2.0-alpha.2"] => Ok(release_finalize_test_git_output(
                    true,
                    "",
                    "gpg: Good signature from AgentK Release Maintainer",
                )),
                _ => panic!("unexpected git args: {args:?}"),
            },
        )
        .expect("finalization should run");

        let publication =
            run_release_publication_check(&out, None).expect("publication check should run");

        assert!(publication.passed);
        assert_eq!(publication.tag.as_deref(), Some("v0.2.0-alpha.2"));
        assert!(
            publication
                .checks
                .iter()
                .all(|check| check.status == ReadinessStatus::Pass)
        );

        fs::remove_dir_all(root).ok();
        let _ = fs::remove_file(evidence);
        let _ = fs::remove_file(notes);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn release_publication_check_blocks_stale_release_notes_after_finalization() {
        let root = test_temp_path("agentk-release-publication-stale-root", "dir");
        let evidence = test_temp_path("agentk-release-publication-stale-evidence", "json");
        let notes = test_temp_path("agentk-release-publication-stale-notes", "md");
        let out = test_temp_path("agentk-release-publication-stale", "json");
        let report = synthetic_release_smoke_report(&root, &evidence);
        write_release_candidate_smoke_evidence(&report, &evidence, false)
            .expect("evidence should write");
        fs::write(
            &notes,
            format!(
                "# AgentK v0.2 Alpha Release Notes\n\n## Final Release Evidence\n\n\
                 - Release commit: `4444444444444444444444444444444444444444`\n\
                 - Package archive: `{}`\n\
                 - Package archive SHA-256: `{}`\n\
                 - Package release manifest: `{}`\n\
                 - Strict release-audit result: `passed`\n\
                 - AgentK evidence signing public key: `abababababababababababababababababababababababababababababababab`\n\
                 - Signed tag: `v0.2.0-alpha.3`\n\
                 - Signed tag verification: `git verify-tag v0.2.0-alpha.3 passed`\n\
                 - Git tag signer: `AgentK Release Maintainer`\n",
                report.package_archive.display(),
                report.package_archive_sha256,
                report.package_release_manifest.display()
            ),
        )
        .expect("notes should write");

        run_release_finalize_with(
            ReleaseFinalizeOptions {
                release: "v0.2-alpha".to_string(),
                evidence: evidence.clone(),
                root: None,
                notes: notes.clone(),
                tag: Some("v0.2.0-alpha.3".to_string()),
                out: out.clone(),
                strict: true,
                force: false,
            },
            release_finalize_test_signer(agentk::SigningKeySource::File, true),
            |args| match args {
                ["rev-parse", "HEAD"] => Ok(release_finalize_test_git_output(
                    true,
                    "4444444444444444444444444444444444444444",
                    "",
                )),
                ["status", "--short"] => Ok(release_finalize_test_git_output(true, "", "")),
                ["verify-tag", "v0.2.0-alpha.3"] => Ok(release_finalize_test_git_output(
                    true,
                    "",
                    "gpg: Good signature from AgentK Release Maintainer",
                )),
                _ => panic!("unexpected git args: {args:?}"),
            },
        )
        .expect("finalization should run");
        fs::write(
            &notes,
            "# AgentK v0.2 Alpha Release Notes\n\n## Final Release Evidence\n\n\
             - Release commit: `4444444444444444444444444444444444444444`\n\
             - Package archive SHA-256: `stale`\n\
             - Signed tag: `v0.2.0-alpha.3`\n\
             - Signed tag verification: `<git verify-tag result>`\n",
        )
        .expect("notes should be tampered");

        let publication =
            run_release_publication_check(&out, None).expect("publication check should run");

        assert!(!publication.passed);
        for name in [
            "release notes artifact",
            "release notes placeholders",
            "notes Package archive SHA-256",
            "notes Signed tag verification",
        ] {
            assert!(
                publication
                    .checks
                    .iter()
                    .any(|check| check.name == name && check.status == ReadinessStatus::Fail),
                "{name} should fail for stale notes"
            );
        }

        fs::remove_dir_all(root).ok();
        let _ = fs::remove_file(evidence);
        let _ = fs::remove_file(notes);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn release_finalize_strict_blocks_draft_notes_dirty_tree_dev_signer_and_missing_tag() {
        let root = test_temp_path("agentk-release-finalize-blocked-root", "dir");
        let evidence = test_temp_path("agentk-release-finalize-blocked-evidence", "json");
        let notes = test_temp_path("agentk-release-finalize-blocked-notes", "md");
        let out = test_temp_path("agentk-release-finalize-blocked", "json");
        let report = synthetic_release_smoke_report(&root, &evidence);
        write_release_candidate_smoke_evidence(&report, &evidence, false)
            .expect("evidence should write");
        fs::write(
            &notes,
            "# AgentK v0.2 Alpha Release Notes Draft\n\n## Final Release Evidence\n\n\
             - Release commit: `<commit-sha>`\n\
             - Package archive SHA-256: `<sha256>`\n\
             - AgentK evidence signing public key: `<hex-public-key>`\n\
             - Signed tag verification: `<git verify-tag result>`\n",
        )
        .expect("draft notes should write");

        let finalized = run_release_finalize_with(
            ReleaseFinalizeOptions {
                release: "v0.2-alpha".to_string(),
                evidence: evidence.clone(),
                root: None,
                notes: notes.clone(),
                tag: None,
                out: out.clone(),
                strict: true,
                force: false,
            },
            release_finalize_test_signer(agentk::SigningKeySource::Development, false),
            |args| match args {
                ["rev-parse", "HEAD"] => Ok(release_finalize_test_git_output(
                    true,
                    "2222222222222222222222222222222222222222",
                    "",
                )),
                ["status", "--short"] => {
                    Ok(release_finalize_test_git_output(true, " M README.md", ""))
                }
                _ => panic!("unexpected git args: {args:?}"),
            },
        )
        .expect("blocked finalization should still write a report");

        assert!(!finalized.ready);
        for name in [
            "release notes final values",
            "git worktree",
            "signing key",
            "signed tag",
        ] {
            assert!(
                finalized
                    .checks
                    .iter()
                    .any(|check| check.name == name && check.status == ReadinessStatus::Fail),
                "{name} should fail in strict mode"
            );
        }
        assert!(out.is_file());

        fs::remove_dir_all(root).ok();
        let _ = fs::remove_file(evidence);
        let _ = fs::remove_file(notes);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn dashboard_http_response_serves_html_json_and_health() {
        let trace_path = test_temp_path("agentk-dashboard-server-trace", "jsonl");
        let decisions_path = test_temp_path("agentk-dashboard-server-decisions", "jsonl");
        let permissions_path = test_temp_path("agentk-dashboard-server-permissions", "toml");
        let store_root = test_temp_path("agentk-dashboard-server-store", "dir");
        let token_env = format!(
            "AGENTK_DASHBOARD_TEST_TOKEN_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        );
        fs::write(
            &permissions_path,
            format!(
                r#"version = 1

[[users]]
id = "tom"
roles = ["owner"]
token_env = "{token_env}"

[[users]]
id = "viewer"
roles = ["read-only"]

[[users]]
id = "slack-reviewer"
roles = ["slack"]

[[roles]]
id = "owner"
can_approve = ["*"]
can_deny = ["*"]

[[roles]]
id = "slack"
can_approve = ["tool.invoke:slack.*"]
can_deny = ["tool.invoke:slack.*"]

[[roles]]
id = "read-only"
can_approve = []
can_deny = []
"#
            ),
        )
        .expect("permissions should write");
        unsafe {
            env::set_var(&token_env, "dashboard-token");
        }
        run_safe_agent_demo(&trace_path).expect("safe agent demo should write a trace");

        let html = dashboard_http_response(
            &dashboard_test_request("GET", "/", Vec::new()),
            &trace_path,
            &decisions_path,
            None,
            None,
            None,
        );
        assert_eq!(html.status, "200 OK");
        assert_eq!(html.content_type, "text/html; charset=utf-8");
        let html_body = String::from_utf8(html.body).expect("html should be utf8");
        assert!(html_body.contains("AgentK Approval Dashboard"));
        assert!(html_body.contains("Evidence Summary"));
        assert!(html_body.contains("Final Hash"));
        assert!(html_body.contains("tool.invoke"));
        assert!(html_body.contains("tool-tainted-input"));
        assert!(html_body.contains("args_sha256"));
        assert!(html_body.contains("response_sha256"));
        assert!(html_body.contains("Open Approvals"));
        assert!(html_body.contains("data-agentk-dashboard=\"server\""));
        assert!(html_body.contains("id=\"reviewer\""));
        assert!(html_body.contains("id=\"reviewer-token\""));
        assert!(html_body.contains("id=\"requester\""));
        assert!(html_body.contains("id=\"admin-token\""));
        assert!(html_body.contains("id=\"load-reviewer-view\""));
        assert!(html_body.contains("id=\"load-requester-view\""));
        assert!(html_body.contains("id=\"open-approvals-panel\""));
        assert!(html_body.contains("id=\"decisions-panel\""));
        assert!(html_body.contains("data-agentk-decision=\"approve\""));
        assert!(html_body.contains("data-agentk-decision=\"deny\""));

        let json = dashboard_http_response(
            &dashboard_test_request("GET", "/api/review", Vec::new()),
            &trace_path,
            &decisions_path,
            None,
            None,
            None,
        );
        assert_eq!(json.status, "200 OK");
        assert_eq!(json.content_type, "application/json");
        let value: serde_json::Value =
            serde_json::from_slice(&json.body).expect("review response should be JSON");
        assert_eq!(value["review"]["signatures_ok"], true);
        assert_eq!(value["review"]["evidence_summary"]["args_sha256"], 9);
        assert_eq!(value["review"]["evidence_summary"]["response_sha256"], 2);
        assert_eq!(
            value["review"]["syscall_summary"]["tool.invoke"]["blocked"],
            4
        );
        assert!(value["viewer"].is_null());
        assert!(
            !value["review"]["open_approvals"]
                .as_array()
                .expect("open approvals should be an array")
                .is_empty()
        );
        let approval_id = value["review"]["open_approvals"][0]["id"]
            .as_str()
            .expect("approval id should be present")
            .to_string();
        let requester_id = "agent://demo/team-sidecar";
        assert_eq!(
            value["review"]["open_approvals"][0]["agent_id"],
            serde_json::json!(requester_id)
        );
        let full_open = value["review"]["open_approvals"]
            .as_array()
            .expect("open approvals should be an array")
            .len();

        let requester_scoped = dashboard_http_response(
            &dashboard_test_request(
                "GET",
                "/api/review?requester=agent%3A%2F%2Fdemo%2Fteam-sidecar",
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(requester_scoped.status, "200 OK");
        let requester_value: serde_json::Value = serde_json::from_slice(&requester_scoped.body)
            .expect("requester review should be JSON");
        assert_eq!(requester_value["requester"]["agent_id"], requester_id);
        assert_eq!(
            requester_value["requester"]["open_visible"],
            serde_json::json!(full_open)
        );
        assert!(requester_value["viewer"].is_null());

        let other_requester = dashboard_http_response(
            &dashboard_test_request(
                "GET",
                "/api/review?requester=agent%3A%2F%2Fdemo%2Fother",
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(other_requester.status, "200 OK");
        let other_requester_value: serde_json::Value =
            serde_json::from_slice(&other_requester.body)
                .expect("other requester review should be JSON");
        assert_eq!(
            other_requester_value["requester"]["open_visible"],
            serde_json::json!(0)
        );
        assert!(
            other_requester_value["review"]["open_approvals"]
                .as_array()
                .expect("other requester open approvals should be an array")
                .is_empty()
        );

        let requester_html = dashboard_http_response(
            &dashboard_test_request(
                "GET",
                "/?requester=agent%3A%2F%2Fdemo%2Fteam-sidecar",
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(requester_html.status, "200 OK");
        let requester_html_body =
            String::from_utf8(requester_html.body).expect("requester HTML should be utf8");
        assert!(requester_html_body.contains("Requester view:"));
        assert!(requester_html_body.contains("agent://demo/team-sidecar"));
        assert!(requester_html_body.contains(&approval_id));

        let scoped_missing_token = dashboard_http_response(
            &dashboard_test_request("GET", "/api/review?reviewer=tom", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(scoped_missing_token.status, "401 Unauthorized");
        let scoped_missing_token_body = String::from_utf8(scoped_missing_token.body)
            .expect("scoped read error body should be utf8");
        assert!(scoped_missing_token_body.contains("requires reviewer_token"));

        let owner_scoped = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "GET",
                "/api/review?reviewer=tom",
                [("X-AgentK-Reviewer-Token", "dashboard-token")],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(owner_scoped.status, "200 OK");
        let owner_scoped_value: serde_json::Value =
            serde_json::from_slice(&owner_scoped.body).expect("scoped review should be JSON");
        assert_eq!(owner_scoped_value["viewer"]["reviewer"], "tom");
        assert_eq!(
            owner_scoped_value["viewer"]["open_visible"],
            serde_json::json!(full_open)
        );

        let reviewer_token_param = "reviewer_token";
        let unsupported_query_targets = [
            "/api/review?refresh=VALUE_SHOULD_NOT_REFLECT",
            "/?ignored=VALUE_SHOULD_NOT_REFLECT",
        ];
        for target in unsupported_query_targets {
            let unsupported_query = dashboard_http_response(
                &dashboard_test_request("GET", target, Vec::new()),
                &trace_path,
                &decisions_path,
                Some(&permissions_path),
                None,
                None,
            );
            assert_eq!(unsupported_query.status, "400 Bad Request");
            let unsupported_query_body = String::from_utf8(unsupported_query.body)
                .expect("unsupported query body should be utf8");
            assert!(unsupported_query_body.contains("dashboard review query parameters"));
            assert!(!unsupported_query_body.contains("VALUE_SHOULD_NOT_REFLECT"));
        }

        let orphan_reviewer_token = dashboard_http_response(
            &dashboard_test_request(
                "GET",
                format!("/api/review?{reviewer_token_param}=VALUE_SHOULD_NOT_REFLECT").as_str(),
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(orphan_reviewer_token.status, "400 Bad Request");
        let orphan_reviewer_token_body = String::from_utf8(orphan_reviewer_token.body)
            .expect("orphan reviewer token body should be utf8");
        assert!(orphan_reviewer_token_body.contains("dashboard reviewer token"));
        assert!(orphan_reviewer_token_body.contains("reviewer scope"));
        assert!(!orphan_reviewer_token_body.contains("VALUE_SHOULD_NOT_REFLECT"));

        let orphan_reviewer_header = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "GET",
                "/?requester=agent%3A%2F%2Fdemo%2Fteam-sidecar",
                [("X-AgentK-Reviewer-Token", "VALUE_SHOULD_NOT_REFLECT")],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(orphan_reviewer_header.status, "400 Bad Request");
        let orphan_reviewer_header_body = String::from_utf8(orphan_reviewer_header.body)
            .expect("orphan reviewer header body should be utf8");
        assert!(orphan_reviewer_header_body.contains("dashboard reviewer token"));
        assert!(orphan_reviewer_header_body.contains("reviewer scope"));
        assert!(!orphan_reviewer_header_body.contains("VALUE_SHOULD_NOT_REFLECT"));

        let duplicate_scope_targets = [
            "/api/review?reviewer=VALUE_SHOULD_NOT_REFLECT&reviewer=VALUE_SHOULD_NOT_REFLECT",
            "/?reviewer=VALUE_SHOULD_NOT_REFLECT&reviewer=VALUE_SHOULD_NOT_REFLECT",
            "/api/review?requester=VALUE_SHOULD_NOT_REFLECT&requester=VALUE_SHOULD_NOT_REFLECT",
            "/?requester=VALUE_SHOULD_NOT_REFLECT&requester=VALUE_SHOULD_NOT_REFLECT",
        ];
        for target in duplicate_scope_targets {
            let duplicate_scope = dashboard_http_response(
                &dashboard_test_request("GET", target, Vec::new()),
                &trace_path,
                &decisions_path,
                Some(&permissions_path),
                None,
                None,
            );
            assert_eq!(duplicate_scope.status, "400 Bad Request");
            let duplicate_scope_body =
                String::from_utf8(duplicate_scope.body).expect("scope error body should be utf8");
            assert!(duplicate_scope_body.contains("dashboard"));
            assert!(duplicate_scope_body.contains("query parameter"));
            assert!(duplicate_scope_body.contains("at most once"));
            assert!(!duplicate_scope_body.contains("VALUE_SHOULD_NOT_REFLECT"));
        }

        let mixed_scope_targets = [
            "/api/review?reviewer=VALUE_SHOULD_NOT_REFLECT&requester=VALUE_SHOULD_NOT_REFLECT",
            "/?reviewer=VALUE_SHOULD_NOT_REFLECT&requester=VALUE_SHOULD_NOT_REFLECT",
        ];
        for target in mixed_scope_targets {
            let mixed_scope = dashboard_http_response(
                &dashboard_test_request("GET", target, Vec::new()),
                &trace_path,
                &decisions_path,
                Some(&permissions_path),
                None,
                None,
            );
            assert_eq!(mixed_scope.status, "400 Bad Request");
            let mixed_scope_body =
                String::from_utf8(mixed_scope.body).expect("scope error body should be utf8");
            assert!(mixed_scope_body.contains("dashboard scope query"));
            assert!(mixed_scope_body.contains("either reviewer or requester"));
            assert!(!mixed_scope_body.contains("VALUE_SHOULD_NOT_REFLECT"));
        }

        let dual_reviewer_targets = [
            format!("/api/review?reviewer=tom&{reviewer_token_param}=VALUE_SHOULD_NOT_REFLECT"),
            format!("/?reviewer=tom&{reviewer_token_param}=VALUE_SHOULD_NOT_REFLECT"),
        ];
        for target in dual_reviewer_targets {
            let dual_reviewer_carrier = dashboard_http_response(
                &dashboard_test_request_with_headers(
                    "GET",
                    target.as_str(),
                    [("X-AgentK-Reviewer-Token", "VALUE_SHOULD_NOT_REFLECT")],
                    Vec::new(),
                ),
                &trace_path,
                &decisions_path,
                Some(&permissions_path),
                None,
                None,
            );
            assert_eq!(dual_reviewer_carrier.status, "400 Bad Request");
            let dual_reviewer_carrier_body = String::from_utf8(dual_reviewer_carrier.body)
                .expect("reviewer carrier body should be utf8");
            assert!(dual_reviewer_carrier_body.contains("dashboard reviewer token"));
            assert!(!dual_reviewer_carrier_body.contains("VALUE_SHOULD_NOT_REFLECT"));
        }

        let duplicate_reviewer_header = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "GET",
                "/api/review?reviewer=tom",
                [
                    ("X-AgentK-Reviewer-Token", "VALUE_SHOULD_NOT_REFLECT"),
                    ("X-AgentK-Reviewer-Token", "VALUE_SHOULD_NOT_REFLECT"),
                ],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(duplicate_reviewer_header.status, "400 Bad Request");
        let duplicate_reviewer_header_body = String::from_utf8(duplicate_reviewer_header.body)
            .expect("duplicate reviewer header body should be utf8");
        assert!(duplicate_reviewer_header_body.contains("dashboard reviewer token"));
        assert!(duplicate_reviewer_header_body.contains("at most once"));
        assert!(!duplicate_reviewer_header_body.contains("VALUE_SHOULD_NOT_REFLECT"));

        let duplicate_reviewer_query = dashboard_http_response(
            &dashboard_test_request(
                "GET",
                format!(
                    "/api/review?reviewer=tom&{reviewer_token_param}=VALUE_SHOULD_NOT_REFLECT&{reviewer_token_param}=VALUE_SHOULD_NOT_REFLECT"
                )
                .as_str(),
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(duplicate_reviewer_query.status, "400 Bad Request");
        let duplicate_reviewer_query_body = String::from_utf8(duplicate_reviewer_query.body)
            .expect("duplicate reviewer query body should be utf8");
        assert!(duplicate_reviewer_query_body.contains("dashboard reviewer token"));
        assert!(duplicate_reviewer_query_body.contains("at most once"));
        assert!(!duplicate_reviewer_query_body.contains("VALUE_SHOULD_NOT_REFLECT"));

        let read_only_scoped = dashboard_http_response(
            &dashboard_test_request("GET", "/api/review?reviewer=viewer", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(read_only_scoped.status, "200 OK");
        let read_only_value: serde_json::Value =
            serde_json::from_slice(&read_only_scoped.body).expect("scoped review should be JSON");
        assert_eq!(read_only_value["viewer"]["reviewer"], "viewer");
        assert_eq!(
            read_only_value["viewer"]["open_visible"],
            serde_json::json!(0)
        );
        assert!(
            read_only_value["review"]["open_approvals"]
                .as_array()
                .expect("read-only open approvals should be an array")
                .is_empty()
        );

        let read_only_html = dashboard_http_response(
            &dashboard_test_request("GET", "/?reviewer=viewer", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(read_only_html.status, "200 OK");
        let read_only_html_body =
            String::from_utf8(read_only_html.body).expect("scoped HTML should be utf8");
        assert!(read_only_html_body.contains("Reviewer view:"));
        assert!(read_only_html_body.contains(">viewer<"));
        assert!(read_only_html_body.contains("No open approvals."));
        assert!(!read_only_html_body.contains(&approval_id));

        let owner_html_missing_token = dashboard_http_response(
            &dashboard_test_request("GET", "/?reviewer=tom", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(owner_html_missing_token.status, "401 Unauthorized");

        let owner_html = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "GET",
                "/?reviewer=tom",
                [("X-AgentK-Reviewer-Token", "dashboard-token")],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(owner_html.status, "200 OK");
        let owner_html_body =
            String::from_utf8(owner_html.body).expect("owner HTML should be utf8");
        assert!(owner_html_body.contains("Reviewer view:"));
        assert!(owner_html_body.contains(">tom<"));
        assert!(owner_html_body.contains(&approval_id));

        let owner_html_query_token = dashboard_http_response(
            &dashboard_test_request(
                "GET",
                format!("/?reviewer=tom&{reviewer_token_param}=dashboard-token").as_str(),
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(owner_html_query_token.status, "200 OK");
        let owner_html_query_token_body = String::from_utf8(owner_html_query_token.body)
            .expect("query-token HTML should be utf8");
        assert!(owner_html_query_token_body.contains("Reviewer view:"));
        assert!(owner_html_query_token_body.contains(">tom<"));
        assert!(owner_html_query_token_body.contains(&approval_id));

        let slack_scoped = dashboard_http_response(
            &dashboard_test_request("GET", "/api/review?reviewer=slack-reviewer", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(slack_scoped.status, "200 OK");
        let slack_value: serde_json::Value =
            serde_json::from_slice(&slack_scoped.body).expect("scoped review should be JSON");
        let slack_open = slack_value["review"]["open_approvals"]
            .as_array()
            .expect("slack open approvals should be an array");
        assert!(!slack_open.is_empty());
        assert!(slack_open.len() < full_open);
        assert!(slack_open.iter().all(|item| {
            item["target"]
                .as_str()
                .is_some_and(|target| target.contains("slack"))
                || item["missing_capability"]
                    .as_str()
                    .is_some_and(|capability| capability.contains("slack"))
        }));

        let missing_token = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [("Content-Type", "application/json")],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "missing reviewer token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(missing_token.status, "400 Bad Request");
        let missing_token_body =
            String::from_utf8(missing_token.body).expect("error body should be utf8");
        assert!(missing_token_body.contains("requires reviewer_token"));

        let invalid_media_type = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [("Content-Type", "text/plain")],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "wrong dashboard media type",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(invalid_media_type.status, "415 Unsupported Media Type");
        let invalid_media_type_body =
            String::from_utf8(invalid_media_type.body).expect("media type body should be utf8");
        assert!(invalid_media_type_body.contains("dashboard decision API"));

        let duplicate_content_type = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [
                    ("Content-Type", "application/json"),
                    (
                        "Content-Type",
                        "text/plain; marker=VALUE_SHOULD_NOT_REFLECT",
                    ),
                ],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "duplicate dashboard content type",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(duplicate_content_type.status, "400 Bad Request");
        let duplicate_content_type_body =
            String::from_utf8(duplicate_content_type.body).expect("content-type body should utf8");
        assert!(duplicate_content_type_body.contains("dashboard decision Content-Type"));
        assert!(duplicate_content_type_body.contains("at most once"));
        assert!(!duplicate_content_type_body.contains("VALUE_SHOULD_NOT_REFLECT"));

        for target in [
            "/api/approve?ignored=QUERY_SHOULD_NOT_REFLECT",
            "/api/deny?ignored=QUERY_SHOULD_NOT_REFLECT",
        ] {
            let decision_query = dashboard_http_response(
                &dashboard_test_request_with_headers(
                    "POST",
                    target,
                    [("Content-Type", "application/json")],
                    serde_json::json!({
                        "id": approval_id,
                        "reviewer": "tom",
                        "reason": "query string should be rejected before decision parsing",
                        "reviewer_token": "dashboard-token"
                    })
                    .to_string()
                    .into_bytes(),
                ),
                &trace_path,
                &decisions_path,
                Some(&permissions_path),
                None,
                None,
            );
            assert_eq!(decision_query.status, "400 Bad Request");
            let decision_query_body =
                String::from_utf8(decision_query.body).expect("decision query body should be utf8");
            assert!(decision_query_body.contains("dashboard decision endpoints"));
            assert!(decision_query_body.contains("query strings"));
            assert!(!decision_query_body.contains("QUERY_SHOULD_NOT_REFLECT"));
        }

        let duplicate_decision_key = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [("Content-Type", "application/json")],
                format!(
                    r#"{{"id":"{approval_id}","reviewer":"tom","reason":"duplicate dashboard decision key","reviewer_token":"VALUE_SHOULD_NOT_REFLECT","reviewer_token":"VALUE_SHOULD_NOT_REFLECT"}}"#
                )
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(duplicate_decision_key.status, "400 Bad Request");
        let duplicate_decision_key_body = String::from_utf8(duplicate_decision_key.body)
            .expect("duplicate decision key body should be utf8");
        assert!(duplicate_decision_key_body.contains("dashboard decision JSON"));
        assert!(duplicate_decision_key_body.contains("at most once"));
        assert!(!duplicate_decision_key_body.contains("VALUE_SHOULD_NOT_REFLECT"));

        let unknown_decision_key = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [("Content-Type", "application/json")],
                format!(
                    r#"{{"id":"{approval_id}","reviewer":"tom","reason":"unsupported dashboard decision key","reviewer_token":"dashboard-token","unsupported_key":"VALUE_SHOULD_NOT_REFLECT"}}"#
                )
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            None,
            None,
        );
        assert_eq!(unknown_decision_key.status, "400 Bad Request");
        let unknown_decision_key_body = String::from_utf8(unknown_decision_key.body)
            .expect("unknown decision key body should be utf8");
        assert!(unknown_decision_key_body.contains("dashboard decision JSON"));
        assert!(unknown_decision_key_body.contains("id, reviewer, reason"));
        assert!(!unknown_decision_key_body.contains("unsupported_key"));
        assert!(!unknown_decision_key_body.contains("VALUE_SHOULD_NOT_REFLECT"));

        let missing_admin = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [("Content-Type", "application/json")],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "missing dashboard admin token",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            None,
        );
        assert_eq!(missing_admin.status, "401 Unauthorized");
        let missing_admin_body =
            String::from_utf8(missing_admin.body).expect("error body should be utf8");
        assert!(missing_admin_body.contains("dashboard admin token is required"));

        let wrong_admin = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [
                    ("Authorization", "Bearer wrong"),
                    ("Content-Type", "application/json"),
                ],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "wrong dashboard admin token",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            None,
        );
        assert_eq!(wrong_admin.status, "401 Unauthorized");
        let wrong_admin_body =
            String::from_utf8(wrong_admin.body).expect("error body should be utf8");
        assert!(wrong_admin_body.contains("dashboard admin token did not match"));

        let dual_admin_carrier = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [
                    ("Authorization", "Bearer TOKEN_SHOULD_NOT_REFLECT"),
                    ("X-AgentK-Admin-Token", "TOKEN_SHOULD_NOT_REFLECT"),
                    ("Content-Type", "application/json"),
                ],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "ambiguous dashboard admin token",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            None,
        );
        assert_eq!(dual_admin_carrier.status, "400 Bad Request");
        let dual_admin_carrier_body =
            String::from_utf8(dual_admin_carrier.body).expect("admin carrier body should be utf8");
        assert!(dual_admin_carrier_body.contains("dashboard admin token"));
        assert!(!dual_admin_carrier_body.contains("TOKEN_SHOULD_NOT_REFLECT"));

        let duplicate_admin_header = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [
                    ("Authorization", "Bearer TOKEN_SHOULD_NOT_REFLECT"),
                    ("Authorization", "Bearer TOKEN_SHOULD_NOT_REFLECT"),
                    ("Content-Type", "application/json"),
                ],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "duplicate dashboard admin token",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            None,
        );
        assert_eq!(duplicate_admin_header.status, "400 Bad Request");
        let duplicate_admin_header_body = String::from_utf8(duplicate_admin_header.body)
            .expect("duplicate admin body should be utf8");
        assert!(duplicate_admin_header_body.contains("dashboard admin token"));
        assert!(duplicate_admin_header_body.contains("at most once"));
        assert!(!duplicate_admin_header_body.contains("TOKEN_SHOULD_NOT_REFLECT"));

        let duplicate_explicit_admin_header = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [
                    ("X-AgentK-Admin-Token", "TOKEN_SHOULD_NOT_REFLECT"),
                    ("X-AgentK-Admin-Token", "TOKEN_SHOULD_NOT_REFLECT"),
                    ("Content-Type", "application/json"),
                ],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "duplicate dashboard explicit admin token",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            None,
        );
        assert_eq!(duplicate_explicit_admin_header.status, "400 Bad Request");
        let duplicate_explicit_admin_header_body =
            String::from_utf8(duplicate_explicit_admin_header.body)
                .expect("duplicate explicit admin body should be utf8");
        assert!(duplicate_explicit_admin_header_body.contains("dashboard admin token"));
        assert!(duplicate_explicit_admin_header_body.contains("at most once"));
        assert!(!duplicate_explicit_admin_header_body.contains("TOKEN_SHOULD_NOT_REFLECT"));

        let approved = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [
                    ("Authorization", "Bearer server-admin"),
                    ("Content-Type", "application/json"),
                ],
                serde_json::json!({
                    "id": approval_id,
                    "reviewer": "tom",
                    "reason": "approved through dashboard API",
                    "reviewer_token": "dashboard-token"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(approved.status, "200 OK");
        let approved_value: serde_json::Value =
            serde_json::from_slice(&approved.body).expect("approval response should be JSON");
        assert_eq!(approved_value["decision"]["reviewer"], "tom");
        assert_eq!(approved_value["decision"]["decision"], "approve");
        assert_eq!(approved_value["review"]["approved"], 1);
        assert!(store_root.join("current/audit.json").exists());
        assert!(store_root.join("current/approvals.json").exists());
        assert!(store_root.join("tables/approval_decisions.jsonl").exists());
        let store_approvals = fs::read_to_string(store_root.join("current/approvals.json"))
            .expect("dashboard store approvals should read");
        assert!(store_approvals.contains("\"approved\": 1"));
        let store_decisions =
            fs::read_to_string(store_root.join("tables/approval_decisions.jsonl"))
                .expect("dashboard store decision rows should read");
        assert!(store_decisions.contains("approved through dashboard API"));

        let unauthorized = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/deny",
                [
                    ("X-AgentK-Admin-Token", "server-admin"),
                    ("Content-Type", "application/json"),
                ],
                serde_json::json!({
                    "id": value["review"]["open_approvals"][1]["id"],
                    "reviewer": "viewer",
                    "reason": "viewer should not be allowed"
                })
                .to_string()
                .into_bytes(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            None,
        );
        assert_eq!(unauthorized.status, "400 Bad Request");
        let unauthorized_body =
            String::from_utf8(unauthorized.body).expect("error body should be utf8");
        assert!(unauthorized_body.contains("not authorized"));

        let health = dashboard_http_response(
            &dashboard_test_request("GET", "/healthz", Vec::new()),
            &trace_path,
            &decisions_path,
            None,
            None,
            None,
        );
        assert_eq!(health.status, "200 OK");
        assert_eq!(health.body, br#"{"ok":true}"#);

        let ready = dashboard_http_response(
            &dashboard_test_request("GET", "/readyz", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(ready.status, "200 OK");
        assert_eq!(ready.content_type, "application/json");
        let ready_value: serde_json::Value =
            serde_json::from_slice(&ready.body).expect("ready response should be JSON");
        assert_eq!(ready_value["ready"], serde_json::json!(true));
        assert_eq!(ready_value["trace_present"], serde_json::json!(true));
        assert_eq!(ready_value["decision_log_present"], serde_json::json!(true));
        assert_eq!(
            ready_value["permissions_configured"],
            serde_json::json!(true)
        );
        assert_eq!(ready_value["permissions_present"], serde_json::json!(true));
        assert_eq!(
            ready_value["store_root_configured"],
            serde_json::json!(true)
        );
        assert_eq!(ready_value["store_root_present"], serde_json::json!(true));
        assert_eq!(ready_value["admin_required"], serde_json::json!(true));
        assert_eq!(
            ready_value["max_body_bytes"],
            serde_json::json!(DASHBOARD_HTTP_MAX_BODY_BYTES)
        );
        assert_eq!(
            ready_value["max_header_bytes"],
            serde_json::json!(DASHBOARD_HTTP_MAX_HEADER_BYTES)
        );
        let ready_body = String::from_utf8(ready.body).expect("ready body should be utf8");
        assert!(!ready_body.contains(&trace_path.display().to_string()));
        assert!(!ready_body.contains(&decisions_path.display().to_string()));
        assert!(!ready_body.contains(&permissions_path.display().to_string()));
        assert!(!ready_body.contains(&store_root.display().to_string()));

        let ready_head = dashboard_http_response(
            &dashboard_test_request("HEAD", "/readyz", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(ready_head.status, "200 OK");
        assert!(ready_head.body.is_empty());

        let metrics = dashboard_http_response(
            &dashboard_test_request("GET", "/metrics", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(metrics.status, "200 OK");
        assert_eq!(
            metrics.content_type,
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let metrics_body = String::from_utf8(metrics.body).expect("metrics should be utf8");
        assert!(metrics_body.contains("agentk_dashboard_ready 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_trace_present 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_decision_log_present 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_permissions_configured 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_permissions_present 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_permissions_ready 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_store_root_configured 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_store_root_present 1\n"));
        assert!(metrics_body.contains("agentk_dashboard_admin_required 1\n"));
        assert!(metrics_body.contains(&format!(
            "agentk_dashboard_max_body_bytes {}\n",
            DASHBOARD_HTTP_MAX_BODY_BYTES
        )));
        assert!(metrics_body.contains(&format!(
            "agentk_dashboard_max_header_bytes {}\n",
            DASHBOARD_HTTP_MAX_HEADER_BYTES
        )));
        assert!(!metrics_body.contains(&trace_path.display().to_string()));
        assert!(!metrics_body.contains(&decisions_path.display().to_string()));
        assert!(!metrics_body.contains(&permissions_path.display().to_string()));
        assert!(!metrics_body.contains(&store_root.display().to_string()));

        let metrics_head = dashboard_http_response(
            &dashboard_test_request("HEAD", "/metrics", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(metrics_head.status, "200 OK");
        assert!(metrics_head.body.is_empty());

        let nonlocal_read_missing_admin = dashboard_http_response_with_read_auth(
            &dashboard_test_request("GET", "/api/review", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_read_missing_admin.status, "401 Unauthorized");
        let nonlocal_read_missing_admin_body = String::from_utf8(nonlocal_read_missing_admin.body)
            .expect("nonlocal read auth body should be utf8");
        assert!(nonlocal_read_missing_admin_body.contains("dashboard admin token is required"));
        assert!(nonlocal_read_missing_admin_body.contains("read requests"));

        let nonlocal_read_wrong_admin = dashboard_http_response_with_read_auth(
            &dashboard_test_request_with_headers(
                "GET",
                "/api/review",
                [("Authorization", "Bearer wrong")],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_read_wrong_admin.status, "401 Unauthorized");
        let nonlocal_read_wrong_admin_body = String::from_utf8(nonlocal_read_wrong_admin.body)
            .expect("nonlocal wrong auth body should be utf8");
        assert!(nonlocal_read_wrong_admin_body.contains("dashboard admin token did not match"));

        let nonlocal_read_dual_admin = dashboard_http_response_with_read_auth(
            &dashboard_test_request_with_headers(
                "GET",
                "/api/review",
                [
                    ("Authorization", "Bearer TOKEN_SHOULD_NOT_REFLECT"),
                    ("X-AgentK-Admin-Token", "TOKEN_SHOULD_NOT_REFLECT"),
                ],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_read_dual_admin.status, "400 Bad Request");
        let nonlocal_read_dual_admin_body = String::from_utf8(nonlocal_read_dual_admin.body)
            .expect("nonlocal dual auth body should be utf8");
        assert!(nonlocal_read_dual_admin_body.contains("dashboard admin token"));
        assert!(!nonlocal_read_dual_admin_body.contains("TOKEN_SHOULD_NOT_REFLECT"));

        let nonlocal_read_ok = dashboard_http_response_with_read_auth(
            &dashboard_test_request_with_headers(
                "GET",
                "/api/review",
                [("X-AgentK-Admin-Token", "server-admin")],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_read_ok.status, "200 OK");

        let nonlocal_ready_missing_admin = dashboard_http_response_with_read_auth(
            &dashboard_test_request("GET", "/readyz", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_ready_missing_admin.status, "401 Unauthorized");

        let nonlocal_ready_ok = dashboard_http_response_with_read_auth(
            &dashboard_test_request_with_headers(
                "GET",
                "/readyz",
                [("X-AgentK-Admin-Token", "server-admin")],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_ready_ok.status, "200 OK");

        let nonlocal_metrics_missing_admin = dashboard_http_response_with_read_auth(
            &dashboard_test_request("GET", "/metrics", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_metrics_missing_admin.status, "401 Unauthorized");

        let nonlocal_metrics_ok = dashboard_http_response_with_read_auth(
            &dashboard_test_request_with_headers(
                "GET",
                "/metrics",
                [("X-AgentK-Admin-Token", "server-admin")],
                Vec::new(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_metrics_ok.status, "200 OK");

        let nonlocal_health_open = dashboard_http_response_with_read_auth(
            &dashboard_test_request("GET", "/healthz", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_health_open.status, "200 OK");

        let nonlocal_ready_head_missing_admin = dashboard_http_response_with_read_auth(
            &dashboard_test_request("HEAD", "/readyz", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_ready_head_missing_admin.status, "401 Unauthorized");
        assert!(nonlocal_ready_head_missing_admin.body.is_empty());

        let nonlocal_authed_read_body = dashboard_http_response_with_read_auth(
            &dashboard_test_request_with_headers(
                "GET",
                "/api/review",
                [("X-AgentK-Admin-Token", "server-admin")],
                b"BODY_SHOULD_NOT_REFLECT".to_vec(),
            ),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            true,
            Some(&store_root),
        );
        assert_eq!(nonlocal_authed_read_body.status, "400 Bad Request");
        let nonlocal_authed_read_body_text = String::from_utf8(nonlocal_authed_read_body.body)
            .expect("nonlocal read body rejection should be utf8");
        assert!(nonlocal_authed_read_body_text.contains("dashboard HTTP request bodies"));
        assert!(!nonlocal_authed_read_body_text.contains("BODY_SHOULD_NOT_REFLECT"));

        for (method, target) in [
            ("GET", "/"),
            ("GET", "/api/review"),
            ("GET", "/healthz"),
            ("GET", "/metrics"),
            ("POST", "/api/review"),
            ("POST", "/missing"),
        ] {
            let body_request = dashboard_http_response(
                &dashboard_test_request(method, target, b"BODY_SHOULD_NOT_REFLECT".to_vec()),
                &trace_path,
                &decisions_path,
                Some(&permissions_path),
                Some("server-admin"),
                Some(&store_root),
            );
            assert_eq!(body_request.status, "400 Bad Request");
            let body_request_body =
                String::from_utf8(body_request.body).expect("body error should be utf8");
            assert!(body_request_body.contains("dashboard HTTP request bodies"));
            assert!(!body_request_body.contains("BODY_SHOULD_NOT_REFLECT"));
        }

        let head_body_request = dashboard_http_response(
            &dashboard_test_request("HEAD", "/readyz", b"BODY_SHOULD_NOT_REFLECT".to_vec()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(head_body_request.status, "400 Bad Request");
        assert!(head_body_request.body.is_empty());

        for target in [
            "/healthz?probe=QUERY_SHOULD_NOT_REFLECT",
            "/readyz?probe=QUERY_SHOULD_NOT_REFLECT",
            "/metrics?probe=QUERY_SHOULD_NOT_REFLECT",
        ] {
            let query_probe = dashboard_http_response(
                &dashboard_test_request("GET", target, Vec::new()),
                &trace_path,
                &decisions_path,
                Some(&permissions_path),
                Some("server-admin"),
                Some(&store_root),
            );
            assert_eq!(query_probe.status, "400 Bad Request");
            let query_probe_body =
                String::from_utf8(query_probe.body).expect("query probe body should be utf8");
            assert!(query_probe_body.contains("dashboard operational probes"));
            assert!(!query_probe_body.contains("QUERY_SHOULD_NOT_REFLECT"));
        }

        let not_ready = dashboard_http_response(
            &dashboard_test_request("GET", "/readyz", Vec::new()),
            &trace_path.with_extension("missing.jsonl"),
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(not_ready.status, "503 Service Unavailable");
        let not_ready_value: serde_json::Value =
            serde_json::from_slice(&not_ready.body).expect("not-ready response should be JSON");
        assert_eq!(not_ready_value["ready"], serde_json::json!(false));
        assert_eq!(not_ready_value["trace_present"], serde_json::json!(false));

        let not_ready_metrics = dashboard_http_response(
            &dashboard_test_request("GET", "/metrics", Vec::new()),
            &trace_path.with_extension("missing.jsonl"),
            &decisions_path,
            Some(&permissions_path),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(not_ready_metrics.status, "200 OK");
        let not_ready_metrics_body =
            String::from_utf8(not_ready_metrics.body).expect("metrics should be utf8");
        assert!(not_ready_metrics_body.contains("agentk_dashboard_ready 0\n"));
        assert!(not_ready_metrics_body.contains("agentk_dashboard_trace_present 0\n"));

        let permissions_not_ready = dashboard_http_response(
            &dashboard_test_request("GET", "/readyz", Vec::new()),
            &trace_path,
            &decisions_path,
            Some(&permissions_path.with_extension("missing.toml")),
            Some("server-admin"),
            Some(&store_root),
        );
        assert_eq!(permissions_not_ready.status, "503 Service Unavailable");
        let permissions_not_ready_value: serde_json::Value =
            serde_json::from_slice(&permissions_not_ready.body)
                .expect("permissions not-ready response should be JSON");
        assert_eq!(
            permissions_not_ready_value["ready"],
            serde_json::json!(false)
        );
        assert_eq!(
            permissions_not_ready_value["permissions_configured"],
            serde_json::json!(true)
        );
        assert_eq!(
            permissions_not_ready_value["permissions_present"],
            serde_json::json!(false)
        );

        let missing = dashboard_http_response(
            &dashboard_test_request("GET", "/missing", Vec::new()),
            &trace_path,
            &decisions_path,
            None,
            None,
            None,
        );
        assert_eq!(missing.status, "404 Not Found");

        let missing_post = dashboard_http_response(
            &dashboard_test_request("POST", "/", Vec::new()),
            &trace_path,
            &decisions_path,
            None,
            None,
            None,
        );
        assert_eq!(missing_post.status, "404 Not Found");

        let disallowed = dashboard_http_response(
            &dashboard_test_request("PUT", "/", Vec::new()),
            &trace_path,
            &decisions_path,
            None,
            None,
            None,
        );
        assert_eq!(disallowed.status, "405 Method Not Allowed");

        let head = dashboard_http_response(
            &dashboard_test_request("HEAD", "/", Vec::new()),
            &trace_path,
            &decisions_path,
            None,
            None,
            None,
        );
        assert_eq!(head.status, "200 OK");
        assert!(head.body.is_empty());

        let _ = fs::remove_file(trace_path);
        let _ = fs::remove_file(decisions_path);
        let _ = fs::remove_file(permissions_path);
        fs::remove_dir_all(store_root).ok();
        unsafe {
            env::remove_var(&token_env);
        }
    }

    #[cfg(unix)]
    #[test]
    fn mcp_proxy_stdio_trace_out_writes_verifiable_events() {
        let trace_path = mcp_proxy_trace_out_test_path("trace");
        let session_report_path = mcp_session_report_path(&trace_path);
        let _ = fs::remove_file(&trace_path);
        let _ = fs::remove_file(&session_report_path);

        let server = mcp_proxy_trace_out_probe_server();
        let input = mcp_proxy_trace_out_probe_input();
        let config = McpSubprocessProxyConfig::new("agent://test", "trace-out-probe", "sh")
            .with_args(["-c".to_string(), server]);
        let mut output = Vec::new();

        mcp_proxy_stdio_with_io(
            config,
            Some(trace_path.clone()),
            Some(session_report_path.clone()),
            BufReader::new(input.as_bytes()),
            &mut output,
        )
        .expect("stdio proxy should write trace output");

        let responses = String::from_utf8(output).expect("proxy output should be utf8");
        assert!(responses.contains("\"tools\""));
        let verify = verify_jsonl(&trace_path).expect("trace-out should be verifiable");
        assert_eq!(verify.events_checked, 1);
        let session_report: agentk::McpSubprocessProxySessionReport = serde_json::from_str(
            &fs::read_to_string(&session_report_path)
                .expect("session report should be written beside trace-out"),
        )
        .expect("session report should be valid json");
        assert_eq!(session_report.agent_id, "agent://test");
        assert_eq!(session_report.server_id, "trace-out-probe");
        assert!(session_report.initialized);
        assert!(session_report.ready);
        assert_eq!(session_report.client_messages_seen, 3);
        assert_eq!(session_report.events, 1);
        assert_eq!(session_report.allowed_events, 1);
        assert_eq!(session_report.denied_events, 0);

        let _ = fs::remove_file(trace_path);
        let _ = fs::remove_file(session_report_path);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_proxy_stdio_trace_out_survives_writer_failure_after_event() {
        let trace_path = mcp_proxy_trace_out_test_path("writer-failure");
        let session_report_path = mcp_session_report_path(&trace_path);
        let _ = fs::remove_file(&trace_path);
        let _ = fs::remove_file(&session_report_path);

        let server = mcp_proxy_trace_out_probe_server();
        let input = mcp_proxy_trace_out_probe_input();
        let config = McpSubprocessProxyConfig::new("agent://test", "trace-out-probe", "sh")
            .with_args(["-c".to_string(), server]);
        let mut output = FailOnSecondNewlineWriter::default();

        let error = mcp_proxy_stdio_with_io(
            config,
            Some(trace_path.clone()),
            Some(session_report_path.clone()),
            BufReader::new(input.as_bytes()),
            &mut output,
        )
        .expect_err("client writer failure should surface");

        assert!(
            error
                .to_string()
                .contains("test writer failure after mediated event")
        );
        assert_eq!(output.newline_count, 2);
        let verify = verify_jsonl(&trace_path).expect("trace-out should survive writer failure");
        assert_eq!(verify.events_checked, 1);
        let session_report: agentk::McpSubprocessProxySessionReport = serde_json::from_str(
            &fs::read_to_string(&session_report_path)
                .expect("session report should survive writer failure"),
        )
        .expect("session report should be valid json");
        assert!(session_report.initialized);
        assert!(session_report.ready);
        assert_eq!(session_report.events, 1);

        let _ = fs::remove_file(trace_path);
        let _ = fs::remove_file(session_report_path);
    }

    #[test]
    fn mcp_proxy_allow_env_collects_explicit_parent_values() {
        let names = vec!["AGENTK_PROXY_DEMO".to_string()];
        let env = collect_mcp_proxy_allowed_env(&names, |name| {
            (name == "AGENTK_PROXY_DEMO").then(|| "demo-value".to_string())
        })
        .expect("explicit env should collect");

        assert_eq!(
            env.get("AGENTK_PROXY_DEMO").map(String::as_str),
            Some("demo-value")
        );
    }

    #[test]
    fn mcp_proxy_allow_env_rejects_unsafe_names_without_value_reflection() {
        let names = vec!["BAD=VALUE".to_string()];
        let error = collect_mcp_proxy_allowed_env(&names, |_| Some("demo-value".to_string()))
            .expect_err("unsafe env name should fail")
            .to_string();

        assert!(error.contains("allowed env names"));
        assert!(!error.contains("demo-value"));
    }

    #[test]
    fn mcp_proxy_allow_env_reports_missing_name_without_value() {
        let names = vec!["MISSING_TOKEN".to_string()];
        let error = collect_mcp_proxy_allowed_env(&names, |_| None)
            .expect_err("missing env var should fail")
            .to_string();

        assert!(error.contains("MISSING_TOKEN"));
        assert!(!error.contains("demo-value"));
    }

    #[test]
    fn mcp_proxy_allow_env_accepts_safe_name_shapes() {
        for name in ["TOKEN", "_TOKEN", "TOKEN_1"] {
            assert!(is_safe_env_name(name), "{name} should be accepted");
        }

        for name in ["", "1DEMO", "DEMO-NAME", "BAD=VALUE"] {
            assert!(!is_safe_env_name(name), "{name} should be rejected");
        }
    }
}
