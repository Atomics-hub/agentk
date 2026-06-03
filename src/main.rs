use agentk::{
    AgentKError, ApprovalDecision, ApprovalDecisionRecord, ApprovalReviewReport, AuditApprovalItem,
    MCP_PROTOCOL_VERSION, McpSubprocessProxy, McpSubprocessProxyConfig, Policy, ReadinessStatus,
    TeamPermissionsReport, Verdict, approval_review_jsonl, audit_inbox_jsonl, check_audit_store,
    check_audit_store_export, check_sidecar_bundle, default_log_path, export_audit_store,
    fork_replay_behavior_jsonl, fork_replay_jsonl, generate_signing_key_file, init_sidecar_bundle,
    inspect_jsonl, mcp_proxy_from_path, mcp_server_json_stream, mcp_subprocess_proxy_json_stream,
    mediate_mcp_json_reader, mediate_mcp_json_stream, package_sidecar_bundle, readiness_report,
    record_approval_decision_jsonl, record_approval_decision_jsonl_with_permissions,
    release_audit_report, replay_jsonl, rotate_signing_key_file, run_mcp_killer_demo,
    run_mcp_security_shim_eval, run_poisoned_webpage_demo, run_safe_agent_demo,
    scope_approval_review_for_reviewer, secret_reference_env_store_report_from_path,
    secret_reference_manifest_report_from_path, sidecar_run_config, signing_key_status,
    sync_durable_audit_store, team_permissions_report_from_path,
    trusted_signing_key_manifest_keys_from_path, trusted_signing_key_manifest_report_from_path,
    verify_jsonl, verify_signatures_jsonl, verify_signatures_jsonl_with_trusted_keys,
    verify_signing_key_rotation_manifest_file, verify_team_reviewer_token,
    write_approval_dashboard_html, write_events_jsonl, write_latest_copy,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "agentk")]
#[command(about = "AgentK: a tiny security kernel prototype for AI agents.")]
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
        /// Bind host for the local dashboard server.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Bind port for the local dashboard server.
        #[arg(long, default_value_t = 8765)]
        port: u16,
        /// Env var containing an optional dashboard write API bearer token.
        #[arg(long, default_value = "AGENTK_DASHBOARD_ADMIN_TOKEN")]
        admin_token_env: String,
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
        /// Durable team store root.
        #[arg(long, default_value = ".agentk/team-store")]
        root: PathBuf,
        /// Emit the sync report as JSON.
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
        /// Additional allowed Origin value. Repeat for multiple browser origins.
        #[arg(long = "allow-origin")]
        allow_origins: Vec<String>,
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
        /// Additional allowed Origin value. Repeat for multiple browser origins.
        #[arg(long = "allow-origin")]
        allow_origins: Vec<String>,
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
        /// Overwrite an existing package directory.
        #[arg(long)]
        force: bool,
        /// Emit the package report as JSON.
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
        /// Emit only version and count as JSON.
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
            host,
            port,
            admin_token_env,
            store_root,
        } => dashboard_serve(
            path,
            decisions,
            permissions,
            host,
            port,
            admin_token_env,
            store_root,
        ),
        Command::StoreExport {
            path,
            decisions,
            permissions,
            out,
            json,
        } => store_export(path, decisions, permissions, out, json),
        Command::StoreCheck { root, json } => store_check(root, json),
        Command::StoreSync {
            path,
            decisions,
            permissions,
            root,
            json,
        } => store_sync(path, decisions, permissions, root, json),
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
            allow_origins,
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
            allow_origins,
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
            allow_origins,
            auth_token_env,
        } => sidecar_serve_http(
            root,
            host,
            port,
            endpoint,
            max_requests,
            max_concurrent_requests,
            allow_origins,
            auth_token_env,
        ),
        Command::SidecarPackage {
            root,
            out,
            force,
            json,
        } => sidecar_package(root, out, force, json),
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

fn dashboard_serve(
    path: PathBuf,
    decisions: Option<PathBuf>,
    permissions: Option<PathBuf>,
    host: String,
    port: u16,
    admin_token_env: String,
    store_root: Option<PathBuf>,
) -> Result<(), AgentKError> {
    if !is_safe_env_name(&admin_token_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "admin-token-env must be a safe environment variable name".to_string(),
        ));
    }
    let decisions = approval_decisions_path(&path, decisions);
    let admin_token = env::var(&admin_token_env)
        .ok()
        .filter(|value| !value.is_empty());
    let bind = format!("{host}:{port}");
    let listener = TcpListener::bind(&bind)?;
    println!("AgentK dashboard server");
    println!("url        http://{bind}/");
    println!("trace      {}", path.display());
    println!("decisions  {}", decisions.display());
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

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_dashboard_http_stream(
                    &mut stream,
                    &path,
                    &decisions,
                    permissions.as_ref(),
                    admin_token.as_deref(),
                    store_root.as_ref(),
                ) {
                    eprintln!("dashboard request failed: {error}");
                }
            }
            Err(error) => eprintln!("dashboard connection failed: {error}"),
        }
    }

    Ok(())
}

fn handle_dashboard_http_stream(
    stream: &mut TcpStream,
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    admin_token: Option<&str>,
    store_root: Option<&PathBuf>,
) -> Result<(), AgentKError> {
    let Some(request) = read_dashboard_http_request(stream)? else {
        return Ok(());
    };
    let response = dashboard_http_response(
        &request,
        trace_path,
        decisions_path,
        permissions_path,
        admin_token,
        store_root,
    );
    write_dashboard_http_response(stream, &response)?;
    Ok(())
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
}

fn read_dashboard_http_request(
    stream: &mut TcpStream,
) -> Result<Option<DashboardHttpRequest>, AgentKError> {
    const MAX_REQUEST_BYTES: usize = 16 * 1024;
    const MAX_BODY_BYTES: usize = 8 * 1024;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    let mut bytes = reader.read_line(&mut request_line)?;
    if bytes == 0 {
        return Ok(None);
    }
    if bytes > MAX_REQUEST_BYTES {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard HTTP request is too large".to_string(),
        ));
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let mut content_length = 0usize;
    let mut headers = Vec::new();

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        bytes += read;
        if bytes > MAX_REQUEST_BYTES {
            return Err(AgentKError::InvalidMcpRequest(
                "dashboard HTTP request is too large".to_string(),
            ));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().map_err(|_| {
                    AgentKError::InvalidMcpRequest(
                        "dashboard HTTP content-length is invalid".to_string(),
                    )
                })?;
                if content_length > MAX_BODY_BYTES {
                    return Err(AgentKError::InvalidMcpRequest(
                        "dashboard HTTP request body is too large".to_string(),
                    ));
                }
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(DashboardHttpRequest {
        method,
        target,
        headers,
        body,
    }))
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

#[derive(Serialize)]
struct DashboardDecisionResponse<'a> {
    decision: &'a agentk::ApprovalDecisionRecord,
    review: &'a ApprovalReviewReport,
}

fn dashboard_http_response(
    request: &DashboardHttpRequest,
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    admin_token: Option<&str>,
    store_root: Option<&PathBuf>,
) -> DashboardHttpResponse {
    let route = request.target.split('?').next().unwrap_or(&request.target);
    let mut response = match (request.method.as_str(), route) {
        ("GET" | "HEAD", "/" | "/index.html") => dashboard_http_html(
            request,
            trace_path,
            decisions_path,
            permissions_path,
            store_root,
        ),
        ("GET" | "HEAD", "/api/review") => dashboard_http_json(
            request,
            trace_path,
            decisions_path,
            permissions_path,
            store_root,
        ),
        ("GET" | "HEAD", "/healthz") => DashboardHttpResponse {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body: br#"{"ok":true}"#.to_vec(),
        },
        ("POST", "/api/approve") => dashboard_http_decision(
            request,
            trace_path,
            decisions_path,
            permissions_path,
            admin_token,
            store_root,
            ApprovalDecision::Approve,
        ),
        ("POST", "/api/deny") => dashboard_http_decision(
            request,
            trace_path,
            decisions_path,
            permissions_path,
            admin_token,
            store_root,
            ApprovalDecision::Deny,
        ),
        ("GET" | "HEAD" | "POST", _) => dashboard_http_text("404 Not Found", "not found\n"),
        _ => dashboard_http_text("405 Method Not Allowed", "method not allowed\n"),
    };

    if request.method == "HEAD" {
        response.body.clear();
    }
    response
}

fn dashboard_http_html(
    request: &DashboardHttpRequest,
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    store_root: Option<&PathBuf>,
) -> DashboardHttpResponse {
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
        if let Err(error) =
            dashboard_verify_reviewer_token_from_request(request, permissions_path, reviewer)
        {
            return dashboard_http_text("401 Unauthorized", &format!("{error}\n"));
        }
    }

    match dashboard_sync_store(trace_path, decisions_path, permissions_path, store_root)
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
    store_root: Option<&PathBuf>,
) -> DashboardHttpResponse {
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
        if let Err(error) =
            dashboard_verify_reviewer_token_from_request(request, permissions_path, reviewer)
        {
            return dashboard_http_text("401 Unauthorized", &format!("{error}\n"));
        }
    }

    match dashboard_sync_store(trace_path, decisions_path, permissions_path, store_root)
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
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    admin_token: Option<&str>,
    store_root: Option<&PathBuf>,
    decision: ApprovalDecision,
) -> DashboardHttpResponse {
    if let Err(error) = dashboard_verify_admin_token(request, admin_token) {
        return dashboard_http_text("401 Unauthorized", &format!("{error}\n"));
    }
    match dashboard_record_decision(
        trace_path,
        decisions_path,
        permissions_path,
        store_root,
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

fn dashboard_verify_admin_token(
    request: &DashboardHttpRequest,
    admin_token: Option<&str>,
) -> Result<(), AgentKError> {
    let Some(expected) = admin_token else {
        return Ok(());
    };
    let provided = dashboard_admin_token_from_request(request).ok_or_else(|| {
        AgentKError::InvalidMcpRequest(
            "dashboard admin token is required for write requests".to_string(),
        )
    })?;
    if !constant_time_token_eq(expected, &provided) {
        return Err(AgentKError::InvalidMcpRequest(
            "dashboard admin token did not match".to_string(),
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
    store_root: Option<&PathBuf>,
    decision: ApprovalDecision,
    body: &[u8],
) -> Result<Vec<u8>, AgentKError> {
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
    dashboard_sync_store(trace_path, decisions_path, permissions_path, store_root)?;
    let review = approval_review_jsonl(trace_path, decisions_path)?;
    serde_json::to_vec_pretty(&DashboardDecisionResponse {
        decision: &record,
        review: &review,
    })
    .map_err(AgentKError::from)
}

fn dashboard_sync_store(
    trace_path: &PathBuf,
    decisions_path: &PathBuf,
    permissions_path: Option<&PathBuf>,
    store_root: Option<&PathBuf>,
) -> Result<(), AgentKError> {
    if let Some(root) = store_root {
        sync_durable_audit_store(
            trace_path,
            decisions_path,
            permissions_path.map(|path| path.as_path()),
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
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
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
    out: PathBuf,
    json: bool,
) -> Result<(), AgentKError> {
    let decisions = approval_decisions_path(&path, decisions);
    let report = export_audit_store(&path, &decisions, permissions.as_deref(), &out)?;

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
    println!("events     {}", report.events_checked);
    println!("signatures {}", report.signatures_ok);
    println!("open       {}", report.open);
    println!("approved   {}", report.approved);
    println!("denied     {}", report.denied);
    println!("stale      {}", report.stale);

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
    root: PathBuf,
    json: bool,
) -> Result<(), AgentKError> {
    let decisions = approval_decisions_path(&path, decisions);
    let report = sync_durable_audit_store(&path, &decisions, permissions.as_deref(), &root)?;

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
    println!("files      {}", report.files.len());
    println!("events     {}", report.audit_events);
    println!("signatures {}", report.signatures_ok);
    println!("open       {}", report.open);
    println!("approved   {}", report.approved);
    println!("denied     {}", report.denied);
    println!("stale      {}", report.stale);
    println!("reviewers  {}", report.reviewers);
    println!("notifications {}", report.notifications);

    if !report.signatures_ok {
        std::process::exit(2);
    }

    Ok(())
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
    allow_origins: Vec<String>,
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
        allow_origins,
        auth_token,
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
    allow_origins: Vec<String>,
    auth_token: Option<String>,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
}

struct McpHttpGatewayState {
    proxy: McpSubprocessProxyConfig,
    endpoint: String,
    max_concurrent_requests: usize,
    allow_origins: Vec<String>,
    auth_token: Option<String>,
    trace_out: Option<PathBuf>,
    session_report_out: Option<PathBuf>,
    sessions: Mutex<BTreeMap<String, McpHttpSession>>,
}

struct McpHttpSession {
    proxy: McpSubprocessProxy,
    protocol_version: String,
}

fn mcp_proxy_http_with_config(config: McpHttpGatewayConfig) -> Result<(), AgentKError> {
    if !config.endpoint.starts_with('/') {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP endpoint must start with /".to_string(),
        ));
    }
    if config.max_concurrent_requests == 0 {
        return Err(AgentKError::InvalidMcpRequest(
            "MCP HTTP max-concurrent-requests must be positive".to_string(),
        ));
    }
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
        allow_origins: config.allow_origins,
        auth_token: config.auth_token,
        trace_out: config.trace_out,
        session_report_out: config.session_report_out,
        sessions: Mutex::new(BTreeMap::new()),
    });
    mcp_proxy_http_accept_loop(
        listener,
        state,
        config.max_requests,
        config.max_concurrent_requests,
    )
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
        stream.set_nodelay(true)?;
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

    if let Some(error) = first_error {
        return Err(AgentKError::InvalidMcpRequest(format!(
            "one or more MCP HTTP requests failed: {error}"
        )));
    }
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
    let Some(request) = read_dashboard_http_request(stream)? else {
        return Ok(());
    };
    let response = mcp_http_response(&request, state)?;
    write_dashboard_http_response(stream, &response)?;
    Ok(())
}

fn mcp_http_response(
    request: &DashboardHttpRequest,
    state: &Arc<McpHttpGatewayState>,
) -> Result<DashboardHttpResponse, AgentKError> {
    let path = request.target.split('?').next().unwrap_or_default();
    if path == "/healthz" || path == "/readyz" {
        let mut response = mcp_http_operational_response(request, state, path)?;
        if request.method == "HEAD" {
            response.body.clear();
        }
        return Ok(response);
    }
    if path != state.endpoint {
        return Ok(dashboard_http_text("404 Not Found", "not found\n"));
    }
    if !mcp_http_origin_allowed(request.header("origin"), &state.allow_origins) {
        return Ok(dashboard_http_text(
            "403 Forbidden",
            "origin is not allowed\n",
        ));
    }
    if !mcp_http_auth_allowed(request, state.auth_token.as_deref()) {
        let mut response = dashboard_http_text("401 Unauthorized", "MCP HTTP token is required\n");
        response.headers.push((
            "WWW-Authenticate".to_string(),
            "Bearer realm=\"agentk-mcp\"".to_string(),
        ));
        return Ok(response);
    }

    match request.method.as_str() {
        "POST" => mcp_http_post_response(request, state),
        "GET" => {
            let mut response = dashboard_http_text(
                "405 Method Not Allowed",
                "SSE streams are not enabled for this AgentK gateway yet\n",
            );
            response
                .headers
                .push(("Allow".to_string(), "POST, DELETE".to_string()));
            Ok(response)
        }
        "DELETE" => mcp_http_delete_response(request, state),
        _ => {
            let mut response =
                dashboard_http_text("405 Method Not Allowed", "method not allowed\n");
            response
                .headers
                .push(("Allow".to_string(), "POST, DELETE".to_string()));
            Ok(response)
        }
    }
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

    let active_sessions = state
        .sessions
        .lock()
        .map_err(|_| AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string()))?
        .len();
    Ok(DashboardHttpResponse {
        status: "200 OK",
        content_type: "application/json",
        headers: Vec::new(),
        body: serde_json::to_vec(&serde_json::json!({
            "ready": true,
            "endpoint": state.endpoint.as_str(),
            "protocol_version": MCP_PROTOCOL_VERSION,
            "active_sessions": active_sessions,
            "max_concurrent_requests": state.max_concurrent_requests,
            "auth_required": state.auth_token.is_some()
        }))?,
    })
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
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"))
    {
        return Ok(dashboard_http_text(
            "415 Unsupported Media Type",
            "MCP HTTP POST requires application/json\n",
        ));
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
    let method = message.get("method").and_then(|value| value.as_str());
    let is_initialize = method == Some("initialize");
    let is_notification_or_response = message.get("id").is_none();

    if is_initialize {
        if let Some(response) = mcp_http_protocol_version_error(request, None) {
            return Ok(response);
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
                sessions.insert(
                    session_id,
                    McpHttpSession {
                        proxy,
                        protocol_version,
                    },
                );
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
    let session_id = session_id.to_string();
    let mut sessions = state.sessions.lock().map_err(|_| {
        AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
    })?;
    let Some(session) = sessions.get_mut(&session_id) else {
        return Ok(dashboard_http_text(
            "404 Not Found",
            "MCP session not found\n",
        ));
    };
    if let Some(response) =
        mcp_http_protocol_version_error(request, Some(session.protocol_version.as_str()))
    {
        return Ok(response);
    }
    let response = session.proxy.handle_json_rpc_line(&request.body, false)?;
    mcp_http_write_session_outputs(&session_id, &session.proxy, state)?;
    drop(sessions);

    if let Some(response) = response {
        Ok(DashboardHttpResponse {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body: serde_json::to_vec(&response)?,
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
    let session_id = session_id.to_string();
    let mut sessions = state.sessions.lock().map_err(|_| {
        AgentKError::InvalidMcpRequest("MCP HTTP session lock poisoned".to_string())
    })?;
    let Some(session) = sessions.remove(&session_id) else {
        return Ok(dashboard_http_text(
            "404 Not Found",
            "MCP session not found\n",
        ));
    };
    if let Some(response) =
        mcp_http_protocol_version_error(request, Some(session.protocol_version.as_str()))
    {
        sessions.insert(session_id, session);
        return Ok(response);
    }
    mcp_http_write_session_outputs(&session_id, &session.proxy, state)?;
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

fn mcp_http_origin_allowed(origin: Option<&str>, allow_origins: &[String]) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let origin = origin.trim();
    origin == "null"
        || origin.starts_with("http://127.0.0.1")
        || origin.starts_with("http://localhost")
        || allow_origins.iter().any(|allowed| allowed == origin)
}

fn mcp_http_auth_allowed(request: &DashboardHttpRequest, auth_token: Option<&str>) -> bool {
    let Some(auth_token) = auth_token else {
        return true;
    };
    request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value == auth_token)
        || request
            .header("x-agentk-mcp-token")
            .is_some_and(|value| value == auth_token)
}

fn mcp_http_accepts(request: &DashboardHttpRequest, expected: &str) -> bool {
    request.header("accept").is_some_and(|value| {
        value
            .split(',')
            .any(|part| part.trim().split(';').next().unwrap_or_default() == expected)
    })
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
    allow_origins: Vec<String>,
    auth_token_env: String,
) -> Result<(), AgentKError> {
    if !is_safe_env_name(&auth_token_env) {
        return Err(AgentKError::InvalidMcpRequest(
            "auth-token-env must be a safe environment variable name".to_string(),
        ));
    }
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
        allow_origins,
        auth_token,
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
    force: bool,
    json: bool,
) -> Result<(), AgentKError> {
    let report = package_sidecar_bundle(&root, &out, force)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("AgentK team sidecar package created");
    println!("root      {}", report.root.display());
    println!("package   {}", report.package.display());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
            "--allow-origin",
            "http://localhost:3000",
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
            allow_origins,
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
        assert_eq!(allow_origins, vec!["http://localhost:3000".to_string()]);
        assert_eq!(auth_token_env, "AGENTK_TEST_HTTP_TOKEN");
        assert_eq!(args, vec!["-c".to_string(), "printf ok".to_string()]);
        assert_eq!(trace_out, Some(PathBuf::from(".agentk/runs/http.jsonl")));
        assert_eq!(
            session_report_out,
            Some(PathBuf::from(".agentk/runs/http.session.json"))
        );
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
            allow_origins: Vec::new(),
            auth_token: None,
            trace_out: None,
            session_report_out: None,
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
    }

    #[test]
    fn mcp_http_response_rejects_bad_origin_and_missing_session() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            allow_origins: Vec::new(),
            auth_token: None,
            trace_out: None,
            session_report_out: None,
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
    fn mcp_http_response_rejects_protocol_version_mismatches() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh")
                .with_args(["-c".to_string(), mcp_proxy_trace_out_probe_server()])
                .with_max_client_messages(10),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            allow_origins: Vec::new(),
            auth_token: None,
            trace_out: None,
            session_report_out: None,
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
    fn mcp_http_response_reports_operational_health_and_readiness() {
        let state = Arc::new(McpHttpGatewayState {
            proxy: McpSubprocessProxyConfig::new("agent://test", "http-probe", "sh"),
            endpoint: "/mcp".to_string(),
            max_concurrent_requests: 8,
            allow_origins: Vec::new(),
            auth_token: Some("secret".to_string()),
            trace_out: None,
            session_report_out: None,
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

        let ready = mcp_http_response(
            &dashboard_test_request("GET", "/readyz?probe=1", Vec::new()),
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
        assert_eq!(ready_json["max_concurrent_requests"], serde_json::json!(8));
        assert_eq!(ready_json["auth_required"], serde_json::json!(true));

        let ready_head = mcp_http_response(
            &dashboard_test_request("HEAD", "/readyz", Vec::new()),
            &state,
        )
        .expect("readyz HEAD should respond");
        assert_eq!(ready_head.status, "200 OK");
        assert!(ready_head.body.is_empty());

        let unsupported = mcp_http_response(
            &dashboard_test_request("POST", "/readyz", Vec::new()),
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
        let cli = Cli::try_parse_from(["agentk", "sidecar-run", "--root", "agentk-sidecar"])
            .expect("sidecar-run should parse");

        let Some(Command::SidecarRun { root }) = cli.command else {
            panic!("expected sidecar-run command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar"));
    }

    #[test]
    fn sidecar_serve_tcp_accepts_bundle_and_bind_args() {
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
            "--allow-origin",
            "http://localhost:3000",
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
            allow_origins,
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
        assert_eq!(allow_origins, vec!["http://localhost:3000".to_string()]);
        assert_eq!(auth_token_env, "AGENTK_TEST_HTTP_TOKEN");
    }

    #[test]
    fn sidecar_package_accepts_root_out_and_force() {
        let cli = Cli::try_parse_from([
            "agentk",
            "sidecar-package",
            "--root",
            "agentk-sidecar",
            "--out",
            "dist/agentk-sidecar",
            "--force",
        ])
        .expect("sidecar-package should parse");

        let Some(Command::SidecarPackage {
            root, out, force, ..
        }) = cli.command
        else {
            panic!("expected sidecar-package command");
        };
        assert_eq!(root, PathBuf::from("agentk-sidecar"));
        assert_eq!(out, PathBuf::from("dist/agentk-sidecar"));
        assert!(force);
    }

    #[test]
    fn approvals_and_decisions_accept_review_metadata() {
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
            "--host",
            "127.0.0.1",
            "--port",
            "8787",
            "--store-root",
            "agentk-sidecar/.agentk/team-store",
        ])
        .expect("dashboard server should parse");
        let Some(Command::DashboardServe {
            path,
            decisions,
            permissions,
            host,
            port,
            admin_token_env,
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
        assert_eq!(
            store_root,
            Some(PathBuf::from("agentk-sidecar/.agentk/team-store"))
        );

        let store_export = Cli::try_parse_from([
            "agentk",
            "store-export",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
            "--permissions",
            "agentk-sidecar/team-permissions.toml",
            "--out",
            "agentk-sidecar/.agentk/store",
        ])
        .expect("store export should parse");
        let Some(Command::StoreExport {
            path,
            decisions,
            permissions,
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
        assert_eq!(out, PathBuf::from("agentk-sidecar/.agentk/store"));

        let store_sync = Cli::try_parse_from([
            "agentk",
            "store-sync",
            "agentk-sidecar/.agentk/runs/team-sidecar.jsonl",
            "--permissions",
            "agentk-sidecar/team-permissions.toml",
            "--root",
            "agentk-sidecar/.agentk/team-store",
        ])
        .expect("store sync should parse");
        let Some(Command::StoreSync {
            path,
            decisions,
            permissions,
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
    }

    #[test]
    fn store_push_dry_run_preflights_without_exposing_database_url() {
        let trace_path = test_temp_path("agentk-store-push-trace", "jsonl");
        let decisions_path = test_temp_path("agentk-store-push-decisions", "jsonl");
        let output_dir = test_temp_path("agentk-store-push-export", "dir");
        run_safe_agent_demo(&trace_path).expect("safe agent demo should write a trace");
        export_audit_store(&trace_path, &decisions_path, None, &output_dir)
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
            &dashboard_test_request("GET", "/api/review?refresh=1", Vec::new()),
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
            &dashboard_test_request(
                "POST",
                "/api/approve",
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

        let missing_admin = dashboard_http_response(
            &dashboard_test_request(
                "POST",
                "/api/approve",
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
                [("Authorization", "Bearer wrong")],
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

        let approved = dashboard_http_response(
            &dashboard_test_request_with_headers(
                "POST",
                "/api/approve",
                [("Authorization", "Bearer server-admin")],
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
                [("X-AgentK-Admin-Token", "server-admin")],
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
