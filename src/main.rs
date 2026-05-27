use agentk::{
    AgentKError, McpSubprocessProxy, McpSubprocessProxyConfig, Policy, ReadinessStatus, Verdict,
    default_log_path, fork_replay_behavior_jsonl, fork_replay_jsonl, generate_signing_key_file,
    inspect_jsonl, mcp_proxy_from_path, mcp_server_json_stream, mcp_subprocess_proxy_json_stream,
    mediate_mcp_json_reader, mediate_mcp_json_stream, readiness_report, release_audit_report,
    replay_jsonl, rotate_signing_key_file, run_mcp_killer_demo, run_mcp_security_shim_eval,
    run_poisoned_webpage_demo, secret_reference_env_store_report_from_path,
    secret_reference_manifest_report_from_path, signing_key_status,
    trusted_signing_key_manifest_keys_from_path, trusted_signing_key_manifest_report_from_path,
    verify_jsonl, verify_signatures_jsonl, verify_signatures_jsonl_with_trusted_keys,
    verify_signing_key_rotation_manifest_file, write_events_jsonl, write_latest_copy,
};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
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
        /// Optional JSONL path for the AgentK proxy flight log.
        #[arg(long)]
        trace_out: Option<PathBuf>,
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
        Command::McpProxyStdio {
            agent_id,
            server_id,
            command,
            args,
            allow_env,
            response_timeout_ms,
            trace_out,
        } => mcp_proxy_stdio(
            agent_id,
            server_id,
            command,
            args,
            allow_env,
            response_timeout_ms,
            trace_out,
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

fn mcp_proxy_stdio(
    agent_id: String,
    server_id: String,
    command: String,
    args: Vec<String>,
    allow_env: Vec<String>,
    response_timeout_ms: u64,
    trace_out: Option<PathBuf>,
) -> Result<(), AgentKError> {
    let mut config = McpSubprocessProxyConfig::new(agent_id, server_id, command)
        .with_args(args)
        .with_response_timeout(Duration::from_millis(response_timeout_ms));
    for (name, value) in collect_mcp_proxy_allowed_env(&allow_env, |name| env::var(name).ok())? {
        config = config.with_env(name, value);
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    mcp_proxy_stdio_with_io(
        config,
        trace_out,
        BufReader::new(stdin.lock()),
        stdout.lock(),
    )
}

fn mcp_proxy_stdio_with_io<R, W>(
    config: McpSubprocessProxyConfig,
    trace_out: Option<PathBuf>,
    reader: R,
    writer: W,
) -> Result<(), AgentKError>
where
    R: BufRead,
    W: Write,
{
    if let Some(path) = trace_out {
        let mut proxy = McpSubprocessProxy::spawn(config)?;
        let stream_result = proxy.proxy_json_stream(reader, writer);
        let trace_result = write_events_jsonl(proxy.events(), path);

        stream_result?;
        trace_result?;
        return Ok(());
    }

    mcp_subprocess_proxy_json_stream(reader, writer, config)
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

        let Some(Command::McpProxyStdio { args, .. }) = cli.command else {
            panic!("expected mcp-proxy-stdio command");
        };
        assert_eq!(args, vec!["-c".to_string(), "printf ok".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_proxy_stdio_trace_out_writes_verifiable_events() {
        let trace_path = env::temp_dir().join(format!(
            "agentk-mcp-proxy-stdio-trace-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        ));
        let _ = fs::remove_file(&trace_path);

        let server = r#"
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
"#;
        let input = r#"
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
"#;
        let config = McpSubprocessProxyConfig::new("agent://test", "trace-out-probe", "sh")
            .with_args(["-c".to_string(), server.to_string()]);
        let mut output = Vec::new();

        mcp_proxy_stdio_with_io(
            config,
            Some(trace_path.clone()),
            BufReader::new(input.as_bytes()),
            &mut output,
        )
        .expect("stdio proxy should write trace output");

        let responses = String::from_utf8(output).expect("proxy output should be utf8");
        assert!(responses.contains("\"tools\""));
        let verify = verify_jsonl(&trace_path).expect("trace-out should be verifiable");
        assert_eq!(verify.events_checked, 1);

        let _ = fs::remove_file(trace_path);
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
