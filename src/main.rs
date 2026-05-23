use agentk::{
    AgentKError, Policy, ReadinessStatus, Verdict, default_log_path, fork_replay_behavior_jsonl,
    fork_replay_jsonl, generate_signing_key_file, inspect_jsonl, mcp_proxy_from_path,
    mcp_server_json_stream, mediate_mcp_json_reader, mediate_mcp_json_stream, readiness_report,
    release_audit_report, replay_jsonl, rotate_signing_key_file, run_poisoned_webpage_demo,
    secret_reference_env_store_report_from_path, secret_reference_manifest_report_from_path,
    signing_key_status, trusted_signing_key_manifest_keys_from_path,
    trusted_signing_key_manifest_report_from_path, verify_jsonl, verify_signatures_jsonl,
    verify_signatures_jsonl_with_trusted_keys, verify_signing_key_rotation_manifest_file,
    write_latest_copy,
};
use clap::{Parser, Subcommand};
use std::io::{self, BufReader};
use std::path::PathBuf;

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
