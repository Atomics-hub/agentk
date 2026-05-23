# Security Policy

AgentK is security-sensitive software. Treat all code, docs, tests, and demos as if they may influence a public runtime that mediates autonomous actions.

## Current Status

This repository is a public prototype. It is not ready for production, remote deployment, or public trust claims.

Current guarantees are intentionally narrow:

- the demo policy blocks secret/private data flowing to `network.send`,
- the demo policy blocks raw `secret.open` without an explicit scoped capability,
- brokered secret handles do not serialize raw secret material into flight logs,
- brokered secret handles bind scope and expiry to their signed capability receipt,
- unknown syscalls are denied by default,
- receipts and secret handles carry Ed25519 development signatures,
- signature verification reports fail closed on tampered proofs or tampered proof-bound receipt/handle fields,
- generated flight logs are hash-chained and locally verifiable,
- flight-log inspection redacts raw event input refs into hash evidence,
- deterministic replay verifies recorded logs without side effects and records synthetic stub output refs for allowed model/tool/network syscalls,
- behavior fork replay compares hashed output refs for model/tool/network changes without accepting raw outputs,
- release audit runs local-only checks and does not configure remotes or push,
- the MCP proxy MVP mediates one `tool.invoke` request without executing the tool,
- MCP descriptor mediation records descriptor/schema hashes without logging raw descriptor text,
- MCP response recording records response hashes without logging raw tool output,
- MCP response recording marks tool outputs as untrusted/external and error responses as poisoned-suspect,
- `tool.invoke` denies secret, private, untrusted, or poisoned-suspect inputs even when a target capability is present,
- the minimal MCP JSON-RPC stdio server exposes only side-effect-free mediation,
- key rotation writes a next private key file and a signed public manifest,
- no actual model, network, secret, or filesystem side effects occur in the demo.

Non-guarantees:

- no production key management yet; the current signer is a static development key,
- no complete sandbox,
- no complete production MCP proxy/server compliance yet,
- no eBPF/cgroup enforcement yet,
- no formal verification,
- no protection against malicious local users,
- no production-grade storage for real secrets yet.

For non-demo runs, configure `AGENTK_SIGNING_KEY_HEX` with a 32-byte hex Ed25519 signing key. Do not commit this value. AgentK prints only the derived public key through `agentk signing-key`.

Set `AGENTK_REQUIRE_SIGNING_KEY=1` in release gates or production-like checks to fail readiness if AgentK would otherwise use the static development key.

`agentk keygen --out <path>` writes a new private signing key to a caller-chosen file with restrictive permissions on Unix. Keep that path outside the repository.

`agentk key-rotate --current <path> --next-out <path> --manifest <path>` reads the current private signing key, writes the next private signing key, and emits a public manifest signed by the previous key. The manifest is intended to be reviewable and contains public keys, a payload hash, and a signature only.

`agentk key-rotate-verify --manifest <path>` verifies the manifest payload hash and signature.

## Maintainer Rules

For every public change:

- No real prompts, real traces, local usernames, local paths, tokens, API keys, or customer data in examples, tests, issues, or docs.
- Every security claim must say whether it is implemented, planned, or experimental.
- Demos must use invalid domains such as `example.invalid`.
- Generated `.agentk/` logs stay ignored by git.
- Security features need tests before being described as supported.
- Any new syscall must document its threat model, labels consumed, labels emitted, and policy failure modes.

## Reporting

GitHub private vulnerability reporting is enabled. Report suspected vulnerabilities through GitHub's **Security** tab with **Report a vulnerability**. Do not open public issues for suspected vulnerabilities.

## Supported Versions

AgentK is currently a public prototype. No tagged public versions are supported yet.

The first tagged prototype release should be the only supported disclosure target until a broader support policy exists.
