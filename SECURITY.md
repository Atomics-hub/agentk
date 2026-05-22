# Security Policy

AgentK is security-sensitive software. Treat all code, docs, tests, and demos as if they may influence a public runtime that mediates autonomous actions.

## Current Status

This repository is a local prototype. It is not ready for production, remote deployment, or public trust claims.

Current guarantees are intentionally narrow:

- the demo policy blocks secret/private data flowing to `network.send`,
- the demo policy blocks raw `secret.open` without an explicit scoped capability,
- brokered secret handles do not serialize raw secret material into flight logs,
- unknown syscalls are denied by default,
- receipts and secret handles carry Ed25519 development signatures,
- signature verification reports fail closed on tampered proofs,
- generated flight logs are hash-chained and locally verifiable,
- deterministic replay verifies recorded logs without side effects,
- the MCP proxy MVP mediates one `tool.invoke` request without executing the tool,
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

`agentk keygen --out <path>` writes a new private signing key to a caller-chosen file with restrictive permissions on Unix. Keep that path outside the repository.

`agentk key-rotate --current <path> --next-out <path> --manifest <path>` reads the current private signing key, writes the next private signing key, and emits a public manifest signed by the previous key. The manifest is intended to be reviewable and contains public keys, a payload hash, and a signature only.

`agentk key-rotate-verify --manifest <path>` verifies the manifest payload hash and signature.

## Maintainer Rules

Before public release:

- No remotes or pushes until explicitly approved.
- No real prompts, real traces, local usernames, local paths, tokens, API keys, or customer data in examples, tests, issues, or docs.
- Every security claim must say whether it is implemented, planned, or experimental.
- Demos must use invalid domains such as `example.invalid`.
- Generated `.agentk/` logs stay ignored by git.
- Security features need tests before being described as supported.
- Any new syscall must document its threat model, labels consumed, labels emitted, and policy failure modes.

## Reporting

While this is local-only, report issues directly to the repository owner.

If AgentK becomes public, replace this section with a private disclosure address and a supported-version table before announcing the repo.
