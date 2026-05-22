# Contributing To AgentK

AgentK is a security-sensitive prototype. Treat every contribution as if it
could become part of a public boundary between an autonomous agent and real
side effects.

## Ground Rules

- Keep changes small, reviewable, and tied to one security claim.
- Do not commit generated `.agentk/` logs, local traces, private prompts, local
  paths, usernames, tokens, signing keys, certificates, `.env` files, or real
  customer data.
- Use invalid domains such as `example.invalid` in examples and tests.
- Mark new behavior as implemented, planned, or experimental. Do not describe a
  security property as supported until it has tests.
- Prefer deny-by-default behavior when a syscall, label, policy, descriptor, or
  evidence format is unknown.
- Do not add production-readiness claims without updating the threat model,
  security policy, tests, and release checklist.

## Required Local Checks

Run these before opening a pull request:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run --locked -- release-audit
```

Before a public release or any high-risk security change, run strict audit with
a local signing key that lives outside the repository:

```sh
AGENTK_SIGNING_KEY_HEX=$(cat ../agentk-signing-key) cargo run --locked -- release-audit --strict
```

The static development signer is acceptable only for demos and CI smoke checks.
Do not use it to make release integrity claims.

## Security-Sensitive Changes

A change is security-sensitive if it touches any of these areas:

- policy parsing or decision logic,
- label propagation or taint handling,
- syscall definitions or default behavior,
- secret handles, signing keys, receipts, or signature verification,
- flight-log serialization, redaction, replay, or fork replay,
- MCP request, descriptor, response, or transport mediation,
- release gates, CI, branch protection, disclosure, or documentation claims.

Security-sensitive pull requests must include:

- the threat being addressed,
- the expected failure mode,
- tests for allow and deny paths,
- proof that raw secrets and raw private context are not logged,
- updates to `docs/threat-model.md`, `SECURITY.md`, or `docs/architecture.md`
  when the claim surface changes.

## Review Rules

- Review the diff as if hostile input may reach every parser.
- Check that new examples cannot be mistaken for real credentials, endpoints, or
  traces.
- Check that errors and debug output do not include raw syscall payloads.
- Check that new hashes, signatures, or receipts are verified fail-closed.
- Keep public issues free of suspected vulnerability details. Use GitHub private
  vulnerability reporting for security reports.

## Pull Request Shape

Use a branch and pull request for public changes. `master` is protected by the
`audit` CI check, strict status checks, linear history, force-push protection,
and branch deletion protection.

Good pull requests include:

- a short summary,
- the exact checks run,
- any remaining warnings from `release-audit`,
- links to relevant threat-model or roadmap updates.

Do not merge a change that weakens a guardrail without explicitly documenting
why the weaker behavior is still safe.
