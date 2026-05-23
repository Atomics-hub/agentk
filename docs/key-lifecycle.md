# Signing Key Lifecycle

AgentK evidence signatures are only useful if key custody is boring, explicit,
and auditable.

This runbook describes the current prototype release-key lifecycle. It is not a
production key-management system.

## Scope

This applies to signing keys used for:

- capability receipts,
- secret handles,
- release-audit evidence,
- key-rotation manifests.

## Generation

Generate private signing keys outside the repository:

```sh
cargo run -- keygen --out ../agentk-release-signing-key
```

On Unix, readiness requires `AGENTK_SIGNING_KEY_FILE` to be owner-only. Use
`chmod 600 <path>` if a key file is too broadly readable.

## Custody

Private signing keys must stay outside git, release artifacts, examples, issues,
logs, and chat transcripts. Do not paste `AGENTK_SIGNING_KEY_HEX` into CI logs or
shell history. Prefer `AGENTK_SIGNING_KEY_FILE` for local release gates.

Only the derived public key, signed manifest, and verification result are public
release evidence.

## Activation

Release gates must require a configured signer:

```sh
AGENTK_REQUIRE_SIGNING_KEY=1 AGENTK_SIGNING_KEY_FILE=../agentk-release-signing-key cargo run --locked -- release-audit --strict
```

The static development signer is acceptable only for demos and CI smoke checks.
It must not be used for tagged releases or production-like deployments.

## Rotation

Rotate from the active private key to a new private key kept outside the repo.
Commit only the public rotation manifest when public evidence is useful:

```sh
cargo run -- key-rotate \
  --current ../agentk-release-signing-key \
  --next-out ../agentk-release-signing-key-next \
  --manifest docs/key-rotation-vNEXT.json

cargo run -- key-rotate-verify --manifest docs/key-rotation-vNEXT.json
```

The manifest contains public keys, a payload hash, and a signature. It must not
contain private key material.

## Retirement

After rotation is verified and the next key is active, remove stale local key
files from active release paths. Keep any required archival copy in an external
secret manager or encrypted maintainer storage, not in this repository.

## Revocation

If a signing key may be exposed, stop using it immediately, rotate to a new key,
publish a signed rotation manifest if possible, and document the affected release
window. Treat all receipts and handles signed by the exposed key after the
suspected exposure time as suspect evidence.

## Incident Response

For suspected key exposure:

1. Pause release activity.
2. Confirm no private key bytes, `.env` files, generated `.agentk/` logs, or
   local paths were committed.
3. Rotate the key and verify the public manifest.
4. Re-run release audit with `AGENTK_REQUIRE_SIGNING_KEY=1`.
5. Use GitHub private vulnerability reporting for coordinated disclosure if
   public users may be affected.

## Production Requirements

Before AgentK can claim production key management, it needs external secret
storage or HSM-backed custody, audited access controls, revocation publication,
key identity pinning for verifiers, and an operator-tested recovery process.
