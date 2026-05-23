# Signed Release Checklist

AgentK releases should be boring, reproducible, and easy to audit. Do not cut a
tag from a dirty tree or with undocumented warnings.

## Before Tagging

- [ ] All intended changes are merged through protected `master`.
- [ ] GitHub Actions `audit` is passing on `master`.
- [ ] `SECURITY.md`, `README.md`, and `docs/roadmap.md` match the released
      behavior.
- [ ] `docs/key-lifecycle.md` matches the release signing-key process.
- [ ] `docs/threat-model.md` covers any new syscall, label, policy, evidence, or
      MCP behavior.
- [ ] Public examples use only dummy data, invalid domains, and synthetic traces.
- [ ] No generated `.agentk/` logs, signing keys, private manifests, `.env`
      files, or local-only artifacts are tracked.
- [ ] GitHub private vulnerability reporting, secret scanning, push protection,
      Dependabot alerts, and Dependabot security updates are enabled.

## Local Release Gate

Create or select a release signing key outside the repository:

```sh
cargo run -- keygen --out ../agentk-release-signing-key
```

If rotating from an existing local signing key, write the next private key
outside the repository and commit only the public manifest if the rotation needs
to be public evidence:

```sh
cargo run -- key-rotate \
  --current ../agentk-release-signing-key \
  --next-out ../agentk-release-signing-key-next \
  --manifest docs/key-rotation-vNEXT.json

cargo run -- key-rotate-verify --manifest docs/key-rotation-vNEXT.json
```

Run the strict audit with the local release key:

```sh
AGENTK_REQUIRE_SIGNING_KEY=1 AGENTK_SIGNING_KEY_FILE=../agentk-release-signing-key cargo run --locked -- release-audit --strict
```

On Unix, the audit fails if the release key file is group- or world-readable.

Then run the explicit command set used by reviewers:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
git status --short
```

Expected result: no failures, no dirty tracked files, and no unreviewed
warnings.

## Manual Public Scan

Inspect exactly what will be public:

```sh
git ls-files
cargo run -- readiness
```

Then manually search tracked files for local paths, provider credential
prefixes, private-key headers, and assignment-style credential names. Allowed
hits must be documented as dummy labels, dummy strings, or tests that prove
redaction. Remove or rewrite anything else before release.

## Signed Tag

Use a signed tag for releases:

```sh
git tag -s v0.1.0 -m "AgentK v0.1.0"
git verify-tag v0.1.0
git push origin v0.1.0
```

If a maintainer cannot sign with GPG or SSH yet, do not publish a release tag.
Open an issue or pull request to establish signing first.

## GitHub Release

- [ ] Release notes list implemented behavior only.
- [ ] Experimental or planned features are clearly marked.
- [ ] Known limitations from `SECURITY.md` are linked.
- [ ] The signed tag verification result is recorded in the release notes.
- [ ] Any public key rotation manifest is linked and verified.

## After Publishing

- [ ] Confirm the release page points at the signed tag.
- [ ] Confirm CI is green for the release commit.
- [ ] Confirm private vulnerability reporting remains enabled.
- [ ] Watch Dependabot and secret scanning alerts.
- [ ] Leave the local release signing key outside the repository.
