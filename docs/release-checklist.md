# Signed Release Checklist

AgentK releases should be boring, reproducible, and easy to audit. Do not cut a
tag from a dirty tree or with undocumented warnings.

Historical v0.1 dry-run notes live in
[`docs/v0.1-release-dry-run.md`](v0.1-release-dry-run.md). Keep them as
archived evidence; do not overwrite them for later release trains.

For v0.2-alpha and later, release notes must be generated for the specific
release branch or tag and must include the package archive checksum, package
release-manifest path, strict release-audit result, signed tag verification,
and signer evidence before publication.
The current v0.2 alpha draft lives in
[`docs/v0.2-alpha-release-notes.md`](v0.2-alpha-release-notes.md).

## Before Tagging

- [ ] All intended changes are merged through protected `master`.
- [ ] GitHub Actions `audit` is passing on `master`.
- [ ] `SECURITY.md`, `README.md`, and `docs/roadmap.md` match the released
      behavior.
- [ ] `docs/productization-plan.md` distinguishes implemented behavior from
      accepted alpha limits and post-alpha work.
- [ ] v0.1 archival docs still match their historical release and are not used
      as the current release source of truth.
- [ ] Release notes list each accepted alpha limit as implemented, deferred, or
      explicitly out of scope, and do not overclaim deferred work.
- [ ] `docs/v0.2-alpha-release-notes.md`, or the release-specific successor
      notes file, matches the final release commit and package artifacts.
- [ ] `docs/key-lifecycle.md` matches the release signing-key process.
- [ ] `docs/threat-model.md` covers any new syscall, label, policy, evidence, or
      MCP behavior.
- [ ] `docs/mcp-proxy.md` matches the packaged stdio, TCP, and HTTP gateway
      behavior.
- [ ] The generated sidecar package includes Claude/Codex/Cursor snippets,
      package lock, deploy templates, durable store workflow launchers, and
      notification bridge launchers expected for this release.
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
AGENTK_REQUIRE_SIGNING_KEY=1 \
AGENTK_RELEASE_REMOTE_APPROVED=1 \
AGENTK_SIGNING_KEY_FILE=../agentk-release-signing-key \
cargo run --locked -- release-audit --strict
```

On Unix, the audit fails if the release key file is group- or world-readable or
if its parent directory allows group/other writes.

Run the packaged sidecar release-candidate smoke in an empty or disposable
directory. This recreates the package/archive, verifies the archive checksum,
installs the package, writes the package release manifest, runs the packaged
safe-agent demo, dashboard, sidecar checks, durable store sync/export/check,
Slack/GitHub/email notification payload exporters, dry-run delivery launchers,
and Postgres dry-run push:

```sh
cargo run --locked -- release-candidate-smoke --json
```

For manual reviewer handoff, also keep the explicit package commands available
in the release notes or deployment ticket:

```sh
cargo run --locked -- sidecar-init --root agentk-sidecar --force
cargo run --locked -- sidecar-package \
  --root agentk-sidecar \
  --out dist/agentk-sidecar \
  --archive-out dist/agentk-sidecar.tar \
  --force \
  --json
cargo run --locked -- sidecar-package-archive-check \
  --archive dist/agentk-sidecar.tar \
  --json
cargo run --locked -- sidecar-package-install \
  --archive dist/agentk-sidecar.tar \
  --out installed/agentk-sidecar \
  --force \
  --json
cargo run --locked -- sidecar-package-release-manifest \
  --package installed/agentk-sidecar \
  --archive dist/agentk-sidecar.tar \
  --out dist/agentk-sidecar-release-manifest.json \
  --force \
  --json
```

If a Homebrew tap update is part of the release, generate the formula from the
final source tarball URL and SHA-256:

```sh
cargo run --locked -- release-homebrew-formula \
  --source-url https://github.com/OWNER/REPO/archive/refs/tags/vX.Y.Z.tar.gz \
  --sha256 <source-tarball-sha256> \
  --version X.Y.Z \
  --homepage https://github.com/OWNER/REPO \
  --out dist/homebrew/agentk.rb
```

Review the generated Ruby formula before committing it to any tap. This command
does not publish a tap.

Then run the explicit command set used by reviewers:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo run --locked -- release-candidate-smoke --json
cargo run -- trusted-signers-check --manifest examples/trusted-signers.toml
cargo run -- verify-signatures .agentk/runs/latest.jsonl --trusted-public-key <release-public-key>
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
git tag -s vX.Y.Z -m "AgentK vX.Y.Z"
git verify-tag vX.Y.Z
git push origin vX.Y.Z
```

If a maintainer cannot sign with GPG or SSH yet, do not publish a release tag.
Open an issue or pull request to establish signing first.

## GitHub Release

- [ ] Release notes are updated for the final commit and tag.
- [ ] Release notes list implemented behavior only.
- [ ] Experimental or planned features are clearly marked.
- [ ] Known limitations from `SECURITY.md` are linked.
- [ ] Package archive SHA-256 and package release-manifest path are recorded.
- [ ] The signed tag verification result is recorded in the release notes.
- [ ] Any public key rotation manifest is linked and verified.

## After Publishing

- [ ] Confirm the release page points at the signed tag.
- [ ] Confirm CI is green for the release commit.
- [ ] Confirm private vulnerability reporting remains enabled.
- [ ] Watch Dependabot and secret scanning alerts.
- [ ] Leave the local release signing key outside the repository.
