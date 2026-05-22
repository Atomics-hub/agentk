# Threat Model

AgentK assumes an AI agent can be confused, compromised, or steered by untrusted context.

The runtime should make dangerous actions structurally difficult even when the agent proposes them.

## Assets

- user files,
- credentials and API tokens,
- private prompts and retrieved context,
- agent memory,
- external network access,
- tool execution authority,
- audit logs and policy decisions.

## Adversaries

- malicious webpages,
- poisoned documents,
- hostile email or ticket content,
- malicious MCP/tool descriptors,
- compromised agent memory,
- prompt injections that ask the model to bypass policy,
- buggy or over-broad tools.

## Security Boundary

The first intended boundary is the AgentK syscall API.

An agent may plan freely, but actions must cross typed syscalls:

```txt
context.read
model.call
tool.describe
tool.invoke
tool.response
secret.open
network.send
file.patch
human.approve
agent.spawn
```

## Core Rule

Untrusted content is data, not authority.

Examples:

```txt
untrusted webpage text cannot authorize network.send
private context cannot flow to external network sinks
raw secrets cannot enter model context
tool output cannot grant itself new tools
```

## Known Gaps

- Policy uses a small typed AST, not a full formal policy language.
- Labels are manually attached in the demo.
- Receipts and secret handles use Ed25519 signatures, but the default signer is still a static development key.
- Replay verifies the log chain and stubs side effects; fork replay currently compares policy decisions only.
- There is no host process sandbox yet.
- MCP support includes side-effect-free mediation commands, descriptor hashing, response hashing, and a minimal JSON-RPC stdio server, not a complete production proxy.
- Key rotation emits a signed public manifest, but there is no production key storage yet.

## Design Bias

AgentK should prefer explicit denial over ambiguous allow.

When unsure:

```txt
deny -> explain -> require capability or approval
```
