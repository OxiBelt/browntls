---
name: subagent-delegation
description: Delegate bounded browntls engineering work to suitable available GPT or Claude workers when parallel investigation, isolated implementation, or independent review improves confidence or efficiency. Keep trivial and tightly coupled work local.
---

# Subagent delegation

Use this skill when delegation materially helps the task. It governs workers,
not the primary agent's plan or execution mode. The parent owns requirements,
architecture decisions, integration, validation claims, and delivery.

Read [contribution policy](../../../CONTRIBUTING.md) before assigning work;
it is authoritative. Follow [agent guidance](../../../AGENTS.md) and
[private disclosure policy](../../../SECURITY.md). This skill does not grant
permission to edit, spawn workers, publish findings, or perform external writes
beyond the active task and runtime's permissions.

## Choose bounded work

Keep trivial commands, obvious typos, and tightly coupled decisions local.
Parallelize independent investigation; delegate implementation only after the
intended behavior is decided and file/API ownership can be separated.

| Responsibility | Selection criteria |
| --- | --- |
| Exploration | Trace callers, data flow, features, tests, and platform constraints; prefer inexpensive evidence collection when interpretation is straightforward. |
| Mechanical implementation | Execute a precise transformation with decided semantics and objective verification. |
| Semantic diagnosis | Resolve ownership, error handling, protocol, concurrency, or non-local behavioral questions with sufficient reasoning capability. |
| Tests and evidence | Run targeted checks, classify logs, and summarize measurements; mark causal explanations as inference unless established. |
| Correctness and security | Challenge invariants, negative cases, trust boundaries, and failure behavior; inspect the actual patch and surrounding code. |
| Final integration | Reconcile independently changed surfaces, public contracts, tests, and unresolved findings when cross-cutting review adds confidence. |

Before selecting any worker model, read the
[model-routing reference](references/model-routing.md). It contains the
permitted GPT and Claude models, availability checks, effort selection, and
fallback rules. GPT and Claude workers may coexist in the same application; the
host's actual tools determine which combinations it supports. Do not assume
separate clients or preconfigured custom agents are necessary.

## Assign and supervise

Give each worker:

- A concrete objective and baseline commit, plus any relevant uncommitted diff.
- Applicable policies, relevant files, decided behavior, and safety invariants.
- Read-only or write permission, owned files/APIs, and forbidden overlap.
- Verification expectations and the specific evidence needed back.

Do not send unrelated history, secrets, or whole logs when local evidence is
available. Workers must receive the applicable policies explicitly; do not
assume that every host passes project instructions to them automatically.

Parallel readers may inspect the same code from different perspectives. Writers
must have disjoint ownership, including shared APIs and generated artifacts.
When work converges on one state machine, schema, or API, gather evidence in
parallel, make one decision, then serialize or repartition the edits. A worker
must report newly discovered overlap instead of editing another worker's scope.

Keep useful independent work moving while workers run. Avoid repeatedly waiting
for results or duplicating their assignments. The parent reviews actual diffs,
integrates them, and owns commits, signing, and external writes. Workers must
not commit, push, publish, or delegate recursively without explicit
authorization. Close completed workers when the host supports lifecycle
management.

## Evidence and escalation

Require a compact return report:

```text
Provenance: actual agent/tool, requested/resolved model and effort, resolution limits.
Observed: paths/symbols and behavior established from source or execution.
Inference: implications and suspected causes, with supporting evidence.
Unresolved: unanswered questions and platform/configuration/coverage limits.
Changes: owned files changed, or none.
Verification: commands, configuration/platform, results, and skipped checks.
Review: reviewer identity, reviewed commit/diff, findings, and remaining limits.
Attribution: participating agents and required assistance notices for integration.
```

Return only relevant excerpts, grouped failures, and measurement summaries.
Do not treat compilation, passing tests, entropy statistics, interoperability,
or an agent's conclusion as proof of cryptographic or protocol correctness.

Use the cheapest applicable checks first, then broaden when policy, changed
behavior, cross-cutting effects, or unresolved failures justify it. Preserve
flaky failures as unresolved evidence until explained; do not suppress them.

Escalate when a mechanical task exposes semantic choices, tests fail for a
non-obvious reason, or correctness depends on non-local invariants. State what
is established, the exact unresolved question, and the evidence the next
reviewer needs. Do not repeatedly upgrade models without narrowing uncertainty.
A plausible high-impact flaw needs capable semantic review, not cost-driven
persistence with an unsuitable worker.

## Independent review and security coverage

Apply the mandatory review gate in
[contribution policy](../../../CONTRIBUTING.md#independent-review) before
landing substantive behavior or safety changes in its listed sensitive areas. A
capable, named non-author person or separate agent must inspect the actual diff
and materially affected code. The same model in a separate agent is allowed;
provider diversity alone proves neither independence nor correctness. Give the
reviewer the contract and evidence, not just the author's conclusions.

Record reviewer identity and the reviewed commit or reproducible diff, findings,
verification, and limits in the task report. Resolve blocking findings and
review material follow-up changes before landing. If a suitable independent
reviewer is unavailable, continue useful local preparation and testing, report
the gap, and leave affected changes unlanded. Never invent a reviewer or claim
self-review satisfies the gate.

Use these prompts where relevant, without turning every task into a full audit:

- Cryptography: algorithm/vector agreement, constant-time behavior, randomness
  and nonce uniqueness, secret lifecycle, and software/accelerated backend
  equivalence. Statistical entropy checks provide bounded evidence only.
- PKI and TLS: certificate/name/peer verification, caller configuration and
  provider selection, negotiation and protocol state, safe errors and negative
  cases, and CPU/memory/buffering limits for untrusted inputs.
- Unsafe, FFI, kernel, and concurrency: confinement, safety invariants,
  ownership/lifetimes, synchronization, cancellation and cleanup, supported
  platforms, and applicable Miri/sanitizer/fuzz/syscall evidence with limits.
  The only kernel mechanism is Linux kernel TLS offload
  (`browntls_core::kernel`, `browntls-ktls`); do not invent others for this
  workflow.

Start from a trustworthy review baseline: an immutable revision with relevant
scope, configuration/platform, retained evidence, and explicit gaps. Check that
subsequent changes have not invalidated its assumptions. Review the delta and
semantically affected callers, sibling paths, trust boundaries, and unchanged
code. Record stale, missing, and deferred coverage. If no trustworthy baseline
exists or a redesign invalidates it, expand through justified risk-directed
partitions; do not default to a monolithic repository scan or claim release
readiness from changed-file review alone.

## Attribution and discovery

Preserve signing and actual-agent assistance notices under contribution policy.
Disclose participating tools accurately; for example, Claude participation needs
its own notice and must not be attributed solely to Codex. Public commit context
must remain portable, without host paths, temporary worker/session aliases,
private evidence links, or undisclosed vulnerability details.

The canonical skill is configured for discovery from `.agents/skills/` by Codex
and through the relative `.claude/skills/` symlink by Claude Code. Invoke it as
`$subagent-delegation` or `/subagent-delegation`, respectively. The checked-in
metadata permits automatic selection; local settings and filesystem access may
restrict discovery or invocation. Verify the actual client's skill listing.
If a checkout cannot preserve the symlink, load the canonical skill explicitly
through agent guidance and report native Claude discovery unavailable until the
local link is restored. Do not maintain a second copy. Client discovery does
not establish worker-model availability.

Adapted from [OxiBelt's delegation
skill](https://github.com/OxiBelt/OxiBelt/blob/f0608e8249e837b41a392ffdd9974426b949eaee/.agents/skills/subagent-delegation/SKILL.md),
revision `f0608e8249e837b41a392ffdd9974426b949eaee`. Copyright 2026 OxiBelt
contributors. Modified for browntls: capability-based routing, shared GPT/Claude
use, permitted models, mandatory sensitive-change review, and
TLS/PKI/backend-specific evidence. Licensed under
[Apache-2.0](../../../LICENSE).
