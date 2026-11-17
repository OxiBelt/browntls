# Worker model routing

Read this reference before spawning workers under the
[delegation skill](../SKILL.md). These are worker-selection constraints, not
requirements on the primary agent's model or operating mode. Explicit task
instructions and higher-priority runtime restrictions take precedence.

## Permitted models

| Provider | Permitted worker models |
| --- | --- |
| OpenAI | GPT-6.1-Terra, GPT-6.1-Sol, GPT-6-luna |
| Anthropic | Claude Opus 5.5, Claude Fable 5.2, Claude Mythos 5.2, only when available |

This is the permitted set, not an availability claim, price table, quality
ranking, or assignment of one provider to one role. In particular, earlier
Claude Fable versions, generic moving aliases, and unrelated security models
are not implicit substitutes. Do not probe subscription entitlements or Codex
Security access as part of model selection.

If GPT-series models mentioned above are unavailable due to cybersecurity limitations, select the following alternative permitted models from the list below if DayBreak Blue is enabled:

| Provider | Permitted alternative models |
| --- | --- |
| OpenAI | GPT-5.6 Sol xhigh or higher, GPT-6-Sol, GPT-6-Luna |

## Resolve against the active host

1. Inspect the active worker tool's advertised catalog and parameters. For a
   native client, use its supported model catalog or documented configuration.
   A model offered by another client, the primary session, or a provider website
   is not evidence that this worker launcher can use it.
2. Match a permitted model to the exact runtime identifier. For example, a host
   may advertise `gpt-6.1-sol` or `gpt-6-luna`. Use those only when advertised.
   For Claude, require catalog or host configuration evidence tying the
   identifier to the permitted version; never construct a guessed provider
   prefix or silently map Fable 5.1 to Fable 5.2.
3. Select a capable available worker for the bounded task using risk, ambiguity,
   tools, context needs, and known cost/latency. There is no GPT-first or
   Claude-first rule. Do not invent prices or assume cross-provider quality or
   reasoning-effort equivalence. If costs are unknown, say so and choose on
   established suitability rather than claiming the worker is cheapest.
4. Use an explicitly resolved model when the launcher permits it. Omit a model
   override only when the effective inherited model is verified as permitted.
   Use only effort settings supported for that model by that launcher. Moderate
   effort is a useful starting point for straightforward exploration; deeper
   effort is justified by semantic ambiguity and consequences, not repository
   size. Do not copy another provider's effort names or assume maximum effort
   is always useful.
5. Report the role, actual model, effort if configurable, and availability
   limits in the task evidence. If the host exposes the resolved execution
   model, check it; report an unexpected model and do not accept that run as
   satisfying the permitted-model or mandatory-review requirement.

Use an inexpensive suitable worker for precise enumeration, repetitive edits,
and evidence extraction when failure is detectable. Use a stronger semantic
worker for non-local correctness, security, or concurrency questions. Reserve
cross-cutting integration review for changes that actually need it. Escalate
an unresolved question, not merely the name of the model.

## Failure and fallback

If a model is absent, rejected, or cannot be resolved confidently, mark it
unavailable and select another permitted, capable worker. Do not repeatedly
retry an unsupported identifier, expand the allowlist, bypass permissions, or
spawn an unverified inherited model to get around the restriction.

If no permitted worker can do the work, the parent may prepare and test locally.
If independent review is required and no eligible reviewer is available, leave
the affected changes unlanded until a capable non-author person or permitted
separate agent reviews them. Report that gap explicitly. Model availability
does not waive the review gate, and using another provider is optional.
