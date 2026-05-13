# SDD charter

> Status: living document, owner = audit team. Refers to the
> Phase 1 findings ledger at `docs/review/99-findings-ledger.md`.

## What an SDD is, here

A **Software Design Document** in this tree is a short,
self-contained markdown file that:

1. Names the problem (one paragraph, plain language).
2. Cites the Phase 1 findings it closes (F-2026-NNN ids).
3. Defines explicit goals and non-goals.
4. Surveys ≥2 alternative designs honestly.
5. Recommends one design and explains why.
6. Specifies enough detail (interfaces, data shapes, file
   paths) that the implementation PR can be reviewed against
   the SDD without re-arguing the architecture.
7. Lists test requirements the implementation must satisfy.
8. Calls out the rollout / migration story if any.
9. Closes with open questions the author hasn't decided.

An SDD is **not** the implementation. The implementation PR
cites the SDD by id, links to it from the PR body, and
references it inline in any non-obvious code comment.

## Numbering

Three-digit zero-padded: `001`, `002`, … `099`. No gaps for
politeness. If an SDD is abandoned, the file stays with status
`abandoned` and a note explaining why; the number is not
recycled.

## Status field

Every SDD opens with:

```
> Status: <draft | review | accepted | implemented | abandoned>
> Owner: <name or team>
> Last updated: <YYYY-MM-DD>
> Closes findings: F-2026-NNN, F-2026-MMM, ...
```

- **draft** — author is still writing it.
- **review** — author wants feedback; not yet a contract.
- **accepted** — the user (or the operating team) has agreed
  this is the design we're building. An implementation PR can
  reference it from now on.
- **implemented** — the implementation has landed in main.
  The SDD is a historical record.
- **abandoned** — superseded or no longer relevant. Body
  explains the path not taken; useful for future readers
  asking "why didn't we do it that way?"

A `draft` or `review` SDD does NOT bind any implementation PR.
Only `accepted` SDDs are contracts.

## Linkage to the findings ledger

Every SDD section "Problem" cites the F-2026-NNN ids it closes.
When an SDD reaches `implemented`, the ledger should
back-reference the SDD id and the PR that landed it. This is
how Phase 2/3 closes the loop with Phase 1's surface area
discovery.

## Template

See `001-ai-machine-end-to-end.md` for the canonical template.
Recommended skeleton:

```
# SDD-NNN — <title>

> Status: draft
> Owner: ...
> Last updated: YYYY-MM-DD
> Closes findings: F-2026-NNN

## Problem
## Goals
## Non-goals
## Glossary
## Current state
## Design alternatives considered
### Alternative A — ...
### Alternative B — ...
### Alternative C — ...
## Recommended design
## Detailed design
## Test plan
## Rollout / migration
## Open questions
## Appendix
```

## What an SDD avoids

- Vendor advocacy ("we use foo because foo is great"). State
  the property foo gives you, name the alternatives, justify
  the trade-off.
- Code listings longer than a function. SDDs sketch
  interfaces; the implementation PR carries the code.
- Speculation past the immediate horizon. If the design has
  Phase 4 / Phase 5 implications, list them as "future work"
  and stop.
- Anything that should be a comment in code. If the rationale
  is one paragraph, it's an inline comment, not an SDD.

## Style

Same as the audit docs: tight paragraphs, file:line citations
where applicable, no emojis, no decorative section dividers,
no marketing language. Every claim either cites code or is
labelled as an open question.
