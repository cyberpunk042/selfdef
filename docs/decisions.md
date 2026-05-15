# Decisions log

Chronological audit trail of design-question resolutions. Each `D-NNN`
entry corresponds to an answered question from one of the SDDs (or a
similar source doc — handoff, audit ledger, RFC). Entries are
append-only — never edit a past entry; if a decision is revisited,
append a new entry that references the prior one.

Driven by the `/questions` skill — when the operator answers an open
question, the SDD's `Q-X` row is annotated **in place** with
`**answered (D-NNN, YYYY-MM-DD)**` and a new entry is appended here.
The two artifacts together form the audit trail: the SDD stays the
canonical source of truth; this log gives the chronological view.

## Format (per entry)

```markdown
## D-NNN — YYYY-MM-DD — <one-line summary>

**Decision**: <what was decided — operator-verbatim if free-text>
**Question**: <full question, copied from source doc>
**Source**: `docs/sdd/<n>-<title>.md`:<line> (Q-X row)
**Rationale**: <why this option beats the alternatives — synthesis +
                any operator commentary>
**Affected items**: <files / future SDDs / impl crates touched>
**Reversibility**: fully-reversible | partial | locked
**Linked**: PR #<n>
```

`Reversibility` legend:

- **fully-reversible** — the decision can be revisited at any time with
  no migration cost. Most design choices land here.
- **partial** — revisiting requires some refactor / migration but no
  data loss or compat break.
- **locked** — revisiting requires a breaking change (data migration,
  protocol break, deprecation cycle).

## Cross-references

- `/questions` skill: `.claude/skills/questions/SKILL.md`
- `/view` orientation: `.claude/skills/view/SKILL.md`
- SDD index: `docs/sdd/000-charter.md` + `001`..`008`
- Audit programme ledgers: `docs/review/phase-*/99-findings-ledger.md`

---

## Entries

_(none yet — the log starts when the first `/questions answer` runs)_
