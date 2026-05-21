# SDD-023 — Cross-repo model-taxonomy mirror doctrine

> Status: **implemented** — codifies the SD-R71 ↔ sovereign-os R212
> lockstep cadence as standing doctrine for the model-class taxonomy;
> shipped:
>  - `selfdefctl models list` surfaces the R212 model-class taxonomy
>    (class, size_class, quantization/weight_format) — operator-
>    readable registry in lockstep with sovereign-os catalog
>  - SD-R34 registry layout `<dir>/<slug>/model.toml` enforced
>  - Cross-repo schema 1.1.0 (sovereign-os R212) honored
>  - Surface pinned by integration test
>    `crates/selfdef-cli/tests/cli_models_taxonomy.rs` — a future
>    round can't silently regress the taxonomy projection
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21 (status: review → implemented).
> Builds on: SDD-022 (hardware-exploit doctrine — same 5-layer
> pattern for hw rollups); sovereign-os R212 (schema 1.1.0); SD-R71
> (registry mirror); R213/R214/R215/R216 (sovereign-os consumers
> of the rich taxonomy).
> Closes findings: none (pattern codification, no F-findings).

## Mission

Codify the lockstep cadence between the selfdef model-registry
surface and the sovereign-os model-catalog surface so the operator
sees a SINGLE TAXONOMY across both CLIs — never two divergent
spellings of "what kind of model is this?".

## Problem

The R212 expansion (sovereign-os main) added a 12-value model
class enum (llm / slm / rlm / ternary-lm / lora-adapter / embed /
vision / multimodal / code / mixture / speculative / reranker)
plus quantization / size_class / purpose / vram_gib_min /
context_window_tokens / base_model. selfdef's SD-R34 model registry
had only `weight_format` — operators couldn't see which model class
their selfdef-side registry entries belonged to.

SD-R71 added the taxonomy mirror on the selfdef side. Without
doctrine, the two surfaces will drift:

- sovereign-os adds a `class=ensemble` value → selfdef registry
  silently accepts a typo `class="ensamble"` because selfdef is
  permissive
- operator uses `--class rlm` on sovereign-os, `weight_format=fp16`
  on selfdef → no link between the two surfaces in their head
- a new operator-facing surface (e.g. wizard "what model do you
  want?") asks the taxonomy question twice differently

SDD-023 closes this gap by making the cadence explicit.

## Required coverage

For every R212-class taxonomy field, ALL of the following must hold:

1. **Sovereign-os is the strict source.**
   `schemas/model-catalog.schema.yaml` uses JSON Schema `enum`
   constraints to enforce the closed value set. CI gates the
   catalog against the schema at L1.

2. **Selfdef-side mirror is permissive (free-string).**
   The selfdef ModelSpec uses `#[serde(default)]` String/Vec<String>
   fields. Pre-mirror registries deserialize cleanly; operators can
   author new entries with operator-meaningful values WITHOUT
   needing the strict enum check in their per-host registry.

3. **Surfaces use the same field NAMES.**
   `class`, `quantization`, `size_class`, `purpose`, `vram_gib_min`,
   `context_window_tokens`, `base_model` — same names on both sides
   so operators reading either YAML/TOML see the same vocabulary.

4. **Doc strings reference the cross-repo source on each side.**
   selfdef ModelSpec docstring cites "R212 (sovereign-os catalog
   schema 1.1.0)"; sovereign-os catalog schema docstring cites
   "SD-R71 selfdef-cli mirror".

5. **The operator surface command set is mirrored.**
   - sovereign-os: `models list` / `models query` / `models suggest`
   - selfdef:      `models list` shows the same columns
   Future taxonomy verbs land on BOTH sides in the same round.

6. **Test pins enforce the mirror.**
   - L1 lint on sovereign-os: every catalog entry declares the full
     taxonomy (R212 test_r212_*)
   - L2 integration on selfdef: cmd_list surfaces the new columns
     (SD-R71 cli_models_taxonomy.rs)
   - Both fail-CI if a field name drifts.

## Goals

- ONE vocabulary across selfdef + sovereign-os for "what kind of
  model is this?". Operators read either repo and find the same
  field names + value sets.
- Selfdef registries stay PERMISSIVE so operators can ship local
  experimental classes (a private "fine-tuned-internal" class)
  without forking the sovereign-os schema.
- The cross-repo lockstep is OBSERVABLE: when sovereign-os bumps
  the schema, R189 lockstep fixture + L1 lint changes are part of
  the same arc.
- Future surfaces (router-by-class, model-aware audit, dashboards)
  inherit the taxonomy automatically because they read either
  YAML/TOML through the canonical fields.

## Non-goals

- We do NOT enforce closed-set validation on the selfdef side.
  The whole point of selfdef as the per-host system is operator
  flexibility; sovereign-os is the strict authority because it's
  the FLEET catalog.
- We do NOT auto-rename old `weight_format` to `quantization` on
  selfdef. Both fields coexist; weight_format stays for backward
  compat. Pre-mirror operator registries deserialize cleanly.
- We do NOT generate selfdef registries from sovereign-os catalog
  entries. Operators own their per-host registry; the catalog is
  the SUGGESTION, not the SOURCE.
- We do NOT require every selfdef registry to declare every
  taxonomy field. Missing fields render as "?" in `models list`
  output; operators see the gap explicitly and can fill it on
  their schedule.

## Reference implementation (R212 + SD-R71 + R213-R217 + R209-R211)

| Layer | Sovereign-os | Selfdef |
|-------|--------------|---------|
| Schema (strict) | `schemas/model-catalog.schema.yaml` 1.1.0 | n/a (permissive) |
| Instance | `models/catalog.yaml` — 17 curated entries | `/etc/selfdef/models/<slug>/model.toml` (per-host) |
| Struct | n/a (YAML → dict) | `crates/selfdef-cli/src/models.rs::ModelSpec` |
| Loader | direct YAML read | `models::load_all` (toml::from_str) |
| Renderer | `scripts/models/render-catalog-md.py` (SDD-028) | `selfdefctl models list` table |
| Operator query | `sovereign-osctl models query` (R213) | `selfdefctl models list` (R71 columns) |
| Operator suggest | `sovereign-osctl models suggest` (R214 + R216) | (deferred — sovereign-os has the rich catalog) |
| Layer B | `sovereign_os_inference_router_class_total{class}` (R215) | (consumes; doesn't emit class metrics) |
| Cross-doc | `docs/src/model-catalog.md` (auto-rendered) | n/a |
| Lint pins | `tests/schema/test_model_catalog_schema_conformance.py` (R212 fields) | `tests/cli_models_taxonomy.rs` (SD-R71 columns) |

## Future candidate extensions

When the operator pulls a new taxonomy field:

1. **Sovereign-os schemas/ first** — add the enum + the lint pin in
   `tests/schema/test_model_catalog_schema_conformance.py`.
2. **Sovereign-os catalog entries next** — populate the new field
   on all 17 (or grown) entries.
3. **Sovereign-os renderer + suggester next** — surface the new
   field in `render-catalog-md.py` and (where applicable)
   `suggest-by-profile.py`.
4. **Selfdef ModelSpec mirror** — add the same field name as
   `#[serde(default)]` Option<String>/Vec<String>; update cmd_list
   columns where operator-relevant; add a cli_models_taxonomy.rs
   test pinning the new column.
5. **Doc cross-references** — each side cites the other in field
   docstrings.

Same round, same operator-meaningful framing. The arc never
closes; the SDDs do.

## Cross-references

- SDD-022 — hardware-exploitation doctrine (same 5-layer pattern;
  this SDD is its cross-repo sibling for the model-class surface)
- sovereign-os R212 (catalog schema 1.1.0 + rich entries)
- SD-R71 (selfdef ModelSpec taxonomy mirror)
- sovereign-os R213 (`models query` filter verb)
- sovereign-os R214 + R216 (`models suggest` super-feature)
- sovereign-os R215 (router class metric + X-Sovereign-Model-Class header)
- sovereign-os R217 (overview surfaces R214 suggester)
- SD-R72 (`slm-cpu-loop` module — first dogfooder of the cross-repo taxonomy)
