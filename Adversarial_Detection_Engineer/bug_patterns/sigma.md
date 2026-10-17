# Sigma — Detection-Logic Bug Patterns

Platform-specific pitfalls for Sigma rules (`SigmaHQ/sigma`, generic YAML) and their transpilation. Sigma is backend-agnostic, so its bugs live in two places: the rule's own logic, and the **transpilation** to a concrete SIEM. Pair with [`sigma_field_semantics.md`](sigma_field_semantics.md) (field naming/modifier catalog) and [`logging_assumption_errors.md`](logging_assumption_errors.md).

## Detection-block Boolean semantics (the #1 authoring bug — ADE4)

Sigma's YAML has implicit Boolean structure that many authors misread:

```yaml
detection:
  selection:
    Image|endswith:            # a LIST under a key = OR
      - '\curl.exe'
      - '\wget.exe'
    CommandLine|contains: 'http'  # separate KEY in the same map = AND
  condition: selection
```

- **List under a key → OR.** Values are alternatives.
- **Multiple keys in a map → AND.** All must match the *same* event.
- Putting alternatives as separate keys accidentally requires all of them (`CommandLine|contains: 'curl'` AND `CommandLine|contains: 'wget'` almost never fires — real bug, *Suspicious Shell Script Detected*, ADE4-03).
- Use `1 of selection_*` / `all of selection_*` and an explicit `condition` to state intent. See [ADE4-03 AND-vs-OR](../ade_framework/ADE4/ADE4-03-incorrect-expression/and-vs-or-confusion.md).

## `logsource` binds the sensor (ADE2-01/2-02, ADE4-04)

`logsource: {product, category, service}` decides which telemetry the rule compiles against. Pitfalls:
- `category: process_creation` maps to Sysmon EID 1 **or** Security 4688 depending on the backend pipeline; field availability differs (`OriginalFileName` is Sysmon-only; 4688 command-line auditing is off by default). Pin `service: sysmon` when you depend on a Sysmon-only field. See [logging_assumption_errors #14/#23](logging_assumption_errors.md).
- A rule bound to one `service`/`product` silently covers only that source.

## Modifiers and their blind spots

| Modifier | Behavior | Blind spot |
|---|---|---|
| `\|contains` | substring | over-matches (`-enc` matches `-encoding`); still literal — breaks on reformatting (ADE1) |
| `\|startswith`/`\|endswith` | anchored | misses trailing space/dot, `.bak`, short names |
| `\|all` | AND across a list | fragmentable — split indicators across events (ADE3-04) |
| `\|base64offset\|contains` | encoded match | misses other encodings/utf16 if omitted |
| `\|windash` | normalizes `-`/`/` | only the prefix half of parameter obfuscation |
| `\|re` | regex | **flavor varies by backend** (see below) |
| `\|cidr` | IP range | none, but only where the field is a clean IP |
| `\|exists` | field presence | use it to guard negated filters (ADE4-04) |

## Transpilation bugs (the Sigma-specific class)

A Sigma rule that reads correctly can **behave differently or fail to compile** per backend:

1. **Regex flavor (`|re`).** Splunk = PCRE (lookaround OK); Elasticsearch = Lucene regex (no lookaround); Sentinel KQL, Google SecOps YARA-L = RE2 (no lookaround/backrefs); CrowdStrike LogScale = JitRex, documented only as *"very similar"* to Perl/JavaScript/re2 syntax ([Regex syntax](https://library.humio.com/crowdstrike-query-language/syntax-regex.html)), so verify lookaround per construct rather than assuming either answer. Sumo Logic is **two flavors in one product** — `matches` takes RE2 while `rlike` takes a *"Java regular expression"* ([Cloud SIEM Rules Syntax](https://www.sumologic.com/help/docs/cse/rules/cse-rules-syntax/)) — so the answer depends on which operator the backend chose, not on the platform. A `|re` using lookbehind silently fails to transpile or matches nothing on RE2 backends — a zero-coverage gap. See [logging_assumption_errors #5](logging_assumption_errors.md).
2. **Field mapping.** The backend pipeline (pySigma processing pipeline) maps Sigma field names to concrete columns. An unmapped field can resolve to *nothing* rather than erroring — `CommandLine` → `Process Command Line` (4688), `process.command_line` (ECS), etc. See [ADE4-04 field mismatch](../ade_framework/ADE4/ADE4-04-field-mismapping-semantics/field-name-mismatch.md).
3. **Case sensitivity.** Sigma is case-insensitive in spec, but the compiled query may be case-sensitive on the target store; a `contains` becomes a case-sensitive substring on some backends.
4. **Null-handling in `not filter`.** `condition: selection and not filter` inverts differently across backends when `filter`'s field is absent (three-valued logic) — false negatives on one SIEM, false positives on another. See [ADE4-04 absent-field inversion](../ade_framework/ADE4/ADE4-04-field-mismapping-semantics/absent-field-inverts-filter.md).

**Always inspect the transpiled query**, not just the Sigma source; a rule that fails to transpile is silent zero coverage.

### Backend notes — Splunk (`pySigma-backend-splunk` @ `d036264`)

Read from the backend source rather than inferred. The emitted SPL is a base `search`, which is the *favorable* position for three of the four hazards above — and that is exactly why editing it afterwards is dangerous.

- **Null handling is correct, and better than hand-written SPL.** `field_null_expression` compiles Sigma's `field: null` to `NOT {field}=*`, which is the form that actually matches absent fields; the intuitive hand-written `field!=*` returns no events at all ([Difference between != and NOT](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/expressions-and-predicates/difference-between-and-not)). Any `not filter` you hand-translate into `!=` re-introduces the three-valued-logic bug the backend avoided.
- **Precedence is carried, not normalized.** `and_token` is a bare space and `or_token` is `OR`, so the compiled condition inherits the search command's precedence (OR binds tighter than AND — the inverse of `where`/eval). The backend guards its own optimizations with a `_has_top_level_or` check so hoisting a term never pulls it out of a disjunction, but **a human who moves a clause from the base search into a `| where` silently flips the grouping.** Parenthesize before editing.
- **Case survives only while the clause stays in the base search.** Sigma is case-insensitive by spec and a Splunk base search compares field values case-insensitively, so intent is preserved — but the same predicate relocated to `where`/`like()`/`match()` becomes case-sensitive, and `in_expressions_allow_wildcards` means a compiled `IN (...)` list changes case behavior with it.
- **`|re` passes through verbatim** (`re_expression` is `{regex}`), and Splunk is PCRE, so lookaround does survive here — unlike the RE2 and Lucene backends in #1. A pattern with no `(?i)` is still case-sensitive.
- **Field quoting:** names outside `^[\w.]+$` are quoted; a CIM field reached through a data model still needs the right pipeline, or it resolves to nothing (ADE4-04).

See [`splunk.md`](splunk.md) for the native-SPL catalog these notes point into.

### Backend notes — LogScale (`fx2301/pySigma-backend-logscale` @ `dfa7f69`)

Read from the backend source. Unlike the Splunk backend, this one is **community-maintained by a single author, not SigmaHQ or CrowdStrike** — zero stars, last commit 2023-12-12 — and the source still carries the pySigma cookiecutter's scaffolding comments (*"TODO: change the token definitions according to the syntax"*, a `FIXME` on the pipeline import). Treat its output as a draft to verify, not a supported conversion path.

- **Sigma's case-insensitivity is silently lost.** `eq_token` is `=`, so every plain Sigma match compiles to LogScale's exact, case-sensitive `=` ([Operators](https://library.humio.com/crowdstrike-query-language/syntax-operators.html)) — the unfavorable mirror of the Splunk backend, where the base search preserved the spec's intent. Every converted rule whose value can vary in case needs a hand-added `/i` regex or `ignoreCase=true` rewrite.
- **No field mapping exists.** `requires_pipeline` is `False` and no processing pipeline ships, so Sigma field names (`CommandLine`, `Image`, `TargetFilename`) pass through unmapped. Where that coincides with a Falcon field name it works by luck; everywhere else the compiled query filters a field that is never populated — and in LQL a comparison on an absent field always fails, so the rule returns nothing rather than erroring (ADE4-04).
- **Several emitted tokens look like template defaults, not LQL.** The source emits `{field} startswith {value}`, a `casematch` expression family, `{field} is null`, and `exists({field})`/`notexists({field})` — none of which appears in the CQL filter or operator syntax documentation. A Sigma rule exercising those constructs (`startswith`/`endswith` modifiers, `field: null`, `|exists`) compiles to a query LogScale may refuse to parse. Wildcards, by contrast, survive correctly (`contains` → `field = "*value*"`, which is native LQL).
- **Regex flags are prepended inline** (`re_flag_prefix = True` → `(?i)` inside the pattern) rather than LQL's documented trailing `/i` ([Regex flags](https://library.humio.com/crowdstrike-query-language/syntax-regex-flags.html)). Verify the inline form on your version before trusting a flagged `|re`.
- **Operational consequence:** test-compile *and execute* every converted rule on a live view. A conversion that parses is not yet a conversion that matches — and one that fails to parse is at least loudly broken, which in this backend's state is the better failure mode.

See [`logscale.md`](logscale.md) for the native-LQL catalog these notes point into.

### Backend notes — Sumo Logic (`SumoLogic/pySigma-backend-sumologic` @ `b328a74`)

Read from the backend source. Unlike the LogScale backend, this one is **vendor-owned and current** — it sits in the `SumoLogic` GitHub org, was last pushed 2026-08-24, and ships real processing pipelines (schema loader, vendor/product mapping, entity classification, a confidence gate that refuses low-confidence conversions). It targets **Cloud SIEM rule expressions**, not Log Search. Treat it as a maintained path whose two sharpest edges are nonetheless unguarded.

- **Sigma's case-insensitivity is silently lost on every plain string match.** `startswith_expression`, `endswith_expression`, `contains_expression` and `wildcard_match_expression` all compile to `{field} matches /.../` with no flag, and Sumo Logic's `matches` is *"case-sensitive"* ([matches](https://www.sumologic.com/help/docs/search/search-query-language/search-operators/matches/)) — the same unfavorable outcome as the LogScale backend, reached through a different operator. The `i` flag *is* mapped (`re_flags`), so it reaches the output only for a `|re` whose Sigma rule carries an explicit ignorecase flag; the spec's default case-insensitivity for ordinary values does not.
- **Absence and emptiness are conflated.** `field_null_expression`, `field_exists_expression` and `field_not_exists_expression` all compile to `isEmpty({field})` / `!isEmpty({field})`, and the rule language documents `isEmpty` as testing whether *"the string contains no characters or whitespace"* — a different question from `isNull`, documented separately as testing whether *"a string is null"* ([Cloud SIEM Rules Syntax](https://www.sumologic.com/help/docs/cse/rules/cse-rules-syntax/)). So Sigma's `field: null`, which means *the field does not exist*, compiles to an empty-string test, and `|exists` compiles to its negation. The backend's own test suite contains **no case covering either construct**, so the emitted form has not been exercised against a tenant upstream either. Hand-verify any converted rule using `field: null`, `|exists`, or `condition: selection and not filter` where the filter's field can be absent.
- **Regex flags are appended, into an undocumented form.** `re_flag_prefix = False` with the source comment *"CSE doesn't use flag prefixes in regex"* means a flagged `|re` emits `field matches /pattern/i`. The `matches` reference documents only `/.../` and wildcard forms and never a trailing flag, so even the flagged path is unverified — the mirror of the LogScale backend's inline-`(?i)` problem, in the other direction.
- **Operational consequence:** the confidence gate makes this backend fail loudly on rules it cannot map well, which is the good failure mode — but the two silent edges above are *successful* conversions that mean something narrower than the rule did. Read the emitted expression for case and for null before deploying.

See [`sumologic.md`](sumologic.md) for the native catalog these notes point into.

## Field-name typos and normalization (ADE4-04)

Exact-spelling matters and fails silently: Sigma uses `TargetFilename` (lowercase `n`), `OriginalFileName`, `ParentImage`. `Commandline`/`command_line`/`TargetFileName` typos resolve to no column on case/spelling-sensitive backends. Prefer the taxonomy's canonical names and let the pipeline map them. Full catalog: [`sigma_field_semantics.md`](sigma_field_semantics.md).

## Literal-string fragility (ADE1)

Because Sigma is largely `contains`/`endswith` on raw fields, it inherits every ADE1 reformatting bypass (carets, quotes, ticks, whitespace, env-var splicing, short names) — Sysmon logs the command line *raw*, so obfuscation survives to match time. Anchor on `OriginalFileName`/behavior and add `|windash`/`|base64offset` where relevant. See [ADE1](../ade_framework/ADE1/overview.md) and [`cmdline_obfuscation.md`](cmdline_obfuscation.md).

## IOC / hash rules and threat-intel specificity (ADE1-01, ADE2-02)

Many Sigma rules encode a point-in-time indicator (a specific filename like `ebpfbackdoor`, a hash, a fixed path). Renaming the file or recompiling defeats them (DLE-2026-00003, *Triple Cross rootkit*). Treat these as IOC rules, not behavioral coverage; generalize to the behavior (persistence dir + content) where possible.

## Correlation rules (newer Sigma spec)

Sigma correlation (`type: event_count | value_count | temporal | temporal_ordered`) adds aggregation/timing — and with it ADE3 exposure: `timespan` windows (ADE3-03 straddle/slow), `group-by` fields that are attacker-controllable (ADE3-02). Apply the same window/aggregation scrutiny as native SIEM rules.

## Quick audit checklist for a Sigma rule

- Are alternatives ORed (list) not accidentally ANDed (separate keys)? Check `condition`.
- Is `logsource` pinned to a source that actually has the fields used?
- Does `|re` use lookaround that won't survive RE2/Lucene backends?
- Read the **transpiled** query for your backend — field mapped? case? null-handling of `not filter`?
- Field names spelled to the canonical taxonomy (`TargetFilename`, `OriginalFileName`)?
- Is it a literal-substring/IOC rule that ADE1 reformatting or a rename defeats?

## References
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) · [Sigma specification](https://github.com/SigmaHQ/sigma-specification) · [Conditions](https://sigmahq.io/docs/basics/conditions.html) · [Modifiers](https://sigmahq.io/docs/basics/modifiers.html) · [pySigma pipelines](https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html)
