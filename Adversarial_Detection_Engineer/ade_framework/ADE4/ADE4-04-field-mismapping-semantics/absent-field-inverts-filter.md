---
id: ADE4-006
title: "Absent Field Inverts a Filter Clause"
ade_category: ADE4
ade_subcategory: ADE4-04
mitre_attack: N/A (logic/telemetry flaw, not an attack technique)
platform: Sigma / Splunk SPL / CrowdStrike LogScale (LQL) / Sumo Logic Cloud SIEM / SIEM (backend- and source-dependent)
testable: logic-analysis
---

# Absent Field Inverts a Filter Clause

## Summary

The dangerous cousin of the plain absent-field bug ([unavailable-field.md](unavailable-field.md)). When an absent field appears inside a **negated filter** — the `not filter` half of a `selection and not filter` rule — its `null` value doesn't merely zero the rule, it can *flip the rule's outcome*. Depending on how the backend evaluates `field != value` against a missing field, the exclusion either swallows every true positive (false negatives) or disables itself and floods the analyst (false positives). Either way the author's intent is inverted, and which way it breaks depends on the backend's null semantics — so the same Sigma source behaves differently across SIEMs.

## ADE Classification

**Category:** ADE4 — Logic Manipulation
**Subcategory:** ADE4-04 — Field Mismapping & Semantics
**Core principle:** `NOT (null == value)` is not the same across backends. Some evaluate a comparison against a missing field as `false` (so `not false → true`, exclusion never applies), some as `null`/unknown (three-valued logic drops the row), and some treat the absent field as a match. The rule author reasoned in two-valued Boolean logic; the backend runs three-valued logic over possibly-missing fields. This is where ADE4-04 (field semantics) meets ADE4-01 (gate inversion): the negation the author trusted is decided by null-handling, not by data.

## The Technique

### The pattern that breaks

```yaml
detection:
    selection:
        Image|endswith: '\rundll32.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'   # "ignore rundll32 launched by Explorer"
    condition: selection and not filter
```

Intent: alert on `rundll32.exe` *unless* its parent is `explorer.exe` (assumed benign). Now run it where `ParentImage` is **absent** — e.g. the event arrives without parent context, or a source/config that doesn't populate it (**#23**), or a backend that renamed it so the mapping resolves to `null`.

### Two inversion modes, by backend null-handling

| Backend evaluates `ParentImage|endswith '\explorer.exe'` on a missing field as… | `filter` | `not filter` | `selection and not filter` | Effect |
|---|---|---|---|---|
| `false` (no match on null) | false | **true** | fires whenever `selection` matches | Exclusion silently disabled → **false positives / noise**, analysts mute the rule |
| `null` → row dropped (three-valued) | null | null | **null → excluded** | Exclusion swallows everything → **false negatives**, rule never fires |
| absent treated as empty string that "matches" a broad pattern | true | false | never fires | **false negatives** |

The author validated the rule on Sysmon (parent populated, behaves as intended) and shipped it. On a segment where the field is absent, the *same YAML* inverts — and the direction differs per backend, so a multi-SIEM org gets both failure modes from one rule.

### Why an attacker cares

Where the flip yields false negatives, the attacker's job is done for them by the telemetry gap. Where the flip merely disables the exclusion, the resulting noise gets the rule tuned down or off — a slower path to the same blind spot. And an attacker who *can* influence the filtered field (poisoning `ParentImage`-adjacent context, or ensuring the event lacks parent context) is doing ADE4-01 gate inversion through the ADE4-04 door.

## Logic Analysis

**Vulnerable rule** (as above) — the exclusion depends on a field that may be absent.

**Hardened rule** — make the filter robust to a missing field so absence can never satisfy or void the exclusion:

```yaml
title: Suspicious rundll32 (Hardened)
status: test
logsource:
    category: process_creation
    product: windows
    service: sysmon                     # pin a source that populates ParentImage
detection:
    selection:
        Image|endswith: '\rundll32.exe'
    # Only exclude when the parent field is BOTH present AND the benign value.
    filter_benign_parent:
        ParentImage|endswith: '\explorer.exe'
    filter_parent_present:
        ParentImage|exists: true        # pySigma |exists guards the negation
    condition: selection and not (filter_benign_parent and filter_parent_present)
falsepositives:
    - rundll32 genuinely launched by explorer.exe (user double-click)
level: medium
```

Now the exclusion applies only when `ParentImage` is present *and* equals the benign value; a missing field can neither trigger nor void it. Backends without an `|exists` equivalent should express the same guard explicitly (e.g. `ParentImage != "" and ParentImage endswith ...`) in the transpiled query, or pin `service:` to a source that always populates the field.

**General rules for negated filters:**

1. Never negate a field that can be absent without also asserting its presence.
2. Pin `logsource.service` so the field's availability is known, not assumed.
3. Inspect the **transpiled** query's null-handling on each target backend — do not trust that `not filter` means what it reads.
4. Prefer excluding on stable, always-present fields (event ID, product-guaranteed fields) over optional ones.

## Other platforms — Splunk SPL

On Splunk the inversion is not backend-ambiguous, it is **documented and deterministic**, which makes it easy to audit and easy to get wrong. The two ways to write "not this value" differ precisely on the absent-field case:

> With `!=`, *"every event that has a value in the field, where that value does not match the value you specify, is returned. Events that do not have a value in the field are not included in the results."* With `NOT`, *"every event is returned except the events that contain the value you specify. This includes events that do not have a value in the field."* — [Difference between != and NOT](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/expressions-and-predicates/difference-between-and-not)

Replayed on Splunk Enterprise 10.4.2 with event A holding `fld="y"` and event B carrying no `fld` at all:

| Query | Keeps | Effect |
|---|---|---|
| `\| search fld!="x"` | A only | B is **silently dropped** — the exclusion became "…and the field must exist" |
| `\| search NOT fld="x"` | A and B | the author's actual intent |

So `field!="benign"` is two filters, one of which nobody wrote. Where the sourcetype, CIM mapping or sensor configuration leaves that field unpopulated, the whole event leaves the pipeline — a false negative on every event the exclusion was never meant to touch. An attacker who can suppress the field (an execution path that emits no parent context, a source whose add-on does not map it) escapes the *search*, not merely the exclusion.

Two related forms worth knowing: wildcards do work with `!=` (`fld!="*temp.dat*"` excludes as expected), but the bare `fld!=*` **returns no events at all**, while `NOT fld=*` is the correct way to ask for "field is null or undefined". Transpiled Sigma gets this right — `pySigma-backend-splunk` compiles `field: null` to `NOT {field}=*` — so the bug is almost always introduced by hand-written or hand-tuned SPL.

**Hardened form:** `| search NOT (parent_process_name="explorer.exe")`, plus an explicit `| where isnotnull(parent_process_name)` only where the field is genuinely required. Seen in *Clop Common Exec Parameter*. See [`bug_patterns/splunk.md`](../../../bug_patterns/splunk.md) #3.

## Other platforms — CrowdStrike LogScale (LQL)

LogScale is also deterministic, and it lands on the **opposite side** of Splunk: *"If a specified field is not present in an event, the comparison always fails unless it is `!=`"* ([Operators](https://library.humio.com/crowdstrike-query-language/syntax-operators.html)). So `FileName != "benign.exe"` **keeps** events with no `FileName` — the negation is the safe direction, with no undeclared presence test. The inversion moves to the *positive* side instead: every `=`, wildcard and numeric comparison silently also requires the field to exist, so a dead extraction or an unmapped source turns a selection clause into a drop-everything gate, and the rule reports quiet rather than broken. The same source rule therefore mis-breaks in *different directions* on the two platforms — Splunk's hand-written `!=` drops absent-field events, LogScale's `=` selections do — which is exactly the backend-dependence this file's Sigma section warns about, realized in two concrete engines. Presence is explicit in LQL when you want it: `field = *` asserts it, `field != *` selects its absence ([Field filters](https://library.humio.com/crowdstrike-query-language/syntax-filters.html)). *Doc-grounded, not replayed — there is no live LogScale tenant behind this file.*

**Hardened form:** keep exclusions as `!=`, assert `field = *` explicitly where a positive filter genuinely depends on the field, and monitor `field != *` volume per feed so extraction failure surfaces as a signal. See [`bug_patterns/logscale.md`](../../../bug_patterns/logscale.md) #3.

## Other platforms — Sumo Logic (Cloud SIEM rule expressions)

Sumo Logic supplies the third answer, and it is the uncomfortable one: **the question is not documented.** The positive side is settled and matches LogScale — the rule language's `=` returns *"false if either expression is null"*, and the reference's worked examples run the same way throughout (`null = "foo"`, `null < 10`, `10 > null`, `null >= 10` and `null IN (...)` all return false), so every positive filter is silently also a presence test ([Cloud SIEM Rules Syntax](https://www.sumologic.com/help/docs/cse/rules/cse-rules-syntax/)). But `!=` on an absent field — the exact operator Splunk and LogScale both document, in opposite directions — is stated nowhere. The inference "null collapses to false, so `!=` is false too" is *not* safe here, because the same reference shows the product does not collapse null uniformly: `like` propagates it instead, where *"If `pattern` or `escape_character` is null, the expression evaluates to null"*. An exclusion clause on this platform therefore has an unknown treatment of absence until someone tests it on a tenant, and the two neighbouring platforms prove both answers are plausible implementations. Separately, absence has a second cause unique to Cloud SIEM: rules read **normalized** records, so a field this tenant's log mapping never populated is absent no matter what the raw log contained. *Doc-grounded, not replayed, and partly a documentation gap — there is no live Sumo Logic tenant behind this file.*

**Hardened form:** write the intent explicitly rather than inheriting a default — `isNull(field) || field != "benign.exe"` to keep absent-field records, `!isNull(field) && field != "benign.exe"` to require the field — and assert `!isNull(field)` wherever a positive filter genuinely depends on one. Confirm the mapping populates the field for *this* source before trusting either form. See [`bug_patterns/sumologic.md`](../../../bug_patterns/sumologic.md) #5 and #6.

## Detection Layers (auditing the rule, not an attack)

| Audit method | Catches? | How |
|---|---|---|
| Truth-table over `{field present, field absent} × backend null-semantics` | Yes | Enumerate all four rows above for each target SIEM |
| Field-population probe on the filtered field | Yes | If `ParentImage` is ever `null` on a target segment, the negation is at risk |
| Transpiled-query null-handling review | Yes | Read how the backend compiles `not (field endswith …)` for a missing field |
| `|exists` / presence guard on every negated optional field | Prevents | Absence can no longer flip the outcome |
| Pin `service:` + collection requirement | Prevents | Removes the availability ambiguity |
| A/B replay: benign-parent event AND parent-absent event | Yes | Confirms the rule fires on the malicious case and suppresses only the intended benign one |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) **#23** (Sysmon config decides whether `ParentImage` and friends are emitted) and **#14** (source-dependent field availability for command-line/parent context).
- This technique is the intersection of [ADE4-01 Gate Inversion](../ADE4-01-gate-inversion/gate-inversion.md) (negation on manipulable/absent input) and ADE4-04 (field semantics); cross-reference both when auditing exclusion-heavy rules.
- Full field catalog: [`bug_patterns/sigma_field_semantics.md`](../../../bug_patterns/sigma_field_semantics.md).
- Three-valued logic (`true`/`false`/`null`) is the root cause: authors reason in two-valued Boolean, backends run SQL-style three-valued logic where `null` propagates. `NOT null = null`, not `true`.
- The failure is backend-divergent: a rule can be correct on Splunk (PCRE, null→false) and inverted on an Elastic/RE2 pipeline that drops null rows. Validate per backend, not once.

## References

- [SigmaHQ — Conditions and the `exists` modifier](https://sigmahq.io/docs/basics/modifiers.html)
- [SigmaHQ — Writing rules & filters](https://sigmahq.io/docs/basics/rules.html)
- [Three-valued logic and NULL comparison (SQL semantics)](https://en.wikipedia.org/wiki/Three-valued_logic)
