# CrowdStrike Falcon LogScale — Detection-Logic Bug Patterns

Platform-specific pitfalls for CrowdStrike Falcon LogScale / Next-Gen SIEM queries (CrowdStrike Query Language, CQL/LQL) and the Falcon sensor telemetry they run over. LQL's distinctive hazard is **strictness that fails silent**: equality is exact and case-sensitive, a comparison on an absent field simply fails, a `case`/`match` ladder drops whatever it cannot label, and the aggregation operators truncate at documented limits without raising an error. Each behavior is individually documented; together they mean a rule that looks like a filter is often also an undeclared field-presence test, a case test, and a volume ceiling. Pair with [`logging_assumption_errors.md`](logging_assumption_errors.md) and, for transpiled rules, [`sigma.md`](sigma.md).

> **Verification footing.** There is no live LogScale tenant behind this file, so nothing here is replayed — a weaker footing than [`splunk.md`](splunk.md), stated rather than hidden. Every semantic claim is quoted from CrowdStrike's own CQL documentation at [library.humio.com](https://library.humio.com/crowdstrike-query-language/), and `Seen in:` names real queries at [`CrowdStrike/logscale-community-content`](https://github.com/CrowdStrike/logscale-community-content) @ `0152b8a` (2026-09-15) whose defects were confirmed by reading the query source — the same 12 findings recorded in [`total_candidate_bugs.md`](../../total_candidate_bugs.md). If you have a tenant, each claim is a one-event test away from being your own.

## Content shapes and where each one breaks

| Shape | Where it lives | Primary exposure |
|---|---|---|
| Hunting queries | `Queries-Only/` | ADE1 literal matching (no alert contract — an analyst must run them) |
| NG-SIEM scheduled alerts | `Next-Gen-SIEM/`, vendor packs under `Log-Sources/` | ADE3 windows and thresholds, ADE3-06 limits (truncation on a schedule is permanent) |
| Correlations via `join()`/`selfJoinFilter()` | both | ADE3-06 subquery limits, ADE4-04 join-key semantics |
| Classification ladders (`case`/`match`) | both | ADE4-01 unmatched events dropped |

## 1. Bare `=` is exact and case-sensitive (ADE1-01)

A field filter compares the entire value, case-sensitively: *"Field is equal to the entire declared string"*, and the operator reference marks string comparison case-sensitive ([Operators](https://library.humio.com/crowdstrike-query-language/syntax-operators.html)). There is no analogue of Splunk's case-insensitive base search — the forgiving position does not exist in LQL. Falcon records command lines and file names as the OS supplied them, so `ParentBaseFileName=powershell.exe` misses `Powershell.exe`, misses a renamed copy, and misses `pwsh.exe` entirely.

Seen in: *[T1059.001] NSLookup Remote Payload - Win* (`ParentBaseFileName=powershell.exe` — exact, case-sensitive, single binary; any other parent, including PowerShell 7's renamed `pwsh.exe`, is out of reach).

**Mitigation:** compare attacker-influenced text with a case-insensitive regex alternation (`ParentBaseFileName=/^(powershell|pwsh)\.exe$/i`) or `in(field, values=[...], ignoreCase=true)`; reserve bare `=` for machine-generated values whose case cannot vary (`#event_simpleName`, event IDs). See [ADE1-01](../ade_framework/ADE1/ADE1-01-substring-manipulation/README.md).

## 2. A regex without `/i` is a case test you didn't mean to write (ADE1-01)

Regex matching is case-sensitive until the pattern carries the `i` flag — *"case-insensitive searching, matching values regardless of the case of the characters"* ([Regex flags](https://library.humio.com/crowdstrike-query-language/syntax-regex-flags.html)). The same applies to `in()`, whose `ignoreCase` parameter defaults to `false` ([`in()`](https://library.humio.com/crowdstrike-query-language/functions-in.html)). The engine is **JitRex** — *"based on the JitRex regular expression engine which was part of the Jint programming language"*, with syntax *"very similar... to Perl, JavaScript or Google's re2 engine"* ([Regex syntax](https://library.humio.com/crowdstrike-query-language/syntax-regex.html)) — so patterns ported from a PCRE or RE2 source need re-verification, not just re-pasting.

Seen in: *[T1059.001] NSLookup Remote Payload - Win* (`CommandLine=/.*\s+\-q\=txt\s+.*/` has no `/i`, and the spelling Microsoft documents is upper-case `TXT` — the rule misses the documented form).

**Mitigation:** treat `/i` as mandatory on every regex over attacker-supplied content (command lines, paths, folder names, URIs); leave it off only where the value is machine-cased by construction.

## 3. A comparison on an absent field always fails — except `!=`, which matches (ADE4-04, ADE4-01)

Documented in one sentence: *"If a specified field is not present in an event, the comparison always fails unless it is `!=`"* ([Operators](https://library.humio.com/crowdstrike-query-language/syntax-operators.html)). This is the **mirror image of Splunk**, where `!=` is the operator that drops absent-field events. In LQL the negation is the safe direction — `FileName!=benign.exe` keeps events with no `FileName` — but every *positive* filter is silently also a presence test. A field extraction that stops matching (a `regex()` capture that no longer fits the format, a parser change upstream) leaves the field absent, and from then on every `=`, wildcard and numeric comparison in the rule fails without an error: the rule reports quiet, not broken. Presence itself is testable — `field = *` matches events that have the field, `field != *` matches events that do not ([Field filters](https://library.humio.com/crowdstrike-query-language/syntax-filters.html)).

**Mitigation:** for fields the rule genuinely requires, assert presence explicitly (`field = *`) so the dependency is visible and auditable; monitor extraction health separately (count `field != *` over the feed) so a dead parser is distinguishable from an absence of attacks. See [ADE4-04 absent-field inversion](../ade_framework/ADE4/ADE4-04-field-mismapping-semantics/absent-field-inverts-filter.md).

## 4. `case` and `match` ladders drop what they cannot label (ADE4-01)

*"If no clauses match, then the events are dropped"* (case), and *"Without a wildcard clause, any events that do not match any of the explicit clauses will be dropped"* (match) ([Conditional evaluation](https://library.humio.com/crowdstrike-query-language/syntax-conditional.html)). A classification ladder is therefore also a filter: any event whose shape drifts from the enumerated clauses — a new sensor version's field spelling, an unanticipated value, a casing difference feeding #1 — exits the pipeline at the ladder, before the detection logic it was written to feed. The documented escape is a wildcard clause (`* => *`).

**Mitigation:** end every `case`/`match` with a wildcard clause that assigns an explicit `"other"` label, keep those events flowing, and alert on the volume of the `"other"` bucket — drift then surfaces as a signal instead of a silent coverage loss. See [ADE4-01 gate inversion](../ade_framework/ADE4/ADE4-01-gate-inversion/gate-inversion.md).

## 5. `groupBy()` keeps the top-N by value — rarity ranks last (ADE3-06)

`groupBy()` defaults to 20,000 groups (`GroupDefaultLimit`; ceiling `GroupMaxLimit`, 1,000,000 by default since 1.127), and above the limit it *"may return incomplete results limited to a restricted subset of groups"*, retained by aggregate output: *"The selection is based on the aggregate numerical output across all specified functions and all time buckets, not the series identifiers themselves"*, with `count` becoming *"a lower bound estimate"* ([`groupBy()`](https://library.humio.com/crowdstrike-query-language/functions-groupby.html)). Hunting queries that gate on rarity (`test(uniqueEndpoints<5)`) are the worst case: the groups the gate selects *for* are exactly the groups the limit evicts *first*.

Seen in: *Hunt PBD File Paths in Reflective .net Module Loads* (no `limit`, three rarity gates downstream of a value-ranked 20,000-group cap), and the Tausight ePHI vendor pack, where `groupBy([UserName], ..., limit=10)` with a `Files>=1` threshold makes the alert unreachable for anyone outside the ten heaviest users in the window — four sibling alerts carry the same construct.

**Mitigation:** set `limit=max` on any `groupBy()` feeding a threshold or rarity gate; reduce key cardinality upstream so the group count stays inside the ceiling; never leave a group limit numerically close to the alert threshold.

## 6. `join()` truncates its subquery and keeps one row per key (ADE3-06)

Two independent defaults bite in the same call: the subquery `limit` defaults to 100,000 rows with a documented maximum of 200,000 — past which rows are silently dropped — and `max` defaults to `1`: *"If a subquery has multiple events with the same join key, then up to max rows are emitted"* ([`join()`](https://library.humio.com/crowdstrike-query-language/functions-join.html)). A subquery over a high-volume Falcon event type (`DnsRequest`, `NetworkListenIP4`) across an estate-wide window saturates the cap, and `max=1` collapses one-process-many-events patterns — often the very pattern the rule exists to reveal.

Seen in: *Process Events - DNS Requests From Processes* (every `DnsRequest` in 7 days at the 200,000 hard ceiling, `max` unset), *Process Events - Identify Low Port Bindings* (same shape over listeners), *Firewall Rule Additions* (default 100,000, one `FirewallSetRule` kept per process).

**Mitigation:** invert the correlation so the *selective* set is the subquery and the high-volume stream is primary; narrow the subquery toward the rule's intent; set `max=` to the number of correlated events worth keeping; for same-stream correlation prefer `selfJoinFilter()` with `groupBy()` and `collect()`, which retains every matching event per key.

## 7. Falcon process IDs are sensor-scoped — join on `[aid, pid]`, never `pid` alone (ADE4-04)

`TargetProcessId`/`ContextProcessId` are unique per sensor, not per estate, so a `join()` keyed on the process ID alone can pair events from different hosts. In `mode=inner` the collision usually yields a wrong attribution or a false positive — the primary event still passes — but it becomes a **false negative** wherever a later stage filters on a field taken from the subquery: the wrong host's value fails the filter and the genuine event is dropped. CrowdStrike's own content shows the correct form — the ISO/IMG and ProxyNotShell queries join on `field=[aid, TargetProcessId], key=[aid, ContextProcessId]`.

Seen in: *Process Events - DNS Requests From Processes* (post-join `DomainName` filters) and *Process Events - Identify Low Port Bindings* (post-join `LocalAddressIP4`/`LocalPort`/`FileName` filters); four further queries omit `aid` without a downstream filter and mislabel rather than miss.

**Mitigation:** always carry `aid` on both sides of the join key, set `max=` explicitly, and treat any filter placed *after* a join as a filter on possibly-foreign data.

## 8. `ProcessRollup2` without `SyntheticProcessRollup2` skips already-running processes (ADE2-02)

A query filtering `#event_simpleName=ProcessRollup2` evaluates process *executions observed by the sensor*; processes already running when the sensor loaded (or that arrive by other paths) surface as `SyntheticProcessRollup2` and are not evaluated. In the community corpus this is systemic: 111 of the 295 in-scope queries filter the former without the latter. Whether it is a defect depends on each query's intent — some deliberately target new executions — but where the rule's claim is "this process activity is detected", the synthetic variant is part of the claim.

**Mitigation:** write process filters as `#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/` (or an `in()` over both) unless new-execution-only is the documented intent; state the intent in the query header either way.

## 9. `sort()` and `tail()` default to 200 rows — but audit the pipeline before filing (ADE3-06)

`sort()` defaults to 200 rows, ceiling governed by `StateRowLimit` ([`sort()`](https://library.humio.com/crowdstrike-query-language/functions-sort.html)). A scheduled search that sorts raw matches before alerting caps itself at 200 candidates per run. The counter-lesson from this catalog's own verification pass: two draft findings on sort/group limits were withdrawn because a *tighter upstream limit* made the downstream default unreachable (a `groupBy(..., limit=10)` feeding `sort()` can never saturate 200) or the key's cardinality was structurally bounded (`geohash(precision=2)` caps at 1,024 cells). A limit is only a finding when the data can actually reach it.

**Mitigation:** set `limit=` explicitly on `sort()`/`tail()` in anything scheduled; when auditing, trace the maximum row count that can arrive at each operator before claiming its limit bites.

## Quick audit checklist for a LogScale query

- Is any bare `=` comparing attacker-influenced text? It is exact and case-sensitive — use `/.../ i` or `in(..., ignoreCase=true)`.
- Does every regex over command lines, paths or names carry `/i`?
- Which positive filters are silently also presence tests? Assert `field = *` explicitly where required; monitor `field != *` volume for extraction health.
- Does every `case`/`match` ladder end in a wildcard clause whose bucket is kept and counted?
- Does any `groupBy()` feeding a threshold or rarity gate run without `limit=max`? Is the group limit anywhere near the alert threshold?
- For every `join()`: can the subquery saturate its `limit`? Is `max=1` collapsing a many-events pattern? Is `aid` in the join key? Is anything filtered on an enriched field after the join?
- Do process filters cover `SyntheticProcessRollup2`, or is new-execution-only the documented intent?
- Can the data volume actually reach the limit you are about to flag? Trace the pipeline first.

## References
- [CrowdStrike/logscale-community-content](https://github.com/CrowdStrike/logscale-community-content) · [CQL documentation](https://library.humio.com/crowdstrike-query-language/)
- [Operators](https://library.humio.com/crowdstrike-query-language/syntax-operators.html) · [Field filters](https://library.humio.com/crowdstrike-query-language/syntax-filters.html) · [Regex flags](https://library.humio.com/crowdstrike-query-language/syntax-regex-flags.html) · [Regex syntax](https://library.humio.com/crowdstrike-query-language/syntax-regex.html) · [Conditional evaluation](https://library.humio.com/crowdstrike-query-language/syntax-conditional.html)
- [`groupBy()`](https://library.humio.com/crowdstrike-query-language/functions-groupby.html) · [`join()`](https://library.humio.com/crowdstrike-query-language/functions-join.html) · [`sort()`](https://library.humio.com/crowdstrike-query-language/functions-sort.html) · [`in()`](https://library.humio.com/crowdstrike-query-language/functions-in.html)
