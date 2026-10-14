# Splunk — Detection-Logic Bug Patterns

Platform-specific pitfalls for Splunk detections (`splunk/security_content` / ESCU, SPL) and the CIM data models they run over. SPL's distinctive hazard is that **the same predicate means different things depending on which command evaluates it**: `search` and `where` disagree on case sensitivity, on Boolean precedence, and on how a missing field is treated, so a filter that is correct in one position silently inverts when moved. Pair with [`logging_assumption_errors.md`](logging_assumption_errors.md) and, for transpiled rules, [`sigma.md`](sigma.md).

> **Verification footing.** Every semantic claim below was replayed on **Splunk Enterprise 10.4.2** with the self-contained probes in [Verifying these on your own instance](#verifying-these-on-your-own-instance), and cited to vendor documentation where the docs state it. Items marked *doc-only* are documented but were not replayed locally. `Seen in:` names real ESCU detections at [`splunk/security_content`](https://github.com/splunk/security_content) @ `adc69d9` (2026-10-14).

## Rule types and where each one breaks

| ESCU `type` | Shape | Primary exposure |
|---|---|---|
| `TTP` / `Anomaly` | single-event `search` or `tstats` filter | ADE1 literal matching, ADE4-04 field availability |
| `Hunting` | broad search, analyst-reviewed | ADE2 enumeration gaps (no alerting contract) |
| `Correlation` | `stats`/`eventstats` + threshold | ADE3-02 aggregation, ADE3-03 windowing |
| `Baseline` | feeds a summary index or lookup | ADE3-02 baseline poisoning |
| any `\| tstats` | data-model accelerated | ADE4-04 acceleration and CIM mapping gaps |

## 1. `search` and `where` disagree on case (ADE1-01, ADE4-03)

Field **values** compared by the `search` command are case-insensitive; the `where` command's eval-expression is **case-sensitive** — *"The eval-expression is case-sensitive"* ([`where`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/where)). On one event holding `f="ABC"`: `search f="abc"` returns it, `where f="abc"` does not. `like(f,"abc")` returns false where `like(f,"ABC")` is true, and `match()` is PCRE and case-sensitive until you write `match(f,"(?i)abc")`. `IN` inherits its position's semantics — `search f IN ("abc")` matches, `where f IN ("abc")` does not.

Splunk stores command lines and paths as supplied rather than normalized, so every case-sensitive comparison over attacker-supplied text is an ADE1 bypass: `-EncodedCommand` spelled `-encodedcommand`, or a mailbox folder the attacker names `archive` instead of `Archive`.

Seen in: *O365 BEC Email Hiding Rule Created* (`match(MoveToFolder, "^(RSS|Conversation History|Archive)")` scores a case-folded folder name 0), *Cisco IOS XE Guestshell Activation and Destroy* (a `like()` ladder assigns `event_type`, and a casing difference routes the event to `"other"`, which the rule's own `mvfind` gate then never matches).

**Mitigation:** fold case explicitly (`lower(field)`) or add `(?i)`; better, anchor on a field the attacker does not author. See [ADE1-01](../ade_framework/ADE1/ADE1-01-substring-manipulation/README.md) and [`cmdline_obfuscation.md`](cmdline_obfuscation.md).

## 2. AND/OR precedence differs between `search` and `where` (ADE4-03)

The `search` command binds **OR tighter than AND**; `where`/eval binds **AND tighter than OR**. The same three-term text inverts: on an event holding `a="9", b="2", c="3"`, `search a="1" b="2" OR c="3"` returns nothing (parsed `a AND (b OR c)`) while `where a="1" AND b="2" OR c="3"` returns the event (parsed `(a AND b) OR c`). An unparenthesized filter therefore changes meaning when it moves between a base search and a `where`, and a transpiler that chooses the other position changes it for you.

**Mitigation:** parenthesize every mixed Boolean; never rely on the default precedence. See [ADE4-03 AND-vs-OR](../ade_framework/ADE4/ADE4-03-incorrect-expression/and-vs-or-confusion.md).

## 3. `field!=value` drops events where the field is absent (ADE4-01, ADE4-04)

Documented: with `!=`, *"every event that has a value in the field, where that value does not match the value you specify, is returned. Events that do not have a value in the field are not included in the results"*, whereas `NOT field="value"` returns everything except the named value *"including events that do not have a value in the field"* ([Difference between != and NOT](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/expressions-and-predicates/difference-between-and-not)). Replayed: with event A holding `fld="y"` and event B holding no `fld` at all, `search fld!="x"` keeps only A; `search NOT fld="x"` keeps both.

An exclusion written with `!=` is therefore **two filters** — the one the author wrote, plus an undeclared "and this field must exist". Wherever the sourcetype, CIM mapping or sensor config leaves that field unpopulated, the entire event leaves the pipeline, which is the opposite of removing one benign value. Wildcards do work with `!=` (`fld!="*temp.dat*"` excludes as expected), but the bare form matches nothing at all: `fld!=*` returns no events, while `NOT fld=*` returns the events whose field is null or undefined.

Seen in: *Clop Common Exec Parameter*, whose `WHERE Processes.process_name != "*temp.dat*"` both excludes the renamed-binary case its own second clause enumerates and discards every event where `process_name` was never populated.

**Mitigation:** express exclusions as `NOT (field="value")`, and assert presence separately and visibly when the field is genuinely required. See [ADE4-04 absent-field inversion](../ade_framework/ADE4/ADE4-04-field-mismapping-semantics/absent-field-inverts-filter.md).

## 4. `stats ... by` silently drops null by-fields (ADE4-04, ADE3-02)

An event whose by-field is null does not appear in `stats` output at all: two events where only one carries `a` yield a single row, and inserting `fillnull value="MISSING" a` yields two. Any upstream extraction failure therefore becomes a coverage hole rather than a visible error, and it compounds with #7.

**Mitigation:** [`fillnull`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/fillnull) before aggregating on optional fields, and alert on the filled bucket rather than discarding it.

## 5. `by` on attacker-controlled fields (ADE3-02)

A threshold is only as strong as its grouping key. `stats count by user, src_ip | where count > 10` counts per *(user, src_ip)* pair, so a spray across usernames or a rotation across source addresses keeps every bucket under the threshold while the aggregate sits far above it — the rule catches the brute force it is named for and misses the spray. The same defect appears whenever the key is a string the client supplies.

Seen in: *ESXi SSH Brute Force* (`by user, src_ip, dest` with `count > 10`), *Azure AD High Number Of Failed Authentications For User* (`by user` with `count > 20`), *O365 Multiple Mailboxes Accessed via API* (`BY ... ClientInfoString` with `unique_mailboxes > 5`, where varying the client string per mailbox keeps the distinct count at 1).

**Mitigation:** count the distinct attacker surface against the target — `stats dc(user) as users dc(src_ip) as sources count as attempts by dest` with an alert on any of the three — rather than counting per attacker-chosen pair. See [ADE3-02 distribution across entities](../ade_framework/ADE3/ADE3-02-aggregation-hijacking/distribute-across-entities.md).

## 6. `bin` / `span` fixed buckets (ADE3-03)

`bin _time span=1m` assigns events to wall-clock-aligned buckets, so events 40 seconds apart at `10:00:50` and `10:01:30` land in *different* buckets and a `count > N` threshold never accumulates them. Any `span` plus threshold is evadable by straddling a boundary, and any correlation requiring two event classes *in the same bucket* is additionally evadable by delay.

Seen in: *ESXi SSH Brute Force* (`span=5m`), *Azure AD High Number Of Failed Authentications For User* (`span=10m`), *O365 Multiple Mailboxes Accessed via API* (`bucket span=10m`), *Cisco IOS XE Guestshell Activation and Destroy* (activation and destruction must share one `span=30m` bucket).

**Mitigation:** overlapping or sliding look-backs, or `streamstats`/`transaction` with an explicit window sized from the behavior rather than a round number. See [ADE3-03 window evasion](../ade_framework/ADE3/ADE3-03-timing-and-scheduling/window-evasion.md).

## 7. `rex` extraction failure zeroes everything downstream (ADE4-04)

A failed `rex` does not error — it leaves the capture group null, and the next `stats ... by` drops the row (#4). The character class *is* the detection boundary: `rex "for (?<user>[\w]+) from ..."` cannot match a username containing a dot, hyphen or `@`, because `\w` is `[A-Za-z0-9_]`, so `first.last` and `root@host` extract nothing and never reach the count.

Seen in: *ESXi SSH Brute Force*, where that exact class precedes `stats count by user, src_ip`.

**Mitigation:** widen the class (`[^\s]+`), then make failure visible — `fillnull value="EXTRACTION_FAILED" user` plus a hunting search on its volume. A parser that stops matching after a vendor format change is otherwise indistinguishable from an absence of attacks (**#2/#14** in [`logging_assumption_errors.md`](logging_assumption_errors.md)).

## 8. CIM data models, `tstats` and acceleration (ADE4-04, ADE2-02)

*Doc-only — not replayed locally.* `tstats` reads indexed and accelerated data, so a detection over `datamodel=Endpoint.Processes` sees only what the CIM add-ons actually mapped for the sourcetypes present. A sourcetype with no CIM mapping contributes nothing while the rule looks healthy; `summariesonly=true` restricts results to the acceleration summary, hiding late-arriving or un-accelerated data; and fields the model declares but no add-on fills are null, which lands you in #3 and #4. In ESCU this is indirected through the `security_content_summariesonly` macro, whose **local** definition decides the behavior.

**Mitigation:** read the macro, not the rule, and verify coverage with `| tstats count from datamodel=<model> by sourcetype` against raw per-sourcetype counts.

## 9. Macro and lookup indirection (ADE2-02, ADE4-04)

ESCU detections end in a `` `<name>_filter` `` macro and often begin with a sourcetype macro; both are locally editable and invisible in the rule text. A filter macro tuned to quiet noise is a permanent, unreviewed exclusion, and a `lookup local=t` depends on file contents that are not in the rule. Resolve every macro and lookup (`| rest /services/data/macros`) and treat them as part of the detection logic.

## Verifying these on your own instance

Each probe is self-contained — no data, no index, no app context — so you can confirm the semantics on your own version rather than trusting this file. Case (#1): `| makeresults | eval f="ABC" | search f="abc" | stats count` returns 1 while the same with `| where f="abc"` returns 0. Precedence (#2): `| makeresults | eval a="9", b="2", c="3" | search a="1" b="2" OR c="3" | stats count` returns 0 while `| where a="1" AND b="2" OR c="3"` returns 1. Absent field (#3): `| makeresults | eval name="A", fld="y" | append [| makeresults | eval name="B"] | search fld!="x" | stats values(name)` returns only `A`. Null by-field (#4): `| makeresults | eval a="1" | append [| makeresults] | stats count by a` returns one row. Bucket straddle (#6): two `makeresults` events at `10:00:50` and `10:01:30` piped through `| bin _time span=1m | stats count by _time` return two rows of 1.

## Quick audit checklist for a Splunk rule

- Is any case-bearing literal compared in `where`, `like()` or `match()` over attacker-supplied text? Fold case or add `(?i)`.
- Is every mixed Boolean parenthesized, so `search`-vs-`where` precedence cannot change its meaning?
- Does any `!=` exclusion sit on a field that can be absent? It is silently also requiring the field to exist.
- Does `stats ... by` group on an optional field with no `fillnull` upstream?
- Is the `by` clause keyed on something the attacker chooses (user, source, a client string)? Count the distinct surface instead.
- Does the `span`/`bin` window plus threshold survive a boundary straddle or a delay?
- Can every `rex` capture class actually match the real values — dots, hyphens, `@`, Unicode?
- For `tstats`: is the data model accelerated, and does every in-scope sourcetype carry a CIM mapping?
- Have you resolved the `_filter` macro and every lookup the rule depends on?

## References
- [splunk/security_content](https://github.com/splunk/security_content) · [research.splunk.com](https://research.splunk.com)
- [Difference between != and NOT](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/expressions-and-predicates/difference-between-and-not) · [Understanding SPL syntax](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/introduction/understanding-spl-syntax)
- [`where`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/where) · [`stats`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.4/search-commands/stats) · [`fillnull`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/fillnull) · [`tstats`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.2/search-commands/tstats)
- [Comparison and conditional functions](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/evaluation-functions/comparison-and-conditional-functions) · [Use CASE() and TERM() to match phrases](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.2/search-primer/use-case-and-term-to-match-phrases) · [Splunk Common Information Model](https://help.splunk.com/en/splunk-cloud-platform/common-information-model)
