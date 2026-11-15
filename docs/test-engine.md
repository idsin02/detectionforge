# Test engine (SQLite)

`dforge test` converts each rule's `sigma.yml` to SQL with **pySigma-backend-sqlite**,
loads each fixture's events into a fresh in-memory SQLite table, runs the query and
compares the match count with `expected_matches`.

Versions used for every run are printed in the header (and in `--json` output), e.g.
`pySigma 2.1.0, pySigma-backend-sqlite 2.1.1, SQLite 3.44.0`.

## Matching semantics

| Behaviour | How it works |
|---|---|
| Missing fields | Every field in the fixture or referenced by the rule becomes a column; absent values are `NULL`, and `NULL` never matches a value. |
| Case | String comparisons are case-insensitive (`COLLATE NOCASE` + `LIKE`). `\|cased` uses `GLOB` and is case-sensitive. |
| Types | JSON types are kept. `EventID: 4662` in Sigma matches the JSON number `4662`, **not** the string `"4662"`. `\|gt`/`\|lt` compare numerically. |
| Regex | `\|re` runs Python `re.search` (unanchored). Case-sensitive unless `\|re\|i`. |
| Field mapping | Optional `mappings/<telemetry_contract.source>.yml` maps Sigma field → fixture field. |
| Logsource | **Not enforced.** The engine does not check that events come from the rule's `logsource`; fixtures must contain only events of the right type. |

## Conversion limits

These were observed with pySigma 2.1.0 / pySigma-backend-sqlite 2.1.1:

| Sigma feature | Result |
|---|---|
| Keyword (unbound) searches, e.g. `keywords: ['mimikatz']` | **Rejected.** The backend needs a full-text column that DetectionForge does not build. Use field-bound `\|contains` instead. |
| Placeholders `\|expand` (`%DomainControllers%`) | **Rejected** unless a pipeline defines the placeholder. |
| Correlation rules, legacy `\| count()` / `\| near` | **Rejected.** Single event rules only. |
| `\|cidr` | Converted to `LIKE 'a.b.%'` prefixes. Works for canonical IPv4 text. IPv6 only matches the exact textual form (`2001:db8::` and `2001:0db8::` differ). |
| Case-insensitivity | ASCII only. `ÄDMIN` does not match `ädmin`. |
| `\|re` | Python regex dialect. PCRE-only syntax such as `(?<name>...)` named groups (Python needs `(?P<name>...)`) or `\h` fails at run time and shows as an error. |
| Time modifiers (`\|hour`, `\|day`, ...) | Use `strftime` on a field named `timestamp` in ISO format. |
| `\|base64offset`, `\|wide`, `\|windash`, `\|contains\|all`, `\|fieldref`, `\|exists`, `null` | Supported (covered by tests). |

A rule that cannot be converted appears as `ERR` in the table, with the reason
under **Errors**, and the run exits non-zero.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every fixture matched its expectation |
| 1 | At least one FAIL or error |
| 2 | Usage problem: missing rules dir, `--rule` matched nothing, engine unavailable |
