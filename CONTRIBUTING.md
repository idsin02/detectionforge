# Contributing to DetectionForge

## Ground rules
- **No client or employer data.** Only lab-generated or public datasets
  (OTRF Security-Datasets, Splunk attack_data, Atomic Red Team), with attribution.
- **No unproven claims.** A rule is "validated" only if a deterministic test proves it.
- CQL queries get static/metadata checks only; there is no free local CQL engine.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pre-commit install
```

## Adding a rule
Rules live at `rules/<attack_technique_id>/<rule_slug>/` and contain:
`rule.yml`, `sigma.yml`, `query.kql`, `query.cql`,
`tests/positive_*.json`, `tests/negative_*.json`.

`rule.yml` must pass `dforge validate`. Key rules:
- `version` is quoted semver (`"1.0.0"`), `id` is a UUID4 and equals the `id` in `sigma.yml`.
- Positive fixtures expect >= 1 match; negative fixtures expect exactly 0.
- `status: production` needs >= 1 positive and >= 2 negative tests.
- `status: deprecated` needs `deprecated_by` pointing at an existing rule id.
- Every `tests/*.json` file must be listed in `rule.yml`.

Fixtures: flat events, JSON numbers for numeric fields, and a `source` that
names the dataset. See `examples/rules/T1105/certutil-urlcache-download/`.

## Before opening a PR
```bash
pre-commit run --all-files
pytest
dforge validate
dforge test
```

## Commit style
Conventional Commits: `feat(rules): add T1003.006 DCSync`, `fix(cli): ...`, `docs: ...`.