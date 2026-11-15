# DetectionForge

Detection-as-Code: every detection is versioned, schema-validated, tested against
malicious and benign events, hashed, and released with an evidence bundle.

> Status: v0.3.0. Rule schema, `dforge validate` and the SQLite test engine
> (`dforge test`) are in place. Rule pack, KQL engine and evidence bundles come next.

```bash
pip install -e ".[dev]"
dforge --version
dforge validate                              # validate every rules/**/rule.yml
dforge test                                  # run every rule against its fixtures
dforge test --rules-dir examples/rules       # engine-proof example rule
dforge test --rule T1105 --json              # filter + machine-readable output
```

See [docs/test-engine.md](docs/test-engine.md) for matching semantics and
Sigma conversion limits.