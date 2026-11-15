# DetectionForge

Detection-as-Code: every detection is versioned, schema-validated, tested against
malicious and benign events, hashed, and released with an evidence bundle.

> Status: v0.2.0, rule schema and `dforge validate`. Test engine and rule pack come next.

```bash
pip install -e ".[dev]"
dforge --version
dforge validate                         # validate every rules/**/rule.yml
dforge validate --update-attack-cache   # one-time ATT&CK download, then offline
python -m detectionforge.schema.export  # regenerate schema/rule_manifest.schema.json