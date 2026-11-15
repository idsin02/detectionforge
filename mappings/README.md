# Field mappings

One optional YAML file per telemetry source, named after
`telemetry_contract.source` in `rule.yml` (e.g. `windows-security.yml`).

Each file maps **Sigma field name → fixture field name**:

```yaml
# mappings/windows-security.yml
Image: NewProcessName
ParentImage: ParentProcessName
```

No file = no mapping (Sigma field names are used as-is, which is correct for
Sysmon-shaped fixtures).