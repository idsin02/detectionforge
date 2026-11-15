"""Export the RuleManifest JSON Schema.

Usage:
    python -m detectionforge.schema.export            # write schema/rule_manifest.schema.json
    python -m detectionforge.schema.export --check    # exit 1 if the file is stale
    python -m detectionforge.schema.export -o path.json

The JSON Schema covers field types and formats for editor autocompletion
(e.g. VS Code YAML extension). Cross-field rules (dates, deprecation, test
counts, files on disk) are enforced only by `dforge validate`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from detectionforge.schema.manifest import RuleManifest

DEFAULT_OUTPUT: Final = Path("schema/rule_manifest.schema.json")
JSON_SCHEMA_DIALECT: Final = "https://json-schema.org/draft/2020-12/schema"


def build_schema() -> dict[str, Any]:
    schema = RuleManifest.model_json_schema(mode="validation")
    schema["$schema"] = JSON_SCHEMA_DIALECT
    schema["description"] = (
        "DetectionForge rule manifest (rule.yml). Cross-field rules are enforced by "
        "`dforge validate`, not by this schema."
    )
    return schema


def render_schema() -> str:
    return json.dumps(build_schema(), indent=2, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m detectionforge.schema.export")
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the file is out of date")
    args = parser.parse_args(argv)
    output: Path = args.output
    rendered = render_schema()

    if args.check:
        current = output.read_text(encoding="utf-8") if output.is_file() else None
        if current != rendered:
            print(
                f"{output} is out of date. Run: python -m detectionforge.schema.export",
                file=sys.stderr,
            )
            return 1
        print(f"{output} is up to date.")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())