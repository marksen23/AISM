#!/usr/bin/env python3
"""Validate AISM policy files against policy/policy.schema.json.

  python3 tools/validate_policy.py policy/policy.example.yaml [more.yaml ...]
"""
from __future__ import annotations

import json
import pathlib
import sys

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "policy" / "policy.schema.json").read_text(encoding="utf-8"))


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit("usage: validate_policy.py POLICY.yaml ...")
    validator = jsonschema.Draft202012Validator(SCHEMA)
    failed = False
    for arg in argv:
        path = pathlib.Path(arg)
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        if errors:
            failed = True
            print(f"FAIL {path}")
            for err in errors:
                loc = "/".join(str(p) for p in err.path) or "(root)"
                print(f"  {loc}: {err.message}")
        else:
            print(f"OK {path}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
