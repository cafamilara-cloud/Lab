#!/usr/bin/env python3
"""CLI wrapper to run the Ownership Assignment Engine."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import importlib.util
from pathlib import Path as _Path

# Load ownership_engine from package path to avoid import issues when running
# as a standalone script in different working directories.
pkg_root = _Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ownership_engine", str(pkg_root / "ownership_engine.py"))
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("input", nargs="?", default="cache/dummy_tenable_findings.json")
    p.add_argument("--rules", default=str(pkg_root / "Library" / "routing_rules.yaml"))
    p.add_argument("-o", "--output", help="output JSON file")
    args = p.parse_args()

    rules = engine.load_rules(Path(args.rules))
    with open(args.input, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        print("Unsupported input format")
        return 2

    assigned = engine.assign_all(findings, rules)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(assigned, fh, indent=2)
        print(f"Wrote assignments to {args.output}")
    else:
        print(json.dumps(assigned, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
