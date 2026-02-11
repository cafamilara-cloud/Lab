#!/usr/bin/env python3
"""
rule_builder.py

Generate `routing_rules.yaml` from sample vulnerability data (CSV or JSON).

Features:
- Load CSV/JSON with columns: plugin_id, plugin_name, plugin_family, known_owner_team (optional)
- Build deduplicated `plugin_id_rules` from explicit `known_owner_team`
- Build `family_rules` by majority vote of known_owner_team within families
- Propose `keyword_rules` by extracting tokens from plugin_name grouped by team
- Validate conflicting plugin_id -> multiple teams
- Merge with an existing routing_rules.yaml when provided

Output: YAML file suitable for the Ownership Assignment Engine
"""
from __future__ import annotations

import argparse
import csv
import datetime
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except Exception:
    print("PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    raise

STOP_WORDS = {
    "the",
    "and",
    "or",
    "for",
    "with",
    "from",
    "of",
    "to",
    "in",
    "on",
    "a",
    "an",
    "by",
    "v",
}


def tokenize(text: str) -> List[str]:
    text = (text or "").lower()
    # split on non-alphanumeric, keep tokens with length >= 3
    tokens = re.split(r"[^a-z0-9]+", text)
    tokens = [t for t in tokens if len(t) >= 3 and t not in STOP_WORDS]
    return tokens


def load_csv(path: Path) -> List[Dict[str, str]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({k: (v or "").strip() for k, v in r.items()})
    return rows


def load_json(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # Accept list of objects or object with 'findings'
    if isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
        return data["findings"]
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported JSON format; expected list or {findings: [...]}")


def build_rules(records: List[Dict[str, str]], min_keyword_support: int = 2) -> Dict:
    plugin_id_map: Dict[str, List[str]] = defaultdict(list)
    family_map: Dict[str, List[str]] = defaultdict(list)
    token_team: Dict[str, List[str]] = defaultdict(list)

    for r in records:
        pid = (r.get("plugin_id") or "").strip()
        team = (r.get("known_owner_team") or "").strip()
        family = (r.get("plugin_family") or r.get("family") or "").strip()
        name = (r.get("plugin_name") or r.get("plugin") or "").strip()

        if pid:
            plugin_id_map[pid].append(team)
        if family and team:
            family_map[family].append(team)
        if name and team:
            for tok in tokenize(name):
                token_team[tok].append(team)

    # plugin_id_rules: only where a team is present and majority exists
    plugin_id_rules = []
    plugin_conflicts = []
    for pid, teams in sorted(plugin_id_map.items(), key=lambda x: int(x[0]) if x[0].isdigit() else x[0]):
        teams = [t for t in teams if t]
        if not teams:
            continue
        c = Counter(teams)
        team, count = c.most_common(1)[0]
        if len(c) > 1 and count < sum(c.values()):
            plugin_conflicts.append({"plugin_id": pid, "teams": dict(c)})
        plugin_id_rules.append({
            "id": f"pid-{pid}",
            "plugin_id": int(pid) if pid.isdigit() else pid,
            "owner_team": team,
        })

    # family_rules: majority
    family_rules = []
    for fam, teams in sorted(family_map.items()):
        teams = [t for t in teams if t]
        if not teams:
            continue
        team, _ = Counter(teams).most_common(1)[0]
        family_rules.append({"id": f"fam-{abs(hash(fam))%100000}", "family": fam, "owner_team": team})

    # keyword_rules: tokens with support >= min_keyword_support and clear majority team
    keyword_rules = []
    kw_id = 1
    for tok, teams in sorted(token_team.items()):
        c = Counter([t for t in teams if t])
        total = sum(c.values())
        if total < min_keyword_support:
            continue
        team, count = c.most_common(1)[0]
        # require at least 60% agreement
        if count / total >= 0.6:
            keyword_rules.append({
                "id": f"kw-gen-{kw_id:04d}",
                "keyword": tok,
                "owner_team": team,
                "weight": 80,
                "fields": ["plugin_name"],
            })
            kw_id += 1

    result = {
        "plugin_id_rules": plugin_id_rules,
        "family_rules": family_rules,
        "keyword_rules": keyword_rules,
        "plugin_conflicts": plugin_conflicts,
    }
    return result


def merge_existing(existing: Dict, generated: Dict) -> Dict:
    # Merge by appending new rules, avoid duplicate plugin_id or exact keyword
    out = dict(existing)
    for key in ("plugin_id_rules", "family_rules", "keyword_rules"):
        existing_list = out.get(key, [])
        gen_list = generated.get(key, [])
        if key == "plugin_id_rules":
            seen = {str(item.get("plugin_id")): item for item in existing_list}
            for item in gen_list:
                pid = str(item.get("plugin_id"))
                if pid in seen:
                    continue
                existing_list.append(item)
        elif key == "family_rules":
            seen = {item.get("family"): item for item in existing_list}
            for item in gen_list:
                fam = item.get("family")
                if fam in seen:
                    continue
                existing_list.append(item)
        elif key == "keyword_rules":
            seen = {item.get("keyword"): item for item in existing_list}
            for item in gen_list:
                kw = item.get("keyword")
                if kw in seen:
                    continue
                existing_list.append(item)
        out[key] = existing_list
    return out


def make_routing_yaml(generated: Dict, rule_version: Optional[str] = None, default_owner_team: str = "vm-triage") -> Dict:
    if rule_version is None:
        rule_version = datetime.datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    out = {
        "rule_version": rule_version,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "plugin_id_rules": generated.get("plugin_id_rules", []),
        "family_rules": generated.get("family_rules", []),
        "keyword_rules": generated.get("keyword_rules", []),
        "precedence": ["database", "middleware", "OS", "network", "security", "default"],
        "default_owner_team": default_owner_team,
        "notes": ["Generated by tools/rule_builder.py"],
    }
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Build routing_rules.yaml from sample vulnerability data")
    default_input = str(Path(__file__).resolve().parent / "cache" / "tenable_export.json")
    p.add_argument("input", nargs="?", help="Input CSV or JSON file with sample vulnerabilities", default=default_input)
    p.add_argument("-o", "--output", help="Output YAML path", default=str(Path(__file__).resolve().parent / "Library" / "routing_rules.yaml"))
    p.add_argument("--merge", help="Existing routing_rules.yaml to merge with", default=None)
    p.add_argument("--min-keyword-support", type=int, default=2, help="Min occurrences for keyword generation")
    p.add_argument("--default-owner", default="vm-triage", help="Default owner team")
    args = p.parse_args(argv)

    inp = Path(args.input)
    if not inp.exists():
        print(f"Input file not found: {inp}", file=sys.stderr)
        return 2

    if inp.suffix.lower() in (".csv", ".tsv"):
        records = load_csv(inp)
    elif inp.suffix.lower() in (".json",):
        records = load_json(inp)
    else:
        print("Unsupported input format. Provide .csv or .json", file=sys.stderr)
        return 2

    generated = build_rules(records, min_keyword_support=args.min_keyword_support)

    # report conflicts
    if generated.get("plugin_conflicts"):
        print("Detected plugin_id conflicts (multiple teams for same plugin_id):", file=sys.stderr)
        for c in generated["plugin_conflicts"]:
            print(json.dumps(c), file=sys.stderr)

    routing = make_routing_yaml(generated, default_owner_team=args.default_owner)

    if args.merge:
        mpath = Path(args.merge)
        if mpath.exists():
            with mpath.open("r", encoding="utf-8") as f:
                existing = yaml.safe_load(f) or {}
            routing = merge_existing(existing, routing)

    outp = Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open("w", encoding="utf-8") as f:
        yaml.safe_dump(routing, f, sort_keys=False, default_flow_style=False)

    print(f"Wrote routing rules to {outp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
