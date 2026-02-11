"""Ownership Assignment Engine

Simple deterministic assignment engine that loads `routing_rules.yaml` and
assigns an `owner_team` to vulnerability findings using this precedence:

- Exact `plugin_id` rules
- `family` rules
- Keyword scoring across configured fields
- Default owner team

Exports a single `assign(finding)` function and a `assign_all(records)` helper.
"""
from __future__ import annotations

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


def load_rules(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _get_plugin_id(finding: Dict[str, Any]) -> Optional[str]:
    plugin = finding.get("plugin")
    if isinstance(plugin, dict):
        pid = plugin.get("id")
        if pid is not None:
            return str(pid)
    # fallback top-level names
    pid = finding.get("plugin_id") or finding.get("pluginId")
    if pid is not None:
        return str(pid)
    return None


def _get_family(finding: Dict[str, Any]) -> str:
    plugin = finding.get("plugin")
    if isinstance(plugin, dict):
        return (plugin.get("family") or plugin.get("plugin_family") or "")
    return finding.get("plugin_family") or finding.get("family") or ""


def _get_field_text(finding: Dict[str, Any], field: str) -> str:
    # support dot notation like 'evidence.output'
    parts = field.split(".")
    cur: Any = finding
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            # support plugin_name -> plugin.name
            if field == "plugin_name":
                plug = finding.get("plugin")
                if isinstance(plug, dict):
                    return str(plug.get("name") or plug.get("plugin") or "")
            return ""
    if isinstance(cur, list):
        return " ".join(str(x) for x in cur)
    return str(cur or "")


def assign(finding: Dict[str, Any], rules: Dict[str, Any]) -> Dict[str, Any]:
    """Assign an owner_team to a single finding and return a dict with metadata."""
    default = rules.get("default_owner_team") or "vm-triage"

    # build lookup maps
    pid_map = {str(item.get("plugin_id")): item.get("owner_team") for item in rules.get("plugin_id_rules", [])}
    family_map = {item.get("family"): item.get("owner_team") for item in rules.get("family_rules", [])}

    # keyword rules list
    kw_rules = []
    for k in rules.get("keyword_rules", []):
        kw_rules.append({
            "keyword": (k.get("keyword") or "").lower(),
            "owner": k.get("owner_team"),
            "weight": int(k.get("weight") or 0),
            "fields": k.get("fields") or ["plugin_name"],
        })

    # 1) plugin_id match
    pid = _get_plugin_id(finding)
    if pid and pid in pid_map and pid_map[pid]:
        return {"owner_team": pid_map[pid], "reason": f"plugin_id:{pid}"}

    # 2) family match
    fam = _get_family(finding)
    if fam and fam in family_map and family_map[fam]:
        return {"owner_team": family_map[fam], "reason": f"family:{fam}"}

    # 3) keyword scoring
    scores: Dict[str, int] = {}
    matches: List[str] = []
    for kr in kw_rules:
        kw = kr["keyword"]
        for field in kr["fields"]:
            text = _get_field_text(finding, field).lower()
            if not text:
                continue
            if kw in text:
                scores[kr["owner"]] = scores.get(kr["owner"], 0) + kr["weight"]
                matches.append(f"{kr['owner']}:+{kr['weight']}({kw})")

    if scores:
        # choose owner with max score
        best_owner = max(scores.items(), key=lambda x: (x[1], x[0]))[0]
        return {"owner_team": best_owner, "reason": f"keywords: {';'.join(matches)}"}

    # fallback default
    return {"owner_team": default, "reason": "default"}


def assign_all(records: List[Dict[str, Any]], rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        assigned = assign(r, rules)
        rec = {"finding_id": r.get("finding_id") or r.get("id"), "owner_team": assigned["owner_team"], "reason": assigned["reason"]}
        out.append(rec)
    return out


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser()
    p.add_argument("input", nargs="?", default="cache/dummy_tenable_findings.json")
    p.add_argument("--rules", default="Library/routing_rules.yaml")
    p.add_argument("-o", "--output", help="Output JSON file (defaults to stdout)")
    args = p.parse_args()

    rules = load_rules(Path(args.rules))
    with open(args.input, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        raise SystemExit("Unsupported input format")

    assigned = assign_all(findings, rules)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(assigned, fh, indent=2)
        print(f"Wrote assignments to {args.output}")
    else:
        print(json.dumps(assigned, indent=2))
