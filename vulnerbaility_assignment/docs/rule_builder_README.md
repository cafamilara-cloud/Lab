Rule Builder
============

This tool generates `routing_rules.yaml` from sample vulnerability data (CSV or JSON).

Quick start
-----------

1. Create a CSV with headers: `plugin_id,plugin_name,plugin_family,known_owner_team`
2. Install dependencies:

```bash
python -m pip install -r tools/requirements.txt
```

3. Run the tool (no args will use `cache/tenable_export.json` by default):

```bash
# with explicit input
python tools/rule_builder.py sample.csv -o Library/routing_rules.yaml

# or using the default cache path
python tools/rule_builder.py
```

Options
-------
- `--merge`: path to existing `routing_rules.yaml` to merge generated rules into.
- `--min-keyword-support`: minimum occurrences for a token to be proposed as a keyword rule.

Notes
-----
- The script makes deterministic decisions (majority vote) and reports plugin_id conflicts to stderr.
- Review generated keyword rules before deploying.
