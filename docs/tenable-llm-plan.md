# LLM-like implementation guide for vulnerability management (Tenable export)

This guide is intentionally designed for a system that **behaves like an LLM** (deterministic rules + templates), with optional LLM assistance only where safe.

## 1) Goal: deterministic, explainable output
Build a pipeline that:
- ingests Tenable vulnerability JSON,
- normalizes records into a stable schema,
- scores/ranks with deterministic rules,
- outputs structured summaries for analysts, owners, and ticketing.

## 2) What your sample confirms
From your sample payload, each finding already includes the minimum data needed for an MVP:
- **Asset context**: hostname, fqdn, ipv4/ipv6, operating_system, asset uuid.
- **Finding context**: finding_id, state, first_found, last_found, resurfaced_date, severity.
- **Vulnerability context**: plugin.id, plugin.name, plugin.description, plugin.solution, plugin.cve/xrefs.
- **Risk context**: risk_factor, CVSS variants, VPR/VPRv2, EPSS, exploitability flags.
- **Evidence context**: plugin output text and affected file/version details.

## 3) Normalize to one canonical finding schema
Use a fixed normalized schema so every record is machine-sortable and template-ready.

### 3.1 Canonical keys (recommended)
```json
{
  "finding_id": "string",
  "asset": {
    "asset_uuid": "string",
    "hostname": "string",
    "fqdn": "string",
    "ipv4": "string|null",
    "ipv6": "string|null",
    "os": "string|null",
    "device_type": "string|null"
  },
  "vuln": {
    "plugin_id": "number",
    "plugin_name": "string",
    "family": "string|null",
    "cves": ["string"],
    "vendor_refs": ["string"],
    "description": "string|null",
    "solution": "string|null"
  },
  "risk": {
    "severity": "info|low|medium|high|critical",
    "severity_id": "number",
    "risk_factor": "string|null",
    "cvss3_base": "number|null",
    "vpr_score": "number|null",
    "vpr_v2_score": "number|null",
    "epss": "number|null",
    "exploit_available": "boolean|null",
    "known_exploited": "boolean|null"
  },
  "lifecycle": {
    "state": "OPEN|FIXED|REOPENED|...",
    "first_found": "datetime",
    "last_found": "datetime",
    "resurfaced_date": "datetime|null",
    "age_days": "number"
  },
  "evidence": {
    "output": "string|null",
    "port": "number|null",
    "protocol": "string|null",
    "service": "string|null"
  },
  "ops": {
    "source": "string",
    "scan_uuid": "string|null",
    "network_id": "string|null"
  }
}
```

### 3.2 Mapping from your sample
- `finding_id` -> `finding_id`
- `asset.uuid` -> `asset.asset_uuid`
- `asset.hostname` / `asset.fqdn` / `asset.ipv4` / `asset.ipv6` -> asset fields
- `plugin.id` -> `vuln.plugin_id`
- `plugin.cve` plus `plugin.xrefs[type=CVE]` -> deduplicated `vuln.cves`
- `plugin.solution` -> `vuln.solution`
- `severity` + `severity_id` + `plugin.risk_factor` -> risk fields
- `plugin.cvss3_base_score` -> `risk.cvss3_base`
- `plugin.vpr.score` -> `risk.vpr_score`
- `plugin.vpr_v2.score` -> `risk.vpr_v2_score`
- `plugin.epss_score` -> `risk.epss`
- `first_found`, `last_found`, `resurfaced_date`, `state` -> lifecycle fields
- `output`, `port.port`, `port.protocol`, `port.service` -> evidence fields

## 4) Data quality guardrails (important from your sample)
Your sample shows why strict guards are needed:
- `plugin.type` may be `local` while network port data exists (do not infer scan modality from one field alone).
- `vpr_v2.cve_id` can be inconsistent with `plugin.cve` list (treat as auxiliary signal only).
- `epss_score` appears on a non-0..1 scale in sample; normalize explicitly before use.
- `workaround` text can mention other vendors/products; never use as primary remediation unless validated.

Recommended guardrails:
- Prefer `plugin.cve[]` + CVE xrefs as source of truth for CVEs.
- Keep an `anomalies[]` array on each record for mapping inconsistencies.
- Never overwrite original raw fields; store raw JSON blob for auditability.

## 5) Deterministic priority model (LLM-like core)
Do not “generate” priority. Calculate it.

### 5.1 Baseline rules
1. If `severity in {critical, high}` and `state=OPEN` -> candidate for patch queue.
2. If `cve` intersects internal KEV list -> escalate priority by +1 tier.
3. If `exploit_available=true` -> escalate by +1 tier.
4. If `age_days > SLA(severity, asset_criticality)` -> mark `breach=true`.
5. If severity is `info` and no exploitability signal -> route to hygiene backlog, not incident queue.

### 5.2 Example SLA table
- Critical: 7 days
- High: 15 days
- Medium: 30 days
- Low: 60 days
- Info: best effort / no strict SLA

## 6) Template-based outputs (no hallucination)
Generate fixed JSON and optional markdown using templates only.

### 6.1 Ticket payload template (JSON)
```json
{
  "title": "[{{priority}}] {{plugin_name}} on {{hostname}}",
  "owner_group": "{{owner_group}}",
  "asset": "{{hostname}} ({{ipv4}})",
  "finding_id": "{{finding_id}}",
  "severity": "{{severity}}",
  "priority": "{{priority}}",
  "cves": ["{{cve_1}}"],
  "first_found": "{{first_found}}",
  "last_found": "{{last_found}}",
  "remediation": "{{solution}}",
  "evidence": "{{short_output}}",
  "sla_due_date": "{{sla_due_date}}",
  "policy_flags": ["{{flag_1}}"]
}
```

### 6.2 Analyst summary template (markdown)
```md
### {{hostname}} - {{plugin_name}}
- Priority: **{{priority}}** (severity={{severity}}, vpr={{vpr_score}})
- CVEs: {{cves_csv}}
- First/Last seen: {{first_found}} / {{last_found}}
- Evidence: {{short_output}}
- Recommended action: {{solution}}
- SLA due: {{sla_due_date}} ({{breach_status}})
```

## 7) MVP data flow (practical)
1. **Ingest**: read Tenable API JSON export.
2. **Normalize**: transform to canonical schema + anomalies.
3. **Enrich**: optional KEV/exploit feeds, owner mapping.
4. **Score**: deterministic priority + SLA.
5. **Render**: JSON ticket payload + markdown summary.
6. **Review**: human approval gate for high/critical actions.
7. **Dispatch**: create/update tickets in ITSM.

## 8) Suggested implementation split
- `normalizer`: field mapping + type coercion + anomaly capture.
- `policy_engine`: priority/SLA/routing rules.
- `renderer`: deterministic JSON + markdown templates.
- `exporter`: write files or POST to ticketing API.

## 9) Security and governance
- Remove or mask sensitive fields before sharing outside VM team.
- Keep provenance: every output should include source finding_id and scan UUID.
- Log rule version used for each priority decision.
- Require explicit approval workflow for any auto-close or deferred risk acceptance.

## 10) What to provide next (safe and useful)
To move from design to implementation quickly, share:
- 20-50 sanitized findings across severities,
- your asset-to-owner mapping format,
- your SLA policy (or confirm the default table above),
- target output channel (Jira, ServiceNow, CSV, markdown, API).

## 11) What to build first (answer to your question)
Start with a **routing library**, then add a lightweight algorithm on top.

Why this order:
- You can reliably export data from Tenable now.
- `plugin.id` is usually the most stable key over time.
- Deterministic team routing is the highest immediate value (ticket ownership and accountability).

### 11.1 Phase 1: routing library (required)
Create a versioned mapping table like:
- `plugin_id -> owner_team`
- optional overrides: `plugin_id + asset_tag -> owner_team`
- fallback: `plugin_family -> owner_team`

Recommended fields in the routing table:
- `plugin_id` (primary key for mapping)
- `plugin_name_snapshot` (for human readability only)
- `family`
- `owner_team`
- `default_priority`
- `notes`
- `rule_version`

### 11.2 Phase 2: routing algorithm (small, deterministic)
Apply routing in this order:
1. Exact `plugin_id` + asset override match
2. Exact `plugin_id` match
3. `plugin.family` match
4. default `vm-triage` queue

Then append confidence labels:
- `HIGH`: exact plugin_id rule
- `MEDIUM`: family-based rule
- `LOW`: default queue fallback

### 11.3 Why not start with plugin name/description/output?
- `plugin.name` can change between plugin versions.
- `description` and `output` are useful as evidence, but noisy for ownership logic.
- `plugin.id` is best for deterministic mapping; use name/family as human context and fallback only.

### 11.4 Minimal starter artifact
A simple CSV or YAML is enough to begin:
```yaml
rules:
  - plugin_id: 156641
    owner_team: collaboration-platform
    default_priority: P2
  - plugin_id: 50344
    owner_team: web-platform
    default_priority: P4
family_fallbacks:
  - family: "Windows : Microsoft Bulletins"
    owner_team: windows-server
  - family: "CGI abuses"
    owner_team: appsec
default_owner_team: vm-triage
rule_version: "2026-02-11"
```
