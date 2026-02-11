# LLM-Like Implementation Guide for Vulnerability Ownership (Tenable Export)
LLM-Like Implementation Guide for Vulnerability Ownership (Tenable Export)

This guide describes a deterministic, explainable ownership engine for Tenable vulnerability data.

The system behaves like an LLM in structure (rules + templates), but all routing decisions are strictly rule-based and auditable.

This module does not compute priority, SLA, or generate tickets. Its sole responsibility is assigning owner teams to findings.

## 1) Goal: Deterministic, Explainable Team Assignment

Build a pipeline that:
- ingests Tenable vulnerability JSON,
- normalizes findings into a stable schema,
- applies deterministic routing rules,
- outputs enriched JSON with assigned ownership metadata.

The output must be:
- machine-consumable,
- reusable across applications,
- fully auditable,
- configuration-driven.

## 2) Confirmed Available Data (From Sample Payload)

Each Tenable finding provides sufficient information for ownership routing.

### Asset Context
- `hostname`
- `fqdn`
- `ipv4` / `ipv6`
- `operating_system`
- `asset.uuid`

### Vulnerability Context
- `plugin.id`
- `plugin.name`
- `plugin.family`
- `plugin.description`
- `plugin.solution`
- `plugin.cve`
- `plugin.xrefs`

### Lifecycle Context
- `finding_id`
- `state`
- `first_found`
- `last_found`
- `resurfaced_date`

### Evidence Context
- plugin output
- `port` / `protocol` / `service`

No risk scoring or priority logic is required for this module.

## 3) Canonical Normalized Finding Schema

All routing must operate against a fixed schema to ensure consistency.

### 3.1 Canonical Structure
```json
{
  "finding_id": "string",
1) Goal: Deterministic, Explainable Team Assignment

Build a pipeline that:

Ingests Tenable vulnerability JSON

Normalizes findings into a stable schema

Applies deterministic routing rules

Outputs enriched JSON with assigned ownership metadata

The output must be:

Machine-consumable

Reusable across applications

Fully auditable

Configuration-driven

2) Confirmed Available Data (From Sample Payload)

Each Tenable finding provides sufficient information for ownership routing:

Asset Context

hostname

fqdn

ipv4 / ipv6

operating_system

asset.uuid

Vulnerability Context

plugin.id

plugin.name

plugin.family

plugin.description

plugin.solution

plugin.cve

plugin.xrefs

Lifecycle Context

finding_id

state

first_found

last_found

resurfaced_date

Evidence Context

plugin output

port / protocol / service

No risk scoring or priority logic is required for this module.

3) Canonical Normalized Finding Schema

All routing must operate against a fixed schema to ensure consistency.

3.1 Canonical Structure
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

4) Data Quality Guardrails

Strict data handling ensures deterministic routing.

CVE Trust Hierarchy

plugin.cve[]

plugin.xrefs where type == CVE

Auxiliary CVE references (informational only)

Always deduplicate CVE lists.

Do Not Infer

Do not infer ownership from plugin description text.

Do not use plugin output for routing.

Do not use workaround text as primary decision logic.

Do not rely on plugin name (may change between versions).

Primary routing key must be plugin.id.

Preserve Raw Data

Always retain original raw finding JSON for audit and replay capability.

5) Deterministic Routing Model

Ownership must be resolved using rule evaluation in strict order.

5.1 Routing Precedence

Exact match: plugin_id + optional asset override

Exact match: plugin_id

Fallback: plugin.family

Default owner team

No probabilistic matching.
No natural language inference.
No partial matching.

6) Routing Rule Configuration (YAML)

Routing logic must live outside code in a versioned configuration file.

Example:

rule_version: "2026-02-11"

rules:
  - id: rule-156641
    plugin_id: 156641
    owner_team: collaboration-platform

  - id: rule-50344
    plugin_id: 50344
    owner_team: web-platform

family_fallbacks:
  - id: fam-001
    family: "Windows : Microsoft Bulletins"
    owner_team: windows-server

default_owner_team: vm-triage


Configuration must be:

Version controlled

Reviewed before deployment

Auditable over time

7) Ownership Output Block

Each enriched finding must append an ownership block.

Example:

"ownership": {
  "owner_team": "windows-server",
  "routing_match_type": "plugin_id",
  "routing_confidence": "HIGH",
  "routing_rule_id": "rule-156641",
  "routing_rule_version": "2026-02-11"
}

Confidence Labels

HIGH → Exact plugin_id match

MEDIUM → Family fallback

LOW → Default fallback

Confidence is informational only and must be deterministic.

8) Output Format

Canonical output format: JSON

Recommended storage format for scale: JSON Lines (JSONL)

Example:

{ enriched_finding_1 }
{ enriched_finding_2 }
{ enriched_finding_3 }


Advantages:

Stream processing

Append-friendly

Scalable for large scans

Easily consumed by APIs and downstream systems

CSV may be generated separately for reporting but must not be the system-of-record.

9) Modular System Design

This module must have a single responsibility: assign ownership.

Suggested pipeline structure:

Ingest → Normalize → Ownership Engine → Output JSON


No coupling with:

Priority engines

SLA engines

Ticketing systems

Risk scoring logic

Separation of concerns ensures reuse across applications.

10) Governance Requirements

Each enriched record must include metadata:

"governance": {
  "engine_version": "1.0.0",
  "routing_rule_version": "2026-02-11",
  "generated_at": "2026-02-11T05:10:00Z"
}


This ensures:

Traceability of rule decisions

Audit defensibility

Change control visibility

Reproducibility

11) Minimal Implementation Order

Normalize Tenable findings into canonical schema

Load routing_rules.yaml

Apply deterministic routing

Append ownership block

Write enriched JSON output

Do not introduce additional enrichment logic until routing stability is achieved.

12) Design Principle

This system must behave like a governed rules engine.

Deterministic

Explainable

Configuration-driven

Audit-ready

Modular

LLM-style assistance, if ever introduced, must never override routing decisions.

The ownership engine is authoritative.
Configuration defines behavior.
Output remains structured and machine-verifiable.
