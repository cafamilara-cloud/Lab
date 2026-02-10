# LLM-like planning guide for vulnerability management (Tenable export)

## 1. Clarify the goal and outputs
- Decide what the system should produce (e.g., remediation summaries, ticket routing, risk narratives, asset group summaries, executive dashboards).
- Define who the outputs are for (SOC analysts, vulnerability management team, asset owners, leadership).
- Decide the level of automation vs. human review.
- If the system is only LLM-like (templated or rules-based), define the limits of generation and where deterministic logic is required.

## 2. Inventory and understand the Tenable export
- Identify the export format (CSV, JSON, Nessus, etc.).
- Document the key fields you have available, such as:
  - Asset identifiers (IP, hostname, asset UUID)
  - Plugin/Vulnerability identifiers (CVE, plugin ID)
  - Severity/risk score (CVSS, VPR)
  - Detection time, last seen
  - Plugin description, solution, references
- Verify data quality (missing fields, duplicates, stale records).

## 3. Normalize and enrich
- Build a normalization step so every record has consistent keys.
- Enrich with external data if required (CVE descriptions, CISA KEV, exploit availability).
- Map assets to owners or business units (CMDB, asset inventory).

## 4. Deterministic logic first (LLM-like behavior)
- Define structured rules for:
  - severity-to-priority mapping
  - SLA/patch windows by asset criticality
  - routing to asset owners or business units
- Use templates for summaries with data-filled slots to keep outputs predictable.

## 5. Data model and storage
- Choose a storage layer for retrieval (PostgreSQL, vector store, or hybrid).
- Recommended baseline schema:
  - Assets
  - Findings (asset, vulnerability, evidence, detection timestamps)
  - Vulnerabilities (CVE, severity, exploitability)
  - Ownership / business context

## 6. Retrieval strategy (RAG)
- Use retrieval to provide relevant findings and context to the LLM-like system.
- Example retrieval queries:
  - “Summarize critical vulnerabilities for business unit X in the last 30 days.”
  - “Generate remediation guidance for CVE-2023-XXXX across all assets.”

## 7. Prompt or template patterns
- If using an actual LLM:
  - Provide explicit instructions: “Only use the provided data.”
  - Include a JSON schema for expected outputs.
- If using templates/rules:
  - Keep output schema fixed.
  - Use deterministic logic for severity ordering and priority labeling.
- Provide a summary of key context (asset, vulnerability, last seen, remediation steps).

## 8. Validation and governance
- Add guardrails for data privacy and secrets.
- Create evaluation metrics:
  - factual correctness
  - coverage of critical vulnerabilities
  - usability for remediation teams
- Require human review for final remediation actions.

## 9. Initial MVP scope (recommended)
- Start with a narrow, high-value use case:
  - “Generate remediation summaries for critical findings per asset group.”
- Build a simple pipeline:
  - ingest Tenable export
  - normalize to a database
  - retrieve relevant data
  - generate LLM-like output (templated or LLM-assisted)

## 10. Suggested next questions to answer
- What format is the Tenable export in?
- How frequently will you refresh the data?
- What LLM infrastructure is allowed (cloud vs. on-prem)?
- Who are the consumers of the outputs?
- What is the minimum viable outcome you need first?
