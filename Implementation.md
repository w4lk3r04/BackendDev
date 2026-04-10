# Implementation Plan: API and Repository Security Audit

## 1 - Project Overview
Project name: Sentinel Audit

Goal: Build a practical security-audit toolchain that can:
1. Analyze an OpenAPI spec (JSON/YAML) for common API security risks.
2. Analyze repository hygiene and secret exposure risks.
3. Produce machine-readable and Markdown reports for triage.

Initial approach: Node.js CLI side-project in this repository, isolated from existing backend code.

## 2 - Scope for MVP
In scope:
1. Static OpenAPI checks aligned with OWASP API Security Top 10 signals.
2. Static repo checks (secret patterns, dangerous files, Docker hardening hints).
3. JSON and Markdown report output.

Out of scope (MVP):
1. Live DAST scanning against running endpoints.
2. Full SAST with AST/dataflow engines.
3. Continuous dashboard UI.

## 3 - High-Level Architecture
Core modules:
1. parser: Reads and normalizes OpenAPI specs.
2. api-checks: Runs rule-based API checks.
3. repo-checks: Scans files and metadata for baseline security issues.
4. report: Aggregates findings and writes outputs.
5. cli: Entry point to run scans and save reports.

Data flow:
1. User runs CLI with spec path and repo path.
2. Parser loads OpenAPI file.
3. API checks and repo checks run independently.
4. Findings are merged with score/severity summary.
5. JSON and Markdown reports are written to disk.

## 4 - Finding Model (baseline)
Each finding must include:
1. id
2. type
3. severity (critical, high, medium, low, info)
4. category (api or repo)
5. title
6. description
7. evidence
8. remediation

## 5 -Baseline Rule Set
API checks:
1. Missing security requirements on operations.
2. Mutating methods (POST/PUT/PATCH/DELETE) without request schema.
3. Missing non-2xx response definitions.
4. Suspicious use of additionalProperties: true in request models.

Repository checks:
1. Potential hardcoded secrets by regex pattern.
2. Presence of .env with sensitive keys.
3. Dockerfile running as root (missing USER).

## 6 - Roadmap
Phase 0 (done in this baseline):
1. CLI scaffold
2. OpenAPI parser
3. API and repo baseline checks
4. JSON/Markdown reporting

Phase 1:
1. Rule suppression file (.auditignore)
2. Configurable severity policy
3. CI integration via exit codes

Phase 2:
1. Git history secret scanning (entropy + diff context)
2. AuthZ heuristics for BOLA/BFLA indicators
3. SARIF export for code scanning platforms

Phase 3:
1. Optional local LLM reviewer to enrich remediation text
2. Endpoint risk ranking with confidence metrics

## 7 - Baseline Files to Create
Create a dedicated side-project folder:
1. security-audit/package.json
2. security-audit/README.md
3. security-audit/src/index.js
4. security-audit/src/parser/openapi.js
5. security-audit/src/checks/apiChecks.js
6. security-audit/src/checks/repoChecks.js
7. security-audit/src/report/writer.js
8. security-audit/src/utils/fs.js

## 8 - Execution Plan
1. Install dependencies in security-audit.
2. Run scanner against a target OpenAPI spec and repository path.
3. Review findings, tune regex/rules, and add suppression support.
4. Integrate into CI once false-positive rate is acceptable.

## 9 - Success Criteria
1. A first report is generated in under 30 seconds for medium repos.
2. Findings are reproducible and traceable to file paths and endpoints.
3. Team can run audit locally with one command.