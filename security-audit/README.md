# Security Audit Baseline

This side project provides a baseline CLI to audit:
1. OpenAPI specifications (JSON or YAML)
2. Repository security hygiene

## Quick Start
1. Install dependencies:
   npm install
2. Run an audit:
   node src/index.js --spec /path/to/openapi.yaml --repo .. --out ./reports/audit-report

## Output
Two files are generated:
1. `<out>.json`
2. `<out>.md`

## Supported Baseline Checks
API checks:
1. Missing operation security requirements
2. Mutating operations without request body schema
3. Operations without non-2xx responses
4. Request schema with additionalProperties: true

Repository checks:
1. Hardcoded secret patterns
2. Potentially sensitive keys in .env
3. Dockerfile missing non-root USER

## Notes
This is a baseline scanner focused on fast local feedback. Extend rule coverage and add suppressions before enforcing in CI.
