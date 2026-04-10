const path = require('path');
const { loadOpenApiSpec } = require('./parser/openapi');
const { runApiChecks } = require('./checks/apiChecks');
const { runRepoChecks } = require('./checks/repoChecks');
const { writeReports } = require('./report/writer');

function parseArgs(argv) {
  const args = { spec: null, repo: null, out: './reports/audit-report' };

  for (let i = 2; i < argv.length; i += 1) {
    const token = argv[i];
    const next = argv[i + 1];
    if (token === '--spec') {
      args.spec = next;
      i += 1;
    } else if (token === '--repo') {
      args.repo = next;
      i += 1;
    } else if (token === '--out') {
      args.out = next;
      i += 1;
    }
  }

  return args;
}

function usage() {
  console.log('Usage: node src/index.js --spec <openapi.yaml|json> --repo <repoPath> [--out <outputPrefix>]');
}

function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    if (bySeverity[finding.severity] === undefined) {
      bySeverity.info += 1;
    } else {
      bySeverity[finding.severity] += 1;
    }
  }
  return bySeverity;
}

async function main() {
  const args = parseArgs(process.argv);

  if (!args.spec || !args.repo) {
    usage();
    process.exitCode = 1;
    return;
  }

  const specPath = path.resolve(process.cwd(), args.spec);
  const repoPath = path.resolve(process.cwd(), args.repo);
  const outPrefix = path.resolve(process.cwd(), args.out);

  const spec = loadOpenApiSpec(specPath);
  const apiFindings = runApiChecks(spec);
  const repoFindings = runRepoChecks(repoPath);
  const findings = [...apiFindings, ...repoFindings];
  const summary = summarize(findings);

  const report = {
    metadata: {
      generatedAt: new Date().toISOString(),
      specPath,
      repoPath,
      totalFindings: findings.length,
      summary
    },
    findings
  };

  const outputs = writeReports(report, outPrefix);
  console.log(`Audit complete. Findings: ${findings.length}`);
  console.log(`JSON report: ${outputs.jsonPath}`);
  console.log(`Markdown report: ${outputs.mdPath}`);
}

main().catch((error) => {
  console.error('Audit failed:', error.message);
  process.exitCode = 1;
});
