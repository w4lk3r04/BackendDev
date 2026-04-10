const fs = require('fs');
const path = require('path');

function ensureDirForFile(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function renderMarkdown(report) {
  const lines = [];
  lines.push('# Security Audit Report');
  lines.push('');
  lines.push(`Generated at: ${report.metadata.generatedAt}`);
  lines.push(`Spec path: ${report.metadata.specPath}`);
  lines.push(`Repo path: ${report.metadata.repoPath}`);
  lines.push(`Total findings: ${report.metadata.totalFindings}`);
  lines.push('');
  lines.push('## Severity Summary');
  lines.push('');
  lines.push(`- Critical: ${report.metadata.summary.critical}`);
  lines.push(`- High: ${report.metadata.summary.high}`);
  lines.push(`- Medium: ${report.metadata.summary.medium}`);
  lines.push(`- Low: ${report.metadata.summary.low}`);
  lines.push(`- Info: ${report.metadata.summary.info}`);
  lines.push('');
  lines.push('## Findings');
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('No findings detected.');
    return `${lines.join('\n')}\n`;
  }

  for (const finding of report.findings) {
    lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push('');
    lines.push(`- ID: ${finding.id}`);
    lines.push(`- Category: ${finding.category}`);
    lines.push(`- Type: ${finding.type}`);
    lines.push(`- Description: ${finding.description}`);
    lines.push(`- Remediation: ${finding.remediation}`);
    lines.push(`- Evidence: ${JSON.stringify(finding.evidence)}`);
    lines.push('');
  }

  return `${lines.join('\n')}\n`;
}

function writeReports(report, outputPrefix) {
  const jsonPath = `${outputPrefix}.json`;
  const mdPath = `${outputPrefix}.md`;

  ensureDirForFile(jsonPath);
  ensureDirForFile(mdPath);

  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  fs.writeFileSync(mdPath, renderMarkdown(report), 'utf8');

  return { jsonPath, mdPath };
}

module.exports = {
  writeReports
};
