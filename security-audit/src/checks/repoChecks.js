const fs = require('fs');
const path = require('path');
const { walkFiles } = require('../utils/fs');

const DEFAULT_IGNORES = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);
const MAX_FILE_SIZE_BYTES = 1024 * 1024;

const SECRET_PATTERNS = [
  { name: 'aws_access_key_id', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'generic_api_key', regex: /(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]/gi },
  { name: 'private_key_block', regex: /-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----/g }
];

function pushFinding(findings, finding) {
  findings.push({
    category: 'repo',
    ...finding
  });
}

function isIgnored(relativePath) {
  const parts = relativePath.split(path.sep);
  return parts.some((part) => DEFAULT_IGNORES.has(part));
}

function safeReadText(filePath) {
  const stat = fs.statSync(filePath);
  if (stat.size > MAX_FILE_SIZE_BYTES) {
    return null;
  }
  return fs.readFileSync(filePath, 'utf8');
}

function checkSecrets(findings, repoPath, files) {
  for (const filePath of files) {
    const relativePath = path.relative(repoPath, filePath);
    if (isIgnored(relativePath)) {
      continue;
    }

    let content;
    try {
      content = safeReadText(filePath);
    } catch {
      continue;
    }

    if (!content) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(content);
      if (match) {
        pushFinding(findings, {
          id: `REPO-SECRET-${pattern.name}-${relativePath}`,
          type: 'potential_hardcoded_secret',
          severity: 'high',
          title: `Potential secret found in ${relativePath}`,
          description: `Detected pattern ${pattern.name} in repository content.`,
          evidence: { file: relativePath, sample: match[0].slice(0, 80) },
          remediation: 'Move secrets to environment variables or secret manager and rotate exposed credentials.'
        });
      }
    }
  }
}

function checkDotEnv(findings, repoPath) {
  const envPath = path.join(repoPath, '.env');
  if (!fs.existsSync(envPath)) {
    return;
  }

  let content = '';
  try {
    content = fs.readFileSync(envPath, 'utf8');
  } catch {
    return;
  }

  const sensitiveKeys = ['PASSWORD', 'SECRET', 'TOKEN', 'API_KEY', 'PRIVATE_KEY'];
  const found = sensitiveKeys.filter((key) => content.toUpperCase().includes(`${key}=`));

  if (found.length > 0) {
    pushFinding(findings, {
      id: 'REPO-DOTENV-SENSITIVE-KEYS',
      type: 'dotenv_contains_sensitive_keys',
      severity: 'medium',
      title: '.env contains sensitive key names',
      description: 'The repository .env file appears to contain sensitive entries.',
      evidence: { file: '.env', keys: found },
      remediation: 'Keep .env out of source control and use environment-specific secret injection in deployment.'
    });
  }
}

function checkDockerfile(findings, repoPath) {
  const dockerPath = path.join(repoPath, 'Dockerfile');
  if (!fs.existsSync(dockerPath)) {
    return;
  }

  let content = '';
  try {
    content = fs.readFileSync(dockerPath, 'utf8');
  } catch {
    return;
  }

  const hasUserDirective = /^\s*USER\s+/im.test(content);
  if (!hasUserDirective) {
    pushFinding(findings, {
      id: 'REPO-DOCKERFILE-NO-USER',
      type: 'dockerfile_runs_as_root',
      severity: 'medium',
      title: 'Dockerfile does not set a non-root user',
      description: 'No USER directive detected; container may run as root.',
      evidence: { file: 'Dockerfile' },
      remediation: 'Create and switch to a least-privileged user in Dockerfile before runtime.'
    });
  }
}

function runRepoChecks(repoPath) {
  if (!fs.existsSync(repoPath)) {
    throw new Error(`Repository path not found: ${repoPath}`);
  }

  const findings = [];
  const files = walkFiles(repoPath);
  checkSecrets(findings, repoPath, files);
  checkDotEnv(findings, repoPath);
  checkDockerfile(findings, repoPath);

  return findings;
}

module.exports = {
  runRepoChecks
};
