const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

function loadOpenApiSpec(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`OpenAPI file not found: ${filePath}`);
  }

  const ext = path.extname(filePath).toLowerCase();
  const raw = fs.readFileSync(filePath, 'utf8');
  let parsed;

  if (ext === '.yaml' || ext === '.yml') {
    parsed = yaml.load(raw);
  } else if (ext === '.json') {
    parsed = JSON.parse(raw);
  } else {
    try {
      parsed = JSON.parse(raw);
    } catch (jsonError) {
      parsed = yaml.load(raw);
    }
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Invalid OpenAPI document. Expected a JSON/YAML object.');
  }

  if (!parsed.paths || typeof parsed.paths !== 'object') {
    throw new Error('Invalid OpenAPI document. Missing paths object.');
  }

  return parsed;
}

module.exports = {
  loadOpenApiSpec
};
