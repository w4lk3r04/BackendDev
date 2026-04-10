const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const MUTATING_METHODS = new Set(['post', 'put', 'patch', 'delete']);

function pushFinding(findings, finding) {
  findings.push({
    category: 'api',
    ...finding
  });
}

function hasDefinedSecurity(operation, spec) {
  if (Array.isArray(operation.security) && operation.security.length > 0) {
    return true;
  }

  if (Array.isArray(spec.security) && spec.security.length > 0) {
    return true;
  }

  return false;
}

function hasRequestSchema(operation) {
  const reqBody = operation.requestBody;
  if (!reqBody || !reqBody.content || typeof reqBody.content !== 'object') {
    return false;
  }

  return Object.values(reqBody.content).some((contentType) => contentType && contentType.schema);
}

function hasErrorResponse(operation) {
  const responses = operation.responses || {};
  const codes = Object.keys(responses);
  return codes.some((code) => code.startsWith('4') || code.startsWith('5') || code === 'default');
}

function requestSchemaAllowsAdditionalProperties(operation) {
  const reqBody = operation.requestBody;
  if (!reqBody || !reqBody.content) {
    return false;
  }

  for (const contentType of Object.values(reqBody.content)) {
    const schema = contentType && contentType.schema;
    if (!schema || typeof schema !== 'object') {
      continue;
    }

    if (schema.additionalProperties === true) {
      return true;
    }
  }

  return false;
}

function runApiChecks(spec) {
  const findings = [];
  const paths = spec.paths || {};

  for (const [apiPath, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') {
      continue;
    }

    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!operation || typeof operation !== 'object') {
        continue;
      }

      const opId = operation.operationId || `${method.toUpperCase()} ${apiPath}`;

      if (!hasDefinedSecurity(operation, spec)) {
        pushFinding(findings, {
          id: `API-MISSING-SECURITY-${method}-${apiPath}`,
          type: 'missing_security_requirement',
          severity: 'high',
          title: `Missing security requirement on ${opId}`,
          description: 'The operation does not define operation-level or global security requirements.',
          evidence: { path: apiPath, method },
          remediation: 'Define a security scheme in components.securitySchemes and apply it globally or per operation.'
        });
      }

      if (MUTATING_METHODS.has(method) && !hasRequestSchema(operation)) {
        pushFinding(findings, {
          id: `API-NO-REQ-SCHEMA-${method}-${apiPath}`,
          type: 'mutating_method_without_request_schema',
          severity: 'medium',
          title: `Missing request schema for ${opId}`,
          description: 'Mutating operations should define request body schema to reduce input ambiguity and over-posting risk.',
          evidence: { path: apiPath, method },
          remediation: 'Add requestBody.content.<mime>.schema for mutating operations.'
        });
      }

      if (!hasErrorResponse(operation)) {
        pushFinding(findings, {
          id: `API-NO-ERROR-RESP-${method}-${apiPath}`,
          type: 'missing_error_responses',
          severity: 'low',
          title: `No non-2xx responses declared for ${opId}`,
          description: 'The operation does not declare 4xx/5xx responses or default fallback.',
          evidence: { path: apiPath, method },
          remediation: 'Add explicit 4xx and 5xx response models with error payload structure.'
        });
      }

      if (requestSchemaAllowsAdditionalProperties(operation)) {
        pushFinding(findings, {
          id: `API-ADDITIONAL-PROPS-${method}-${apiPath}`,
          type: 'request_schema_allows_additional_properties',
          severity: 'medium',
          title: `Request schema allows additionalProperties for ${opId}`,
          description: 'Permissive request schema may increase mass-assignment and unwanted input risks.',
          evidence: { path: apiPath, method },
          remediation: 'Set additionalProperties to false where strict field-level input control is required.'
        });
      }
    }
  }

  return findings;
}

module.exports = {
  runApiChecks
};
