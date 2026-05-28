/**
 * Static analysis layer — runs all 10 OWASP Agentic AI checks without any
 * external API calls. Works offline and requires no API key.
 */
import type { AgentMetadata, StaticFinding, Severity } from '../types';

// Sensitive tool name keywords that warrant human approval
const SENSITIVE_TOOL_KEYWORDS = ['email', 'send', 'message', 'delete', 'remove', 'drop', 'pay', 'payment', 'charge', 'transfer', 'deploy', 'publish', 'shell', 'exec', 'bash', 'sql', 'database', 'notify'];

// Tools that are clearly destructive
const DESTRUCTIVE_KEYWORDS = ['delete', 'remove', 'drop', 'destroy', 'purge', 'wipe', 'truncate', 'terminate'];

// Map model IDs to tier for performance scoring
const EXPENSIVE_MODELS = ['claude-opus', 'gpt-4o', 'gemini-1.5-pro'];
const BUDGET_MODELS = ['claude-haiku', 'gpt-4o-mini', 'gemini-1.5-flash', 'deepseek', 'llama', 'mistral-small'];

function passed(ruleId: string, title: string, message: string): StaticFinding {
  return { ruleId, severity: 'LOW', title, message, passed: true };
}

function finding(ruleId: string, severity: Severity, title: string, message: string, location?: string): StaticFinding {
  return { ruleId, severity, title, message, location, passed: false };
}

function hasSensitiveTool(metadata: AgentMetadata): string | null {
  for (const tool of metadata.tools) {
    if (SENSITIVE_TOOL_KEYWORDS.some((kw) => tool.name.toLowerCase().includes(kw))) {
      return tool.name;
    }
  }
  return null;
}

function hasDestructiveTool(metadata: AgentMetadata): string | null {
  for (const tool of metadata.tools) {
    if (DESTRUCTIVE_KEYWORDS.some((kw) => tool.name.toLowerCase().includes(kw))) {
      return tool.name;
    }
    if (tool.permissions.includes('delete')) return tool.name;
  }
  return null;
}

// OAA-01: Prompt Injection
function checkPromptInjection(metadata: AgentMetadata): StaticFinding {
  // Risk is elevated if agent has write/execute tools and processes external content
  const hasExternalInputTools = metadata.tools.some((t) =>
    ['search', 'browse', 'fetch', 'web', 'read', 'scrape', 'email', 'message'].some((kw) => t.name.toLowerCase().includes(kw))
  );

  const hasDangerousPerms = metadata.tools.some((t) =>
    t.permissions.some((p) => ['write', 'delete', 'execute'].includes(p))
  );

  if (hasExternalInputTools && hasDangerousPerms) {
    return finding(
      'OAA-01',
      'CRITICAL',
      'Prompt Injection Risk',
      'Agent reads external content (web/email/files) and has write/delete tools — high prompt injection risk. An attacker-controlled document could instruct the agent to execute destructive actions.',
      'Tools with external read + write/delete permissions'
    );
  }

  if (hasExternalInputTools) {
    return finding(
      'OAA-01',
      'HIGH',
      'Prompt Injection Risk',
      'Agent processes external content (web/email/documents). Without input sanitization, malicious content could hijack agent behavior.',
      'External input tools detected'
    );
  }

  return passed('OAA-01', 'Prompt Injection', 'No high-risk external input + write/delete combination detected.');
}

// OAA-02: Over-permissioned Tools
function checkOverPermissioned(metadata: AgentMetadata): StaticFinding[] {
  const findings: StaticFinding[] = [];

  if (metadata.tools.length === 0) {
    findings.push(passed('OAA-02', 'Over-permissioned Tools', 'No tools to evaluate.'));
    return findings;
  }

  const overPermissioned = metadata.tools.filter((t) =>
    t.permissions.includes('delete') || t.permissions.includes('execute') || t.permissions.includes('admin')
  );

  if (overPermissioned.length > 0) {
    for (const tool of overPermissioned) {
      const dangerPerms = tool.permissions.filter((p) => ['delete', 'execute', 'admin'].includes(p));
      findings.push(
        finding(
          'OAA-02',
          'HIGH',
          'Over-permissioned Tool',
          `Tool "${tool.name}" has ${dangerPerms.join('/')} permission. Verify this is the minimum required for the task.`,
          `Tool: ${tool.name}`
        )
      );
    }
  } else {
    findings.push(passed('OAA-02', 'Over-permissioned Tools', 'No tools with delete/execute/admin permissions detected.'));
  }

  return findings;
}

// OAA-03: Missing Human Approval on Sensitive Actions
function checkHumanApproval(metadata: AgentMetadata): StaticFinding {
  const sensitiveTool = hasSensitiveTool(metadata);
  const destructiveTool = hasDestructiveTool(metadata);

  if (!metadata.hasHumanApproval) {
    if (destructiveTool) {
      return finding(
        'OAA-03',
        'CRITICAL',
        'No Human Approval on Destructive Action',
        `Tool "${destructiveTool}" can delete or destroy data with no human approval gate. A single malicious prompt could cause irreversible data loss.`,
        `Tool: ${destructiveTool}`
      );
    }
    if (sensitiveTool) {
      return finding(
        'OAA-03',
        'CRITICAL',
        'No Human Approval on Sensitive Action',
        `Tool "${sensitiveTool}" performs a sensitive action (email, payment, deploy) without requiring human confirmation. This is a high-impact risk.`,
        `Tool: ${sensitiveTool}`
      );
    }
    if (metadata.tools.some((t) => t.permissions.includes('write'))) {
      return finding(
        'OAA-03',
        'HIGH',
        'No Human Approval on Write Actions',
        'Agent has write-permission tools but no human approval mechanism detected. Consider adding a confirmation step for state-changing operations.',
        'Write-permission tools'
      );
    }
  }

  return passed('OAA-03', 'Human Approval', 'Human approval mechanism detected or no sensitive tools found.');
}

// OAA-04: Hardcoded Secrets
function checkHardcodedSecrets(metadata: AgentMetadata): StaticFinding {
  if (metadata.potentialSecrets && metadata.potentialSecrets.length > 0) {
    const locations = metadata.potentialSecrets
      .slice(0, 3)
      .map((s) => `${s.file}:${s.line} (${s.pattern})`)
      .join(', ');

    return finding(
      'OAA-04',
      'CRITICAL',
      'Potential Hardcoded Credentials',
      `Found ${metadata.potentialSecrets.length} potential secret(s) in source files. Rotate these immediately and move to environment variables.`,
      locations
    );
  }

  return passed('OAA-04', 'Hardcoded Credentials', 'No hardcoded credentials detected in scanned files.');
}

// OAA-05: Tool Scope Creep
function checkToolScopeCreep(metadata: AgentMetadata): StaticFinding {
  if (!metadata.description || metadata.tools.length === 0) {
    return passed('OAA-05', 'Tool Scope', 'Not enough metadata to evaluate tool scope.');
  }

  const desc = metadata.description.toLowerCase();

  // Heuristic: if agent is described as "read-only" or "search" but has write/delete tools
  const isDescribedReadOnly = /read.?only|fetch|search|lookup|query|retrieve/.test(desc);
  const hasWriteDelete = metadata.tools.some((t) =>
    t.permissions.some((p) => ['write', 'delete', 'execute'].includes(p))
  );

  if (isDescribedReadOnly && hasWriteDelete) {
    return finding(
      'OAA-05',
      'MEDIUM',
      'Tool Scope Creep',
      'Agent is described as read/search/lookup but has tools with write or delete permissions. Verify all tools are necessary for the stated purpose.',
      'Description vs. tool permissions mismatch'
    );
  }

  if (metadata.tools.length > 10) {
    return finding(
      'OAA-05',
      'MEDIUM',
      'Large Tool Surface Area',
      `Agent has ${metadata.tools.length} tools. A large tool surface increases the attack surface and the risk of unintended actions.`,
      `${metadata.tools.length} tools registered`
    );
  }

  return passed('OAA-05', 'Tool Scope', 'Tool set appears consistent with stated agent purpose.');
}

// OAA-06: Missing Error Handling
function checkErrorHandling(metadata: AgentMetadata): StaticFinding {
  if (metadata.source === 'scan' && metadata.hasErrorHandling === undefined) {
    return passed('OAA-06', 'Error Handling', 'Could not determine error handling status from scan.');
  }

  if (!metadata.hasErrorHandling) {
    return finding(
      'OAA-06',
      'MEDIUM',
      'Missing Error Handling',
      'No error handling or fallback strategy detected. Tool failures could leave the agent in an undefined state or cause cascading failures.',
      metadata.source === 'scan' ? 'Source files analyzed' : 'User-reported'
    );
  }

  return passed('OAA-06', 'Error Handling', 'Error handling patterns detected.');
}

// OAA-07: Unconstrained Sub-agent Permissions
function checkSubAgentPermissions(metadata: AgentMetadata): StaticFinding[] {
  if (metadata.subAgents.length === 0) {
    return [passed('OAA-07', 'Sub-agent Permissions', 'No sub-agents detected.')];
  }

  const findings: StaticFinding[] = [];

  for (const agent of metadata.subAgents) {
    if (agent.receivesRawUserInput) {
      findings.push(
        finding(
          'OAA-07',
          'HIGH',
          'Sub-agent Receives Raw User Input',
          `Sub-agent "${agent.name || 'unnamed'}" receives unvalidated user input directly from the orchestrator. This enables prompt injection through the sub-agent pathway.`,
          `Sub-agent: ${agent.name || 'unnamed'}`
        )
      );
    }
  }

  if (findings.length === 0) {
    findings.push(passed('OAA-07', 'Sub-agent Permissions', `${metadata.subAgents.length} sub-agent(s) detected, no raw input pass-through found.`));
  }

  return findings;
}

// OAA-08: No Output Validation
function checkOutputValidation(metadata: AgentMetadata): StaticFinding {
  if (metadata.source === 'scan' && metadata.hasOutputValidation === undefined) {
    return passed('OAA-08', 'Output Validation', 'Could not determine output validation from scan.');
  }

  if (!metadata.hasOutputValidation) {
    return finding(
      'OAA-08',
      'MEDIUM',
      'No Output Validation',
      'No output validation or guardrails detected. Agent outputs could contain PII, policy violations, or hallucinated instructions without detection.',
      metadata.source === 'scan' ? 'Source files analyzed' : 'User-reported'
    );
  }

  return passed('OAA-08', 'Output Validation', 'Output validation layer detected.');
}

// OAA-09: PII Exposure
function checkPiiExposure(metadata: AgentMetadata): StaticFinding {
  const piiRiskTools = metadata.tools.filter((t) =>
    ['crm', 'user', 'customer', 'profile', 'personal', 'contact', 'account', 'member'].some((kw) =>
      t.name.toLowerCase().includes(kw)
    )
  );

  if (piiRiskTools.length > 0 && !metadata.hasOutputValidation) {
    return finding(
      'OAA-09',
      'HIGH',
      'PII Exposure Risk',
      `Tool(s) "${piiRiskTools.map((t) => t.name).join(', ')}" access user/customer data, and no output validation is in place. PII could be leaked in responses.`,
      piiRiskTools.map((t) => t.name).join(', ')
    );
  }

  return passed('OAA-09', 'PII Exposure', 'No high-risk PII exposure pattern detected.');
}

// OAA-10: Missing Rate Limiting
function checkRateLimiting(metadata: AgentMetadata): StaticFinding {
  const externalApiTools = metadata.tools.filter((t) =>
    ['search', 'fetch', 'http', 'web', 'api', 'request', 'browse', 'scrape', 'stripe', 'twilio', 'sendgrid'].some((kw) =>
      t.name.toLowerCase().includes(kw)
    )
  );

  if (externalApiTools.length > 0 && !metadata.hasRateLimiting) {
    return finding(
      'OAA-10',
      'MEDIUM',
      'No Rate Limiting on External API Tools',
      `Tool(s) "${externalApiTools.map((t) => t.name).join(', ')}" call external APIs with no rate limiting. A runaway agent could exhaust quotas or generate unexpected costs.`,
      externalApiTools.map((t) => t.name).join(', ')
    );
  }

  return passed('OAA-10', 'Rate Limiting', 'Rate limiting detected or no external API tools found.');
}

// OAA-11: Self-modifying Agent
function checkSelfModification(metadata: AgentMetadata): StaticFinding {
  const selfModKeywords = ['system_prompt', 'update_prompt', 'set_instruction', 'modify_config', 'write_config', 'patch_agent', 'update_system', 'set_system'];
  const dangerous = metadata.tools.filter((t) => {
    const name = t.name.toLowerCase();
    return selfModKeywords.some((kw) => name.includes(kw)) ||
      (t.permissions.includes('write') && ['prompt', 'instruction', 'config', 'system'].some((kw) => name.includes(kw)));
  });

  if (dangerous.length > 0) {
    return finding(
      'OAA-11',
      'CRITICAL',
      'Self-modifying Agent Risk',
      `Tool(s) "${dangerous.map((t) => t.name).join(', ')}" can write to agent instructions or configuration. A compromised agent could rewrite its own behavior.`,
      dangerous.map((t) => t.name).join(', ')
    );
  }
  return passed('OAA-11', 'Self-modification', 'No tools detected that can modify agent instructions or configuration.');
}

// OAA-12: No Audit Logging
function checkAuditLogging(metadata: AgentMetadata): StaticFinding {
  const sensitiveTools = metadata.tools.filter((t) =>
    t.permissions.some((p) => ['write', 'delete', 'execute'].includes(p))
  );
  if (sensitiveTools.length === 0) {
    return passed('OAA-12', 'Audit Logging', 'No write/delete/execute tools to audit.');
  }

  if (metadata.source === 'scan') {
    if (!metadata.hasAuditLogging) {
      return finding(
        'OAA-12',
        'HIGH',
        'No Audit Logging Detected',
        `Agent has ${sensitiveTools.length} write/delete/execute tool(s) but no audit logging patterns found. State-changing calls are untracked.`,
        sensitiveTools.map((t) => t.name).join(', ')
      );
    }
    return passed('OAA-12', 'Audit Logging', 'Audit logging patterns detected.');
  }

  // Interactive mode: flag as unconfirmed — we can't know from Q&A alone
  return finding(
    'OAA-12',
    'HIGH',
    'Audit Logging Not Confirmed',
    `Agent has ${sensitiveTools.length} write/delete/execute tool(s). Confirm all state-changing calls are logged with timestamp, sanitized input, and outcome.`,
    sensitiveTools.map((t) => t.name).join(', ')
  );
}

// OAA-13: Missing Input Validation
function checkInputValidation(metadata: AgentMetadata): StaticFinding {
  const hasRiskyTools = metadata.tools.some((t) =>
    t.permissions.some((p) => ['write', 'delete', 'execute'].includes(p))
  );
  if (!hasRiskyTools) {
    return passed('OAA-13', 'Input Validation', 'No write/execute tools detected that require strict input validation.');
  }

  if (metadata.source === 'scan') {
    if (!metadata.hasInputValidation) {
      return finding(
        'OAA-13',
        'MEDIUM',
        'No Input Validation Detected',
        'Agent has write/execute tools but no input validation or schema patterns found. Malformed inputs can reach tools directly.',
        'Source files analyzed'
      );
    }
    return passed('OAA-13', 'Input Validation', 'Input validation patterns detected.');
  }

  return finding(
    'OAA-13',
    'MEDIUM',
    'Input Validation Not Confirmed',
    'Agent has write/execute tools but input validation was not confirmed. Without schema validation, malformed inputs can reach tools directly.',
    'Write/execute tools present'
  );
}

// OAA-14: No Tool Timeout
function checkToolTimeout(metadata: AgentMetadata): StaticFinding {
  const externalTools = metadata.tools.filter((t) =>
    ['api', 'http', 'fetch', 'web', 'search', 'browse', 'request', 'call'].some((kw) =>
      t.name.toLowerCase().includes(kw)
    )
  );
  if (externalTools.length === 0) {
    return passed('OAA-14', 'Tool Timeout', 'No external API tools detected.');
  }

  if (metadata.source === 'scan') {
    if (!metadata.hasToolTimeout) {
      return finding(
        'OAA-14',
        'HIGH',
        'No Tool Timeout Detected',
        `${externalTools.length} external tool(s) found but no timeout patterns detected. A network failure can stall the agent indefinitely.`,
        externalTools.map((t) => t.name).join(', ')
      );
    }
    return passed('OAA-14', 'Tool Timeout', 'Timeout patterns detected for external tool calls.');
  }

  return finding(
    'OAA-14',
    'HIGH',
    'Tool Timeout Not Confirmed',
    `${externalTools.length} external tool(s) detected but no timeout configuration was confirmed. A hanging call can block the agent indefinitely.`,
    externalTools.map((t) => t.name).join(', ')
  );
}

// OAA-15: Non-idempotent Write Operations
function checkIdempotency(metadata: AgentMetadata): StaticFinding {
  // Look for tool names that suggest accumulating/appending operations (inherently non-idempotent)
  const nonIdempotentTools = metadata.tools.filter((t) => {
    const name = t.name.toLowerCase();
    return ['append', 'increment', 'add_to', 'push', 'insert'].some((kw) => name.includes(kw));
  });

  if (nonIdempotentTools.length > 0) {
    return finding(
      'OAA-15',
      'MEDIUM',
      'Potentially Non-idempotent Operations',
      `Tool(s) "${nonIdempotentTools.map((t) => t.name).join(', ')}" suggest accumulating operations. Retries or duplicate calls could corrupt data. Ensure idempotency keys are used.`,
      nonIdempotentTools.map((t) => t.name).join(', ')
    );
  }
  return passed('OAA-15', 'Idempotency', 'No non-idempotent accumulation patterns detected.');
}

// OAA-16: Context Window Overflow Risk
const TOOL_COUNT_WARNING_THRESHOLD = 15;
function checkContextOverflow(metadata: AgentMetadata): StaticFinding {
  if (metadata.tools.length > TOOL_COUNT_WARNING_THRESHOLD) {
    return finding(
      'OAA-16',
      'MEDIUM',
      'Context Window Overflow Risk',
      `Agent has ${metadata.tools.length} tools. At this scale, tool definitions alone can consume a significant portion of the context window, degrading reasoning quality and increasing cost.`,
      `${metadata.tools.length} tools registered`
    );
  }
  return passed('OAA-16', 'Context Window', `Tool count (${metadata.tools.length}) is within safe limits.`);
}

// OAA-17: No Fallback Model
function checkFallbackModel(metadata: AgentMetadata): StaticFinding {
  // Only meaningful when we know calls per day (higher volume = higher availability risk)
  const highVolume = metadata.callsPerDay !== undefined && metadata.callsPerDay > 200;
  if (highVolume && metadata.source === 'interactive') {
    return finding(
      'OAA-17',
      'LOW',
      'No Fallback Model',
      `Agent runs ${metadata.callsPerDay} calls/day with no confirmed fallback model. Primary model unavailability causes total agent failure. Consider a secondary model for degraded-mode operation.`,
      'High call volume, single model dependency'
    );
  }
  return passed('OAA-17', 'Fallback Model', 'Low call volume or fallback not required at this scale.');
}

// OAA-18: Missing Session Isolation
function checkSessionIsolation(metadata: AgentMetadata): StaticFinding {
  const dataAccessTools = metadata.tools.filter((t) =>
    ['crm', 'user', 'customer', 'profile', 'account', 'record', 'tenant', 'member'].some((kw) =>
      t.name.toLowerCase().includes(kw)
    )
  );

  if (dataAccessTools.length === 0) {
    return passed('OAA-18', 'Session Isolation', 'No multi-tenant data access tools detected.');
  }

  if (metadata.source === 'scan') {
    return passed('OAA-18', 'Session Isolation', 'Data access tools present — verify tenant/user scoping manually.');
  }

  return finding(
    'OAA-18',
    'HIGH',
    'Session Isolation Not Confirmed',
    `Tool(s) "${dataAccessTools.map((t) => t.name).join(', ')}" access user or customer data. Without user_id/tenant_id scoping, one session could access another user's data.`,
    dataAccessTools.map((t) => t.name).join(', ')
  );
}

// OAA-19: Unconstrained Memory Retention
function checkMemoryRetention(metadata: AgentMetadata): StaticFinding {
  const memoryTools = metadata.tools.filter((t) =>
    ['memory', 'store', 'vector', 'cache', 'history', 'knowledge', 'context_store'].some((kw) =>
      t.name.toLowerCase().includes(kw)
    )
  );

  if (memoryTools.length === 0) {
    return passed('OAA-19', 'Memory Retention', 'No persistent memory or vector store tools detected.');
  }

  if (metadata.source === 'scan') {
    return passed('OAA-19', 'Memory Retention', 'Memory tools detected — verify TTL and cleanup policy manually.');
  }

  return finding(
    'OAA-19',
    'MEDIUM',
    'Unconstrained Memory Retention',
    `Tool(s) "${memoryTools.map((t) => t.name).join(', ')}" store data but no TTL or cleanup policy was confirmed. Without expiry, sensitive data accumulates indefinitely.`,
    memoryTools.map((t) => t.name).join(', ')
  );
}

// Calculate static scores without AI
export function computeStaticScores(findings: StaticFinding[]): {
  securityScore: number;
  performanceScore: number;
  costEfficiencyScore: number;
  overallScore: number;
} {
  const failed = findings.filter((f) => !f.passed);
  const critical = failed.filter((f) => f.severity === 'CRITICAL').length;
  const high = failed.filter((f) => f.severity === 'HIGH').length;
  const medium = failed.filter((f) => f.severity === 'MEDIUM').length;

  // Weights: CRITICAL findings are 3× more penalizing than HIGH (irreversible damage potential).
  const secDeduc = Math.min(10, critical * 3 + high * 2 + medium * 0.5);
  const securityScore = Math.max(0, Math.round((10 - secDeduc) * 10) / 10);

  // Performance tracks reliability risk — HIGH findings (e.g. missing error handling) hurt it more.
  const perfDeduc = Math.min(10, high * 1.5 + medium * 1);
  const performanceScore = Math.max(0, Math.round((10 - perfDeduc) * 10) / 10);

  // Cost can't be scored without AI analysis (no call volume or model data in static mode).
  const costEfficiencyScore = 5;

  // Overall: security-heavy weighting (50%) since security failures are hardest to recover from.
  // Overall: weighted composite (security 50%, performance 30%, cost 20%)
  const overallScore = Math.round(
    (securityScore / 10) * 50 + (performanceScore / 10) * 30 + (costEfficiencyScore / 10) * 20
  );

  return { securityScore, performanceScore, costEfficiencyScore, overallScore };
}

export function runStaticAnalysis(metadata: AgentMetadata): StaticFinding[] {
  const findings: StaticFinding[] = [];

  findings.push(checkPromptInjection(metadata));
  findings.push(...checkOverPermissioned(metadata));
  findings.push(checkHumanApproval(metadata));
  findings.push(checkHardcodedSecrets(metadata));
  findings.push(checkToolScopeCreep(metadata));
  findings.push(checkErrorHandling(metadata));
  findings.push(...checkSubAgentPermissions(metadata));
  findings.push(checkOutputValidation(metadata));
  findings.push(checkPiiExposure(metadata));
  findings.push(checkRateLimiting(metadata));
  findings.push(checkSelfModification(metadata));
  findings.push(checkAuditLogging(metadata));
  findings.push(checkInputValidation(metadata));
  findings.push(checkToolTimeout(metadata));
  findings.push(checkIdempotency(metadata));
  findings.push(checkContextOverflow(metadata));
  findings.push(checkFallbackModel(metadata));
  findings.push(checkSessionIsolation(metadata));
  findings.push(checkMemoryRetention(metadata));

  return findings;
}
