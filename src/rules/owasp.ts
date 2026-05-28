import type { Severity } from '../types';

export interface OWASPRule {
  id: string;
  name: string;
  description: string;
  defaultSeverity: Severity;
  category: string;
  mitigationHint: string;
}

// Based on OWASP Agentic AI Top 10 (2026)
// Attribution: Inspired by HeadyZhang/agent-audit (MIT)
export const OWASP_RULES: OWASPRule[] = [
  {
    id: 'OAA-01',
    name: 'Prompt Injection',
    description: 'Agent may be vulnerable to prompt injection via user-controlled input or tool outputs',
    defaultSeverity: 'CRITICAL',
    category: 'Input Security',
    mitigationHint: 'Sanitize all external input before passing to the LLM. Use a separate validation layer.',
  },
  {
    id: 'OAA-02',
    name: 'Over-permissioned Tools',
    description: 'Tools have write or delete permissions where read-only access would suffice',
    defaultSeverity: 'HIGH',
    category: 'Least Privilege',
    mitigationHint: 'Apply principle of least privilege. Grant only the minimum permissions each tool needs.',
  },
  {
    id: 'OAA-03',
    name: 'Missing Human Approval on Sensitive Actions',
    description: 'Sensitive operations (email, delete, payment, deploy) can execute without human confirmation',
    defaultSeverity: 'CRITICAL',
    category: 'Human Oversight',
    mitigationHint: 'Require explicit human approval before executing irreversible or high-impact actions.',
  },
  {
    id: 'OAA-04',
    name: 'Hardcoded Credentials',
    description: 'API keys, secrets, or credentials found directly in code or prompt definitions',
    defaultSeverity: 'CRITICAL',
    category: 'Secrets Management',
    mitigationHint: 'Use environment variables or a secrets manager. Never hardcode credentials.',
  },
  {
    id: 'OAA-05',
    name: 'Tool Scope Creep',
    description: 'Agent has tools that appear unrelated to its stated purpose, expanding the attack surface',
    defaultSeverity: 'MEDIUM',
    category: 'Minimal Footprint',
    mitigationHint: 'Remove or disable tools not required for the core agent task.',
  },
  {
    id: 'OAA-06',
    name: 'Missing Error Handling',
    description: 'No error handling or fallback strategy detected for tool failures',
    defaultSeverity: 'MEDIUM',
    category: 'Reliability',
    mitigationHint: 'Define explicit error handlers and fallback behaviors for each tool.',
  },
  {
    id: 'OAA-07',
    name: 'Unconstrained Sub-agent Permissions',
    description: 'Sub-agents receive elevated permissions or raw user input without validation from the orchestrator',
    defaultSeverity: 'HIGH',
    category: 'Multi-agent Trust',
    mitigationHint: 'Orchestrators must validate sub-agent inputs/outputs and enforce permission boundaries.',
  },
  {
    id: 'OAA-08',
    name: 'No Output Validation',
    description: 'Agent outputs are not validated before being acted upon or returned to users',
    defaultSeverity: 'MEDIUM',
    category: 'Output Safety',
    mitigationHint: 'Add an output validation layer to check for PII leakage, policy violations, and hallucinations.',
  },
  {
    id: 'OAA-09',
    name: 'PII Exposure in Tool Outputs',
    description: 'Tools that access user data may expose personally identifiable information without controls',
    defaultSeverity: 'HIGH',
    category: 'Data Privacy',
    mitigationHint: 'Mask or redact PII in tool outputs. Log access to sensitive data.',
  },
  {
    id: 'OAA-10',
    name: 'Missing Rate Limiting',
    description: 'External API tools lack rate limiting, enabling runaway costs or abuse',
    defaultSeverity: 'MEDIUM',
    category: 'Resource Control',
    mitigationHint: 'Add per-tool rate limits and circuit breakers for all external API calls.',
  },

  // --- Extended rules (OAA-11 to OAA-19) ---
  {
    id: 'OAA-11',
    name: 'Self-modifying Agent',
    description: 'Agent has tools that can overwrite its own system prompt or configuration',
    defaultSeverity: 'CRITICAL',
    category: 'Integrity',
    mitigationHint: 'Remove any tool that can write to agent instructions or configuration. System prompts must be immutable at runtime.',
  },
  {
    id: 'OAA-12',
    name: 'No Audit Logging',
    description: 'Sensitive tool calls (write/delete/execute) are not logged for forensic review',
    defaultSeverity: 'HIGH',
    category: 'Observability',
    mitigationHint: 'Log every tool invocation with timestamp, input parameters (sanitized), and outcome. Store logs outside agent reach.',
  },
  {
    id: 'OAA-13',
    name: 'Missing Input Validation',
    description: 'No input sanitization or schema validation before data is passed to tools',
    defaultSeverity: 'MEDIUM',
    category: 'Input Security',
    mitigationHint: 'Validate and sanitize all inputs against a schema before passing to tools. Reject unexpected types or lengths.',
  },
  {
    id: 'OAA-14',
    name: 'No Tool Call Timeout',
    description: 'Tools can hang indefinitely — no timeout or deadline enforced',
    defaultSeverity: 'HIGH',
    category: 'Reliability',
    mitigationHint: 'Set a max execution time on every tool call. Treat timeout as a hard failure with defined fallback.',
  },
  {
    id: 'OAA-15',
    name: 'Non-idempotent Write Operations',
    description: 'Write tools lack idempotency protection — retries or duplicate calls cause data corruption',
    defaultSeverity: 'MEDIUM',
    category: 'Reliability',
    mitigationHint: 'Use idempotency keys on all write operations so retries are safe.',
  },
  {
    id: 'OAA-16',
    name: 'Context Window Overflow Risk',
    description: 'High tool count combined with large descriptions risks exceeding the model context window',
    defaultSeverity: 'MEDIUM',
    category: 'Performance',
    mitigationHint: 'Reduce tool count, trim descriptions, or use dynamic tool loading to keep prompt size manageable.',
  },
  {
    id: 'OAA-17',
    name: 'No Fallback Model',
    description: 'Single model dependency with no fallback — model unavailability causes total agent failure',
    defaultSeverity: 'LOW',
    category: 'Availability',
    mitigationHint: 'Configure a fallback model for when the primary is unavailable or rate-limited.',
  },
  {
    id: 'OAA-18',
    name: 'Missing Session Isolation',
    description: 'Data access tools lack user/tenant scoping — one session can read another user\'s data',
    defaultSeverity: 'HIGH',
    category: 'Data Privacy',
    mitigationHint: 'Enforce user_id or tenant_id scoping on every data access tool at the infrastructure level.',
  },
  {
    id: 'OAA-19',
    name: 'Unconstrained Memory Retention',
    description: 'Agent memory or vector store has no TTL or cleanup — data accumulates indefinitely',
    defaultSeverity: 'MEDIUM',
    category: 'Data Privacy',
    mitigationHint: 'Set TTL on all stored memories. Implement a cleanup routine and expose a user-facing "forget" mechanism.',
  },
];

export function getRuleById(id: string): OWASPRule | undefined {
  return OWASP_RULES.find((r) => r.id === id);
}
