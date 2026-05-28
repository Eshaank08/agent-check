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
];

export function getRuleById(id: string): OWASPRule | undefined {
  return OWASP_RULES.find((r) => r.id === id);
}
