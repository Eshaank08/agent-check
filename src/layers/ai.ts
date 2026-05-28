/**
 * AI reasoning layer — sends only extracted metadata (never raw code) to Claude
 * and parses the structured JSON response. Skipped entirely when ANTHROPIC_API_KEY
 * is not set or --no-ai is passed.
 */
import Anthropic from '@anthropic-ai/sdk';
import type { AgentMetadata, StaticFinding, AIAnalysis } from '../types';
import { MODEL_CATALOG, estimateMonthlyCost, formatCost } from '../models/recommendations';

const MODEL = 'claude-sonnet-4-6';
// Estimated tokens per audit call — used for cost projection in model recommendations.
const AVG_INPUT_TOKENS = 2000;
const AVG_OUTPUT_TOKENS = 500;

function buildMetadataSummary(metadata: AgentMetadata): string {
  const lines: string[] = ['AGENT METADATA:'];

  lines.push(`- Name: ${metadata.name ?? 'unnamed'}`);
  lines.push(`- Description: ${metadata.description ?? 'not provided'}`);
  lines.push(`- Current Model: ${metadata.model ?? 'not detected'}`);
  lines.push(`- Source: ${metadata.source === 'scan' ? `file scan (${metadata.filesScanned ?? 0} files)` : 'interactive input'}`);
  lines.push(`- Approximate calls/day: ${metadata.callsPerDay ?? 'unknown'}`);
  lines.push('');

  // Tools — names and permissions only, never source code
  if (metadata.tools.length > 0) {
    lines.push(`TOOLS (${metadata.tools.length} total):`);
    for (const tool of metadata.tools) {
      lines.push(`  - ${tool.name} [${tool.permissions.join(', ')}]`);
    }
  } else {
    lines.push('TOOLS: none detected');
  }
  lines.push('');

  // Sub-agents
  if (metadata.subAgents.length > 0) {
    lines.push(`SUB-AGENTS (${metadata.subAgents.length}):`);
    for (const agent of metadata.subAgents) {
      lines.push(`  - ${agent.name ?? 'unnamed'}: ${agent.description ?? 'no description'}`);
      if (agent.receivesRawUserInput) lines.push('    ⚠ Receives raw user input from orchestrator');
    }
  } else {
    lines.push('SUB-AGENTS: none');
  }
  lines.push('');

  // Safety flags
  lines.push('SAFETY FLAGS:');
  lines.push(`  - Human approval on sensitive actions: ${metadata.hasHumanApproval ? 'YES' : 'NO'}`);
  lines.push(`  - Error handling present: ${metadata.hasErrorHandling ? 'YES' : metadata.hasErrorHandling === false ? 'NO' : 'UNKNOWN'}`);
  lines.push(`  - Output validation/guardrails: ${metadata.hasOutputValidation ? 'YES' : metadata.hasOutputValidation === false ? 'NO' : 'UNKNOWN'}`);
  lines.push(`  - Rate limiting on APIs: ${metadata.hasRateLimiting ? 'YES' : metadata.hasRateLimiting === false ? 'NO' : 'UNKNOWN'}`);
  lines.push(`  - System prompt present: ${metadata.systemPromptPresent ? 'YES' : metadata.systemPromptPresent === false ? 'NO' : 'UNKNOWN'}`);
  lines.push(`  - Potential secrets in code: ${(metadata.potentialSecrets?.length ?? 0) > 0 ? `YES (${metadata.potentialSecrets!.length} detected)` : 'NO'}`);

  return lines.join('\n');
}

function buildStaticSummary(findings: StaticFinding[]): string {
  const failed = findings.filter((f) => !f.passed);
  const passed = findings.filter((f) => f.passed);

  const lines: string[] = ['STATIC ANALYSIS FINDINGS:'];
  for (const f of failed) {
    lines.push(`  [${f.severity}] ${f.ruleId} — ${f.title}: ${f.message}`);
  }
  for (const f of passed) {
    lines.push(`  [PASS] ${f.ruleId} — ${f.title}`);
  }

  return lines.join('\n');
}

function buildModelCatalog(callsPerDay: number): string {
  const lines: string[] = ['MODEL CATALOG (for recommendations):'];
  for (const spec of MODEL_CATALOG) {
    const cost = estimateMonthlyCost(spec, AVG_INPUT_TOKENS, AVG_OUTPUT_TOKENS, callsPerDay);
    lines.push(
      `  - ${spec.id} (${spec.provider}): ${formatCost(cost)} at ${callsPerDay} calls/day | tier: ${spec.tier} | GDPR: ${spec.gdprFriendly ? 'yes' : 'no'} | self-hostable: ${spec.selfHostable ? 'yes' : 'no'}`
    );
  }
  return lines.join('\n');
}

function buildPrompt(metadata: AgentMetadata, findings: StaticFinding[]): string {
  const callsPerDay = metadata.callsPerDay ?? 100;

  return `You are an expert AI security reviewer and architect. Analyze this AI agent and return a structured JSON assessment.

${buildMetadataSummary(metadata)}

${buildStaticSummary(findings)}

${buildModelCatalog(callsPerDay)}

Analyze the agent and return ONLY a valid JSON object with this exact structure:
{
  "contradictions": [
    "string — logical contradictions: tools conflicting with stated purpose, misleading agent description, etc."
  ],
  "subAgentTrustIssues": [
    "string — trust and permission issues in multi-agent setup, or empty array if no sub-agents"
  ],
  "workflowGaps": [
    "string — what happens when a tool fails mid-workflow? Missing fallbacks? Partial execution risks?"
  ],
  "permissionIssues": [
    "string — any permission levels that seem unjustified for the stated task"
  ],
  "modelRecommendations": [
    {
      "model": "model-id from catalog",
      "provider": "provider name",
      "estimatedMonthlyCost": "formatted cost string",
      "qualityMatch": "e.g. 95% quality match for this task type",
      "reasoning": "one sentence on why this model fits"
    }
  ],
  "mostCriticalFix": "The single most important security or reliability issue to fix immediately, in one sentence.",
  "securityScore": <integer 0-10>,
  "performanceScore": <integer 0-10>,
  "costEfficiencyScore": <integer 0-10>,
  "overallScore": <integer 0-100>
}

Rules:
- modelRecommendations must contain exactly 3 entries (current/alternative options)
- If current model is optimal, still provide 3 alternatives
- Scores must reflect the actual risk profile — do not pad
- Return ONLY the JSON object, no markdown, no explanation`;
}

function extractJson(raw: string): string {
  // Try direct parse first
  const trimmed = raw.trim();
  if (trimmed.startsWith('{')) return trimmed;

  // Extract from code block
  const codeBlock = trimmed.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
  if (codeBlock) return codeBlock[1];

  // Find first { to last }
  const start = trimmed.indexOf('{');
  const end = trimmed.lastIndexOf('}');
  if (start !== -1 && end !== -1 && end > start) {
    return trimmed.slice(start, end + 1);
  }

  return trimmed;
}

export async function runAiAnalysis(
  metadata: AgentMetadata,
  findings: StaticFinding[]
): Promise<AIAnalysis | null> {
  const apiKey = process.env['ANTHROPIC_API_KEY'];
  if (!apiKey) return null;

  const client = new Anthropic({ apiKey });

  const prompt = buildPrompt(metadata, findings);

  let rawContent: string;

  try {
    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 2000,
      messages: [{ role: 'user', content: prompt }],
    });

    const block = response.content[0];
    if (block.type !== 'text') throw new Error('Unexpected response type');
    rawContent = block.text;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`AI analysis failed: ${msg}`);
  }

  let parsed: AIAnalysis;
  try {
    const jsonStr = extractJson(rawContent);
    parsed = JSON.parse(jsonStr) as AIAnalysis;
  } catch {
    throw new Error('Could not parse AI response as JSON. Raw: ' + rawContent.slice(0, 200));
  }

  // Validate and sanitize required fields
  parsed.contradictions = Array.isArray(parsed.contradictions) ? parsed.contradictions : [];
  parsed.subAgentTrustIssues = Array.isArray(parsed.subAgentTrustIssues) ? parsed.subAgentTrustIssues : [];
  parsed.workflowGaps = Array.isArray(parsed.workflowGaps) ? parsed.workflowGaps : [];
  parsed.permissionIssues = Array.isArray(parsed.permissionIssues) ? parsed.permissionIssues : [];
  parsed.modelRecommendations = Array.isArray(parsed.modelRecommendations) ? parsed.modelRecommendations : [];
  parsed.mostCriticalFix = parsed.mostCriticalFix ?? 'No critical fix identified.';
  parsed.securityScore = clampScore(parsed.securityScore, 0, 10);
  parsed.performanceScore = clampScore(parsed.performanceScore, 0, 10);
  parsed.costEfficiencyScore = clampScore(parsed.costEfficiencyScore, 0, 10);
  parsed.overallScore = clampScore(parsed.overallScore, 0, 100);

  return parsed;
}

function clampScore(value: unknown, min: number, max: number): number {
  const n = typeof value === 'number' ? value : parseFloat(String(value));
  if (isNaN(n)) return Math.round((min + max) / 2);
  return Math.max(min, Math.min(max, Math.round(n)));
}
