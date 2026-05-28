/**
 * Mode 1 — File scanner. Extracts agent metadata from source files without
 * reading any content to external services. Only names, patterns, and flags
 * are forwarded to the analysis layers — never raw source code.
 */
import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import type { AgentMetadata, ToolDefinition, SubAgentInfo, SecretHit, Permission } from '../types';

const SUPPORTED_EXTENSIONS = ['**/*.py', '**/*.ts', '**/*.js', '**/*.json', '**/*.yaml', '**/*.yml', '**/*.env', '**/.env'];

// Secret patterns — we detect location only, never log the value
const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{20,}/g },
  { name: 'Anthropic API Key', regex: /sk-ant-[a-zA-Z0-9\-_]{20,}/g },
  { name: 'Generic API Key assignment', regex: /(?:API_KEY|APIKEY|api_key)\s*[=:]\s*["']?[a-zA-Z0-9\-_]{16,}/gi },
  { name: 'Bearer token', regex: /Bearer\s+[a-zA-Z0-9\-_\.]{20,}/g },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Private key header', regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g },
];

// Model identifier patterns found in source files
const MODEL_PATTERNS: RegExp[] = [
  /["'](gpt-4[o\-][a-zA-Z0-9\-]*|gpt-3\.5[a-zA-Z0-9\-]*)["']/g,
  /["'](claude-[a-zA-Z0-9\-\.]+)["']/g,
  /["'](gemini-[a-zA-Z0-9\-\.]+)["']/g,
  /["'](llama-[0-9a-zA-Z\-\.]+)["']/g,
  /["'](mistral-[a-zA-Z0-9\-\.]+)["']/g,
  /["'](deepseek-[a-zA-Z0-9\-\.]+)["']/g,
];

// Sensitive action keywords in tool names
const SENSITIVE_ACTIONS = ['send_email', 'send_message', 'delete', 'remove', 'drop', 'pay', 'charge', 'deploy', 'publish', 'transfer', 'execute_sql', 'run_code', 'shell', 'bash', 'exec'];

// Write/delete permission signals in tool function names or bodies
const WRITE_SIGNALS = ['write', 'create', 'update', 'insert', 'post', 'put', 'patch', 'upload', 'save', 'store', 'set'];
const DELETE_SIGNALS = ['delete', 'remove', 'drop', 'destroy', 'purge', 'wipe', 'truncate'];
const EXECUTE_SIGNALS = ['exec', 'execute', 'run', 'shell', 'bash', 'spawn', 'subprocess'];

// Human approval patterns — require positive confirmation signals, not negations
const APPROVAL_PATTERNS = [
  /human.?in.?the.?loop/i,
  /require.?approval/i,
  /approval.?required/i,
  /hitl/i,
  /confirm.?before.?(?:executing|running|sending|deleting)/i,
  /interrupt.?(?:before|for|on)/i,
  /await.?(?:human|user).?(?:approval|confirmation|input)/i,
  /human_approval\s*[=:]\s*true/i,
  /needs_approval/i,
];

// Error handling patterns
const ERROR_PATTERNS = [
  /try\s*{/,
  /catch\s*\(/,
  /except\s+/,
  /\.on.?error/i,
  /error.?handler/i,
  /fallback/i,
  /retry/i,
  /on_error/i,
];

// Output validation patterns
const OUTPUT_VALIDATION_PATTERNS = [
  /validate.?output/i,
  /output.?validation/i,
  /guardrail/i,
  /output.?filter/i,
  /response.?check/i,
  /pii.?detect/i,
  /content.?filter/i,
];

// Rate limiting patterns
const RATE_LIMIT_PATTERNS = [
  /rate.?limit/i,
  /throttle/i,
  /ratelimit/i,
  /circuit.?breaker/i,
  /max.?calls/i,
  /calls.?per/i,
  /backoff/i,
];

// Sub-agent patterns
const SUB_AGENT_PATTERNS = [
  /sub.?agent/i,
  /child.?agent/i,
  /create.?agent/i,
  /agent.?executor/i,
  /orchestrat/i,
  /spawn.?agent/i,
  /delegate/i,
];

// Tool definition extraction from JSON (OpenAI/Anthropic format)
interface RawToolDef {
  name?: string;
  function?: { name?: string; description?: string };
  input_schema?: unknown;
  parameters?: unknown;
  description?: string;
}

function extractPermissionsFromName(name: string, body: string): Permission[] {
  const combined = (name + ' ' + body).toLowerCase();
  const perms: Permission[] = [];

  const hasWrite = WRITE_SIGNALS.some((s) => combined.includes(s));
  const hasDelete = DELETE_SIGNALS.some((s) => combined.includes(s));
  const hasExecute = EXECUTE_SIGNALS.some((s) => combined.includes(s));

  // delete supersedes write — a tool that deletes also implicitly writes
  if (hasDelete) perms.push('delete');
  if (hasWrite && !hasDelete) perms.push('write');
  if (hasExecute) perms.push('execute');
  if (perms.length === 0) perms.push('read');

  return perms;
}

function extractToolsFromJson(content: string, filePath: string): ToolDefinition[] {
  const tools: ToolDefinition[] = [];
  try {
    const parsed = JSON.parse(content);
    const candidates: RawToolDef[] = [];

    if (Array.isArray(parsed)) {
      candidates.push(...(parsed as RawToolDef[]));
    } else if (parsed && typeof parsed === 'object') {
      // OpenAI-style: { tools: [...] }
      if (Array.isArray(parsed.tools)) candidates.push(...(parsed.tools as RawToolDef[]));
      // Single tool definition
      if (parsed.name || parsed.function) candidates.push(parsed as RawToolDef);
    }

    for (const candidate of candidates) {
      const name = candidate.name ?? candidate.function?.name;
      if (!name) continue;
      const desc = candidate.description ?? candidate.function?.description ?? '';
      const perms = extractPermissionsFromName(name, desc);
      tools.push({ name, permissions: perms, description: desc });
    }
  } catch {
    // Not valid JSON or not a tool definition file
  }
  return tools;
}

function extractToolsFromCode(content: string): ToolDefinition[] {
  const tools: ToolDefinition[] = [];

  // Python: @tool decorator above a def
  const pyToolRegex = /@tool\s*\n\s*(?:async\s+)?def\s+(\w+)/g;
  let m: RegExpExecArray | null;
  while ((m = pyToolRegex.exec(content)) !== null) {
    const name = m[1];
    const surroundingBody = content.slice(m.index, m.index + 500);
    tools.push({ name, permissions: extractPermissionsFromName(name, surroundingBody) });
  }

  // Match "name": "tool_name" (JSON-in-code style, Python dicts, TS objects)
  // This is more targeted than extracting all identifiers from a block
  const quotedNameRegex = /["']name["']\s*:\s*["']([a-z_][a-z0-9_]{1,50})["']/gi;
  const namesSeen = new Set<string>(tools.map((t) => t.name));
  while ((m = quotedNameRegex.exec(content)) !== null) {
    const name = m[1];
    if (namesSeen.has(name)) continue;
    // Use only the tool name for permission inference to avoid false positives from nearby code
    tools.push({ name, permissions: extractPermissionsFromName(name, '') });
    namesSeen.add(name);
  }

  // Also catch unquoted TS/JS object: { name: identifier, ... } (non-quoted value)
  const tsNameRegex = /(?<!['"a-zA-Z])name:\s*["']([a-z_][a-z0-9_]{1,50})["']/gi;
  while ((m = tsNameRegex.exec(content)) !== null) {
    const name = m[1];
    if (namesSeen.has(name)) continue;
    // Only use the tool name itself for permission inference, not surrounding file context
    tools.push({ name, permissions: extractPermissionsFromName(name, '') });
    namesSeen.add(name);
  }

  // LangChain-style: tools = [var_name, other_var] — only simple comma-separated identifiers
  // Must not contain quotes (to avoid matching description strings)
  const toolsVarListRegex = /\btools\s*=\s*\[\s*((?:[a-z_][a-z0-9_]*\s*,?\s*){1,20})\s*\]/g;
  while ((m = toolsVarListRegex.exec(content)) !== null) {
    const inner = m[1];
    const idents = inner.split(/[\s,]+/).filter((s) => /^[a-z_][a-z0-9_]{2,40}$/.test(s));
    for (const ident of idents) {
      if (namesSeen.has(ident) || ['tools', 'true', 'false', 'none', 'null'].includes(ident)) continue;
      tools.push({ name: ident, permissions: extractPermissionsFromName(ident, '') });
      namesSeen.add(ident);
    }
  }

  return tools;
}

function detectModel(content: string): string | undefined {
  for (const pattern of MODEL_PATTERNS) {
    pattern.lastIndex = 0;
    const m = pattern.exec(content);
    if (m) return m[1];
  }
  return undefined;
}

function detectSecrets(content: string, filePath: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const { name, regex } of SECRET_PATTERNS) {
      regex.lastIndex = 0;
      if (regex.test(lines[i])) {
        hits.push({ pattern: name, file: filePath, line: i + 1 });
      }
    }
  }

  return hits;
}

function booleanCheck(content: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(content));
}

function detectSubAgents(content: string): SubAgentInfo[] {
  const agents: SubAgentInfo[] = [];
  if (!booleanCheck(content, SUB_AGENT_PATTERNS)) return agents;

  // Try to count sub-agent instantiations
  const agentCreateMatches = content.match(/(?:create_agent|SubAgent|AgentExecutor|spawn_agent)\s*\(/g) ?? [];
  const count = Math.max(agentCreateMatches.length, 1);

  for (let i = 0; i < count; i++) {
    agents.push({
      name: `sub-agent-${i + 1}`,
      description: 'Detected in source',
      receivesRawUserInput: /user.?input|user.?message|human.?message/i.test(content),
    });
  }

  return agents;
}

export async function scanDirectory(scanPath: string): Promise<AgentMetadata> {
  const absolutePath = path.resolve(scanPath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Path does not exist: ${absolutePath}`);
  }

  const allTools: ToolDefinition[] = [];
  const allSecrets: SecretHit[] = [];
  const modelsSeen = new Set<string>();

  let hasHumanApproval = false;
  let hasErrorHandling = false;
  let hasRateLimiting = false;
  let hasOutputValidation = false;
  let systemPromptPresent = false;
  let agentName: string | undefined;
  let agentDescription: string | undefined;
  let filesScanned = 0;

  // Sub-agent signals are aggregated across all files — one finding per logical agent,
  // not one per file that happens to mention orchestration patterns.
  let maxSubAgentCount = 0;
  let subAgentReceivesRawInput = false;

  const toolNamesSeen = new Set<string>();

  const patterns = SUPPORTED_EXTENSIONS.map((p) => path.join(absolutePath, p));
  const files = await glob(patterns, { nodir: true, ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/__pycache__/**'] });

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    filesScanned++;
    const ext = path.extname(file).toLowerCase();
    const relPath = path.relative(absolutePath, file);

    // Secret detection in all files
    allSecrets.push(...detectSecrets(content, relPath));

    // Skip binary-like or very large files for deeper analysis
    if (content.length > 500_000) continue;

    // Tool extraction
    let filTools: ToolDefinition[] = [];
    if (ext === '.json') {
      filTools = extractToolsFromJson(content, relPath);
    } else {
      filTools = extractToolsFromCode(content);
    }

    for (const tool of filTools) {
      if (!toolNamesSeen.has(tool.name)) {
        allTools.push(tool);
        toolNamesSeen.add(tool.name);
      }
    }

    // Model detection
    const model = detectModel(content);
    if (model) modelsSeen.add(model);

    // Boolean checks
    if (!hasHumanApproval) hasHumanApproval = booleanCheck(content, APPROVAL_PATTERNS);
    if (!hasErrorHandling) hasErrorHandling = booleanCheck(content, ERROR_PATTERNS);
    if (!hasRateLimiting) hasRateLimiting = booleanCheck(content, RATE_LIMIT_PATTERNS);
    if (!hasOutputValidation) hasOutputValidation = booleanCheck(content, OUTPUT_VALIDATION_PATTERNS);

    // System prompt detection
    if (!systemPromptPresent) {
      systemPromptPresent =
        /role.*system|system.*prompt|SystemMessage|system=["']/i.test(content) ||
        (ext === '.json' && /"role"\s*:\s*"system"/.test(content));
    }

    // Sub-agent detection — aggregate, don't accumulate per-file
    const subAgents = detectSubAgents(content);
    if (subAgents.length > 0) {
      maxSubAgentCount = Math.max(maxSubAgentCount, subAgents.length);
      if (subAgents.some((a) => a.receivesRawUserInput)) subAgentReceivesRawInput = true;
    }

    // Try to extract agent name from common patterns
    if (!agentName) {
      const nameMatch = content.match(/agent.?name\s*[=:]\s*["']([^"']+)["']/i);
      if (nameMatch) agentName = nameMatch[1];
    }

    // Description hint from package.json or README
    if (!agentDescription && file.endsWith('package.json')) {
      try {
        const pkg = JSON.parse(content) as { description?: string; name?: string };
        if (pkg.description) agentDescription = pkg.description;
        if (!agentName && pkg.name) agentName = pkg.name;
      } catch {
        // ignore
      }
    }
  }

  const detectedModel = modelsSeen.size > 0 ? [...modelsSeen][0] : undefined;

  const allSubAgents: SubAgentInfo[] = [];
  for (let i = 0; i < maxSubAgentCount; i++) {
    allSubAgents.push({
      name: `sub-agent-${i + 1}`,
      description: 'Detected in source',
      receivesRawUserInput: subAgentReceivesRawInput,
    });
  }

  return {
    name: agentName,
    description: agentDescription,
    model: detectedModel,
    tools: allTools,
    subAgents: allSubAgents,
    hasHumanApproval,
    hasErrorHandling,
    hasRateLimiting,
    hasOutputValidation,
    systemPromptPresent,
    potentialSecrets: allSecrets,
    source: 'scan',
    filesScanned,
    scanPath: absolutePath,
  };
}
