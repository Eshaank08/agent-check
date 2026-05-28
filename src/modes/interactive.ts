import * as p from '@clack/prompts';
import chalk from 'chalk';
import type { AgentMetadata, ToolDefinition, SubAgentInfo, Permission } from '../types';

const COMMON_MODELS = [
  { value: 'gpt-4o', label: 'GPT-4o (OpenAI)' },
  { value: 'gpt-4o-mini', label: 'GPT-4o Mini (OpenAI)' },
  { value: 'claude-sonnet-4-6', label: 'Claude Sonnet (Anthropic)' },
  { value: 'claude-haiku-4-5', label: 'Claude Haiku (Anthropic)' },
  { value: 'claude-opus-4-7', label: 'Claude Opus (Anthropic)' },
  { value: 'gemini-1.5-flash', label: 'Gemini Flash (Google)' },
  { value: 'gemini-1.5-pro', label: 'Gemini Pro (Google)' },
  { value: 'deepseek-v3', label: 'DeepSeek V3 (DeepSeek)' },
  { value: 'llama-3.3-70b', label: 'Llama 3.3 70B (Meta/self-hosted)' },
  { value: 'mistral-small', label: 'Mistral Small (Mistral AI)' },
  { value: 'other', label: 'Other / custom model' },
];

const PERMISSION_OPTIONS = [
  { value: 'read' as Permission, label: 'Read — fetch or retrieve data' },
  { value: 'write' as Permission, label: 'Write — create or update data' },
  { value: 'delete' as Permission, label: 'Delete — remove data permanently' },
  { value: 'execute' as Permission, label: 'Execute — run code or shell commands' },
];

function isCancelled(value: unknown): boolean {
  return p.isCancel(value);
}

function cancelExit(): never {
  p.outro(chalk.yellow('Audit cancelled.'));
  process.exit(0);
}

async function collectTools(): Promise<ToolDefinition[]> {
  const tools: ToolDefinition[] = [];

  console.log('');
  p.log.info('Now let\'s catalog your agent\'s tools. Enter each tool one by one.');

  let addMore = true;
  while (addMore) {
    const toolName = await p.text({
      message: tools.length === 0 ? 'First tool name:' : 'Next tool name:',
      placeholder: 'e.g. send_email, read_database, search_web',
      validate: (v) => (!v.trim() ? 'Tool name cannot be empty' : undefined),
    });

    if (isCancelled(toolName)) cancelExit();

    const rawPerms = await p.multiselect<Permission>({
      message: `Permissions for "${toolName as string}":`,
      options: PERMISSION_OPTIONS,
      required: true,
    });

    if (isCancelled(rawPerms)) cancelExit();

    tools.push({
      name: (toolName as string).trim(),
      permissions: rawPerms as Permission[],
    });

    const more = await p.confirm({ message: 'Add another tool?' });
    if (isCancelled(more)) cancelExit();
    addMore = more as boolean;
  }

  return tools;
}

async function collectSubAgents(): Promise<SubAgentInfo[]> {
  const hasSubAgents = await p.confirm({ message: 'Does this agent use sub-agents or spawn other agents?' });
  if (isCancelled(hasSubAgents)) cancelExit();
  if (!(hasSubAgents as boolean)) return [];

  const countStr = await p.text({
    message: 'How many sub-agents?',
    placeholder: '2',
    validate: (v) => {
      const n = parseInt(v, 10);
      return isNaN(n) || n < 1 ? 'Enter a number ≥ 1' : undefined;
    },
  });
  if (isCancelled(countStr)) cancelExit();

  const count = parseInt(countStr as string, 10);
  const subAgents: SubAgentInfo[] = [];

  for (let i = 0; i < count; i++) {
    p.log.info(`Sub-agent ${i + 1} of ${count}`);

    const name = await p.text({
      message: `Sub-agent ${i + 1} name (optional):`,
      placeholder: 'e.g. data-fetcher, code-runner',
    });
    if (isCancelled(name)) cancelExit();

    const desc = await p.text({
      message: `What does sub-agent ${i + 1} do?`,
      placeholder: 'e.g. Fetches customer data from CRM',
    });
    if (isCancelled(desc)) cancelExit();

    const rawInput = await p.confirm({
      message: `Does sub-agent ${i + 1} receive raw user input without orchestrator filtering?`,
    });
    if (isCancelled(rawInput)) cancelExit();

    subAgents.push({
      name: ((name as string) || `sub-agent-${i + 1}`).trim() || `sub-agent-${i + 1}`,
      description: (desc as string).trim(),
      receivesRawUserInput: rawInput as boolean,
    });
  }

  return subAgents;
}

export async function runInteractive(): Promise<AgentMetadata> {
  p.intro(chalk.bold.cyan(' AgentCheck — Interactive Audit '));

  // 1. Agent name
  const name = await p.text({
    message: 'Agent name:',
    placeholder: 'unnamed (press Enter to skip)',
  });
  if (isCancelled(name)) cancelExit();

  // 2. Description
  const description = await p.text({
    message: 'What does this agent do? (one sentence)',
    placeholder: 'e.g. Books calendar appointments based on email conversations',
    validate: (v) => (!v.trim() ? 'Please provide a brief description' : undefined),
  });
  if (isCancelled(description)) cancelExit();

  // 3. Model
  const modelChoice = await p.select({
    message: 'Which model is this agent using?',
    options: COMMON_MODELS,
  });
  if (isCancelled(modelChoice)) cancelExit();

  let model = modelChoice as string;
  if (model === 'other') {
    const customModel = await p.text({
      message: 'Enter your model identifier:',
      placeholder: 'e.g. my-fine-tuned-model',
    });
    if (isCancelled(customModel)) cancelExit();
    model = (customModel as string).trim();
  }

  // 4. Tools
  const tools = await collectTools();

  // 5. Sub-agents
  const subAgents = await collectSubAgents();

  // 6. Human approval
  const hasHumanApproval = await p.confirm({
    message: 'Does the agent require explicit human approval before taking sensitive actions?',
  });
  if (isCancelled(hasHumanApproval)) cancelExit();

  // 7. Error handling
  const hasErrorHandling = await p.confirm({
    message: 'Does the agent have error handling / fallback strategies for tool failures?',
  });
  if (isCancelled(hasErrorHandling)) cancelExit();

  // 8. Output validation
  const hasOutputValidation = await p.confirm({
    message: 'Is there an output validation layer (guardrails, PII checks, content filters)?',
  });
  if (isCancelled(hasOutputValidation)) cancelExit();

  // 9. Rate limiting
  const hasRateLimiting = await p.confirm({
    message: 'Are rate limits applied to external API tool calls?',
  });
  if (isCancelled(hasRateLimiting)) cancelExit();

  // 10. Call volume
  const callsStr = await p.text({
    message: 'Approximate agent calls per day:',
    placeholder: '500',
    validate: (v) => {
      if (!v.trim()) return undefined; // optional
      const n = parseInt(v, 10);
      return isNaN(n) || n < 0 ? 'Enter a valid number or leave blank' : undefined;
    },
  });
  if (isCancelled(callsStr)) cancelExit();

  const callsPerDay = callsStr ? parseInt(callsStr as string, 10) || undefined : undefined;

  p.outro(chalk.green('Input collected. Running audit...'));

  return {
    name: ((name as string) || '').trim() || undefined,
    description: (description as string).trim(),
    model,
    tools,
    subAgents,
    hasHumanApproval: hasHumanApproval as boolean,
    hasErrorHandling: hasErrorHandling as boolean,
    hasOutputValidation: hasOutputValidation as boolean,
    hasRateLimiting: hasRateLimiting as boolean,
    callsPerDay,
    systemPromptPresent: true, // assume present if user built an agent
    potentialSecrets: [],
    source: 'interactive',
  };
}
