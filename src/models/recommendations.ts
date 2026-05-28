export interface ModelSpec {
  id: string;
  displayName: string;
  provider: string;
  inputCostPerMillion: number;   // USD
  outputCostPerMillion: number;  // USD
  contextWindow: number;         // tokens
  strengths: string[];
  weaknesses: string[];
  gdprFriendly: boolean;
  selfHostable: boolean;
  tier: 'budget' | 'standard' | 'premium';
}

export const MODEL_CATALOG: ModelSpec[] = [
  {
    id: 'claude-haiku-4-5',
    displayName: 'Claude Haiku',
    provider: 'Anthropic',
    inputCostPerMillion: 0.80,
    outputCostPerMillion: 4.00,
    contextWindow: 200000,
    strengths: ['Fastest Claude model', 'Low cost', 'Good for simple tasks', 'Long context'],
    weaknesses: ['Less reasoning depth than Sonnet/Opus'],
    gdprFriendly: true,
    selfHostable: false,
    tier: 'budget',
  },
  {
    id: 'claude-sonnet-4-6',
    displayName: 'Claude Sonnet',
    provider: 'Anthropic',
    inputCostPerMillion: 3.00,
    outputCostPerMillion: 15.00,
    contextWindow: 200000,
    strengths: ['Balanced speed and intelligence', 'Strong reasoning', 'Long context'],
    weaknesses: ['Higher cost than Haiku'],
    gdprFriendly: true,
    selfHostable: false,
    tier: 'standard',
  },
  {
    id: 'claude-opus-4-7',
    displayName: 'Claude Opus',
    provider: 'Anthropic',
    inputCostPerMillion: 15.00,
    outputCostPerMillion: 75.00,
    contextWindow: 200000,
    strengths: ['Most capable Claude model', 'Complex reasoning', 'Best for hard tasks'],
    weaknesses: ['Most expensive', 'Slower than Sonnet/Haiku'],
    gdprFriendly: true,
    selfHostable: false,
    tier: 'premium',
  },
  {
    id: 'gpt-4o-mini',
    displayName: 'GPT-4o Mini',
    provider: 'OpenAI',
    inputCostPerMillion: 0.15,
    outputCostPerMillion: 0.60,
    contextWindow: 128000,
    strengths: ['Very cheap', 'Fast', 'Good for high-volume simple tasks'],
    weaknesses: ['Less capable than GPT-4o', 'US data residency only'],
    gdprFriendly: false,
    selfHostable: false,
    tier: 'budget',
  },
  {
    id: 'gpt-4o',
    displayName: 'GPT-4o',
    provider: 'OpenAI',
    inputCostPerMillion: 2.50,
    outputCostPerMillion: 10.00,
    contextWindow: 128000,
    strengths: ['Strong multimodal capability', 'Wide ecosystem', 'Tool use support'],
    weaknesses: ['US data residency only', 'Shorter context than Claude'],
    gdprFriendly: false,
    selfHostable: false,
    tier: 'standard',
  },
  {
    id: 'gemini-1.5-flash',
    displayName: 'Gemini Flash',
    provider: 'Google',
    inputCostPerMillion: 0.075,
    outputCostPerMillion: 0.30,
    contextWindow: 1000000,
    strengths: ['Extremely cheap', 'Massive 1M context window', 'Fast'],
    weaknesses: ['Reasoning depth below Sonnet/GPT-4o', 'Google data practices'],
    gdprFriendly: false,
    selfHostable: false,
    tier: 'budget',
  },
  {
    id: 'gemini-1.5-pro',
    displayName: 'Gemini Pro',
    provider: 'Google',
    inputCostPerMillion: 1.25,
    outputCostPerMillion: 5.00,
    contextWindow: 2000000,
    strengths: ['Largest context window available', 'Strong reasoning', 'Multimodal'],
    weaknesses: ['Google data practices', 'Slower than Flash'],
    gdprFriendly: false,
    selfHostable: false,
    tier: 'standard',
  },
  {
    id: 'deepseek-v3',
    displayName: 'DeepSeek V3',
    provider: 'DeepSeek',
    inputCostPerMillion: 0.27,
    outputCostPerMillion: 1.10,
    contextWindow: 128000,
    strengths: ['Cheapest frontier model', 'Open source', 'Strong coding'],
    weaknesses: ['Data stored in China', 'Not GDPR friendly', 'Availability concerns'],
    gdprFriendly: false,
    selfHostable: true,
    tier: 'budget',
  },
  {
    id: 'llama-3.3-70b',
    displayName: 'Llama 3.3 70B',
    provider: 'Meta (via Groq/self-hosted)',
    inputCostPerMillion: 0.59,
    outputCostPerMillion: 0.79,
    contextWindow: 128000,
    strengths: ['Free when self-hosted', 'Open source', 'Data sovereignty', 'GDPR friendly when self-hosted'],
    weaknesses: ['Requires infrastructure to self-host', 'Less capable than frontier models'],
    gdprFriendly: true,
    selfHostable: true,
    tier: 'budget',
  },
  {
    id: 'mistral-small',
    displayName: 'Mistral Small',
    provider: 'Mistral AI',
    inputCostPerMillion: 0.10,
    outputCostPerMillion: 0.30,
    contextWindow: 32000,
    strengths: ['Very cheap', 'European company', 'GDPR compliant', 'Data stays in EU'],
    weaknesses: ['Smaller context window', 'Less capable than larger models'],
    gdprFriendly: true,
    selfHostable: false,
    tier: 'budget',
  },
];

// Estimate monthly cost given tokens per call and calls per day
export function estimateMonthlyCost(
  spec: ModelSpec,
  avgInputTokens: number,
  avgOutputTokens: number,
  callsPerDay: number
): number {
  const callsPerMonth = callsPerDay * 30;
  const inputCost = (avgInputTokens / 1_000_000) * spec.inputCostPerMillion * callsPerMonth;
  const outputCost = (avgOutputTokens / 1_000_000) * spec.outputCostPerMillion * callsPerMonth;
  return inputCost + outputCost;
}

export function formatCost(usd: number): string {
  if (usd < 1) return `~$${(usd * 100).toFixed(0)}¢/month`;
  if (usd < 10) return `~$${usd.toFixed(2)}/month`;
  return `~$${Math.round(usd)}/month`;
}

export function getModelById(id: string): ModelSpec | undefined {
  return MODEL_CATALOG.find((m) => m.id === id);
}
