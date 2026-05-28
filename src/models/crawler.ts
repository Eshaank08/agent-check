/**
 * Live model pricing from OpenRouter's free public API (no key required).
 * Called before AI analysis to replace static catalog prices with current ones.
 * On any failure (network, timeout, parse), returns null — caller uses static catalog.
 */

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/models';
const TIMEOUT_MS = 5000;

// Maps OpenRouter model ID patterns to our static catalog IDs.
// Order matters — more specific patterns first.
const MODEL_MATCH_RULES: Array<{
  pattern: RegExp;
  staticId: string;
  selfHostable: boolean;
  paramBillions?: number;
}> = [
  { pattern: /claude.*haiku/i,              staticId: 'claude-haiku-4-5',  selfHostable: false },
  { pattern: /claude.*sonnet/i,             staticId: 'claude-sonnet-4-6', selfHostable: false },
  { pattern: /claude.*opus/i,               staticId: 'claude-opus-4-7',   selfHostable: false },
  { pattern: /gpt-4o-mini/i,               staticId: 'gpt-4o-mini',        selfHostable: false },
  { pattern: /gpt-4o(?!-mini)/i,           staticId: 'gpt-4o',             selfHostable: false },
  { pattern: /gemini.*flash/i,             staticId: 'gemini-1.5-flash',   selfHostable: false },
  { pattern: /gemini.*pro/i,               staticId: 'gemini-1.5-pro',     selfHostable: false },
  { pattern: /deepseek.*chat|deepseek.*v3/i, staticId: 'deepseek-v3',     selfHostable: true, paramBillions: 671 },
  { pattern: /llama.*3.*70b|llama-3\.3/i,  staticId: 'llama-3.3-70b',     selfHostable: true, paramBillions: 70 },
  { pattern: /mistral.*small/i,            staticId: 'mistral-small',      selfHostable: false },
];

export interface LiveModelUpdate {
  staticId: string;
  inputCostPerMillion: number;
  outputCostPerMillion: number;
  contextWindow: number;
  // GPU/VRAM requirement string for self-hosted models only
  computeEstimate?: string;
  liveModelName: string;
}

function buildComputeEstimate(paramBillions: number): string {
  const vramFp16Gb = paramBillions * 2;
  const vramInt4Gb = Math.ceil(paramBillions * 0.5);

  let minGpu: string;
  if (vramInt4Gb <= 8)       minGpu = '1× RTX 4060 (8GB)';
  else if (vramInt4Gb <= 16) minGpu = '1× RTX 4080 (16GB)';
  else if (vramInt4Gb <= 24) minGpu = '1× RTX 4090 (24GB)';
  else if (vramInt4Gb <= 48) minGpu = '1× A6000 (48GB)';
  else if (vramInt4Gb <= 80) minGpu = '1× H100 (80GB)';
  else                       minGpu = `${Math.ceil(vramInt4Gb / 80)}× H100 (80GB)`;

  return `~${vramFp16Gb}GB VRAM (fp16) / ~${vramInt4Gb}GB (int4 quantized) — min ${minGpu}`;
}

interface OpenRouterModel {
  id: string;
  name: string;
  pricing: { prompt: string; completion: string };
  context_length: number;
}

interface OpenRouterResponse {
  data: OpenRouterModel[];
}

export async function fetchLiveModelUpdates(): Promise<LiveModelUpdate[] | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const response = await fetch(OPENROUTER_URL, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timeoutId);

    if (!response.ok) return null;

    const data = (await response.json()) as OpenRouterResponse;
    if (!Array.isArray(data?.data)) return null;

    const updates: LiveModelUpdate[] = [];
    const claimedStaticIds = new Set<string>();

    for (const model of data.data) {
      for (const rule of MODEL_MATCH_RULES) {
        if (claimedStaticIds.has(rule.staticId)) continue;
        if (!rule.pattern.test(model.id) && !rule.pattern.test(model.name)) continue;

        const inputCost = parseFloat(model.pricing.prompt);
        const outputCost = parseFloat(model.pricing.completion);
        if (isNaN(inputCost) || isNaN(outputCost)) continue;

        updates.push({
          staticId: rule.staticId,
          // OpenRouter pricing is per-token; convert to per-million for our format
          inputCostPerMillion: inputCost * 1_000_000,
          outputCostPerMillion: outputCost * 1_000_000,
          contextWindow: model.context_length,
          computeEstimate: rule.selfHostable && rule.paramBillions
            ? buildComputeEstimate(rule.paramBillions)
            : undefined,
          liveModelName: model.name,
        });
        claimedStaticIds.add(rule.staticId);
        break;
      }
    }

    return updates.length > 0 ? updates : null;
  } catch {
    // Network failure, timeout, or parse error — caller falls back to static catalog
    return null;
  }
}
