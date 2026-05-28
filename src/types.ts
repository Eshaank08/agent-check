export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Permission = 'read' | 'write' | 'delete' | 'execute' | 'admin';

export interface ToolDefinition {
  name: string;
  permissions: Permission[];
  description?: string;
}

export interface SubAgentInfo {
  name?: string;
  description?: string;
  permissions?: string[];
  receivesRawUserInput?: boolean;
}

export interface AgentMetadata {
  name?: string;
  description?: string;
  model?: string;
  tools: ToolDefinition[];
  subAgents: SubAgentInfo[];
  hasHumanApproval: boolean;
  callsPerDay?: number;
  systemPromptPresent?: boolean;
  hasErrorHandling?: boolean;
  hasRateLimiting?: boolean;
  hasOutputValidation?: boolean;
  hasAuditLogging?: boolean;
  hasInputValidation?: boolean;
  hasToolTimeout?: boolean;
  potentialSecrets?: SecretHit[];
  source: 'scan' | 'interactive';
  filesScanned?: number;
  scanPath?: string;
}

export interface SecretHit {
  pattern: string;
  file: string;
  line: number;
}

export interface StaticFinding {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  location?: string;
  passed: boolean;
}

export interface ModelRecommendation {
  model: string;
  provider: string;
  estimatedMonthlyCost: string;
  qualityMatch: string;
  reasoning: string;
  computeRequirement?: string;  // GPU/VRAM estimate for self-hosted models
}

export interface AIAnalysis {
  contradictions: string[];
  subAgentTrustIssues: string[];
  workflowGaps: string[];
  permissionIssues: string[];
  modelRecommendations: ModelRecommendation[];
  mostCriticalFix: string;
  securityScore: number;
  performanceScore: number;
  costEfficiencyScore: number;
  overallScore: number;
  pricingDataSource?: 'live' | 'static';
}

export interface AuditOptions {
  path?: string;
  noAi: boolean;
}

export interface AuditResult {
  metadata: AgentMetadata;
  staticFindings: StaticFinding[];
  aiAnalysis?: AIAnalysis;
  timestamp: string;
}
