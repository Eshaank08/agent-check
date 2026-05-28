import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticAnalysis, computeStaticScores } from '../layers/static';
import type { AgentMetadata, StaticFinding } from '../types';

function makeMetadata(overrides: Partial<AgentMetadata> = {}): AgentMetadata {
  return {
    tools: [],
    subAgents: [],
    hasHumanApproval: false,
    source: 'interactive',
    ...overrides,
  };
}

function findingFor(findings: StaticFinding[], ruleId: string): StaticFinding | undefined {
  return findings.find((f) => f.ruleId === ruleId);
}

// --- computeStaticScores ---

describe('computeStaticScores', () => {
  it('returns full scores when all findings pass', () => {
    const allPassed: StaticFinding[] = [
      { ruleId: 'OAA-01', severity: 'CRITICAL', title: 'x', message: '', passed: true },
      { ruleId: 'OAA-02', severity: 'HIGH', title: 'x', message: '', passed: true },
    ];
    const scores = computeStaticScores(allPassed);
    assert.equal(scores.securityScore, 10);
    assert.equal(scores.performanceScore, 10);
    // Cost is always 5 in static mode (no model data) → max overall is 90
    assert.equal(scores.overallScore, 90);
  });

  it('deducts heavily for CRITICAL findings', () => {
    const findings: StaticFinding[] = [
      { ruleId: 'OAA-01', severity: 'CRITICAL', title: 'x', message: '', passed: false },
      { ruleId: 'OAA-03', severity: 'CRITICAL', title: 'x', message: '', passed: false },
    ];
    const scores = computeStaticScores(findings);
    // 2 criticals × 3 = 6 deducted → securityScore = 4
    assert.equal(scores.securityScore, 4);
    assert.ok(scores.overallScore < 70, 'overall should be low with 2 criticals');
  });

  it('cost efficiency is always 5 in static mode', () => {
    const scores = computeStaticScores([]);
    assert.equal(scores.costEfficiencyScore, 5);
  });
});

// --- runStaticAnalysis ---

describe('runStaticAnalysis — OAA-03: human approval', () => {
  it('flags CRITICAL when delete tool present and no human approval', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'delete_record', permissions: ['delete'] }],
      hasHumanApproval: false,
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-03');
    assert.ok(f && !f.passed, 'OAA-03 should fail');
    assert.equal(f!.severity, 'CRITICAL');
  });

  it('passes when human approval is set', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'send_email', permissions: ['write'] }],
      hasHumanApproval: true,
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-03');
    assert.ok(f?.passed, 'OAA-03 should pass when human approval is set');
  });
});

describe('runStaticAnalysis — OAA-04: hardcoded secrets', () => {
  it('flags CRITICAL when potential secrets detected', () => {
    const metadata = makeMetadata({
      potentialSecrets: [{ pattern: 'OpenAI API Key', file: 'config.ts', line: 12 }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-04');
    assert.ok(f && !f.passed, 'OAA-04 should fail');
    assert.equal(f!.severity, 'CRITICAL');
  });

  it('passes when no secrets found', () => {
    const metadata = makeMetadata({ potentialSecrets: [] });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-04');
    assert.ok(f?.passed, 'OAA-04 should pass when no secrets');
  });
});

describe('runStaticAnalysis — OAA-01: prompt injection', () => {
  it('flags CRITICAL when external-read + write/delete tools are combined', () => {
    const metadata = makeMetadata({
      tools: [
        { name: 'fetch_webpage', permissions: ['read'] },
        { name: 'write_file', permissions: ['write'] },
      ],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-01');
    assert.ok(f && !f.passed, 'OAA-01 should fail');
    assert.equal(f!.severity, 'CRITICAL');
  });

  it('passes when no external input tools', () => {
    // Tool name must not match external-input keywords: search/browse/fetch/web/read/scrape/email/message
    const metadata = makeMetadata({
      tools: [{ name: 'calculate_total', permissions: ['read'] }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-01');
    assert.ok(f?.passed, 'OAA-01 should pass without external input tools');
  });
});

describe('runStaticAnalysis — OAA-05: tool scope creep', () => {
  it('flags MEDIUM when read-only description but write tools present', () => {
    const metadata = makeMetadata({
      description: 'A read-only search agent that retrieves information',
      tools: [{ name: 'update_record', permissions: ['write'] }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-05');
    assert.ok(f && !f.passed, 'OAA-05 should fail');
    assert.equal(f!.severity, 'MEDIUM');
  });
});

describe('runStaticAnalysis — OAA-07: sub-agent permissions', () => {
  it('flags HIGH when sub-agent receives raw user input', () => {
    const metadata = makeMetadata({
      subAgents: [{ name: 'data-agent', receivesRawUserInput: true }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-07');
    assert.ok(f && !f.passed, 'OAA-07 should fail');
    assert.equal(f!.severity, 'HIGH');
  });

  it('passes when no sub-agents', () => {
    const metadata = makeMetadata({ subAgents: [] });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-07');
    assert.ok(f?.passed, 'OAA-07 should pass with no sub-agents');
  });
});

describe('runStaticAnalysis — OAA-11: self-modifying agent', () => {
  it('flags CRITICAL when tool name suggests writing to system prompt', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'update_system_prompt', permissions: ['write'] }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-11');
    assert.ok(f && !f.passed, 'OAA-11 should fail');
    assert.equal(f!.severity, 'CRITICAL');
  });

  it('passes for a normal write tool', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'save_document', permissions: ['write'] }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-11');
    assert.ok(f?.passed, 'OAA-11 should pass for unrelated write tool');
  });
});

describe('runStaticAnalysis — OAA-14: tool timeout', () => {
  it('flags HIGH in interactive mode with external tool and no timeout confirmed', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'fetch_data', permissions: ['read'] }],
      source: 'interactive',
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-14');
    assert.ok(f && !f.passed, 'OAA-14 should fail with external tool');
    assert.equal(f!.severity, 'HIGH');
  });

  it('passes in scan mode when timeout pattern detected', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'api_call', permissions: ['read'] }],
      source: 'scan',
      hasToolTimeout: true,
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-14');
    assert.ok(f?.passed, 'OAA-14 should pass when timeout detected in scan');
  });
});

describe('runStaticAnalysis — OAA-15: non-idempotent writes', () => {
  it('flags MEDIUM for accumulating tool names', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'append_to_log', permissions: ['write'] }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-15');
    assert.ok(f && !f.passed, 'OAA-15 should fail for append tool');
    assert.equal(f!.severity, 'MEDIUM');
  });
});

describe('runStaticAnalysis — OAA-16: context window overflow', () => {
  it('flags MEDIUM when agent has more than 15 tools', () => {
    const manyTools = Array.from({ length: 16 }, (_, i) => ({
      name: `tool_${i}`,
      permissions: ['read' as const],
    }));
    const metadata = makeMetadata({ tools: manyTools });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-16');
    assert.ok(f && !f.passed, 'OAA-16 should fail with 16 tools');
    assert.equal(f!.severity, 'MEDIUM');
  });

  it('passes when tool count is within limits', () => {
    const metadata = makeMetadata({
      tools: [{ name: 'tool_a', permissions: ['read'] }],
    });
    const findings = runStaticAnalysis(metadata);
    const f = findingFor(findings, 'OAA-16');
    assert.ok(f?.passed, 'OAA-16 should pass with few tools');
  });
});
