/**
 * Terminal report formatter. All output goes through here — nothing is printed
 * directly from other modules so the format stays consistent and testable.
 */
import chalk from 'chalk';
import type { AuditResult, StaticFinding, AIAnalysis, Severity } from '../types';
import { computeStaticScores } from '../layers/static';

const WIDTH = 56;
const BORDER = '═'.repeat(WIDTH);
const DIVIDER = '─'.repeat(WIDTH);

function center(text: string): string {
  const pad = Math.max(0, Math.floor((WIDTH - text.length) / 2));
  return ' '.repeat(pad) + text;
}

function scoreEmoji(score: number, max: number): string {
  const ratio = score / max;
  if (ratio >= 0.75) return chalk.green('✓');
  if (ratio >= 0.45) return chalk.yellow('⚠');
  return chalk.red('✗');
}

function severityLabel(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return chalk.red.bold('❌ CRITICAL');
    case 'HIGH':     return chalk.red('❌ HIGH    ');
    case 'MEDIUM':   return chalk.yellow('⚠️  MEDIUM  ');
    case 'LOW':      return chalk.blue('ℹ  LOW     ');
  }
}

function formatFinding(f: StaticFinding): string {
  const label = severityLabel(f.severity);
  const msg = f.message.length > 90 ? f.message.slice(0, 87) + '...' : f.message;
  const lines = [`  ${label}  ${chalk.bold(f.title)}`];

  // Word-wrap the message at ~70 chars
  const words = msg.split(' ');
  let line = '             ';
  for (const word of words) {
    if (line.length + word.length > 72) {
      lines.push(line);
      line = '             ' + word + ' ';
    } else {
      line += word + ' ';
    }
  }
  if (line.trim()) lines.push(line);

  if (f.location) {
    lines.push(chalk.dim(`             📍 ${f.location}`));
  }

  return lines.join('\n');
}

function printStaticSection(findings: StaticFinding[]): void {
  console.log('');
  console.log(chalk.bold.white('STATIC ANALYSIS'));
  console.log(chalk.dim(DIVIDER));

  const failed = findings.filter((f) => !f.passed);
  const passed = findings.filter((f) => f.passed);

  for (const f of failed) {
    console.log(formatFinding(f));
    console.log('');
  }

  for (const f of passed) {
    const name = f.title.length > 40 ? f.title.slice(0, 37) + '...' : f.title;
    console.log(`  ${chalk.green('✅ PASSED  ')} ${name}`);
  }
}

function printAiSection(ai: AIAnalysis): void {
  console.log('');
  console.log(chalk.bold.white('AI ANALYSIS'));
  console.log(chalk.dim(DIVIDER));

  if (ai.contradictions.length > 0) {
    console.log(chalk.bold('  Logical Gaps'));
    for (const c of ai.contradictions) {
      console.log(`  ${chalk.yellow('💡')} ${c}`);
    }
    console.log('');
  }

  if (ai.subAgentTrustIssues.length > 0) {
    console.log(chalk.bold('  Sub-agent Trust'));
    for (const s of ai.subAgentTrustIssues) {
      console.log(`  ${chalk.red('❌')} ${s}`);
    }
    console.log('');
  }

  if (ai.workflowGaps.length > 0) {
    console.log(chalk.bold('  Workflow Gaps'));
    for (const w of ai.workflowGaps) {
      console.log(`  ${chalk.yellow('⚠️ ')} ${w}`);
    }
    console.log('');
  }

  if (ai.permissionIssues.length > 0) {
    console.log(chalk.bold('  Permission Issues'));
    for (const p of ai.permissionIssues) {
      console.log(`  ${chalk.red('❌')} ${p}`);
    }
    console.log('');
  }

  const allEmpty =
    ai.contradictions.length === 0 &&
    ai.subAgentTrustIssues.length === 0 &&
    ai.workflowGaps.length === 0 &&
    ai.permissionIssues.length === 0;

  if (allEmpty) {
    console.log(chalk.green('  ✅ No additional issues identified by AI analysis.'));
  }
}

function printModelSection(ai: AIAnalysis, currentModel?: string): void {
  console.log('');
  console.log(chalk.bold.white('MODEL RECOMMENDATION'));
  console.log(chalk.dim(DIVIDER));

  if (currentModel) {
    console.log(`  ${chalk.dim('Current:    ')} ${chalk.white(currentModel)}`);
    console.log('');
  }

  for (let i = 0; i < ai.modelRecommendations.length; i++) {
    const rec = ai.modelRecommendations[i];
    const tag = i === 0 ? chalk.green.bold('Recommended') : chalk.cyan(`Alternative ${i}`);
    console.log(`  ${tag}`);
    console.log(`  ${chalk.bold(rec.model)} ${chalk.dim(`(${rec.provider})`)}  ${chalk.yellow(rec.estimatedMonthlyCost)}`);
    console.log(`  ${chalk.dim(rec.qualityMatch)} — ${rec.reasoning}`);
    console.log('');
  }
}

function printSummary(result: AuditResult): void {
  const ai = result.aiAnalysis;

  let sec: number, perf: number, cost: number, overall: number;

  if (ai) {
    sec = ai.securityScore;
    perf = ai.performanceScore;
    cost = ai.costEfficiencyScore;
    overall = ai.overallScore;
  } else {
    const scores = computeStaticScores(result.staticFindings);
    sec = scores.securityScore;
    perf = scores.performanceScore;
    cost = scores.costEfficiencyScore;
    overall = scores.overallScore;
  }

  console.log('');
  console.log(chalk.bold.white('SUMMARY'));
  console.log(chalk.dim(DIVIDER));
  console.log(`  Security Score:     ${chalk.bold(`${sec}/10`)}  ${scoreEmoji(sec, 10)}`);
  console.log(`  Performance Score:  ${chalk.bold(`${perf}/10`)}  ${scoreEmoji(perf, 10)}`);
  console.log(`  Cost Efficiency:    ${chalk.bold(`${cost}/10`)}  ${scoreEmoji(cost, 10)}`);
  console.log('');
  console.log(`  Overall Score:      ${chalk.bold.white(`${overall}/100`)}  ${scoreEmoji(overall, 100)}`);
  console.log('');

  if (ai?.mostCriticalFix) {
    console.log(`  ${chalk.bold.yellow('Most critical fix:')}`);
    // Word-wrap
    const words = ai.mostCriticalFix.split(' ');
    let line = '  ';
    for (const word of words) {
      if (line.length + word.length > 70) {
        console.log(chalk.white(line));
        line = '  ' + word + ' ';
      } else {
        line += word + ' ';
      }
    }
    if (line.trim()) console.log(chalk.white(line));
    console.log('');
  }

  if (!result.aiAnalysis) {
    console.log(chalk.dim('  Run with ANTHROPIC_API_KEY set for deeper AI analysis.'));
  }
}

function printNoAiNote(): void {
  console.log('');
  console.log(chalk.bold.white('AI ANALYSIS'));
  console.log(chalk.dim(DIVIDER));
  console.log(chalk.dim('  Skipped — ANTHROPIC_API_KEY not set or --no-ai flag used.'));
  console.log(chalk.dim('  Set ANTHROPIC_API_KEY to enable AI reasoning layer.'));
}

export function printReport(result: AuditResult): void {
  const agentName = result.metadata.name ?? 'unnamed';
  const ts = new Date(result.timestamp).toLocaleString();

  console.log('');
  console.log(chalk.cyan(BORDER));
  console.log(chalk.cyan.bold(center('AgentCheck Audit Report')));
  console.log(chalk.dim(center(`Agent: ${agentName}`)));
  console.log(chalk.dim(center(`Scanned: ${ts}`)));
  if (result.metadata.source === 'scan' && result.metadata.scanPath) {
    console.log(chalk.dim(center(`Path: ${result.metadata.scanPath}`)));
    console.log(chalk.dim(center(`Files: ${result.metadata.filesScanned ?? 0}`)));
  }
  console.log(chalk.cyan(BORDER));

  printStaticSection(result.staticFindings);

  if (result.aiAnalysis) {
    printAiSection(result.aiAnalysis);
    printModelSection(result.aiAnalysis, result.metadata.model);
  } else {
    printNoAiNote();
  }

  printSummary(result);

  console.log(chalk.dim('  Run with --no-ai for static analysis only (no API key needed)'));
  console.log(chalk.cyan(BORDER));
  console.log('');
}

export function printAiPrivacyNotice(): void {
  console.log('');
  console.log(chalk.dim('┌─────────────────────────────────────────────────────┐'));
  console.log(chalk.dim('│ Privacy notice: AI analysis uses your                │'));
  console.log(chalk.dim('│ ANTHROPIC_API_KEY. Only agent metadata is sent —     │'));
  console.log(chalk.dim('│ never your raw code or system prompt content.        │'));
  console.log(chalk.dim('└─────────────────────────────────────────────────────┘'));
  console.log('');
}
