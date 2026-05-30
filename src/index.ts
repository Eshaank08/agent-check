#!/usr/bin/env node
import chalk from 'chalk';
import { runAudit } from './commands/audit';
import type { AuditOptions } from './types';

const VERSION = '0.1.0';

function printHelp(): void {
  console.log(`
${chalk.bold.cyan('AgentCheck')} ${chalk.dim(`v${VERSION}`)} — AI agent security auditor

${chalk.bold('Usage:')}
  npx agentcheck audit               Interactive mode (no path needed)
  npx agentcheck audit --path ./dir  Scan an agent directory

${chalk.bold('Options:')}
  --path <dir>   Path to agent source directory
  --no-ai        Run static analysis only (no Anthropic API key needed)
  --json         Output raw JSON (useful for CI pipelines and scripting)
  --version      Print version
  --help         Show this help

${chalk.bold('Environment:')}
  ANTHROPIC_API_KEY   Required for AI reasoning layer

${chalk.bold('Examples:')}
  npx agentcheck audit
  npx agentcheck audit --path ./my-agent
  npx agentcheck audit --path ./my-agent --no-ai

${chalk.dim('Built by Socialease Labs — MIT License')}
`);
}

function parseArgs(argv: string[]): { command: string | null; options: AuditOptions } {
  const args = argv.slice(2);
  const command = args[0] ?? null;

  const options: AuditOptions = {
    noAi: args.includes('--no-ai'),
    json: args.includes('--json'),
  };

  const pathIndex = args.indexOf('--path');
  if (pathIndex !== -1 && args[pathIndex + 1]) {
    options.path = args[pathIndex + 1];
  }

  return { command, options };
}

async function main(): Promise<void> {
  const { command, options } = parseArgs(process.argv);

  if (command === '--version' || command === '-v') {
    console.log(`agentcheck v${VERSION}`);
    process.exit(0);
  }

  if (command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    process.exit(0);
  }

  if (command === 'audit') {
    try {
      await runAudit(options);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`\nUnexpected error: ${msg}`));
      process.exit(1);
    }
    return;
  }

  // No command — show help
  if (!command) {
    printHelp();
    process.exit(0);
  }

  console.error(chalk.red(`\nUnknown command: ${command}`));
  console.error(chalk.dim('Run `npx agentcheck --help` for usage.'));
  process.exit(1);
}

main().catch((err) => {
  console.error(chalk.red('\nFatal error:'), err instanceof Error ? err.message : String(err));
  process.exit(1);
});
