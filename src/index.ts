#!/usr/bin/env node
import chalk from 'chalk';
import { runAudit } from './commands/audit';
import type { AuditOptions } from './types';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const VERSION: string = (require('../package.json') as { version: string }).version;

function printHelp(): void {
  console.log(`
${chalk.bold.cyan('AgentCheck')} ${chalk.dim(`v${VERSION}`)} — AI agent security auditor

${chalk.bold('Usage:')}
  npx agentcheck audit                  Scan current directory
  npx agentcheck audit --path ./dir     Scan a specific directory
  npx agentcheck audit --interactive    Answer questions instead of scanning

${chalk.bold('Options:')}
  --path <dir>    Path to agent source directory
  --interactive   Force interactive mode (no source code needed)
  --no-ai         Static analysis only — no API key, no network
  --json          Machine-readable JSON output (for CI pipelines)
  --version       Print version
  --help          Show this help

${chalk.bold('Environment:')}
  ANTHROPIC_API_KEY   Enables AI reasoning layer (optional)

${chalk.bold('Examples:')}
  npx agentcheck audit
  npx agentcheck audit --path ./my-agent
  npx agentcheck audit --path ./my-agent --no-ai
  npx agentcheck audit --interactive
  npx agentcheck audit --path ./my-agent --json > report.json

${chalk.dim('Built by Socialease Labs — MIT License')}
`);
}

function parseArgs(argv: string[]): { command: string | null; options: AuditOptions } {
  const args = argv.slice(2);
  const command = args[0] ?? null;

  const options: AuditOptions = {
    noAi: args.includes('--no-ai'),
    json: args.includes('--json'),
    interactive: args.includes('--interactive'),
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
