import chalk from 'chalk';
import type { AuditOptions, AuditResult } from '../types';
import { scanDirectory } from '../modes/scanner';
import { runInteractive } from '../modes/interactive';
import { runStaticAnalysis } from '../layers/static';
import { runAiAnalysis } from '../layers/ai';
import { printReport, printAiPrivacyNotice } from '../output/report';

export async function runAudit(options: AuditOptions): Promise<void> {
  let metadata;

  // Determine input mode
  if (options.path) {
    console.log(chalk.dim(`\nScanning ${options.path} ...`));
    try {
      metadata = await scanDirectory(options.path);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`\nScan failed: ${msg}`));
      process.exit(1);
    }

    if ((metadata.filesScanned ?? 0) === 0) {
      console.log(chalk.yellow('\nNo supported files found in the given path.'));
      console.log(chalk.dim('Supported: .py, .ts, .js, .json, .yaml, .yml, .env'));
      process.exit(0);
    }

    console.log(chalk.dim(`Found ${metadata.filesScanned} file(s). Running analysis...`));
  } else {
    try {
      metadata = await runInteractive();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`\nInteractive mode failed: ${msg}`));
      process.exit(1);
    }
  }

  // Static analysis — always runs, no API key needed
  const staticFindings = runStaticAnalysis(metadata);

  // AI analysis — runs only if API key is set and --no-ai not passed
  let aiAnalysis;

  if (!options.noAi) {
    const hasKey = !!process.env['ANTHROPIC_API_KEY'];

    if (hasKey) {
      printAiPrivacyNotice();
      console.log(chalk.dim('Running AI analysis...'));

      try {
        aiAnalysis = await runAiAnalysis(metadata, staticFindings) ?? undefined;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(chalk.yellow(`\nAI analysis failed: ${msg}`));
        console.error(chalk.dim('Continuing with static analysis only.\n'));
      }
    }
  }

  const result: AuditResult = {
    metadata,
    staticFindings,
    aiAnalysis,
    timestamp: new Date().toISOString(),
  };

  if (options.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  printReport(result);
}
