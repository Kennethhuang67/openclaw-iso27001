import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { runScan, getLastScanResult, computeDiff } from './scanner';
import { generateMarkdownReport, generateDiffReport } from './reporter/markdown';
import { generateJsonReport, generateJsonDiff } from './reporter/json';
import { autoFix } from './fixer/auto-fix';
import { ModuleName, Finding, RiskLevel } from './types';

const VALID_MODULES: ModuleName[] = ['cryptography', 'access-control', 'communications', 'operations', 'system'];

function riskIcon(risk: RiskLevel): string {
  switch (risk) {
    case 'high': return chalk.red('●');
    case 'medium': return chalk.yellow('●');
    case 'low': return chalk.blue('●');
    case 'good': return chalk.green('●');
  }
}

function printFindingSummary(findings: Finding[]): void {
  for (const f of findings) {
    const icon = riskIcon(f.risk);
    const fixTag = f.autoFixable ? chalk.cyan(' [auto-fixable]') : '';
    console.log(`  ${icon} ${f.risk.toUpperCase().padEnd(6)} ${f.id.padEnd(12)} ${f.title}${fixTag}`);
  }
}

function printBanner(): void {
  console.log(chalk.bold('\n  OpenClaw ISO 27001 Security Scanner'));
  console.log(chalk.gray('  ISO/IEC 27001:2022 compliance for AI agents\n'));
}

export function createCLI(): Command {
  const program = new Command();

  program
    .name('openclaw-iso27001')
    .description('ISO 27001 security compliance scanner for OpenClaw AI agents')
    .version('1.0.0');

  program
    .command('scan')
    .description('Run security compliance scan')
    .option('--fix', 'Auto-fix remediable findings')
    .option('--json', 'Output results as JSON')
    .option('--diff', 'Compare with previous scan')
    .option('--module <module>', `Scan specific module only (${VALID_MODULES.join(', ')})`)
    .action(async (opts) => {
      printBanner();

      // Validate module option
      if (opts.module && !VALID_MODULES.includes(opts.module)) {
        console.error(chalk.red(`Invalid module: ${opts.module}`));
        console.error(`Valid modules: ${VALID_MODULES.join(', ')}`);
        process.exit(1);
      }

      // Get previous scan for diff mode
      const previousScan = opts.diff ? getLastScanResult() : null;
      if (opts.diff && !previousScan) {
        console.log(chalk.yellow('  No previous scan found. Running first scan...\n'));
      }

      // Run scan
      console.log(chalk.gray('  Scanning...'));
      const startTime = Date.now();

      const result = await runScan({
        fix: opts.fix || false,
        json: opts.json || false,
        diff: opts.diff || false,
        module: opts.module as ModuleName | undefined,
      });

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(chalk.gray(`  Scan completed in ${elapsed}s\n`));

      // Auto-fix
      if (opts.fix) {
        const allFindings = Object.values(result.modules).flat();
        const fixable = allFindings.filter(f => f.autoFixable);

        if (fixable.length > 0) {
          console.log(chalk.cyan(`  Applying ${fixable.length} auto-fix(es)...\n`));
          const fixResults = await autoFix(allFindings);

          for (const fr of fixResults) {
            const icon = fr.success ? chalk.green('✓') : chalk.red('✗');
            console.log(`  ${icon} ${fr.title}: ${fr.action}`);
            if (fr.error) {
              console.log(chalk.red(`    Error: ${fr.error}`));
            }
          }
          console.log('');
        } else {
          console.log(chalk.green('  No auto-fixable findings.\n'));
        }
      }

      // Output
      if (opts.json) {
        if (opts.diff && previousScan) {
          const diff = computeDiff(previousScan, result);
          console.log(generateJsonDiff(diff));
        } else {
          console.log(generateJsonReport(result));
        }
        return;
      }

      // Print summary to console
      const { summary } = result;
      const scoreColor = summary.riskScore <= 10 ? chalk.green
        : summary.riskScore <= 25 ? chalk.blue
        : summary.riskScore <= 50 ? chalk.yellow
        : chalk.red;

      console.log(chalk.bold('  Risk Score: ') + scoreColor(`${summary.riskScore}/100`));
      console.log(`  Findings:  ${chalk.red(String(summary.high))} high  ${chalk.yellow(String(summary.medium))} medium  ${chalk.blue(String(summary.low))} low  ${chalk.green(String(summary.good))} good`);
      console.log('');

      // Print findings by module
      const moduleNames: Record<string, string> = {
        cryptography: 'Cryptography (A.8)',
        'access-control': 'Access Control (A.9)',
        communications: 'Communications (A.10)',
        operations: 'Operations (A.12)',
        system: 'System Security (A.13)',
      };

      for (const [mod, findings] of Object.entries(result.modules)) {
        if (findings.length === 0) continue;
        console.log(chalk.bold(`  ${moduleNames[mod] || mod}`));
        const sorted = [...findings].sort((a, b) => {
          const order: Record<RiskLevel, number> = { high: 0, medium: 1, low: 2, good: 3 };
          return order[a.risk] - order[b.risk];
        });
        printFindingSummary(sorted);
        console.log('');
      }

      // Diff output
      if (opts.diff && previousScan) {
        const diff = computeDiff(previousScan, result);
        const scoreDelta = diff.currentScore - diff.previousScore;
        const trend = scoreDelta < 0 ? chalk.green('↓ improved') : scoreDelta > 0 ? chalk.red('↑ worsened') : 'unchanged';
        console.log(chalk.bold('  Diff vs Previous Scan'));
        console.log(`  Score: ${diff.previousScore} → ${diff.currentScore} (${trend})`);
        console.log(`  New findings: ${diff.newFindings.length}`);
        console.log(`  Resolved: ${diff.resolvedFindings.length}`);
        console.log('');
      }

      // Tip
      if (!opts.fix) {
        const fixableCount = Object.values(result.modules).flat().filter(f => f.autoFixable).length;
        if (fixableCount > 0) {
          console.log(chalk.cyan(`  Tip: ${fixableCount} finding(s) can be auto-fixed with --fix`));
        }
      }
      console.log(chalk.gray('  Run with --json for machine-readable output'));
      console.log(chalk.gray('  Full report: openclaw-iso27001 report\n'));
    });

  program
    .command('report')
    .description('Generate full markdown report from latest scan')
    .option('--json', 'Generate JSON report instead')
    .option('-o, --output <file>', 'Write report to file')
    .action(async (opts) => {
      printBanner();

      // Run a fresh scan
      console.log(chalk.gray('  Running scan for report...\n'));
      const result = await runScan({ fix: false, json: false, diff: false });

      let report: string;
      let ext: string;
      if (opts.json) {
        report = generateJsonReport(result);
        ext = 'json';
      } else {
        report = generateMarkdownReport(result);
        ext = 'md';
      }

      if (opts.output) {
        fs.writeFileSync(opts.output, report);
        console.log(chalk.green(`  Report written to ${opts.output}`));
      } else {
        const defaultPath = path.join(process.cwd(), `iso27001-report-${new Date().toISOString().slice(0, 10)}.${ext}`);
        fs.writeFileSync(defaultPath, report);
        console.log(chalk.green(`  Report written to ${defaultPath}`));
      }
      console.log('');
    });

  return program;
}
