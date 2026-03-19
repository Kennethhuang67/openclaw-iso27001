import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Finding } from '../types';
import { getClauseName } from '../iso-clauses';

// Patterns that indicate secrets/keys
const SECRET_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, label: 'OpenAI API key' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/, label: 'Anthropic API key' },
  { pattern: /ghp_[a-zA-Z0-9]{36,}/, label: 'GitHub personal access token' },
  { pattern: /gho_[a-zA-Z0-9]{36,}/, label: 'GitHub OAuth token' },
  { pattern: /github_pat_[a-zA-Z0-9_]{20,}/, label: 'GitHub fine-grained PAT' },
  { pattern: /xoxb-[a-zA-Z0-9-]+/, label: 'Slack bot token' },
  { pattern: /xoxp-[a-zA-Z0-9-]+/, label: 'Slack user token' },
  { pattern: /AKIA[0-9A-Z]{16}/, label: 'AWS access key' },
  { pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/, label: 'Private key' },
  { pattern: /api[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{16,}/, label: 'Generic API key' },
  { pattern: /token\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}/, label: 'Generic token' },
  { pattern: /secret\s*[:=]\s*["']?[a-zA-Z0-9_-]{16,}/, label: 'Generic secret' },
];

// False positive patterns to filter out
const FALSE_POSITIVE_PATTERNS = [
  /task-system/i,
  /task-decomposer/i,
  /skill-[a-z-]+/i,
  /token\s*[:=]\s*["']?(true|false|null|undefined|none|placeholder|your[_-])/i,
  /api[_-]?key\s*[:=]\s*["']?(your[_-]|placeholder|changeme|xxx|TODO)/i,
  /secret\s*[:=]\s*["']?(your[_-]|placeholder|changeme|xxx|TODO)/i,
  /token_type/i,
  /token_count/i,
  /tokenize/i,
];

function isFalsePositive(line: string): boolean {
  return FALSE_POSITIVE_PATTERNS.some(fp => fp.test(line));
}

function scanFileForSecrets(filePath: string): Array<{ label: string; line: number; pattern: string }> {
  const results: Array<{ label: string; line: number; pattern: string }> = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isFalsePositive(line)) continue;
      for (const sp of SECRET_PATTERNS) {
        if (sp.pattern.test(line)) {
          results.push({ label: sp.label, line: i + 1, pattern: sp.pattern.source });
        }
      }
    }
  } catch {
    // File not readable — that's fine
  }
  return results;
}

function checkFilePermissions(filePath: string): string | null {
  try {
    const stats = fs.statSync(filePath);
    const mode = (stats.mode & 0o777).toString(8);
    if (mode !== '600' && mode !== '400') {
      return mode;
    }
  } catch {
    // skip
  }
  return null;
}

function getConfigDirs(): string[] {
  const home = os.homedir();
  return [
    path.join(home, '.openclaw'),
    path.join(home, '.openclaw', 'workspace', 'config'),
    path.join(home, '.openclaw', 'workspace'),
    path.join(home, '.openclaw', 'memory'),
    path.join(home, '.openclaw', 'knowledge'),
  ];
}

function walkDir(dir: string, maxDepth = 3, depth = 0): string[] {
  const files: string[] = [];
  if (depth > maxDepth) return files;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        files.push(...walkDir(fullPath, maxDepth, depth + 1));
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  } catch {
    // directory not accessible
  }
  return files;
}

export async function scanCryptography(): Promise<Finding[]> {
  const findings: Finding[] = [];
  const configDirs = getConfigDirs();
  const scannedFiles: string[] = [];

  for (const dir of configDirs) {
    scannedFiles.push(...walkDir(dir));
  }

  // Also scan common env files
  const home = os.homedir();
  const envFiles = ['.env', '.env.local', '.env.production'].map(f => path.join(home, f));
  for (const ef of envFiles) {
    if (fs.existsSync(ef)) scannedFiles.push(ef);
  }

  // Check for secrets in files
  const filesWithSecrets: Array<{ file: string; secrets: Array<{ label: string; line: number }> }> = [];
  for (const file of scannedFiles) {
    const secrets = scanFileForSecrets(file);
    if (secrets.length > 0) {
      filesWithSecrets.push({ file, secrets });
    }
  }

  if (filesWithSecrets.length > 0) {
    const details = filesWithSecrets.flatMap(f =>
      f.secrets.map(s => `${f.file}:${s.line} - ${s.label}`)
    );
    findings.push({
      id: 'CRYPTO-001',
      title: 'Secrets detected in configuration files',
      description: 'API keys, tokens, or secrets were found in plain text configuration files.',
      risk: 'high',
      isoClause: 'A.8.2',
      isoClauseName: getClauseName('A.8.2'),
      module: 'cryptography',
      details,
      recommendation: 'Move secrets to a dedicated secrets manager or encrypted vault. Use environment variables for runtime access.',
      autoFixable: false,
    });
  } else {
    findings.push({
      id: 'CRYPTO-001',
      title: 'No secrets detected in configuration files',
      description: 'No API keys, tokens, or secrets were found in scanned configuration files.',
      risk: 'good',
      isoClause: 'A.8.2',
      isoClauseName: getClauseName('A.8.2'),
      module: 'cryptography',
      details: [`Scanned ${scannedFiles.length} files across OpenClaw directories`],
      recommendation: 'Continue monitoring for accidental secret commits.',
      autoFixable: false,
    });
  }

  // Check file permissions
  const badPerms: string[] = [];
  for (const file of scannedFiles) {
    const mode = checkFilePermissions(file);
    if (mode) {
      badPerms.push(`${file} (mode: ${mode})`);
    }
  }

  if (badPerms.length > 0) {
    findings.push({
      id: 'CRYPTO-002',
      title: 'Config files with overly permissive permissions',
      description: 'Configuration files that may contain secrets have permissions more permissive than 600.',
      risk: 'medium',
      isoClause: 'A.8.9',
      isoClauseName: getClauseName('A.8.9'),
      module: 'cryptography',
      details: badPerms,
      recommendation: 'Set file permissions to 600 (owner read/write only) for files containing secrets.',
      autoFixable: true,
    });
  } else if (scannedFiles.length > 0) {
    findings.push({
      id: 'CRYPTO-002',
      title: 'Config file permissions are properly restricted',
      description: 'All scanned configuration files have appropriate file permissions.',
      risk: 'good',
      isoClause: 'A.8.9',
      isoClauseName: getClauseName('A.8.9'),
      module: 'cryptography',
      details: [`${scannedFiles.length} files checked`],
      recommendation: 'Maintain current permission settings.',
      autoFixable: false,
    });
  }

  // Check for .env files in home directory
  const envFilesFound: string[] = [];
  for (const ef of envFiles) {
    if (fs.existsSync(ef)) {
      envFilesFound.push(ef);
    }
  }
  if (envFilesFound.length > 0) {
    findings.push({
      id: 'CRYPTO-003',
      title: 'Environment files found in home directory',
      description: 'Environment files in the home directory may contain secrets accessible to all user processes.',
      risk: 'low',
      isoClause: 'A.8.10',
      isoClauseName: getClauseName('A.8.10'),
      module: 'cryptography',
      details: envFilesFound,
      recommendation: 'Consider using a project-specific .env file instead of a home directory .env file.',
      autoFixable: false,
    });
  }

  return findings;
}
