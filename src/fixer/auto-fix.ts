import * as fs from 'fs';
import * as os from 'os';
import { execSync } from 'child_process';
import { Finding, FixResult } from '../types';

function execSafe(cmd: string): string {
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return '';
  }
}

function fixFilePermissions(finding: Finding): FixResult {
  const results: string[] = [];
  let success = true;

  for (const detail of finding.details) {
    // Extract file path from detail like "/path/to/file (mode: 644)"
    const match = detail.match(/^(.+)\s+\(mode:\s*\d+\)$/);
    if (!match) continue;

    const filePath = match[1].trim();
    try {
      fs.chmodSync(filePath, 0o600);
      results.push(`chmod 600 ${filePath}`);
    } catch (e) {
      success = false;
      results.push(`Failed to chmod ${filePath}: ${e}`);
    }
  }

  return {
    findingId: finding.id,
    title: finding.title,
    action: results.join('; ') || 'No files to fix',
    success,
  };
}

function fixStealthMode(): FixResult {
  if (os.platform() !== 'darwin') {
    return {
      findingId: 'SYS-002',
      title: 'Enable stealth mode',
      action: 'Not applicable on this platform',
      success: false,
      error: 'Stealth mode is macOS-only',
    };
  }

  const result = execSafe('sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>&1');
  if (result.includes('enabled') || result.includes('on')) {
    return {
      findingId: 'SYS-002',
      title: 'Enable stealth mode',
      action: 'Enabled macOS firewall stealth mode',
      success: true,
    };
  }

  return {
    findingId: 'SYS-002',
    title: 'Enable stealth mode',
    action: 'Attempted to enable stealth mode',
    success: false,
    error: result || 'Failed (may require sudo)',
  };
}

export async function autoFix(findings: Finding[]): Promise<FixResult[]> {
  const results: FixResult[] = [];

  for (const finding of findings) {
    if (!finding.autoFixable) continue;

    switch (finding.id) {
      case 'CRYPTO-002':
        results.push(fixFilePermissions(finding));
        break;
      case 'SYS-002':
        if (finding.details.some(d => d === 'Stealth mode is DISABLED')) {
          results.push(fixStealthMode());
        }
        break;
      default:
        // No auto-fix available for this finding
        break;
    }
  }

  return results;
}
