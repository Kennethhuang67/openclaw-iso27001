import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { ScanResult, ScanSummary, ScanOptions, Finding, ModuleName, DiffResult } from '../types';
import { scanCryptography } from './cryptography';
import { scanAccessControl } from './access-control';
import { scanCommunications } from './communications';
import { scanOperations } from './operations';
import { scanSystem } from './system';

const SCAN_HISTORY_DIR = path.join(os.homedir(), '.openclaw-iso27001');

function calculateSummary(allFindings: Finding[]): ScanSummary {
  const high = allFindings.filter(f => f.risk === 'high').length;
  const medium = allFindings.filter(f => f.risk === 'medium').length;
  const low = allFindings.filter(f => f.risk === 'low').length;
  const good = allFindings.filter(f => f.risk === 'good').length;

  // Risk score: 0-100, lower is better
  // high = 15pts each, medium = 8pts each, low = 2pts each, good = -3pts each
  const rawScore = (high * 15) + (medium * 8) + (low * 2) + (good * -3);
  const riskScore = Math.max(0, Math.min(100, rawScore));

  return {
    totalFindings: allFindings.length,
    high,
    medium,
    low,
    good,
    riskScore,
  };
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const modules: Record<ModuleName, Finding[]> = {
    cryptography: [],
    'access-control': [],
    communications: [],
    operations: [],
    system: [],
  };

  const moduleRunner: Record<ModuleName, () => Promise<Finding[]>> = {
    cryptography: scanCryptography,
    'access-control': scanAccessControl,
    communications: scanCommunications,
    operations: scanOperations,
    system: scanSystem,
  };

  if (options.module) {
    // Scan specific module only
    const runner = moduleRunner[options.module];
    if (runner) {
      modules[options.module] = await runner();
    }
  } else {
    // Scan all modules in parallel
    const results = await Promise.all([
      scanCryptography(),
      scanAccessControl(),
      scanCommunications(),
      scanOperations(),
      scanSystem(),
    ]);
    modules.cryptography = results[0];
    modules['access-control'] = results[1];
    modules.communications = results[2];
    modules.operations = results[3];
    modules.system = results[4];
  }

  const allFindings = Object.values(modules).flat();

  const result: ScanResult = {
    timestamp: new Date().toISOString(),
    platform: os.platform() as 'darwin' | 'linux' | 'unknown',
    hostname: os.hostname(),
    modules,
    summary: calculateSummary(allFindings),
  };

  // Save scan result for diff mode
  saveScanResult(result);

  return result;
}

function saveScanResult(result: ScanResult): void {
  try {
    if (!fs.existsSync(SCAN_HISTORY_DIR)) {
      fs.mkdirSync(SCAN_HISTORY_DIR, { recursive: true });
    }
    const filename = `scan-${result.timestamp.replace(/[:.]/g, '-')}.json`;
    fs.writeFileSync(
      path.join(SCAN_HISTORY_DIR, filename),
      JSON.stringify(result, null, 2)
    );

    // Also save as "latest"
    fs.writeFileSync(
      path.join(SCAN_HISTORY_DIR, 'latest.json'),
      JSON.stringify(result, null, 2)
    );
  } catch {
    // Non-critical — continue without saving
  }
}

export function getLastScanResult(): ScanResult | null {
  try {
    const latestPath = path.join(SCAN_HISTORY_DIR, 'latest.json');
    if (fs.existsSync(latestPath)) {
      return JSON.parse(fs.readFileSync(latestPath, 'utf-8'));
    }
  } catch {
    // No previous scan
  }
  return null;
}

export function computeDiff(previous: ScanResult, current: ScanResult): DiffResult {
  const prevFindings = Object.values(previous.modules).flat();
  const currFindings = Object.values(current.modules).flat();

  const prevIds = new Set(prevFindings.map(f => `${f.id}-${f.risk}`));
  const currIds = new Set(currFindings.map(f => `${f.id}-${f.risk}`));

  const newFindings = currFindings.filter(f => !prevIds.has(`${f.id}-${f.risk}`));
  const resolvedFindings = prevFindings.filter(f => !currIds.has(`${f.id}-${f.risk}`));
  const unchangedFindings = currFindings.filter(f => prevIds.has(`${f.id}-${f.risk}`));

  return {
    newFindings,
    resolvedFindings,
    unchangedFindings,
    previousScore: previous.summary.riskScore,
    currentScore: current.summary.riskScore,
    previousTimestamp: previous.timestamp,
    currentTimestamp: current.timestamp,
  };
}
