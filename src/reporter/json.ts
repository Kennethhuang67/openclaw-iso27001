import { ScanResult, DiffResult } from '../types';

export function generateJsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function generateJsonDiff(diff: DiffResult): string {
  return JSON.stringify(diff, null, 2);
}
