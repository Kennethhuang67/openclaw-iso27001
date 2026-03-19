import { runScan, computeDiff } from '../src/scanner';
import { ScanResult, ScanOptions } from '../src/types';

describe('Scanner', () => {
  const defaultOptions: ScanOptions = {
    fix: false,
    json: false,
    diff: false,
  };

  it('should complete a full scan without errors', async () => {
    const result = await runScan(defaultOptions);

    expect(result).toBeDefined();
    expect(result.timestamp).toBeDefined();
    expect(result.platform).toBeDefined();
    expect(result.hostname).toBeDefined();
    expect(result.summary).toBeDefined();
    expect(result.summary.totalFindings).toBeGreaterThan(0);
    expect(result.summary.riskScore).toBeGreaterThanOrEqual(0);
    expect(result.summary.riskScore).toBeLessThanOrEqual(100);
  }, 30000);

  it('should scan individual modules', async () => {
    const modules = ['cryptography', 'access-control', 'communications', 'operations', 'system'] as const;

    for (const mod of modules) {
      const result = await runScan({ ...defaultOptions, module: mod });
      expect(result.modules[mod].length).toBeGreaterThan(0);

      // Other modules should be empty
      for (const other of modules) {
        if (other !== mod) {
          expect(result.modules[other].length).toBe(0);
        }
      }
    }
  }, 60000);

  it('should produce valid findings with required fields', async () => {
    const result = await runScan(defaultOptions);
    const allFindings = Object.values(result.modules).flat();

    for (const f of allFindings) {
      expect(f.id).toBeDefined();
      expect(f.title).toBeDefined();
      expect(f.description).toBeDefined();
      expect(['high', 'medium', 'low', 'good']).toContain(f.risk);
      expect(f.isoClause).toMatch(/^A\.\d+/);
      expect(f.isoClauseName).toBeDefined();
      expect(f.module).toBeDefined();
      expect(Array.isArray(f.details)).toBe(true);
      expect(f.recommendation).toBeDefined();
      expect(typeof f.autoFixable).toBe('boolean');
    }
  }, 30000);

  it('should compute diff between two scans', async () => {
    const scan1 = await runScan(defaultOptions);

    // Small delay to get different timestamps
    await new Promise(resolve => setTimeout(resolve, 100));

    const scan2 = await runScan(defaultOptions);

    const diff = computeDiff(scan1, scan2);

    expect(diff).toBeDefined();
    expect(diff.previousTimestamp).toBe(scan1.timestamp);
    expect(diff.currentTimestamp).toBe(scan2.timestamp);
    expect(diff.previousScore).toBe(scan1.summary.riskScore);
    expect(diff.currentScore).toBe(scan2.summary.riskScore);
    expect(Array.isArray(diff.newFindings)).toBe(true);
    expect(Array.isArray(diff.resolvedFindings)).toBe(true);
    expect(Array.isArray(diff.unchangedFindings)).toBe(true);
  }, 60000);

  it('should calculate summary correctly', async () => {
    const result = await runScan(defaultOptions);
    const allFindings = Object.values(result.modules).flat();

    const high = allFindings.filter(f => f.risk === 'high').length;
    const medium = allFindings.filter(f => f.risk === 'medium').length;
    const low = allFindings.filter(f => f.risk === 'low').length;
    const good = allFindings.filter(f => f.risk === 'good').length;

    expect(result.summary.high).toBe(high);
    expect(result.summary.medium).toBe(medium);
    expect(result.summary.low).toBe(low);
    expect(result.summary.good).toBe(good);
    expect(result.summary.totalFindings).toBe(allFindings.length);
  }, 30000);
});

describe('Report Generation', () => {
  it('should generate markdown report', async () => {
    const { generateMarkdownReport } = require('../src/reporter/markdown');
    const result = await runScan({ fix: false, json: false, diff: false });
    const report = generateMarkdownReport(result);

    expect(report).toContain('# OpenClaw ISO 27001');
    expect(report).toContain('Executive Summary');
    expect(report).toContain('Risk Score');
  }, 30000);

  it('should generate JSON report', async () => {
    const { generateJsonReport } = require('../src/reporter/json');
    const result = await runScan({ fix: false, json: false, diff: false });
    const report = generateJsonReport(result);

    const parsed = JSON.parse(report);
    expect(parsed.timestamp).toBeDefined();
    expect(parsed.summary).toBeDefined();
  }, 30000);
});
