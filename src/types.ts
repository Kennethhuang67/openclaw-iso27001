export type RiskLevel = 'high' | 'medium' | 'low' | 'good';

export interface Finding {
  id: string;
  title: string;
  description: string;
  risk: RiskLevel;
  isoClause: string;
  isoClauseName: string;
  module: ModuleName;
  details: string[];
  recommendation: string;
  autoFixable: boolean;
}

export type ModuleName = 'cryptography' | 'access-control' | 'communications' | 'operations' | 'system';

export interface ScanResult {
  timestamp: string;
  platform: 'darwin' | 'linux' | 'unknown';
  hostname: string;
  modules: Record<ModuleName, Finding[]>;
  summary: ScanSummary;
}

export interface ScanSummary {
  totalFindings: number;
  high: number;
  medium: number;
  low: number;
  good: number;
  riskScore: number; // 0-100, lower is better
}

export interface ScanOptions {
  fix: boolean;
  json: boolean;
  diff: boolean;
  module?: ModuleName;
}

export interface DiffResult {
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
  previousScore: number;
  currentScore: number;
  previousTimestamp: string;
  currentTimestamp: string;
}

export interface FixResult {
  findingId: string;
  title: string;
  action: string;
  success: boolean;
  error?: string;
}
