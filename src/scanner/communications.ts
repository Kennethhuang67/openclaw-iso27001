import * as os from 'os';
import { execSync } from 'child_process';
import { Finding } from '../types';
import { getClauseName } from '../iso-clauses';

function execSafe(cmd: string): string {
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return '';
  }
}

function checkTailscaleStatus(): Finding[] {
  const findings: Finding[] = [];
  const tailscaleStatus = execSafe('tailscale status 2>/dev/null');

  if (!tailscaleStatus) {
    findings.push({
      id: 'COMM-001',
      title: 'Tailscale not available',
      description: 'Tailscale VPN is not installed or not running.',
      risk: 'low',
      isoClause: 'A.8.20',
      isoClauseName: getClauseName('A.8.20'),
      module: 'communications',
      details: ['Tailscale CLI not found or not connected'],
      recommendation: 'Consider using Tailscale or another VPN for secure agent communication.',
      autoFixable: false,
    });
    return findings;
  }

  const lines = tailscaleStatus.split('\n').filter(l => l.trim().length > 0);
  const devices: string[] = [];
  const offlineDevices: string[] = [];

  for (const line of lines) {
    if (line.includes('offline')) {
      offlineDevices.push(line.trim());
    } else if (!line.startsWith('#')) {
      devices.push(line.trim());
    }
  }

  const details = [
    `Connected devices: ${devices.length}`,
    `Offline devices: ${offlineDevices.length}`,
  ];

  if (offlineDevices.length > 0) {
    details.push('Offline devices:');
    details.push(...offlineDevices.map(d => `  - ${d}`));
  }

  findings.push({
    id: 'COMM-001',
    title: 'Tailscale network status',
    description: 'Tailscale VPN network status and connected devices.',
    risk: offlineDevices.length > 3 ? 'medium' : 'good',
    isoClause: 'A.8.20',
    isoClauseName: getClauseName('A.8.20'),
    module: 'communications',
    details,
    recommendation: offlineDevices.length > 0
      ? 'Review offline devices — remove any that are no longer in use.'
      : 'Network looks healthy.',
    autoFixable: false,
  });

  // Check Tailscale Funnel
  const funnelStatus = execSafe('tailscale funnel status 2>/dev/null');
  if (funnelStatus && !funnelStatus.includes('not configured') && !funnelStatus.includes('No Funnel')) {
    const funnelDetails = funnelStatus.split('\n').filter(l => l.trim().length > 0);
    findings.push({
      id: 'COMM-002',
      title: 'Tailscale Funnel routes exposed',
      description: 'Tailscale Funnel is exposing routes to the public internet.',
      risk: 'high',
      isoClause: 'A.8.21',
      isoClauseName: getClauseName('A.8.21'),
      module: 'communications',
      details: funnelDetails,
      recommendation: 'Review Funnel routes. Only expose services that absolutely need public access. Prefer tailnet-only access.',
      autoFixable: false,
    });
  }

  return findings;
}

function checkOpenPorts(): Finding {
  const platform = os.platform();
  let portOutput = '';

  if (platform === 'darwin') {
    portOutput = execSafe('lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | tail -50');
  } else {
    portOutput = execSafe('ss -tlnp 2>/dev/null | tail -50');
    if (!portOutput) {
      portOutput = execSafe('netstat -tlnp 2>/dev/null | tail -50');
    }
  }

  if (!portOutput) {
    return {
      id: 'COMM-003',
      title: 'Could not enumerate open ports',
      description: 'Unable to list open listening ports.',
      risk: 'low',
      isoClause: 'A.8.20',
      isoClauseName: getClauseName('A.8.20'),
      module: 'communications',
      details: ['Could not run port scan (insufficient permissions or tools not available)'],
      recommendation: 'Run the scanner with elevated privileges for a complete port audit.',
      autoFixable: false,
    };
  }

  const lines = portOutput.split('\n').filter(l => l.trim().length > 0);

  // Check for concerning ports
  const highRiskPorts = ['0.0.0.0', '*:'];
  const publicListeners = lines.filter(l =>
    highRiskPorts.some(p => l.includes(p)) && !l.includes('127.0.0.1') && !l.includes('[::1]')
  );

  const details = [`Total listening services: ${lines.length - 1}`]; // minus header
  if (publicListeners.length > 0) {
    details.push(`Services listening on all interfaces: ${publicListeners.length}`);
    details.push(...publicListeners.slice(0, 10).map(l => `  ${l.trim()}`));
    if (publicListeners.length > 10) {
      details.push(`  ... and ${publicListeners.length - 10} more`);
    }
  }

  return {
    id: 'COMM-003',
    title: 'Open listening ports',
    description: 'Services listening for network connections on this host.',
    risk: publicListeners.length > 5 ? 'medium' : 'low',
    isoClause: 'A.8.20',
    isoClauseName: getClauseName('A.8.20'),
    module: 'communications',
    details,
    recommendation: publicListeners.length > 0
      ? 'Review services listening on all interfaces. Bind to localhost where possible.'
      : 'Port configuration looks reasonable.',
    autoFixable: false,
  };
}

function checkWebhookEndpoints(): Finding {
  const details: string[] = [];

  // Check common webhook config locations
  const home = os.homedir();
  const webhookPaths = [
    `${home}/.openclaw/webhooks.yaml`,
    `${home}/.openclaw/workspace/config/webhooks.yaml`,
    `${home}/.openclaw/config/webhooks.json`,
  ];

  let found = false;
  for (const wp of webhookPaths) {
    try {
      const content = require('fs').readFileSync(wp, 'utf-8');
      found = true;
      details.push(`Webhook config found: ${wp}`);

      // Check for HTTP (non-HTTPS) endpoints
      const httpMatches = content.match(/http:\/\/[^\s"']+/g);
      if (httpMatches) {
        details.push(`WARNING: Non-HTTPS webhook endpoints found:`);
        details.push(...httpMatches.map((m: string) => `  - ${m}`));
        return {
          id: 'COMM-004',
          title: 'Insecure webhook endpoints',
          description: 'Webhook endpoints using plain HTTP were detected.',
          risk: 'high',
          isoClause: 'A.8.21',
          isoClauseName: getClauseName('A.8.21'),
          module: 'communications',
          details,
          recommendation: 'Use HTTPS for all webhook endpoints to ensure data in transit is encrypted.',
          autoFixable: false,
        };
      }
    } catch {
      // not found
    }
  }

  if (!found) {
    details.push('No webhook configuration files found');
  }

  return {
    id: 'COMM-004',
    title: 'Webhook endpoint review',
    description: 'Checked webhook configurations for security issues.',
    risk: 'good',
    isoClause: 'A.8.21',
    isoClauseName: getClauseName('A.8.21'),
    module: 'communications',
    details,
    recommendation: 'Ensure all webhook endpoints use HTTPS and validate signatures.',
    autoFixable: false,
  };
}

export async function scanCommunications(): Promise<Finding[]> {
  const findings: Finding[] = [];

  findings.push(...checkTailscaleStatus());
  findings.push(checkOpenPorts());
  findings.push(checkWebhookEndpoints());

  return findings;
}
