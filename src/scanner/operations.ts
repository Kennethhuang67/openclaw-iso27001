import * as fs from 'fs';
import * as path from 'path';
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

function checkLaunchAgents(): Finding {
  const platform = os.platform();
  const details: string[] = [];
  const suspicious: string[] = [];

  if (platform === 'darwin') {
    const home = os.homedir();
    const agentDirs = [
      path.join(home, 'Library', 'LaunchAgents'),
      '/Library/LaunchAgents',
      '/Library/LaunchDaemons',
    ];

    for (const dir of agentDirs) {
      try {
        const files = fs.readdirSync(dir);
        const plists = files.filter(f => f.endsWith('.plist'));
        details.push(`${dir}: ${plists.length} agents`);

        for (const plist of plists) {
          // Check for recently added agents (last 7 days)
          const fullPath = path.join(dir, plist);
          const stats = fs.statSync(fullPath);
          const daysSinceModified = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60 * 24);
          if (daysSinceModified < 7) {
            suspicious.push(`Recently modified: ${fullPath} (${Math.floor(daysSinceModified)}d ago)`);
          }

          // Check for openclaw-related agents
          if (plist.toLowerCase().includes('openclaw') || plist.toLowerCase().includes('claw')) {
            details.push(`  OpenClaw agent: ${plist}`);
          }
        }
      } catch {
        // dir not accessible
      }
    }

    if (suspicious.length > 0) {
      details.push('Recently modified LaunchAgents:');
      details.push(...suspicious.map(s => `  - ${s}`));
    }
  } else {
    // Linux: check systemd services
    const services = execSafe('systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -30');
    if (services) {
      details.push('Running systemd services:');
      const lines = services.split('\n').filter(l => l.trim().length > 0);
      details.push(`Total running services: ${lines.length}`);

      // Check for openclaw services
      const clawServices = lines.filter(l => /openclaw|claw/i.test(l));
      if (clawServices.length > 0) {
        details.push('OpenClaw services:');
        details.push(...clawServices.map(s => `  - ${s.trim()}`));
      }
    }
  }

  return {
    id: 'OPS-001',
    title: platform === 'darwin' ? 'LaunchAgents audit' : 'Systemd services audit',
    description: 'Review of scheduled services and background agents.',
    risk: suspicious.length > 0 ? 'medium' : 'good',
    isoClause: 'A.8.16',
    isoClauseName: getClauseName('A.8.16'),
    module: 'operations',
    details: details.length > 0 ? details : ['No agents/services found'],
    recommendation: suspicious.length > 0
      ? 'Review recently modified LaunchAgents for unauthorized additions.'
      : 'No suspicious changes detected.',
    autoFixable: false,
  };
}

function checkCronJobs(): Finding {
  const details: string[] = [];
  const currentUser = os.userInfo().username;

  const crontab = execSafe(`crontab -l 2>/dev/null`);
  if (crontab && !crontab.includes('no crontab')) {
    const jobs = crontab.split('\n').filter(l => l.trim().length > 0 && !l.startsWith('#'));
    details.push(`User ${currentUser} has ${jobs.length} cron jobs:`);
    details.push(...jobs.map(j => `  - ${j}`));
  } else {
    details.push(`User ${currentUser} has no cron jobs`);
  }

  // Check for openclaw-related cron jobs
  if (crontab && /openclaw|claw/i.test(crontab)) {
    details.push('OpenClaw-related cron jobs detected');
  }

  return {
    id: 'OPS-002',
    title: 'Cron job audit',
    description: 'Review of scheduled cron jobs.',
    risk: 'low',
    isoClause: 'A.8.16',
    isoClauseName: getClauseName('A.8.16'),
    module: 'operations',
    details,
    recommendation: 'Periodically review cron jobs for unauthorized entries.',
    autoFixable: false,
  };
}

function checkRunningProcesses(): Finding {
  const details: string[] = [];

  // Look for OpenClaw-related processes
  const processes = execSafe('ps aux 2>/dev/null');
  if (processes) {
    const lines = processes.split('\n');
    const clawProcesses = lines.filter(l =>
      /openclaw|claw.*agent|claw.*gateway|claw.*worker/i.test(l) && !l.includes('grep')
    );

    if (clawProcesses.length > 0) {
      details.push(`OpenClaw processes running: ${clawProcesses.length}`);
      details.push(...clawProcesses.map(p => `  - ${p.trim().substring(0, 120)}`));
    } else {
      details.push('No OpenClaw processes currently running');
    }

    // Check for suspicious node processes
    const nodeProcesses = lines.filter(l =>
      /node\s/i.test(l) && !l.includes('grep')
    );
    details.push(`Total Node.js processes: ${nodeProcesses.length}`);
  }

  return {
    id: 'OPS-003',
    title: 'Running process audit',
    description: 'Check for OpenClaw-related running processes.',
    risk: 'low',
    isoClause: 'A.8.6',
    isoClauseName: getClauseName('A.8.6'),
    module: 'operations',
    details,
    recommendation: 'Monitor running processes for unexpected entries.',
    autoFixable: false,
  };
}

function checkLogFiles(): Finding {
  const details: string[] = [];
  const home = os.homedir();

  const logPaths = [
    path.join(home, '.openclaw', 'logs'),
    path.join(home, '.openclaw', 'workspace', 'logs'),
    '/var/log',
  ];

  let authFailures = 0;

  for (const logDir of logPaths) {
    try {
      if (!fs.existsSync(logDir)) continue;

      const files = fs.readdirSync(logDir)
        .filter(f => f.endsWith('.log') || f.endsWith('.txt'))
        .slice(0, 10); // limit to 10 files

      for (const file of files) {
        try {
          const fullPath = path.join(logDir, file);
          const stats = fs.statSync(fullPath);
          // Only check files modified in last 7 days
          if (Date.now() - stats.mtimeMs > 7 * 24 * 60 * 60 * 1000) continue;

          const content = fs.readFileSync(fullPath, 'utf-8');
          const failures = (content.match(/401|403|unauthorized|authentication failed|access denied/gi) || []).length;
          if (failures > 0) {
            authFailures += failures;
            details.push(`${fullPath}: ${failures} auth failure(s)`);
          }
        } catch {
          // skip unreadable files
        }
      }
    } catch {
      // dir not accessible
    }
  }

  // Also check system auth log on Linux
  if (os.platform() === 'linux') {
    const authLog = execSafe('grep -c "authentication failure" /var/log/auth.log 2>/dev/null');
    if (authLog && parseInt(authLog) > 0) {
      authFailures += parseInt(authLog);
      details.push(`/var/log/auth.log: ${authLog} authentication failures`);
    }
  }

  if (authFailures > 0) {
    details.unshift(`Total authentication failures detected: ${authFailures}`);
  } else {
    details.push('No recent authentication failures detected in accessible logs');
  }

  return {
    id: 'OPS-004',
    title: 'Log file audit for auth failures',
    description: 'Scanned log files for authentication failures and access denials.',
    risk: authFailures > 20 ? 'high' : authFailures > 5 ? 'medium' : 'good',
    isoClause: 'A.8.15',
    isoClauseName: getClauseName('A.8.15'),
    module: 'operations',
    details,
    recommendation: authFailures > 0
      ? 'Investigate authentication failures. Check for brute force attempts or misconfigured services.'
      : 'Continue monitoring logs for anomalies.',
    autoFixable: false,
  };
}

export async function scanOperations(): Promise<Finding[]> {
  return [
    checkLaunchAgents(),
    checkCronJobs(),
    checkRunningProcesses(),
    checkLogFiles(),
  ];
}
