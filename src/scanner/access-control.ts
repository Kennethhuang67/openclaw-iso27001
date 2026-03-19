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

function checkGatewayPermissions(): Finding | null {
  const home = os.homedir();
  const gatewayPaths = [
    path.join(home, '.openclaw', 'gateway.yaml'),
    path.join(home, '.openclaw', 'workspace', 'config', 'gateway.yaml'),
    path.join(home, '.openclaw', 'config', 'gateway.yaml'),
  ];

  for (const gp of gatewayPaths) {
    if (fs.existsSync(gp)) {
      const content = fs.readFileSync(gp, 'utf-8');
      const details: string[] = [`Found gateway config: ${gp}`];

      // Check for overly permissive rules
      if (/allow\s*:\s*\*|permissions\s*:\s*all/i.test(content)) {
        details.push('WARNING: Wildcard permissions detected');
        return {
          id: 'ACCESS-001',
          title: 'Overly permissive agent gateway configuration',
          description: 'The OpenClaw gateway configuration has wildcard or overly broad permissions.',
          risk: 'high',
          isoClause: 'A.5.15',
          isoClauseName: getClauseName('A.5.15'),
          module: 'access-control',
          details,
          recommendation: 'Apply principle of least privilege to agent permissions. Define specific allowed actions per agent.',
          autoFixable: false,
        };
      }

      // Check for unsigned agent definitions
      if (/trust\s*:\s*unsigned|verify\s*:\s*false/i.test(content)) {
        details.push('WARNING: Unsigned agent trust enabled');
        return {
          id: 'ACCESS-001',
          title: 'Gateway allows unsigned agents',
          description: 'The OpenClaw gateway is configured to trust unsigned agent definitions.',
          risk: 'medium',
          isoClause: 'A.5.15',
          isoClauseName: getClauseName('A.5.15'),
          module: 'access-control',
          details,
          recommendation: 'Enable agent signature verification in gateway configuration.',
          autoFixable: false,
        };
      }

      return {
        id: 'ACCESS-001',
        title: 'Gateway configuration reviewed',
        description: 'OpenClaw gateway configuration found and reviewed.',
        risk: 'good',
        isoClause: 'A.5.15',
        isoClauseName: getClauseName('A.5.15'),
        module: 'access-control',
        details,
        recommendation: 'Regularly review gateway permissions as agent capabilities change.',
        autoFixable: false,
      };
    }
  }

  return null;
}

function checkSudoConfig(): Finding {
  const details: string[] = [];

  // Check if user has passwordless sudo
  const sudoCheck = execSafe('sudo -n true 2>&1 && echo "NOPASSWD" || echo "PASSWD_REQUIRED"');
  if (sudoCheck.includes('NOPASSWD')) {
    details.push('User has passwordless sudo access');
    return {
      id: 'ACCESS-002',
      title: 'Passwordless sudo enabled',
      description: 'The current user can execute sudo commands without a password.',
      risk: 'high',
      isoClause: 'A.5.17',
      isoClauseName: getClauseName('A.5.17'),
      module: 'access-control',
      details,
      recommendation: 'Remove NOPASSWD from sudoers configuration. Use targeted sudo rules instead.',
      autoFixable: false,
    };
  }

  details.push('Sudo requires password authentication');
  return {
    id: 'ACCESS-002',
    title: 'Sudo requires authentication',
    description: 'Sudo is properly configured to require password authentication.',
    risk: 'good',
    isoClause: 'A.5.17',
    isoClauseName: getClauseName('A.5.17'),
    module: 'access-control',
    details,
    recommendation: 'Maintain current sudo configuration.',
    autoFixable: false,
  };
}

function checkSSHConfig(): Finding {
  const sshConfigPath = '/etc/ssh/sshd_config';
  const details: string[] = [];
  const issues: string[] = [];

  if (!fs.existsSync(sshConfigPath)) {
    // Try alternate locations
    const altPath = '/etc/ssh/sshd_config.d/';
    if (fs.existsSync(altPath)) {
      details.push(`SSH config directory found at ${altPath}`);
    } else {
      details.push('SSH server config not found (sshd may not be installed)');
      return {
        id: 'ACCESS-003',
        title: 'SSH server not configured',
        description: 'No SSH server configuration was found on the system.',
        risk: 'good',
        isoClause: 'A.8.5',
        isoClauseName: getClauseName('A.8.5'),
        module: 'access-control',
        details,
        recommendation: 'If SSH is not needed, this is the secure default.',
        autoFixable: false,
      };
    }
  }

  try {
    const content = fs.readFileSync(sshConfigPath, 'utf-8');

    if (/PermitRootLogin\s+yes/i.test(content)) {
      issues.push('PermitRootLogin is set to yes');
    }
    if (/PasswordAuthentication\s+yes/i.test(content)) {
      issues.push('PasswordAuthentication is enabled');
    }
    if (/PermitEmptyPasswords\s+yes/i.test(content)) {
      issues.push('Empty passwords are permitted');
    }

    if (issues.length > 0) {
      return {
        id: 'ACCESS-003',
        title: 'SSH server has insecure settings',
        description: 'The SSH server configuration has security issues that should be addressed.',
        risk: issues.includes('PermitEmptyPasswords is permitted') ? 'high' : 'medium',
        isoClause: 'A.8.5',
        isoClauseName: getClauseName('A.8.5'),
        module: 'access-control',
        details: issues,
        recommendation: 'Disable root login, use key-based authentication, and disable empty passwords.',
        autoFixable: false,
      };
    }

    details.push('SSH configuration follows security best practices');
  } catch {
    details.push('Could not read SSH config (permission denied — run as root for full audit)');
  }

  return {
    id: 'ACCESS-003',
    title: 'SSH configuration reviewed',
    description: 'SSH server configuration was checked for security issues.',
    risk: details.length > 0 && details[0].includes('best practices') ? 'good' : 'low',
    isoClause: 'A.8.5',
    isoClauseName: getClauseName('A.8.5'),
    module: 'access-control',
    details,
    recommendation: 'Periodically review SSH configuration.',
    autoFixable: false,
  };
}

function listUserAccounts(): Finding {
  const platform = os.platform();
  const details: string[] = [];

  if (platform === 'darwin') {
    const users = execSafe('dscl . list /Users | grep -v "^_"');
    if (users) {
      const userList = users.split('\n').filter(u => u.trim().length > 0);
      details.push(`Found ${userList.length} user accounts:`);
      details.push(...userList.map(u => `  - ${u}`));

      // Check for admin users
      const admins = execSafe('dscl . -read /Groups/admin GroupMembership 2>/dev/null');
      if (admins) {
        details.push(`Admin group: ${admins.replace('GroupMembership:', '').trim()}`);
      }
    }
  } else {
    const users = execSafe('getent passwd | awk -F: \'$3 >= 1000 && $3 < 65534 {print $1}\'');
    if (users) {
      const userList = users.split('\n').filter(u => u.trim().length > 0);
      details.push(`Found ${userList.length} user accounts:`);
      details.push(...userList.map(u => `  - ${u}`));
    }
  }

  if (details.length === 0) {
    details.push('Could not enumerate user accounts');
  }

  return {
    id: 'ACCESS-004',
    title: 'User account inventory',
    description: 'Enumeration of local user accounts for access control review.',
    risk: 'low',
    isoClause: 'A.8.3',
    isoClauseName: getClauseName('A.8.3'),
    module: 'access-control',
    details,
    recommendation: 'Review user accounts periodically. Remove inactive accounts.',
    autoFixable: false,
  };
}

export async function scanAccessControl(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const gatewayFinding = checkGatewayPermissions();
  if (gatewayFinding) findings.push(gatewayFinding);

  findings.push(checkSudoConfig());
  findings.push(checkSSHConfig());
  findings.push(listUserAccounts());

  return findings;
}
