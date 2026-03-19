import * as os from 'os';
import { execSync } from 'child_process';
import { Finding } from '../types';
import { getClauseName } from '../iso-clauses';

function execSafe(cmd: string): string {
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 15000, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return '';
  }
}

function checkDiskEncryption(): Finding {
  const platform = os.platform();
  const details: string[] = [];

  if (platform === 'darwin') {
    const fvStatus = execSafe('fdesetup status 2>/dev/null');
    if (fvStatus.includes('On')) {
      details.push('FileVault is enabled');
      return {
        id: 'SYS-001',
        title: 'Disk encryption enabled (FileVault)',
        description: 'Full disk encryption via FileVault is active.',
        risk: 'good',
        isoClause: 'A.8.12',
        isoClauseName: getClauseName('A.8.12'),
        module: 'system',
        details,
        recommendation: 'Ensure FileVault recovery key is stored securely.',
        autoFixable: false,
      };
    } else if (fvStatus.includes('Off')) {
      details.push('FileVault is DISABLED');
      return {
        id: 'SYS-001',
        title: 'Disk encryption disabled',
        description: 'FileVault full disk encryption is not enabled.',
        risk: 'high',
        isoClause: 'A.8.12',
        isoClauseName: getClauseName('A.8.12'),
        module: 'system',
        details,
        recommendation: 'Enable FileVault immediately: System Preferences > Security & Privacy > FileVault.',
        autoFixable: false,
      };
    }
    details.push(`FileVault status: ${fvStatus || 'unknown (run as admin)'}`);
  } else {
    const luksCheck = execSafe('lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | grep -i crypt');
    if (luksCheck) {
      details.push('LUKS encrypted volumes detected');
      details.push(luksCheck);
      return {
        id: 'SYS-001',
        title: 'Disk encryption enabled (LUKS)',
        description: 'Encrypted disk volumes detected.',
        risk: 'good',
        isoClause: 'A.8.12',
        isoClauseName: getClauseName('A.8.12'),
        module: 'system',
        details,
        recommendation: 'Ensure encryption passphrases are stored securely.',
        autoFixable: false,
      };
    }
    details.push('No LUKS encrypted volumes detected');
  }

  return {
    id: 'SYS-001',
    title: 'Disk encryption status',
    description: 'Could not confirm full disk encryption.',
    risk: 'medium',
    isoClause: 'A.8.12',
    isoClauseName: getClauseName('A.8.12'),
    module: 'system',
    details,
    recommendation: 'Enable full disk encryption to protect data at rest.',
    autoFixable: false,
  };
}

function checkFirewall(): Finding {
  const platform = os.platform();
  const details: string[] = [];

  if (platform === 'darwin') {
    // Check Application Firewall
    const fwStatus = execSafe('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null');
    if (fwStatus.includes('enabled')) {
      details.push('Application Firewall is enabled');
    } else if (fwStatus.includes('disabled')) {
      details.push('Application Firewall is DISABLED');
      return {
        id: 'SYS-002',
        title: 'Firewall disabled',
        description: 'The macOS Application Firewall is not enabled.',
        risk: 'high',
        isoClause: 'A.8.20',
        isoClauseName: getClauseName('A.8.20'),
        module: 'system',
        details,
        recommendation: 'Enable the firewall: System Preferences > Security & Privacy > Firewall.',
        autoFixable: false,
      };
    } else {
      details.push(`Firewall status: ${fwStatus || 'unknown'}`);
    }

    // Check stealth mode
    const stealthStatus = execSafe('/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null');
    if (stealthStatus.includes('enabled')) {
      details.push('Stealth mode is enabled');
    } else {
      details.push('Stealth mode is DISABLED');
    }

    const risk = details.some(d => d.includes('DISABLED')) ? 'medium' : 'good';
    return {
      id: 'SYS-002',
      title: 'Firewall status',
      description: 'macOS firewall and stealth mode status.',
      risk,
      isoClause: 'A.8.20',
      isoClauseName: getClauseName('A.8.20'),
      module: 'system',
      details,
      recommendation: risk === 'good'
        ? 'Firewall configuration looks good.'
        : 'Enable stealth mode to prevent the system from responding to probing requests.',
      autoFixable: details.some(d => d === 'Stealth mode is DISABLED'),
    };
  } else {
    // Linux: check iptables/nftables/ufw
    const ufwStatus = execSafe('ufw status 2>/dev/null');
    if (ufwStatus.includes('active')) {
      details.push('UFW firewall is active');
      details.push(ufwStatus);
      return {
        id: 'SYS-002',
        title: 'Firewall enabled (UFW)',
        description: 'UFW firewall is active.',
        risk: 'good',
        isoClause: 'A.8.20',
        isoClauseName: getClauseName('A.8.20'),
        module: 'system',
        details,
        recommendation: 'Periodically review firewall rules.',
        autoFixable: false,
      };
    }

    const iptables = execSafe('iptables -L -n 2>/dev/null | head -20');
    if (iptables && !iptables.includes('ACCEPT     all')) {
      details.push('iptables rules detected');
    } else {
      details.push('No active firewall rules detected');
    }
  }

  return {
    id: 'SYS-002',
    title: 'Firewall status',
    description: 'Firewall configuration check.',
    risk: details.some(d => d.includes('No active')) ? 'high' : 'good',
    isoClause: 'A.8.20',
    isoClauseName: getClauseName('A.8.20'),
    module: 'system',
    details,
    recommendation: 'Enable and configure a firewall.',
    autoFixable: false,
  };
}

function checkGatekeeper(): Finding {
  if (os.platform() !== 'darwin') {
    return {
      id: 'SYS-003',
      title: 'Gatekeeper (macOS only)',
      description: 'Gatekeeper check is only applicable on macOS.',
      risk: 'low',
      isoClause: 'A.8.7',
      isoClauseName: getClauseName('A.8.7'),
      module: 'system',
      details: ['Not applicable on this platform'],
      recommendation: 'Use equivalent malware protection on Linux.',
      autoFixable: false,
    };
  }

  const status = execSafe('spctl --status 2>/dev/null');
  if (status.includes('enabled')) {
    return {
      id: 'SYS-003',
      title: 'Gatekeeper enabled',
      description: 'macOS Gatekeeper is enabled, preventing unauthorized software from running.',
      risk: 'good',
      isoClause: 'A.8.7',
      isoClauseName: getClauseName('A.8.7'),
      module: 'system',
      details: ['Gatekeeper is enabled'],
      recommendation: 'Keep Gatekeeper enabled.',
      autoFixable: false,
    };
  }

  return {
    id: 'SYS-003',
    title: 'Gatekeeper disabled',
    description: 'macOS Gatekeeper is disabled, allowing unsigned software to run.',
    risk: 'high',
    isoClause: 'A.8.7',
    isoClauseName: getClauseName('A.8.7'),
    module: 'system',
    details: ['Gatekeeper is DISABLED'],
    recommendation: 'Re-enable Gatekeeper: sudo spctl --master-enable',
    autoFixable: false,
  };
}

function checkAutoLogin(): Finding {
  if (os.platform() !== 'darwin') {
    return {
      id: 'SYS-004',
      title: 'Auto-login check (macOS only)',
      description: 'Auto-login check is only applicable on macOS.',
      risk: 'low',
      isoClause: 'A.5.17',
      isoClauseName: getClauseName('A.5.17'),
      module: 'system',
      details: ['Not applicable on this platform'],
      recommendation: 'Check /etc/lightdm/ or /etc/gdm/ for auto-login on Linux.',
      autoFixable: false,
    };
  }

  const autoLogin = execSafe('defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null');
  if (autoLogin && !autoLogin.includes('does not exist')) {
    return {
      id: 'SYS-004',
      title: 'Auto-login enabled',
      description: 'Automatic login is enabled, bypassing authentication at boot.',
      risk: 'high',
      isoClause: 'A.5.17',
      isoClauseName: getClauseName('A.5.17'),
      module: 'system',
      details: [`Auto-login user: ${autoLogin}`],
      recommendation: 'Disable auto-login: System Preferences > Users & Groups > Login Options.',
      autoFixable: false,
    };
  }

  return {
    id: 'SYS-004',
    title: 'Auto-login disabled',
    description: 'Automatic login is not configured.',
    risk: 'good',
    isoClause: 'A.5.17',
    isoClauseName: getClauseName('A.5.17'),
    module: 'system',
    details: ['Auto-login is disabled'],
    recommendation: 'Keep auto-login disabled.',
    autoFixable: false,
  };
}

function checkSoftwareInventory(): Finding {
  const details: string[] = [];

  // Check brew packages
  const brewList = execSafe('brew list --formula 2>/dev/null | wc -l');
  if (brewList) {
    details.push(`Homebrew formulae installed: ${brewList.trim()}`);
  }

  const brewCasks = execSafe('brew list --cask 2>/dev/null | wc -l');
  if (brewCasks) {
    details.push(`Homebrew casks installed: ${brewCasks.trim()}`);
  }

  // Check for outdated brew packages
  const outdated = execSafe('brew outdated 2>/dev/null | wc -l');
  if (outdated && parseInt(outdated.trim()) > 0) {
    details.push(`Outdated Homebrew packages: ${outdated.trim()}`);
  }

  // Check npm global packages
  const npmGlobal = execSafe('npm list -g --depth=0 2>/dev/null | tail -n +2 | wc -l');
  if (npmGlobal) {
    details.push(`npm global packages: ${npmGlobal.trim()}`);
  }

  // List npm global packages for review
  const npmGlobalList = execSafe('npm list -g --depth=0 2>/dev/null | tail -n +2');
  if (npmGlobalList) {
    const packages = npmGlobalList.split('\n').filter(l => l.trim().length > 0).slice(0, 15);
    details.push('Global npm packages:');
    details.push(...packages.map(p => `  ${p.trim()}`));
  }

  const outdatedCount = parseInt(outdated?.trim() || '0');
  return {
    id: 'SYS-005',
    title: 'Software inventory',
    description: 'Installed software packages for vulnerability management review.',
    risk: outdatedCount > 10 ? 'medium' : 'low',
    isoClause: 'A.8.8',
    isoClauseName: getClauseName('A.8.8'),
    module: 'system',
    details: details.length > 0 ? details : ['Could not enumerate installed software'],
    recommendation: outdatedCount > 0
      ? `Update ${outdatedCount} outdated packages: brew upgrade`
      : 'Keep software up to date.',
    autoFixable: false,
  };
}

export async function scanSystem(): Promise<Finding[]> {
  return [
    checkDiskEncryption(),
    checkFirewall(),
    checkGatekeeper(),
    checkAutoLogin(),
    checkSoftwareInventory(),
  ];
}
