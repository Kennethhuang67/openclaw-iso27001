# openclaw-iso27001

ISO 27001:2022 security compliance scanner for [OpenClaw](https://openclaw.ai) AI agents.

Scans your OpenClaw installation and host system for security issues, maps findings to ISO/IEC 27001:2022 Annex A controls, and generates actionable compliance reports.

## Why ISO 27001 for AI Agents?

AI agents operate with broad system access — reading files, making network requests, executing code, and managing credentials. Traditional security audits don't account for the unique attack surface of autonomous AI agent infrastructure:

- **API keys and tokens** scattered across agent workspace directories
- **Agent gateway permissions** that may be overly broad
- **Network exposure** through Tailscale Funnel or open ports
- **Background services** (LaunchAgents, cron) running agent workloads
- **Disk encryption and OS hardening** protecting the agent host

This tool brings ISO 27001 compliance practices to AI agent infrastructure, whether you're running a single OpenClaw instance or managing a fleet.

## Installation

```bash
npm install -g openclaw-iso27001
```

Or run directly:

```bash
npx openclaw-iso27001 scan
```

Or clone and build:

```bash
git clone https://github.com/openclaw/openclaw-iso27001.git
cd openclaw-iso27001
npm install
npm run build
node bin/iso27001.js scan
```

## Usage

### Full Scan

```bash
openclaw-iso27001 scan
```

Sample output:

```
  OpenClaw ISO 27001 Security Scanner
  ISO/IEC 27001:2022 compliance for AI agents

  Scanning...
  Scan completed in 2.3s

  Risk Score: 18/100
  Findings:  1 high  2 medium  3 low  8 good

  Cryptography (A.8)
  ● HIGH   CRYPTO-001   Secrets detected in configuration files
  ● MEDIUM CRYPTO-002   Config files with overly permissive permissions [auto-fixable]
  ● GOOD   CRYPTO-003   No environment files in home directory

  Access Control (A.9)
  ● GOOD   ACCESS-001   Gateway configuration reviewed
  ● GOOD   ACCESS-002   Sudo requires authentication
  ● GOOD   ACCESS-003   SSH configuration reviewed
  ● LOW    ACCESS-004   User account inventory

  System Security (A.13)
  ● GOOD   SYS-001      Disk encryption enabled (FileVault)
  ● MEDIUM SYS-002      Firewall status [auto-fixable]
  ● GOOD   SYS-003      Gatekeeper enabled
  ● GOOD   SYS-004      Auto-login disabled

  Tip: 2 finding(s) can be auto-fixed with --fix
```

### Auto-Fix

```bash
openclaw-iso27001 scan --fix
```

Automatically remediates fixable findings:
- Sets file permissions to `600` on config files containing secrets
- Enables macOS firewall stealth mode

### JSON Output

```bash
openclaw-iso27001 scan --json
```

Outputs structured JSON for integration with CI/CD pipelines or monitoring tools.

### Scan Specific Module

```bash
openclaw-iso27001 scan --module crypto
openclaw-iso27001 scan --module access-control
openclaw-iso27001 scan --module communications
openclaw-iso27001 scan --module operations
openclaw-iso27001 scan --module system
```

### Diff Mode

```bash
openclaw-iso27001 scan --diff
```

Compare current scan results with the previous scan. Shows new, resolved, and unchanged findings with risk score trends.

### Generate Report

```bash
openclaw-iso27001 report                    # Markdown report
openclaw-iso27001 report --json             # JSON report
openclaw-iso27001 report -o audit.md        # Write to specific file
```

## ISO 27001:2022 Clause Mapping

| Module | ISO Clause | Controls Checked |
|--------|-----------|------------------|
| Cryptography | A.8.2, A.8.9, A.8.10 | Secret detection, file permissions, env files |
| Access Control | A.5.15, A.5.17, A.8.3, A.8.5 | Gateway config, sudo, SSH, user accounts |
| Communications | A.8.20, A.8.21 | Tailscale status, Funnel routes, open ports, webhooks |
| Operations | A.8.6, A.8.15, A.8.16 | LaunchAgents, cron, processes, log analysis |
| System | A.5.17, A.8.7, A.8.8, A.8.12, A.8.20 | Encryption, firewall, Gatekeeper, auto-login, software |

See [docs/ISO-CLAUSE-MAPPING.md](docs/ISO-CLAUSE-MAPPING.md) for the complete mapping.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    CLI (commander)                │
│         scan | report | --fix | --diff           │
└──────────┬──────────────────────┬────────────────┘
           │                      │
           ▼                      ▼
┌─────────────────┐    ┌─────────────────────┐
│     Scanner      │    │     Reporter         │
│  ┌────────────┐  │    │  ┌───────────────┐  │
│  │ Crypto A.8 │  │    │  │   Markdown     │  │
│  ├────────────┤  │    │  ├───────────────┤  │
│  │ Access A.9 │  │    │  │     JSON       │  │
│  ├────────────┤  │    │  └───────────────┘  │
│  │ Comms A.10 │  │───▶│                     │
│  ├────────────┤  │    └─────────────────────┘
│  │ Ops   A.12 │  │
│  ├────────────┤  │    ┌─────────────────────┐
│  │ System A.13│  │    │      Fixer           │
│  └────────────┘  │    │  ┌───────────────┐  │
│                  │───▶│  │   Auto-Fix     │  │
└─────────────────┘    │  │  chmod, stealth │  │
                        │  └───────────────┘  │
                        └─────────────────────┘
```

## Platform Support

| Feature | macOS | Linux |
|---------|-------|-------|
| Secret scanning | ✅ | ✅ |
| File permissions | ✅ | ✅ |
| SSH config audit | ✅ | ✅ |
| Sudo check | ✅ | ✅ |
| Tailscale status | ✅ | ✅ |
| Open ports | ✅ (lsof) | ✅ (ss/netstat) |
| Disk encryption | ✅ (FileVault) | ✅ (LUKS) |
| Firewall | ✅ (Application Firewall) | ✅ (UFW/iptables) |
| Gatekeeper | ✅ | N/A |
| LaunchAgents | ✅ | ✅ (systemd) |
| Software inventory | ✅ (brew + npm) | ✅ (npm) |

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Run `npm test` to verify
5. Submit a pull request

### Adding a New Check

1. Add the check function to the appropriate scanner module in `src/scanner/`
2. Reference the ISO 27001 clause in `src/iso-clauses.ts`
3. Update the clause mapping in `docs/ISO-CLAUSE-MAPPING.md`
4. Add test coverage in `tests/scanner.test.ts`

## License

Apache 2.0 — see [LICENSE](LICENSE).
