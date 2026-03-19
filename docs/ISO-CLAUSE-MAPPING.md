# ISO 27001:2022 Clause Mapping

This document maps each scanner check to its corresponding ISO/IEC 27001:2022 Annex A control.

## Cryptography Module

| Finding ID | Check | ISO Clause | Control Name |
|-----------|-------|------------|-------------|
| CRYPTO-001 | Secrets in config files | A.8.2 | Key management |
| CRYPTO-002 | File permissions | A.8.9 | Configuration management |
| CRYPTO-003 | .env files in home dir | A.8.10 | Information deletion |

## Access Control Module

| Finding ID | Check | ISO Clause | Control Name |
|-----------|-------|------------|-------------|
| ACCESS-001 | Gateway permissions | A.5.15 | Access control |
| ACCESS-002 | Sudo configuration | A.5.17 | Authentication information |
| ACCESS-003 | SSH configuration | A.8.5 | Secure authentication |
| ACCESS-004 | User account inventory | A.8.3 | Information access restriction |

## Communications Security Module

| Finding ID | Check | ISO Clause | Control Name |
|-----------|-------|------------|-------------|
| COMM-001 | Tailscale network status | A.8.20 | Network security |
| COMM-002 | Tailscale Funnel routes | A.8.21 | Security of network services |
| COMM-003 | Open listening ports | A.8.20 | Network security |
| COMM-004 | Webhook endpoints | A.8.21 | Security of network services |

## Operations Security Module

| Finding ID | Check | ISO Clause | Control Name |
|-----------|-------|------------|-------------|
| OPS-001 | LaunchAgents/systemd | A.8.16 | Monitoring activities |
| OPS-002 | Cron jobs | A.8.16 | Monitoring activities |
| OPS-003 | Running processes | A.8.6 | Capacity management |
| OPS-004 | Log auth failures | A.8.15 | Logging |

## System Security Module

| Finding ID | Check | ISO Clause | Control Name |
|-----------|-------|------------|-------------|
| SYS-001 | Disk encryption | A.8.12 | Data leakage prevention |
| SYS-002 | Firewall & stealth mode | A.8.20 | Network security |
| SYS-003 | Gatekeeper | A.8.7 | Protection against malware |
| SYS-004 | Auto-login | A.5.17 | Authentication information |
| SYS-005 | Software inventory | A.8.8 | Management of technical vulnerabilities |

## ISO 27001:2022 Annex A Reference

The controls referenced by this scanner fall under the following themes from ISO/IEC 27001:2022:

- **Clause 5**: Organizational controls (A.5.15, A.5.17)
- **Clause 8**: Technological controls (A.8.2–A.8.23)

For the full ISO/IEC 27001:2022 standard, see: https://www.iso.org/standard/27001
