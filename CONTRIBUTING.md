# Contributing to OpenClaw ISO 27001 Scanner

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

### Prerequisites
- Node.js 18+
- npm or yarn

### Setup
```bash
git clone https://github.com/Kennethhuang67/openclaw-iso27001.git
cd openclaw-iso27001
npm install
npm run build
```

### Running
```bash
# Scan your OpenClaw installation
node bin/iso27001.js scan

# Scan with auto-fix
node bin/iso27001.js scan --fix

# JSON output
node bin/iso27001.js scan --json

# Compare with last scan
node bin/iso27001.js scan --diff

# Test
npm test
```

## How to Contribute

### Reporting Bugs
Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) template when filing issues. Include:
- Your OS and Node.js version
- Steps to reproduce
- Expected vs actual behavior
- Full error output

### Suggesting Features
Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) template. Describe:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives considered

### Submitting Changes
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `npm test`
6. Commit: `git commit -m 'feat: description of change'`
7. Push: `git push origin feature/my-feature`
8. Open a Pull Request

### Commit Convention
We use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Maintenance tasks

## Code Style
- TypeScript with strict mode
- Follow existing patterns in `src/`
- Keep scanner modules focused on a single ISO 27001 clause area
- Handle missing commands gracefully (different platforms)
- Filter false positives for key detection

## ISO 27001 Clause Mapping
Each scanner module maps to specific ISO 27001 clauses:
- `cryptography.ts` → A.8 (Cryptography)
- `access-control.ts` → A.9 (Access Control)
- `communications.ts` → A.10 (Communications Security)
- `operations.ts` → A.12 (Operations Security)
- `system.ts` → A.13 (System Security)

When adding new checks, reference the specific clause in the finding.

## Questions?
Open an issue and we'll help you out!
