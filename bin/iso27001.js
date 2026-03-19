#!/usr/bin/env node

const { createCLI } = require('../dist/cli');

const program = createCLI();
program.parseAsync(process.argv).catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
