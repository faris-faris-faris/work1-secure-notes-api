#!/usr/bin/env node
/**
 * Summarise an ESLint JSON report as a short SAST report.
 * Usage: node scripts/sast-summary.mjs eslint-report.json
 */
import fs from 'node:fs';

const path = process.argv[2] || 'eslint-report.json';
// eslint-disable-next-line security/detect-non-literal-fs-filename -- CLI argument, this is a local reporting script
const report = JSON.parse(fs.readFileSync(path, 'utf8'));

const ruleCounts = new Map();
let errors = 0;
let warnings = 0;
let files = 0;

for (const file of report) {
  files += 1;
  for (const message of file.messages) {
    if (message.severity === 2) errors += 1;
    else warnings += 1;
    const key = message.ruleId || '(fatal)';
    ruleCounts.set(key, (ruleCounts.get(key) || 0) + 1);
  }
}

console.log('SAST report — ESLint with eslint-plugin-security');
console.log(`files analysed      : ${files}`);
console.log(`errors              : ${errors}`);
console.log(`warnings            : ${warnings}`);
console.log(`distinct rules hit  : ${ruleCounts.size}`);
console.log('');
if (ruleCounts.size === 0) {
  console.log('findings by rule: none');
} else {
  console.log('findings by rule:');
  for (const [rule, count] of [...ruleCounts.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${rule}: ${count}`);
  }
}
console.log('');
console.log(errors === 0 ? 'RESULT: no errors — the SAST gate passes.' : 'RESULT: errors found — the SAST gate fails.');
process.exit(errors === 0 ? 0 : 1);
