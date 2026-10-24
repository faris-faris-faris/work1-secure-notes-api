#!/usr/bin/env node
/**
 * Software Composition Analysis against the OSV.dev database.
 *
 * CI uses `npm audit`; this script exists because some corporate/regional npm
 * mirrors do not implement the audit endpoint. It resolves every locked
 * dependency (package-lock.json) against OSV, which aggregates GHSA, CVE and
 * ecosystem advisories, and exits non-zero if anything is reported.
 *
 * Usage: node scripts/sca-osv.mjs [package-lock.json]
 */
import fs from 'node:fs';

const lockPath = process.argv[2] || 'package-lock.json';
// eslint-disable-next-line security/detect-non-literal-fs-filename -- CLI argument, this is a local reporting script
const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));

// npm v2/v3 lockfile: "packages" with "" for the root, node_modules/... for deps.
const packages = Object.entries(lock.packages || {})
  .filter(([key, value]) => key && value.version && !value.dev)
  .map(([key, value]) => ({
    name: key.replace(/^.*node_modules\//, ''),
    version: value.version,
  }));

const devPackages = Object.entries(lock.packages || {})
  .filter(([key, value]) => key && value.version && value.dev)
  .map(([key]) => key.replace(/^.*node_modules\//, ''));

console.log('SCA report — OSV.dev (aggregates GHSA / CVE / ecosystem advisories)');
console.log(`runtime dependencies : ${packages.length}`);
console.log(`dev dependencies     : ${devPackages.length} (not shipped, still scanned for completeness)`);
console.log('');

const all = Object.entries(lock.packages || {})
  .filter(([key, value]) => key && value.version)
  .map(([key, value]) => ({
    name: key.replace(/^.*node_modules\//, ''),
    version: value.version,
  }));

/** @type {Array<{package:{name:string,version:string}, vulns:any[]}>} */
const findings = [];

for (let i = 0; i < all.length; i += 100) {
  const chunk = all.slice(i, i + 100);
  const response = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      queries: chunk.map((pkg) => ({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version })),
    }),
  });
  if (!response.ok) {
    console.error(`OSV request failed: HTTP ${response.status}`);
    process.exit(2);
  }
  const body = await response.json();
  body.results.forEach((result, index) => {
    if (result.vulns && result.vulns.length > 0) {
      findings.push({ package: chunk[index], vulns: result.vulns });
    }
  });
}

if (findings.length === 0) {
  console.log(`No known vulnerabilities found in ${all.length} locked packages.`);
  console.log('RESULT: SCA gate passes.');
  process.exit(0);
}

console.log(`Vulnerable packages: ${findings.length}`);
for (const finding of findings) {
  const ids = finding.vulns.map((v) => v.id).join(', ');
  const summaries = finding.vulns.map((v) => v.summary).filter(Boolean);
  console.log(`  ${finding.package.name}@${finding.package.version}: ${ids}`);
  for (const summary of summaries.slice(0, 2)) console.log(`      ${summary}`);
}
console.log('RESULT: SCA gate fails.');
process.exit(1);
