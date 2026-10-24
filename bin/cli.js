#!/usr/bin/env node
'use strict';

const dns = require('node:dns/promises');
const { checkDomain } = require('../src/checker');

function parseArgs(argv) {
  const args = { domain: null, selectors: [], json: false };
  for (const arg of argv) {
    if (arg === '--json') {
      args.json = true;
    } else if (arg.startsWith('--dkim-selector=')) {
      args.selectors.push(arg.slice('--dkim-selector='.length));
    } else if (!arg.startsWith('--')) {
      args.domain = arg;
    }
  }
  return args;
}

function printSection(title, section) {
  const status = section.found ? 'FOUND' : 'MISSING';
  console.log(`\n${title}: ${status}`);
  if (section.record) console.log(`  record: ${section.record}`);
  if (section.matches) {
    for (const m of section.matches) {
      console.log(`  selector "${m.selector}": ${m.record}`);
      for (const issue of m.issues) console.log(`    ! ${issue}`);
    }
  }
  for (const issue of section.issues) console.log(`  ! ${issue}`);
  if (section.issues.length === 0 && section.found) console.log('  ok, no issues found');
}

async function main() {
  const { domain, selectors, json } = parseArgs(process.argv.slice(2));
  if (!domain) {
    console.error('Usage: dns-email-auth-checker <domain> [--dkim-selector=name ...] [--json]');
    process.exitCode = 1;
    return;
  }

  const result = await checkDomain(domain, { resolveTxt: dns.resolveTxt, selectors });

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`DNS email authentication report for ${domain}`);
    printSection('SPF', result.spf);
    printSection('DMARC', result.dmarc);
    printSection('DKIM', result.dkim);
  }

  const totalIssues = result.spf.issues.length + result.dmarc.issues.length + result.dkim.issues.length;
  if (totalIssues > 0) process.exitCode = 2;
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exitCode = 1;
});
