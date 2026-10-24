'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { checkDomain, checkSpf, checkDmarc, checkDkim } = require('../src/checker');

function fakeResolver(map) {
  return async (name) => {
    if (!(name in map)) {
      const err = new Error('not found');
      err.code = 'ENOTFOUND';
      throw err;
    }
    return map[name];
  };
}

test('SPF: missing record is flagged', async () => {
  const resolveTxt = fakeResolver({});
  const result = await checkSpf('example.com', resolveTxt);
  assert.equal(result.found, false);
  assert.match(result.issues[0], /No SPF record/);
});

test('SPF: clean record with -all has no issues', async () => {
  const resolveTxt = fakeResolver({
    'example.com': [['v=spf1 include:_spf.google.com -all']],
  });
  const result = await checkSpf('example.com', resolveTxt);
  assert.equal(result.found, true);
  assert.deepEqual(result.issues, []);
});

test('SPF: multiple records and +all are both flagged', async () => {
  const resolveTxt = fakeResolver({
    'example.com': [
      ['v=spf1 include:_spf.google.com +all'],
      ['v=spf1 include:mailgun.org ~all'],
    ],
  });
  const result = await checkSpf('example.com', resolveTxt);
  assert.equal(result.issues.length, 2);
  assert.match(result.issues[0], /2 SPF records/);
  assert.match(result.issues[1], /\+all/);
});

test('SPF: record split across multiple TXT chunks is joined before parsing', async () => {
  const resolveTxt = fakeResolver({
    'example.com': [['v=spf1 ', 'include:_spf.google.com ', '-all']],
  });
  const result = await checkSpf('example.com', resolveTxt);
  assert.equal(result.found, true);
  assert.equal(result.record, 'v=spf1 include:_spf.google.com -all');
});

test('SPF: redirect= without a local "all" is not flagged (RFC 7208 6.1 - policy lives at the redirect target)', async () => {
  const resolveTxt = fakeResolver({
    'example.com': [['v=spf1 redirect=_spf.google.com']],
  });
  const result = await checkSpf('example.com', resolveTxt);
  assert.deepEqual(result.issues, []);
});

test('SPF: too many lookup mechanisms triggers the 10-lookup warning', async () => {
  const includes = Array.from({ length: 11 }, (_, i) => `include:provider${i}.example.net`).join(' ');
  const resolveTxt = fakeResolver({
    'example.com': [[`v=spf1 ${includes} -all`]],
  });
  const result = await checkSpf('example.com', resolveTxt);
  assert.ok(result.issues.some((i) => /10 DNS lookups|permerror/.test(i)));
});

test('DMARC: missing record is flagged with the right lookup name', async () => {
  const resolveTxt = fakeResolver({});
  const result = await checkDmarc('example.com', resolveTxt);
  assert.equal(result.found, false);
  assert.match(result.issues[0], /_dmarc\.example\.com/);
});

test('DMARC: p=none and missing rua= are both flagged', async () => {
  const resolveTxt = fakeResolver({
    '_dmarc.example.com': [['v=DMARC1; p=none']],
  });
  const result = await checkDmarc('example.com', resolveTxt);
  assert.equal(result.policy, 'none');
  assert.equal(result.issues.length, 2);
});

test('DMARC: reject policy with rua has no issues', async () => {
  const resolveTxt = fakeResolver({
    '_dmarc.example.com': [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']],
  });
  const result = await checkDmarc('example.com', resolveTxt);
  assert.equal(result.policy, 'reject');
  assert.deepEqual(result.issues, []);
});

test('DKIM: tries common selectors and reports which one matched', async () => {
  const resolveTxt = fakeResolver({
    'google._domainkey.example.com': [['v=DKIM1; k=rsa; p=MIGfMA0GCSq...']],
  });
  const result = await checkDkim('example.com', resolveTxt, []);
  assert.equal(result.found, true);
  assert.equal(result.matches[0].selector, 'google');
});

test('DKIM: empty public key means revoked selector', async () => {
  const resolveTxt = fakeResolver({
    'mail._domainkey.example.com': [['v=DKIM1; k=rsa; p=']],
  });
  const result = await checkDkim('example.com', resolveTxt, ['mail']);
  assert.match(result.matches[0].issues[0], /revoked/);
});

test('DKIM: no match across any selector is explained as inconclusive, not proof', async () => {
  const resolveTxt = fakeResolver({});
  const result = await checkDkim('example.com', resolveTxt, ['google']);
  assert.equal(result.found, false);
  assert.match(result.issues[0], /inconclusive/);
});

test('checkDomain runs all three checks together', async () => {
  const resolveTxt = fakeResolver({
    'example.com': [['v=spf1 -all']],
    '_dmarc.example.com': [['v=DMARC1; p=reject; rua=mailto:a@example.com']],
    'google._domainkey.example.com': [['v=DKIM1; p=abc']],
  });
  const result = await checkDomain('example.com', { resolveTxt, selectors: ['google'] });
  assert.equal(result.domain, 'example.com');
  assert.equal(result.spf.found, true);
  assert.equal(result.dmarc.found, true);
  assert.equal(result.dkim.found, true);
});
