'use strict';

const COMMON_DKIM_SELECTORS = [
  'google', 'selector1', 'selector2', 'default', 'dkim',
  'k1', 's1', 's2', 'mail', 'smtp',
];

function joinTxt(txtRecord) {
  // Node returns each TXT record as an array of strings (DNS allows a TXT
  // record to be split into multiple <=255 byte chunks); real parsers must
  // join them back into one string before reading tags.
  return txtRecord.join('');
}

async function safeResolveTxt(resolveTxt, name) {
  try {
    return await resolveTxt(name);
  } catch (err) {
    if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) return [];
    throw err;
  }
}

function countSpfLookups(record) {
  // RFC 7208 4.6.4: mechanisms/modifiers that cost a DNS lookup. Exceeding
  // 10 causes receivers to return a permerror and SPF to fail outright.
  const lookupMechanisms = /\b(include|a|mx|ptr|exists):?|%{|redirect=/gi;
  const matches = record.match(/\b(include:|a(?![a-z])|mx(?![a-z])|ptr(?![a-z])|exists:|redirect=)/gi);
  return matches ? matches.length : 0;
}

async function checkSpf(domain, resolveTxt) {
  const records = await safeResolveTxt(resolveTxt, domain);
  const spfRecords = records.map(joinTxt).filter((r) => /^v=spf1\b/i.test(r));

  if (spfRecords.length === 0) {
    return {
      found: false,
      record: null,
      issues: ['No SPF record found. Without SPF, receiving mail servers have no way to verify your outgoing servers are authorized, which hurts deliverability and lets others spoof your domain.'],
    };
  }

  const issues = [];
  if (spfRecords.length > 1) {
    issues.push(`Found ${spfRecords.length} SPF records (RFC 7208 allows only one TXT record starting with v=spf1 per domain) - this causes a permerror and SPF will fail for every message.`);
  }

  const record = spfRecords[0];
  const lookups = countSpfLookups(record);
  if (lookups > 10) {
    issues.push(`SPF record needs ~${lookups} DNS lookups to evaluate (include/a/mx/ptr/exists/redirect); RFC 7208 caps this at 10 - receivers will treat it as a permerror.`);
  }

  const hasRedirect = /\bredirect=/i.test(record);
  if (/[+]all\b/i.test(record)) {
    issues.push('SPF ends in "+all" which allows ANY server to send mail as this domain - this is equivalent to having no SPF protection at all.');
  } else if (!/[-~?]all\b/i.test(record) && !hasRedirect) {
    issues.push('SPF record has no "all" mechanism at the end - without it, receivers fall back to a neutral result and spoofed mail is not rejected.');
  } else if (/[?]all\b/i.test(record)) {
    issues.push('SPF ends in "?all" (neutral) - this provides no real protection; "-all" (hard fail) or at least "~all" (soft fail) is recommended.');
  }

  return { found: true, record, issues };
}

async function checkDmarc(domain, resolveTxt) {
  const records = await safeResolveTxt(resolveTxt, `_dmarc.${domain}`);
  const dmarcRecords = records.map(joinTxt).filter((r) => /^v=DMARC1\b/i.test(r));

  if (dmarcRecords.length === 0) {
    return {
      found: false,
      record: null,
      issues: ['No DMARC record found at _dmarc.' + domain + '. Without DMARC, SPF/DKIM failures are not enforced anywhere and you get no visibility into who is sending mail as your domain.'],
    };
  }

  const record = dmarcRecords[0];
  const issues = [];
  const policyMatch = record.match(/\bp=(none|quarantine|reject)\b/i);
  const policy = policyMatch ? policyMatch[1].toLowerCase() : null;

  if (!policyMatch) {
    issues.push('DMARC record has no p= policy tag, which is mandatory - receivers may ignore the record entirely.');
  } else if (policy === 'none') {
    issues.push('DMARC policy is "p=none" - this only monitors and reports, it does not block spoofed mail. Move to "quarantine" then "reject" once reports look clean.');
  }

  if (!/\brua=/i.test(record)) {
    issues.push('No rua= aggregate-report address set - you will not receive any reports showing who is sending mail (legitimately or not) as your domain.');
  }

  return { found: true, record, policy, issues };
}

async function checkDkim(domain, resolveTxt, selectors) {
  const candidates = selectors && selectors.length ? selectors : COMMON_DKIM_SELECTORS;
  const results = [];

  for (const selector of candidates) {
    const name = `${selector}._domainkey.${domain}`;
    const records = await safeResolveTxt(resolveTxt, name);
    const dkimRecords = records.map(joinTxt).filter((r) => /\bv=DKIM1\b/i.test(r) || /\bp=/i.test(r));
    if (dkimRecords.length === 0) continue;

    const record = dkimRecords[0];
    const issues = [];
    const pMatch = record.match(/\bp=([^;]*)/i);
    if (pMatch && pMatch[1].trim() === '') {
      issues.push('Public key (p=) is empty - this selector has been explicitly revoked.');
    }
    results.push({ selector, record, issues });
  }

  return {
    found: results.length > 0,
    checkedSelectors: candidates,
    matches: results,
    issues: results.length === 0
      ? [`No DKIM record found under any of the checked selectors (${candidates.join(', ')}). DKIM uses a per-provider selector name, so this is inconclusive, not proof DKIM is unset - pass the real selector with --dkim-selector if you know it (e.g. your email provider's setup docs will name it).`]
      : [],
  };
}

async function checkDomain(domain, { resolveTxt, selectors } = {}) {
  const [spf, dmarc, dkim] = await Promise.all([
    checkSpf(domain, resolveTxt),
    checkDmarc(domain, resolveTxt),
    checkDkim(domain, resolveTxt, selectors),
  ]);

  return { domain, spf, dmarc, dkim };
}

module.exports = { checkDomain, checkSpf, checkDmarc, checkDkim, COMMON_DKIM_SELECTORS };
