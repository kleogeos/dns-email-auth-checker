# dns-email-auth-checker

Zero-dependency Node.js CLI that checks a domain's **SPF**, **DKIM** and **DMARC**
DNS records and tells you exactly what's missing or misconfigured, in plain
English instead of raw RFC text.

Built as part of setting up Google Workspace / email authentication for a
client (DNS verification + SPF/DKIM/DMARC records) - the kind of job where
you need a fast, repeatable way to confirm records actually propagated
correctly instead of eyeballing `dig` output.

## Install

```bash
git clone https://github.com/kleogeos/dns-email-auth-checker.git
cd dns-email-auth-checker
npm install
```

No runtime dependencies - `npm install` only pulls dev tooling (none, in
fact; `node --test` is built into Node 18+).

## Usage

```bash
node bin/cli.js example.com
node bin/cli.js example.com --dkim-selector=google   # DKIM selector name is provider-specific
node bin/cli.js example.com --json                   # machine-readable output
```

Exit code is `2` if any issue was found (missing record, misconfiguration),
so it can be dropped into a CI/deployment check.

### Example

```
DNS email authentication report for gmail.com

SPF: FOUND
  record: v=spf1 redirect=_spf.google.com
  ok, no issues found

DMARC: FOUND
  record: v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com
  ! DMARC policy is "p=none" - this only monitors and reports, it does not block spoofed mail. Move to "quarantine" then "reject" once reports look clean.

DKIM: MISSING
  ! No DKIM record found under any of the checked selectors (google, selector1, ...). DKIM uses a per-provider selector name, so this is inconclusive, not proof DKIM is unset - pass the real selector with --dkim-selector if you know it.
```

## What it actually checks

- **SPF**: record present, exactly one record (a second `v=spf1` TXT record
  is an RFC 7208 violation that causes a permerror), DNS-lookup budget (10
  max - `include`/`a`/`mx`/`ptr`/`exists`/`redirect` all count), and the
  `all` mechanism (`+all` = no protection, `?all` = neutral/no protection,
  missing `all` without a `redirect=` = receivers fall back to neutral).
- **DMARC**: record present at `_dmarc.<domain>`, `p=` policy tag present,
  warns on `p=none` (monitor-only) and on missing `rua=` (no visibility into
  who's sending mail as you).
- **DKIM**: tries a list of common selectors (`google`, `selector1`,
  `selector2`, `default`, `k1`, ...) or a selector you pass explicitly, and
  flags an empty `p=` (revoked key). DKIM selectors are provider-chosen and
  not discoverable without one, so a clean miss is reported as *inconclusive*,
  not as "DKIM is broken".

## Tests

```bash
npm test
```

13 tests using `node:test`, all DNS resolution is dependency-injected (a fake
resolver), so the suite runs offline and deterministically - no real network
calls in tests.

## Related tools

Part of the same toolbox as
[freelance-invoice-cli](https://github.com/kleogeos/freelance-invoice-cli),
[sqlite-items-api](https://github.com/kleogeos/sqlite-items-api) and
[erc20-token-stats-api](https://github.com/kleogeos/erc20-token-stats-api) -
small, tested, zero/minimal-dependency backend tools.

## License

MIT
