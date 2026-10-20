// Detection-engine tests. Runs under Node (`node tests/run-tests.js`) or under
// macOS's built-in JavaScriptCore shell (`./scripts/test.sh`), from the repo root.
/* global load, print, require, process */
(function () {
  'use strict';
  const ENGINE = ['punycode', 'domain', 'brands', 'url-rules', 'page-rules', 'scorer'].map((f) => `src/engine/${f}.js`);
  const isNode = typeof require === 'function' && typeof process !== 'undefined';
  if (isNode) {
    const path = require('path');
    ENGINE.forEach((f) => require(path.resolve(__dirname, '..', f)));
  } else {
    ENGINE.forEach((f) => load(f));
  }
  const log = isNode ? console.log : print;
  const { evaluate, domain, punycode } = globalThis.Verano;

  let passed = 0;
  const failures = [];
  function test(name, fn) {
    try {
      fn();
      passed++;
    } catch (e) {
      failures.push(`${name}\n      ${e.message}`);
    }
  }
  function assert(cond, msg) {
    if (!cond) throw new Error(msg);
  }
  function describe(r) {
    return `score=${r.score} verdict=${r.verdict} [${r.findings.map((f) => `${f.id}:${f.weight}`).join(', ')}]`;
  }
  const ORDER = { safe: 0, suspicious: 1, phishing: 2 };
  function expectVerdict(url, expected, extra) {
    const r = evaluate(Object.assign({ url }, extra || {}));
    assert(r.verdict === expected, `${url}: expected ${expected}, got ${describe(r)}`);
    return r;
  }
  function expectAtLeast(url, min, extra) {
    const r = evaluate(Object.assign({ url }, extra || {}));
    assert(ORDER[r.verdict] >= ORDER[min], `${url}: expected at least ${min}, got ${describe(r)}`);
    return r;
  }
  function hasFinding(r, id) {
    assert(r.findings.some((f) => f.id === id), `expected ${id} in ${describe(r)}`);
  }

  // ---- helpers ----------------------------------------------------------
  test('punycode decodes a Cyrillic homograph', () => {
    const u = punycode.hostToUnicode('xn--80ak6aa92e.com');
    assert(u === 'аррӏе.com', `got ${u}`);
    assert(domain.skeleton('аррӏе') === 'apple', 'skeleton should fold to apple');
  });
  test('punycode round-trips a mixed-script label', () => {
    assert(punycode.hostToUnicode('xn--pypal-4ve.com') === 'pаypal.com', punycode.hostToUnicode('xn--pypal-4ve.com'));
  });
  test('splitHost handles multi-part suffixes and hosting platforms', () => {
    assert(domain.splitHost('login.amazon.co.uk').registrable === 'amazon.co.uk', 'co.uk');
    const h = domain.splitHost('amazon-verify.web.app');
    assert(h.registrable === 'amazon-verify.web.app' && h.hosting === 'web.app', JSON.stringify(h));
  });
  test('parseUrl separates userinfo from host', () => {
    const p = domain.parseUrl('https://www.paypal.com@203.0.113.5/login');
    assert(p.host === '203.0.113.5' && p.userinfo === 'www.paypal.com', JSON.stringify(p));
  });
  test('ipKind spots integer and hex IPs', () => {
    assert(domain.ipKind('3232235777') === 'ipv4-integer', 'integer');
    assert(domain.ipKind('0xc0.0xa8.1.1') === 'ipv4-obfuscated', 'hex');
    assert(domain.ipKind('example.com') === null, 'domain');
  });

  // ---- legitimate sites: must stay safe ---------------------------------
  [
    'https://www.paypal.com/signin',
    'https://accounts.google.com/v3/signin/identifier',
    'https://login.microsoftonline.com/common/oauth2/authorize',
    'https://www.amazon.co.uk/ap/signin',
    'https://finance.yahoo.com/',
    'https://www.binance.com/en/login',
    'https://www.wikipedia.org/',
    'https://www.applebees.com/en',
    'https://www.pineapple-recipes.example/',
    'https://paypay.ne.jp/',
    'https://someone.github.io/portfolio/',
    'http://localhost:3000/login',
    'https://groups.example.org/',
    'https://www.finance.example/',
    'https://news.example.com/2026/10/paypal-earnings',
  ].forEach((url) => test(`safe: ${url}`, () => expectVerdict(url, 'safe')));

  // ---- phishing URLs -----------------------------------------------------
  test('homograph PayPal (mixed script) is phishing', () => {
    const r = expectVerdict('https://xn--pypal-4ve.com/signin', 'phishing');
    hasFinding(r, 'LOOKALIKE_HOMOGLYPH');
    hasFinding(r, 'MIXED_SCRIPT');
    assert(!r.findings.some((f) => f.id === 'MANY_HYPHENS'), `xn-- prefix counted as hyphens: ${describe(r)}`);
  });
  test('all-Cyrillic Apple homograph is phishing', () => hasFinding(expectVerdict('https://xn--80ak6aa92e.com/', 'phishing'), 'LOOKALIKE_HOMOGLYPH'));
  test('fake address before "@" is phishing', () => hasFinding(expectVerdict('https://www.paypal.com@203.0.113.5/login', 'phishing'), 'USERINFO_BRAND'));
  test('brand domain as subdomain is phishing', () => hasFinding(expectVerdict('http://paypal.com.secure-login.example/webscr', 'phishing'), 'BRAND_DOMAIN_IN_SUBDOMAIN'));
  test('netflix billing on .xyz is phishing', () => expectVerdict('https://netflix.com.billing-update.xyz/', 'phishing'));
  test('leet typosquat is at least suspicious', () => hasFinding(expectAtLeast('https://paypa1-secure.example/', 'suspicious'), 'LOOKALIKE_TYPO'));
  test('edit-distance typosquat is at least suspicious', () => hasFinding(expectAtLeast('https://micros0ft-online.example/', 'suspicious'), 'LOOKALIKE_TYPO'));
  test('rn->m trick is caught', () => hasFinding(expectAtLeast('https://arnazon.example/', 'suspicious'), 'LOOKALIKE_TYPO'));
  test('brand + keywords on free hosting is suspicious', () => expectAtLeast('https://amazon-account-verify.web.app/', 'suspicious'));
  test('brand path on raw IP is suspicious', () => {
    const r = expectAtLeast('http://192.0.2.10/paypal/login.php', 'suspicious');
    hasFinding(r, 'IP_HOST');
    hasFinding(r, 'BRAND_IN_PATH');
  });
  test('decimal IP is suspicious', () => hasFinding(expectAtLeast('http://3232235777/', 'suspicious'), 'IP_OBFUSCATED'));
  test('keyword soup on a cheap TLD is suspicious', () => expectAtLeast('https://secure-paypal-login-verify.top/', 'suspicious'));
  test('data: URL is flagged', () => hasFinding(expectAtLeast('data:text/html;base64,PGgxPkxvZ2luPC9oMT4=', 'suspicious'), 'DATA_URL'));

  // ---- settings ----------------------------------------------------------
  test('allowlist overrides findings', () => {
    const r = evaluate({ url: 'https://paypa1-secure.example/', settings: { allowlist: ['paypa1-secure.example'] } });
    assert(r.verdict === 'safe' && r.trusted, describe(r));
  });
  test('strict sensitivity lowers the bar', () => {
    const url = 'https://micros0ft-online.example/';
    const relaxed = evaluate({ url, settings: { sensitivity: 'relaxed' } });
    const strict = evaluate({ url, settings: { sensitivity: 'strict' } });
    assert(ORDER[strict.verdict] > ORDER[relaxed.verdict], `${describe(relaxed)} vs ${describe(strict)}`);
  });

  // ---- page snapshots ----------------------------------------------------
  function snapshot(over) {
    return Object.assign({
      url: '', title: '', headings: [], imageHints: [], formText: [], textSample: '', forms: [],
      passwordFields: 0, cardFields: 0, seedPhrase: false, links: { total: 0, empty: 0 },
      resourceHosts: [], hiddenIframes: 0, contextMenuBlocked: false, metaRefreshExternal: false,
    }, over);
  }

  test('cloned PayPal login posting to an IP is phishing', () => {
    const url = 'https://account-review.example/session';
    const r = evaluate({
      url,
      snapshot: snapshot({
        url,
        title: 'Log in to your PayPal account',
        imageHints: ['paypal-logo.svg'],
        passwordFields: 1,
        forms: [{ action: 'http://198.51.100.7/collect.php', hasPassword: true, hasCard: false }],
        textSample: 'Your account has been limited. Verify your identity within 24 hours.',
        links: { total: 10, empty: 9 },
        resourceHosts: ['www.paypalobjects.com'],
      }),
    });
    assert(r.verdict === 'phishing', describe(r));
    ['BRAND_IMPERSONATION', 'FORM_TO_IP', 'FORM_INSECURE_ACTION', 'BRAND_ASSETS', 'URGENCY_LANGUAGE', 'DEAD_LINKS'].forEach((id) => hasFinding(r, id));
  });
  test('wallet seed-phrase harvester is phishing', () => {
    const url = 'https://wallet-restore.example/';
    const r = evaluate({
      url,
      snapshot: snapshot({ url, title: 'MetaMask - Restore your wallet', seedPhrase: true, forms: [{ action: url, hasPassword: false }] }),
    });
    assert(r.verdict === 'phishing', describe(r));
    hasFinding(r, 'SEED_PHRASE');
  });
  test('news article mentioning PayPal is safe', () => {
    const url = 'https://news.example.com/fintech';
    const r = evaluate({
      url,
      snapshot: snapshot({ url, title: 'PayPal posts record quarter', textSample: 'PayPal said on Tuesday... PayPal shares rose.', links: { total: 40, empty: 2 } }),
    });
    assert(r.verdict === 'safe', describe(r));
  });
  test('ordinary site login is safe', () => {
    const url = 'https://forum.example.org/login';
    const r = evaluate({
      url,
      snapshot: snapshot({ url, title: 'Sign in - Example Forum', passwordFields: 1, forms: [{ action: 'https://forum.example.org/session', hasPassword: true }], links: { total: 30, empty: 1 } }),
    });
    assert(r.verdict === 'safe', describe(r));
  });
  test('login on official domain is trusted even with page signals', () => {
    const url = 'https://www.paypal.com/signin';
    const r = evaluate({ url, snapshot: snapshot({ url, title: 'Log in to your PayPal account', passwordFields: 1 }) });
    assert(r.verdict === 'safe' && r.trusted, describe(r));
  });
  test('password over HTTP on a real host is flagged', () => {
    const url = 'http://intranet-portal.example/';
    const r = evaluate({ url, snapshot: snapshot({ url, passwordFields: 1, forms: [{ action: url, hasPassword: true }] }) });
    hasFinding(r, 'PASSWORD_OVER_HTTP');
  });

  log(`\n${passed} passed, ${failures.length} failed`);
  failures.forEach((f) => log(`  ✗ ${f}`));
  if (failures.length) {
    if (isNode) process.exit(1);
    else throw new Error('tests failed');
  }
})();
