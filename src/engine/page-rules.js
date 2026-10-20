// Page-content heuristics. Input is the JSON snapshot built by
// src/content/collector.js, so these rules can be unit-tested without a DOM.
(function (root) {
  'use strict';
  const Verano = (root.Verano = root.Verano || {});

  const URGENCY = [
    /account (has been|was|will be) (suspended|locked|limited|disabled|closed|restricted)/,
    /verify (your|the) (identity|account|information) (within|in) \d+/,
    /within (24|48|72) hours/,
    /unusual (sign-?in|login) activity/,
    /(confirm|update) (your )?(billing|payment) (information|details|method)/,
    /your (password|mailbox|storage) (will expire|has expired|is full)/,
    /failure to (verify|comply|confirm)/,
    /immediate(ly)? action (is )?required/,
    /payment (was )?declined/,
    /(claim|receive) your (refund|reward|prize)/,
  ];

  function finding(id, weight, severity, title, detail) {
    return { id, weight, severity, title, detail, source: 'page' };
  }

  function escapeRe(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function mentions(text, keyword) {
    return (text.match(new RegExp('(^|[^a-z0-9])' + escapeRe(keyword) + '(?![a-z0-9])', 'g')) || []).length;
  }

  // Which brands does the page present itself as?
  function detectBrands(snapshot, brands) {
    const strongText = [snapshot.title, (snapshot.headings || []).join(' '), (snapshot.imageHints || []).join(' '),
      (snapshot.formText || []).join(' ')].join(' \n ').toLowerCase();
    const body = (snapshot.textSample || '').toLowerCase();
    const result = [];
    for (const brand of brands) {
      const kws = brand.keywords.concat(brand.tokens.filter((t) => t.length >= 5));
      const strong = kws.some((k) => mentions(strongText, k) > 0);
      const weak = kws.reduce((n, k) => n + mentions(body, k), 0);
      if (strong || weak >= 2) result.push({ brand, strong });
    }
    return result;
  }

  function analyzePage(snapshot, urlInfo, opts) {
    const L = Verano.domain;
    const brands = (opts && opts.brands) || Verano.brands.BRANDS;
    const findings = [];
    if (!snapshot) return { findings, brandsSeen: [] };

    const page = L.parseUrl(snapshot.url);
    const pageHost = page ? page.host : '';
    const pageReg = urlInfo ? urlInfo.registrable : pageHost;
    const loopback = L.isLoopback(pageHost);

    const credentialForm = snapshot.passwordFields > 0;
    const capturesSecrets = credentialForm || snapshot.cardFields > 0 || snapshot.seedPhrase;

    // 1. Brand impersonation: the page says it is Brand X and asks for secrets,
    //    but the domain is not Brand X's.
    const seen = detectBrands(snapshot, brands);
    const strong = seen.find((s) => s.strong);
    if (capturesSecrets && strong) {
      findings.push(finding('BRAND_IMPERSONATION', 45, 'critical', `Impersonates ${strong.brand.name}`,
        `The page uses ${strong.brand.name} branding and asks for credentials, but it is hosted on ${pageReg}.`));
    } else if (capturesSecrets && seen.length) {
      findings.push(finding('BRAND_MENTION_LOGIN', 20, 'medium', `Mentions ${seen[0].brand.name} next to a login form`,
        `${seen[0].brand.name} appears in the page text and the page asks for credentials.`));
    }

    // 2. Brand assets hot-linked from the real brand's servers.
    if (capturesSecrets) {
      const assetBrand = (snapshot.resourceHosts || [])
        .map((h) => Verano.brands.brandOwning(h))
        .find(Boolean);
      if (assetBrand) {
        findings.push(finding('BRAND_ASSETS', 15, 'medium', `Loads ${assetBrand.name} images or styles`,
          `Logos/CSS are pulled straight from ${assetBrand.name}'s servers to look authentic.`));
      }
    }

    // 3. Where do the credentials go?
    let crossDomain = false, toIp = false, insecureAction = false;
    for (const form of snapshot.forms || []) {
      if (!form.hasPassword && !form.hasCard) continue;
      const action = L.parseUrl(form.action || '');
      if (!action) continue;
      if (action.scheme === 'mailto') {
        crossDomain = true;
        continue;
      }
      if (!/^https?$/.test(action.scheme)) continue;
      const actionInfo = L.splitHost(action.host);
      if (actionInfo.ip && !L.isLoopback(action.host)) toIp = true;
      else if (action.host && actionInfo.registrable !== pageReg && !Verano.brands.brandOwning(action.host)) crossDomain = true;
      if (page && page.scheme === 'https' && action.scheme === 'http') insecureAction = true;
    }
    if (toIp) {
      findings.push(finding('FORM_TO_IP', 30, 'high', 'Login form posts to a raw IP address',
        'The credentials are sent to a bare IP, not to the site you are on.'));
    } else if (crossDomain) {
      findings.push(finding('FORM_CROSS_DOMAIN', 25, 'high', 'Login form posts to another domain',
        `What you type here is sent somewhere other than ${pageReg}.`));
    }
    if (insecureAction) {
      findings.push(finding('FORM_INSECURE_ACTION', 20, 'high', 'Secure page submits over HTTP',
        'The page is HTTPS, but the form sends its data unencrypted.'));
    }

    if (credentialForm && page && page.scheme === 'http' && !loopback) {
      findings.push(finding('PASSWORD_OVER_HTTP', 30, 'high', 'Password field on an unencrypted page',
        'No legitimate service asks for a password over plain HTTP.'));
    }

    // 4. Specific high-value asks.
    if (snapshot.seedPhrase) {
      findings.push(finding('SEED_PHRASE', 40, 'critical', 'Asks for a wallet recovery phrase',
        'No wallet, exchange or support team will ever ask for your seed phrase.'));
    }
    if (snapshot.cardFields > 0 && (strong || (page && page.scheme === 'http'))) {
      findings.push(finding('CARD_HARVEST', 15, 'high', 'Collects payment card details',
        'Card number / CVV fields on a page that is impersonating a brand or is not encrypted.'));
    }

    // 5. Social-engineering text and phishing-kit tells.
    const text = ((snapshot.title || '') + ' ' + (snapshot.textSample || '')).toLowerCase();
    const urgency = URGENCY.filter((re) => re.test(text)).length;
    if (urgency >= 2 || (urgency >= 1 && capturesSecrets)) {
      findings.push(finding('URGENCY_LANGUAGE', 10, 'medium', 'Pressure / urgency language',
        'Threats of suspension or deadlines are used to rush you past your judgment.'));
    }

    const links = snapshot.links || { total: 0, empty: 0 };
    if (credentialForm && links.total >= 5 && links.empty / links.total >= 0.8) {
      findings.push(finding('DEAD_LINKS', 10, 'medium', 'Most links go nowhere',
        `${links.empty} of ${links.total} links are "#" or empty, typical of a cloned page.`));
    }

    if (snapshot.contextMenuBlocked) {
      findings.push(finding('RIGHT_CLICK_BLOCKED', 5, 'low', 'Right-click is disabled', 'Used to stop visitors from inspecting the page.'));
    }
    if (snapshot.hiddenIframes > 0) {
      findings.push(finding('HIDDEN_IFRAME', 5, 'low', 'Hidden iframe', `${snapshot.hiddenIframes} invisible frame(s) on the page.`));
    }
    if (snapshot.metaRefreshExternal) {
      findings.push(finding('META_REFRESH', 10, 'medium', 'Automatic redirect to another site', 'A meta refresh forwards you to a different domain.'));
    }

    return { findings, brandsSeen: seen.map((s) => s.brand.name) };
  }

  Verano.pageRules = { analyzePage, detectBrands };
})(typeof globalThis !== 'undefined' ? globalThis : this);
