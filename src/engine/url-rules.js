// URL-level heuristics. These run in the service worker *before* a page loads,
// so they only see the address, never page content.
(function (root) {
  'use strict';
  const Verano = (root.Verano = root.Verano || {});
  const D = () => Verano.domain;

  const SUSPICIOUS_TLDS = new Set([
    'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'cyou', 'sbs', 'buzz', 'rest', 'cam',
    'monster', 'quest', 'bond', 'click', 'zip', 'mov', 'country', 'support', 'work', 'best',
    'cfd', 'lat', 'beauty', 'hair', 'skin', 'autos', 'boats', 'mom',
  ]);

  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'rb.gy', 'tiny.cc', 'buff.ly', 's.id', 't.ly', 'v.gd', 'lnkd.in', 'qrco.de',
  ]);

  const CREDENTIAL_WORDS = [
    'login', 'signin', 'logon', 'verify', 'verification', 'secure', 'security', 'account',
    'update', 'confirm', 'banking', 'password', 'wallet', 'unlock', 'suspend', 'suspended',
    'billing', 'recover', 'recovery', 'support', 'auth', 'webscr', 'authenticate', 'validate',
    'restore', 'unusual', 'helpdesk', 'invoice', 'refund', 'claim', 'reward',
  ];

  function finding(id, weight, severity, title, detail) {
    return { id, weight, severity, title, detail, source: 'url' };
  }

  // How does `part` (a hostname label) relate to a brand token?
  //   'exact'     the token appears as-is ("paypal-login")
  //   'homoglyph' it appears only after folding look-alike Unicode ("pаypal")
  //   'typo'      it appears only after folding leet/edit tricks ("paypa1", "paypai")
  function matchToken(asciiPart, unicodePart, token, brand) {
    const L = D();
    const pieces = asciiPart.split('-');
    const long = token.length >= 5;
    const contains = (s, parts) => (long ? s.includes(token) : parts.includes(token));
    if (contains(asciiPart, pieces)) return 'exact';

    const sk = L.skeleton(unicodePart);
    if (contains(sk, sk.split('-'))) return L.hasNonAscii(unicodePart) ? 'homoglyph' : 'typo';

    if (token.length >= 6) {
      const max = token.length >= 9 ? 2 : 1;
      for (const p of pieces.concat(pieces.length > 1 ? [pieces.join('')] : [])) {
        if ((brand.ignore || []).includes(p)) continue;
        if (Math.abs(p.length - token.length) <= max && L.levenshtein(p, token, max) <= max) return 'typo';
      }
    }
    return null;
  }

  function brandFindings(info, brands) {
    const candidates = [];
    const subAscii = info.subdomains.join('.');
    const subUnicode = info.unicodeHost.split('.').slice(0, info.subdomains.length);

    for (const brand of brands) {
      // "paypal.com.account-check.example": a full brand domain used as a subdomain.
      const fullDomain = brand.domains.find((d) => ('.' + subAscii + '.').includes('.' + d + '.'));
      if (fullDomain) {
        candidates.push(finding('BRAND_DOMAIN_IN_SUBDOMAIN', 50, 'critical', `${brand.name} domain used as a subdomain`,
          `"${fullDomain}" appears in front of the real domain ${info.registrable}.`));
        continue;
      }
      for (const token of brand.tokens) {
        const m = matchToken(info.label, info.unicodeLabel, token, brand);
        if (m === 'homoglyph') {
          candidates.push(finding('LOOKALIKE_HOMOGLYPH', 55, 'critical', `Look-alike of ${brand.name} using Unicode characters`,
            `"${info.unicodeLabel}" imitates "${token}" with characters from another alphabet.`));
        } else if (m === 'typo') {
          candidates.push(finding('LOOKALIKE_TYPO', 45, 'high', `Typosquat of ${brand.name}`,
            `"${info.label}" is one or two characters away from "${token}".`));
        } else if (m === 'exact') {
          candidates.push(finding('BRAND_IN_DOMAIN', 25, 'medium', `${brand.name} name inside an unrelated domain`,
            `${info.registrable} is not owned by ${brand.name}.`));
        }
        info.subdomains.forEach((sub, i) => {
          const sm = matchToken(sub, subUnicode[i] || sub, token, brand);
          if (sm === 'exact') {
            candidates.push(finding('BRAND_IN_SUBDOMAIN', 30, 'high', `${brand.name} name in a subdomain`,
              `"${sub}" is a subdomain of ${info.registrable}, which ${brand.name} does not own.`));
          } else if (sm) {
            candidates.push(finding('LOOKALIKE_SUBDOMAIN', 40, 'high', `Look-alike of ${brand.name} in a subdomain`,
              `"${subUnicode[i] || sub}" imitates "${token}".`));
          }
        });
      }
    }
    // One brand finding is enough evidence; keep only the strongest.
    candidates.sort((a, b) => b.weight - a.weight);
    return candidates.slice(0, 1);
  }

  function analyzeUrl(url, opts) {
    const L = D();
    const brands = (opts && opts.brands) || Verano.brands.BRANDS;
    const parsed = L.parseUrl(url);
    if (!parsed) return { url, parsed: null, info: null, findings: [] };
    const findings = [];

    if (parsed.scheme === 'data') {
      findings.push(finding('DATA_URL', 60, 'critical', 'Page loaded from a data: URL',
        'The whole page is embedded in the address, a trick used to dodge URL filters.'));
      return { url, parsed, info: null, findings };
    }

    const info = L.splitHost(parsed.host);
    const loopback = L.isLoopback(parsed.host);

    if (parsed.userinfo) {
      const hit = brands.find((b) => b.tokens.some((t) => parsed.userinfo.toLowerCase().includes(t)));
      if (hit) {
        findings.push(finding('USERINFO_BRAND', 70, 'critical', `Fake ${hit.name} address before an "@"`,
          `Everything before "@" is ignored, so "${parsed.userinfo}@" hides the real host ${parsed.host}.`));
      } else {
        findings.push(finding('USERINFO', 30, 'high', 'Credentials-style "@" in the address',
          `Text before "@" ("${parsed.userinfo}") is ignored by the browser and can disguise the real host.`));
      }
    }

    if (!loopback) {
      if (info.ip === 'ipv4-integer' || info.ip === 'ipv4-obfuscated') {
        findings.push(finding('IP_OBFUSCATED', 40, 'critical', 'Obfuscated IP address host',
          `"${parsed.host}" is an IP address written in decimal, hex or octal to look less suspicious.`));
      } else if (info.ip) {
        findings.push(finding('IP_HOST', 25, 'high', 'Raw IP address instead of a domain',
          `Legitimate sign-in pages are almost never served from a bare IP (${parsed.host}).`));
      }
      if (parsed.scheme === 'http') {
        findings.push(finding('NO_TLS', 5, 'low', 'Unencrypted connection (HTTP)', 'Anything typed here travels in clear text.'));
      }
      if (parsed.port && !['80', '443'].includes(parsed.port)) {
        findings.push(finding('ODD_PORT', 10, 'medium', `Non-standard port :${parsed.port}`,
          'Phishing kits on compromised servers often listen on unusual ports.'));
      }
    }

    if (loopback) return { url, parsed, info, findings };

    const pathLower = (parsed.path + parsed.query).toLowerCase();
    const pathBrand = brands.find((b) => b.tokens.some((t) => t.length >= 5 && pathLower.includes(t)));
    if (pathBrand) {
      findings.push(finding('BRAND_IN_PATH', 20, 'medium', `${pathBrand.name} name in the page path`,
        `The path mentions ${pathBrand.name}, but the site is ${info.registrable}.`));
    }

    if (info.ip) return { url, parsed, info, findings };

    if (info.host.split('.').some((l) => l.startsWith('xn--'))) {
      findings.push(finding('PUNYCODE', 15, 'medium', 'Internationalized (punycode) domain',
        `${info.host} displays as "${info.unicodeHost}".`));
      if (info.unicodeHost.split('.').some((l) => L.isMixedScript(l))) {
        findings.push(finding('MIXED_SCRIPT', 30, 'high', 'Mixed alphabets in one domain label',
          'Latin letters mixed with Cyrillic/Greek characters is a classic homograph attack.'));
      }
    }

    findings.push(...brandFindings(info, brands));

    const hostWords = info.subdomains.concat(info.label).join('-').split(/[-.]/);
    const credHits = CREDENTIAL_WORDS.filter((w) => hostWords.some((h) => h === w || (w.length >= 6 && h.includes(w))));
    if (credHits.length) {
      findings.push(finding('CREDENTIAL_WORDS_IN_HOST', credHits.length > 1 ? 15 : 10, 'medium', 'Account/security words in the hostname',
        `Hostname contains: ${credHits.slice(0, 4).join(', ')}.`));
    }

    const tld = info.suffix.split('.').pop();
    if (SUSPICIOUS_TLDS.has(tld)) {
      findings.push(finding('SUSPICIOUS_TLD', 10, 'medium', `High-abuse top-level domain .${tld}`,
        'This TLD is heavily used for phishing and malware because names are cheap or free.'));
    }

    if (info.hosting) {
      findings.push(finding('FREE_HOSTING', 15, 'medium', `Hosted on a free platform (${info.hosting})`,
        'Anyone can publish a page here in minutes, so the platform name says nothing about who runs it.'));
    }

    if (SHORTENERS.has(info.registrable)) {
      findings.push(finding('URL_SHORTENER', 5, 'low', 'Link shortener', 'The final destination is hidden until the redirect happens.'));
    }

    if (info.subdomains.length >= 3) {
      findings.push(finding('DEEP_SUBDOMAINS', info.subdomains.length >= 5 ? 15 : 10, 'medium', `${info.subdomains.length} levels of subdomains`,
        'Long subdomain chains push the real domain out of view on narrow address bars.'));
    }

    const hyphens = (info.label.match(/-/g) || []).length;
    if (hyphens >= 3) {
      findings.push(finding('MANY_HYPHENS', 10, 'low', 'Many hyphens in the domain', `"${info.label}" strings several words together.`));
    }

    if (info.label.length >= 12 && !info.label.includes('-') && L.shannonEntropy(info.label) > 3.5 && /\d.*\d/.test(info.label) && /[a-z]/.test(info.label)) {
      findings.push(finding('RANDOM_DOMAIN', 10, 'low', 'Random-looking domain name', `"${info.label}" looks machine-generated.`));
    }

    if (/[?&](url|redirect|redirect_uri|next|goto|dest|destination|continue|return|returnurl|target)=(https?(:|%3a)|%2f%2f|\/\/)/i.test(parsed.query)) {
      findings.push(finding('EMBEDDED_REDIRECT', 5, 'low', 'Redirect target embedded in the URL', 'Open redirects are used to bounce victims through trusted domains.'));
    }

    if (parsed.href.length > 200) {
      findings.push(finding('LONG_URL', 5, 'low', 'Very long URL', `${parsed.href.length} characters, which hides the meaningful part.`));
    }

    return { url, parsed, info, findings };
  }

  Verano.urlRules = { analyzeUrl, CREDENTIAL_WORDS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
