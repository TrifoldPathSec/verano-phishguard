// URL and hostname helpers: parsing, registrable-domain splitting, IP detection,
// homoglyph "skeletons" and edit distance. No browser APIs, so the same code
// runs in the service worker, the content script and the test runner.
(function (root) {
  'use strict';
  const Verano = (root.Verano = root.Verano || {});

  // Two-label public suffixes we care about (a tiny slice of the Public Suffix List).
  const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'gov.au',
    'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'co.in', 'co.za', 'com.br', 'com.mx', 'com.ar',
    'com.cn', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.co', 'co.id', 'com.my', 'com.ph',
  ]);

  // Free hosting / app platforms. Each subdomain belongs to a different person,
  // so they behave like public suffixes, and phishing kits love them.
  const HOSTING_SUFFIXES = new Set([
    'github.io', 'gitlab.io', 'web.app', 'firebaseapp.com', 'netlify.app', 'vercel.app',
    'pages.dev', 'workers.dev', 'r2.dev', 'herokuapp.com', 'glitch.me', 'repl.co', 'replit.app',
    'onrender.com', 'fly.dev', 'azurewebsites.net', 'web.core.windows.net', 'appspot.com',
    'blogspot.com', 'weebly.com', 'wixsite.com', 'square.site', 'webflow.io', 'framer.app',
    '000webhostapp.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com',
    'ipfs.dweb.link', 'ipfs.io', 'surge.sh', 'translate.goog', 'sites.google.com',
    'carrd.co', 'mystrikingly.com', 'jimdosite.com', 'godaddysites.com',
  ]);

  function parseUrl(input) {
    const href = String(input || '').trim();
    const m = /^([a-z][a-z0-9+.-]*):(?:\/\/([^/?#\\]*))?([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(href);
    if (!m) return null;
    let authority = m[2] || '';
    let userinfo = '';
    const at = authority.lastIndexOf('@');
    if (at !== -1) {
      userinfo = authority.slice(0, at);
      authority = authority.slice(at + 1);
    }
    let host = authority;
    let port = '';
    const v6 = /^\[([^\]]+)\](?::(\d*))?$/.exec(authority);
    if (v6) {
      host = v6[1];
      port = v6[2] || '';
    } else {
      const colon = authority.lastIndexOf(':');
      if (colon !== -1) {
        host = authority.slice(0, colon);
        port = authority.slice(colon + 1);
      }
    }
    return {
      href,
      scheme: m[1].toLowerCase(),
      userinfo: safeDecode(userinfo),
      host: host.toLowerCase().replace(/\.$/, ''),
      port,
      path: m[3] || '/',
      query: m[4] || '',
      fragment: m[5] || '',
    };
  }

  function safeDecode(s) {
    try {
      return decodeURIComponent(s);
    } catch (e) {
      return s;
    }
  }

  function ipKind(host) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return 'ipv4';
    if (host.includes(':')) return 'ipv6';
    if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) return 'ipv4-integer';
    if (/^((0x[0-9a-f]+|\d+)\.){1,3}(0x[0-9a-f]+|\d+)$/i.test(host)) return 'ipv4-obfuscated';
    return null;
  }

  function isLoopback(host) {
    return (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      /^127\.\d+\.\d+\.\d+$/.test(host) ||
      host === '::1'
    );
  }

  // Split a hostname into subdomains / registrable domain / public suffix.
  function splitHost(host) {
    const unicodeHost = Verano.punycode.hostToUnicode(host);
    const ip = ipKind(host);
    if (ip) {
      return { host, unicodeHost, ip, registrable: host, label: host, unicodeLabel: host, suffix: '', subdomains: [], hosting: null };
    }
    const labels = host.split('.').filter(Boolean);
    const uLabels = unicodeHost.split('.').filter(Boolean);
    let suffixLen = 1;
    let hosting = null;
    for (const n of [3, 2]) {
      if (labels.length <= n) continue;
      const candidate = labels.slice(-n).join('.');
      if (HOSTING_SUFFIXES.has(candidate)) {
        suffixLen = n;
        hosting = candidate;
        break;
      }
      if (MULTI_PART_SUFFIXES.has(candidate)) {
        suffixLen = n;
        break;
      }
    }
    const regLen = Math.min(labels.length, suffixLen + 1);
    return {
      host,
      unicodeHost,
      ip: null,
      registrable: labels.slice(-regLen).join('.'),
      label: labels.length > suffixLen ? labels[labels.length - regLen] : labels[0] || '',
      unicodeLabel: uLabels.length > suffixLen ? uLabels[uLabels.length - regLen] : uLabels[0] || '',
      suffix: labels.slice(-suffixLen).join('.'),
      subdomains: labels.slice(0, labels.length - regLen),
      hosting,
    };
  }

  // Characters that render like Latin letters (Cyrillic, Greek, Armenian, misc).
  const CONFUSABLES = {
    'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p',
    'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ӏ': 'l',
    'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'ɡ': 'g', 'ɑ': 'a', 'ı': 'i', 'ⅼ': 'l', 'ｌ': 'l',
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'ս': 'u', 'ո': 'n', 'օ': 'o', 'ց': 'g', 'հ': 'h',
  };
  // ASCII tricks used in typosquats.
  const LEET = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '9': 'g', '!': 'i', '|': 'l' };

  // Reduce a label to what it *looks like*, so "pаypa1" and "paypal" compare equal.
  function skeleton(s) {
    let out = '';
    const folded = String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
    for (const ch of folded) out += CONFUSABLES[ch] || LEET[ch] || ch;
    return out.replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  function hasNonAscii(s) {
    return /[^\x00-\x7f]/.test(s);
  }

  // Latin mixed with Cyrillic/Greek/Armenian inside one label.
  function isMixedScript(label) {
    const latin = /[a-z]/i.test(label);
    const other = /[Ͱ-ϿЀ-ӿԀ-ԯ԰-֏]/.test(label);
    return latin && other;
  }

  function levenshtein(a, b, max) {
    if (a === b) return 0;
    if (Math.abs(a.length - b.length) > max) return max + 1;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      let rowMin = i;
      for (let j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        if (cur[j] < rowMin) rowMin = cur[j];
      }
      if (rowMin > max) return max + 1;
      prev = cur;
    }
    return prev[b.length];
  }

  function shannonEntropy(s) {
    const counts = {};
    for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
    let h = 0;
    for (const k in counts) {
      const p = counts[k] / s.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  // Remove the scheme dots so IOCs shown to the user are not clickable.
  function defang(url) {
    return String(url).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  }

  Verano.domain = {
    parseUrl, ipKind, isLoopback, splitHost, skeleton, hasNonAscii, isMixedScript,
    levenshtein, shannonEntropy, defang, HOSTING_SUFFIXES,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
