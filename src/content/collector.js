// Turns the live DOM into a small JSON snapshot for src/engine/page-rules.js.
// Read-only: it never changes the page and never reads what the user types.
(function (root) {
  'use strict';
  const Verano = (root.Verano = root.Verano || {});

  const CARD_RE = /(card.?(num|no)|cc.?(num|no)|cvv|cvc|csc|security.?code|exp(iry|iration)?.?(date|month|year)|\bssn\b|social.?security)/i;
  const SEED_TEXT_RE = /(secret recovery phrase|recovery phrase|seed phrase|mnemonic phrase|12.word|24.word|wallet phrase|private key)/i;

  function text(el, max) {
    return ((el && (el.innerText || el.textContent)) || '').replace(/\s+/g, ' ').trim().slice(0, max);
  }

  function absolute(url, base) {
    try {
      return new URL(url, base).href;
    } catch (e) {
      return '';
    }
  }

  function hostOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      return '';
    }
  }

  function describeInput(input) {
    return [input.name, input.id, input.placeholder, input.getAttribute('autocomplete'), input.getAttribute('aria-label')]
      .filter(Boolean)
      .join(' ');
  }

  function isCardInput(input) {
    const ac = (input.getAttribute('autocomplete') || '').toLowerCase();
    return ac.startsWith('cc-') || CARD_RE.test(describeInput(input));
  }

  function isHidden(el, view) {
    const rect = el.getBoundingClientRect();
    if (rect.width <= 2 || rect.height <= 2) return true;
    const style = view.getComputedStyle(el);
    return style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0;
  }

  function collectSnapshot(doc) {
    const view = doc.defaultView || root;
    const pageUrl = doc.location ? doc.location.href : doc.URL;
    const base = doc.baseURI || pageUrl;
    const visibleInputs = Array.from(doc.querySelectorAll('input, textarea')).filter(
      (i) => !['hidden', 'submit', 'button', 'checkbox', 'radio', 'image', 'reset', 'file'].includes((i.type || '').toLowerCase())
    );

    const forms = Array.from(doc.forms).slice(0, 25).map((form) => {
      const inputs = Array.from(form.querySelectorAll('input'));
      return {
        // getAttribute, because an <input name="action"> shadows form.action.
        action: absolute(form.getAttribute('action') || pageUrl, base),
        method: (form.getAttribute('method') || 'get').toLowerCase(),
        hasPassword: inputs.some((i) => i.type === 'password'),
        hasCard: inputs.some(isCardInput),
      };
    });

    // Seed-phrase pages: lots of word boxes, or a textarea next to "recovery phrase".
    const bodyText = text(doc.body, 6000);
    const textInputs = visibleInputs.filter((i) => i.tagName === 'TEXTAREA' || ['text', 'password', ''].includes(i.type));
    const seedPhrase =
      (textInputs.length >= 12 && SEED_TEXT_RE.test(bodyText)) ||
      (SEED_TEXT_RE.test(bodyText) && doc.querySelector('textarea') !== null && /(enter|import|restore|paste|type)/i.test(bodyText));

    const links = Array.from(doc.links);
    const emptyLinks = links.filter((a) => {
      const href = (a.getAttribute('href') || '').trim();
      return href === '' || href === '#' || /^javascript:/i.test(href);
    }).length;

    const resourceHosts = new Set();
    doc.querySelectorAll('img[src], link[href][rel~="icon"], link[href][rel="stylesheet"], script[src]').forEach((el) => {
      const h = hostOf(absolute(el.getAttribute('src') || el.getAttribute('href'), base));
      if (h && resourceHosts.size < 60) resourceHosts.add(h);
    });

    const imageHints = [];
    doc.querySelectorAll('img, svg[aria-label], [class*="logo" i], [id*="logo" i]').forEach((el) => {
      if (imageHints.length >= 40) return;
      const src = el.getAttribute('src') || '';
      const file = src.startsWith('data:') ? '' : src.split(/[?#]/)[0].split('/').pop();
      const hint = [el.getAttribute('alt'), el.getAttribute('aria-label'), el.getAttribute('title'), file].filter(Boolean).join(' ');
      if (hint) imageHints.push(hint.slice(0, 120));
    });

    const formText = Array.from(doc.querySelectorAll('form, [role="form"]')).slice(0, 5).map((f) => text(f, 400));

    let metaRefreshExternal = false;
    const refresh = doc.querySelector('meta[http-equiv="refresh" i]');
    if (refresh) {
      const m = /url\s*=\s*['"]?([^'";]+)/i.exec(refresh.getAttribute('content') || '');
      const target = m && hostOf(absolute(m[1], base));
      if (target && Verano.domain) {
        metaRefreshExternal = Verano.domain.splitHost(target).registrable !== Verano.domain.splitHost(hostOf(pageUrl)).registrable;
      }
    }

    const body = doc.body;
    const contextMenuBlocked =
      /return\s+false|preventDefault/.test((body && body.getAttribute('oncontextmenu')) || '') ||
      /return\s+false|preventDefault/.test(doc.documentElement.getAttribute('oncontextmenu') || '');

    return {
      url: pageUrl,
      title: (doc.title || '').slice(0, 200),
      headings: Array.from(doc.querySelectorAll('h1, h2, h3')).slice(0, 10).map((h) => text(h, 150)),
      imageHints,
      formText,
      textSample: bodyText,
      forms,
      passwordFields: doc.querySelectorAll('input[type="password"]').length,
      cardFields: visibleInputs.filter(isCardInput).length,
      seedPhrase: !!seedPhrase,
      links: { total: links.length, empty: emptyLinks },
      resourceHosts: Array.from(resourceHosts),
      hiddenIframes: Array.from(doc.querySelectorAll('iframe')).slice(0, 20).filter((f) => isHidden(f, view)).length,
      contextMenuBlocked,
      metaRefreshExternal,
    };
  }

  Verano.collectSnapshot = collectSnapshot;
})(typeof globalThis !== 'undefined' ? globalThis : this);
