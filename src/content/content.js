// Content script: snapshots the page, asks the service worker for a verdict,
// shows a warning banner, and stops credentials from being submitted on a
// flagged page until the user confirms.
(function () {
  'use strict';
  if (window.__veranoPhishGuard) return;
  window.__veranoPhishGuard = true;

  const Verano = globalThis.Verano;
  const MAX_SCANS = 8;
  let state = null; // last response from the service worker
  let scans = 0;
  let lastSignature = '';
  let bannerDismissed = false;
  const confirmedForms = new WeakSet();
  let ui = null;

  // ---- scanning --------------------------------------------------------------

  async function scan() {
    if (scans >= MAX_SCANS) return;
    let snapshot;
    try {
      snapshot = Verano.collectSnapshot(document);
    } catch (e) {
      return;
    }
    // Only re-ask when something that matters changed.
    const signature = [snapshot.url, snapshot.passwordFields, snapshot.cardFields, snapshot.seedPhrase, snapshot.forms.length, snapshot.title].join('|');
    if (signature === lastSignature) return;
    lastSignature = signature;
    scans++;
    try {
      const response = await chrome.runtime.sendMessage({ type: 'page-snapshot', snapshot });
      if (!response || response.blocked) return;
      state = response;
      render();
    } catch (e) {
      // The extension was reloaded or updated; this copy of the script is orphaned.
      observer.disconnect();
    }
  }

  let timer = null;
  function scheduleScan(delay) {
    clearTimeout(timer);
    timer = setTimeout(scan, delay);
  }

  // Phishing kits often inject the login form after load (or after a fake CAPTCHA).
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1 && (node.matches('input, form, textarea') || node.querySelector('input, form, textarea'))) {
          scheduleScan(600);
          return;
        }
      }
    }
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'rescan') {
      lastSignature = '';
      scans = Math.min(scans, MAX_SCANS - 1);
      scheduleScan(300);
    }
  });

  // ---- submit guard ----------------------------------------------------------

  function flagged() {
    return state && state.result && state.result.verdict !== 'safe' && !state.result.trusted;
  }

  function sendsSecrets(form) {
    return Array.from(form.querySelectorAll('input')).some(
      (i) => i.type === 'password' || /^cc-/.test(i.getAttribute('autocomplete') || '') || /card|cvv|cvc|ssn/i.test(i.name || i.id || '')
    );
  }

  document.addEventListener(
    'submit',
    (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || !flagged() || !state.ui.guardSubmit) return;
      if (confirmedForms.has(form) || !sendsSecrets(form)) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      showSubmitDialog(form, event.submitter);
    },
    true
  );

  // ---- UI (isolated in a closed shadow root so page CSS can't touch it) ------

  const STYLE = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .banner { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647; display: flex; gap: 12px;
      align-items: flex-start; padding: 12px 16px; color: #fff; font-size: 14px; line-height: 1.4;
      box-shadow: 0 2px 12px rgba(0,0,0,.35); }
    .banner.suspicious { background: #b45309; }
    .banner.phishing { background: #b91c1c; }
    .icon { font-size: 20px; line-height: 1; }
    .body { flex: 1; min-width: 0; }
    .title { font-weight: 700; }
    ul { margin: 4px 0 0; padding-left: 18px; }
    li { margin: 1px 0; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    button { cursor: pointer; border-radius: 6px; padding: 6px 12px; font-size: 13px; font-weight: 600;
      border: 1px solid rgba(255,255,255,.7); background: transparent; color: #fff; }
    button.primary { background: #fff; color: #111; border-color: #fff; }
    .backdrop { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,.55);
      display: flex; align-items: center; justify-content: center; padding: 16px; }
    .dialog { background: #fff; color: #111; max-width: 460px; width: 100%; border-radius: 12px; padding: 20px;
      box-shadow: 0 10px 40px rgba(0,0,0,.4); font-size: 14px; line-height: 1.45; }
    .dialog h2 { margin: 0 0 8px; font-size: 18px; color: #b91c1c; }
    .dialog .host { font-family: ui-monospace, Menlo, monospace; background: #f3f4f6; padding: 1px 5px; border-radius: 4px; }
    .dialog .actions { justify-content: flex-end; margin-top: 16px; }
    .dialog button { border-color: #d1d5db; color: #111; }
    .dialog button.primary { background: #111827; color: #fff; border-color: #111827; }
    .dialog button.danger { color: #b91c1c; }
  `;

  function mountUi() {
    if (ui) return ui;
    const host = document.createElement('verano-phishguard');
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = STYLE;
    shadow.appendChild(style);
    document.documentElement.appendChild(host);
    ui = { host, shadow };
    return ui;
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'onclick') node.addEventListener('click', v);
      else node.setAttribute(k, v);
    });
    (children || []).forEach((c) => node.append(c));
    return node;
  }

  function render() {
    const r = state.result;
    const { shadow } = mountUi();
    const old = shadow.querySelector('.banner');
    if (old) old.remove();
    if (!flagged() || !state.ui.showBanner || bannerDismissed) return;

    const heading =
      r.verdict === 'phishing'
        ? `Verano: this looks like a phishing page (${r.score}/100)`
        : `Verano: this page looks suspicious (${r.score}/100)`;
    const reasons = el('ul', {}, r.findings.slice(0, 3).map((f) => el('li', {}, [f.title])));
    const banner = el('div', { class: `banner ${r.verdict}`, role: 'alert' }, [
      el('div', { class: 'icon' }, [r.verdict === 'phishing' ? '⛔' : '⚠️']),
      el('div', { class: 'body' }, [el('div', { class: 'title' }, [heading]), reasons]),
      el('div', { class: 'actions' }, [
        el('button', { class: 'primary', onclick: leave }, ['Leave site']),
        el('button', { onclick: () => { bannerDismissed = true; render(); } }, ['Dismiss']),
      ]),
    ]);
    shadow.appendChild(banner);
  }

  function showSubmitDialog(form, submitter) {
    const { shadow } = mountUi();
    const r = state.result;
    const close = () => backdrop.remove();
    const backdrop = el('div', { class: 'backdrop' }, [
      el('div', { class: 'dialog', role: 'alertdialog', 'aria-modal': 'true' }, [
        el('h2', {}, ['Hold on before you sign in']),
        el('p', {}, ['You are about to send a password or card details to ', el('span', { class: 'host' }, [r.unicodeHost || r.host]), '.']),
        el('p', {}, [`Verano rated this page ${r.verdict} (${r.score}/100):`]),
        el('ul', {}, r.findings.slice(0, 4).map((f) => el('li', {}, [f.title]))),
        el('div', { class: 'actions' }, [
          el('button', {
            class: 'danger',
            onclick: () => {
              close();
              confirmedForms.add(form);
              // requestSubmit re-runs validation and fires submit; our guard now lets it through.
              form.requestSubmit(submitter && submitter.form === form ? submitter : undefined);
            },
          }, ['Send anyway']),
          el('button', { class: 'primary', onclick: () => { close(); leave(); } }, ['Leave site']),
        ]),
      ]),
    ]);
    shadow.appendChild(backdrop);
    backdrop.querySelector('button.primary').focus();
  }

  function leave() {
    if (history.length > 1) history.back();
    else location.replace('about:blank');
  }

  // ---- start -------------------------------------------------------------------

  scan();
  observer.observe(document.documentElement, { childList: true, subtree: true });
  // Stop watching after a while; long-lived apps don't need constant re-scans.
  setTimeout(() => observer.disconnect(), 60000);
})();
