(async function () {
  'use strict';
  const { h, findingsList, VERDICT_LABEL, send } = window.VeranoUI;
  const app = document.getElementById('app');

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const state = tab ? await send('get-tab-state', { tabId: tab.id }) : null;

  if (!state) {
    app.replaceChildren(h('p', { class: 'muted empty' }, ['Verano only scans regular http(s) web pages. Nothing to check on this one.']));
    return;
  }

  const settings = await send('get-settings');
  const userTrusted = settings.allowlist.includes(state.registrable);
  const color = `var(--${state.verdict})`;
  const C = 2 * Math.PI * 32;

  const ring = h('div', { class: 'ring' }, [h('span', { class: `verdict-${state.verdict}` }, [String(state.score)])]);
  ring.insertAdjacentHTML('afterbegin',
    `<svg width="76" height="76" viewBox="0 0 76 76" aria-hidden="true">
       <circle class="track" cx="38" cy="38" r="32" fill="none" stroke-width="7"/>
       <circle class="value" cx="38" cy="38" r="32" fill="none" stroke-width="7" stroke-linecap="round"
         stroke="${color}" stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - state.score / 100)}"/>
     </svg>`);

  const summary = h('div', { class: 'summary' }, [
    ring,
    h('div', {}, [
      h('div', { class: `verdict verdict-${state.verdict}` }, [VERDICT_LABEL[state.verdict]]),
      h('div', { class: 'site mono' }, [state.unicodeHost || state.host]),
      state.trusted ? h('div', { class: 'trusted verdict-safe' }, ['✓ ', state.trusted.reason]) : null,
    ]),
  ]);

  const stage = h('div', { class: 'stage muted' }, [
    state.stage === 'page' ? 'Checked the address and the page content.' : 'Checked the address only (page still loading or not scanned).',
  ]);

  const body = state.findings.length
    ? findingsList(state.findings)
    : h('p', { class: 'muted' }, [state.trusted ? 'No checks needed for a trusted site.' : 'No phishing indicators found.']);

  const trustBtn = h('button', {
    onclick: async () => {
      await send(userTrusted ? 'untrust-site' : 'trust-site', { registrable: state.registrable });
      await chrome.tabs.sendMessage(tab.id, { type: 'rescan' }).catch(() => {});
      window.close();
    },
  }, [userTrusted ? `Stop trusting ${state.registrable}` : `Trust ${state.registrable}`]);

  const rescanBtn = h('button', {
    onclick: async () => {
      await chrome.tabs.sendMessage(tab.id, { type: 'rescan' }).catch(() => {});
      setTimeout(() => location.reload(), 900);
    },
  }, ['Rescan']);

  // Official brand domains don't need (and can't lose) trust.
  const showTrust = userTrusted || !state.trusted;
  app.replaceChildren(summary, stage, body, h('div', { class: 'footer' }, [rescanBtn, showTrust ? trustBtn : null]));
})();
