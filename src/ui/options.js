(async function () {
  'use strict';
  const { h, findingsList, VERDICT_LABEL, send } = window.VeranoUI;
  const $ = (id) => document.getElementById(id);
  $('version').textContent = chrome.runtime.getManifest().version;

  let settings = await send('get-settings');

  // ---- protection toggles ----
  const toggles = ['blockPhishing', 'showBanner', 'guardSubmit'];
  toggles.forEach((key) => {
    $(key).checked = !!settings[key];
    $(key).addEventListener('change', () => save({ [key]: $(key).checked }));
  });
  $('sensitivity').value = settings.sensitivity;
  $('sensitivity').addEventListener('change', () => save({ sensitivity: $('sensitivity').value }));

  let savedTimer;
  async function save(patch) {
    settings = await send('save-settings', { patch });
    $('saved').classList.add('show');
    clearTimeout(savedTimer);
    savedTimer = setTimeout(() => $('saved').classList.remove('show'), 1200);
  }

  // ---- URL tester ----
  async function analyze(url) {
    const r = await send('analyze-url', { url });
    $('tester-result').replaceChildren(
      h('div', { class: 'tester-head' }, [
        h('strong', { class: `verdict-${r.verdict}` }, [`${VERDICT_LABEL[r.verdict]} · ${r.score}/100`]),
        h('span', { class: 'mono muted' }, [r.unicodeHost !== r.host ? `${r.host} → ${r.unicodeHost}` : r.host]),
      ]),
      r.trusted ? h('p', { class: 'verdict-safe' }, ['✓ ', r.trusted.reason]) : null,
      r.findings.length ? findingsList(r.findings) : h('p', { class: 'muted' }, [r.trusted ? '' : 'No phishing indicators in the URL.'])
    );
  }
  $('tester').addEventListener('submit', (e) => {
    e.preventDefault();
    const url = $('tester-url').value.trim();
    if (url) analyze(/^[a-z][a-z0-9+.-]*:/i.test(url) ? url : `https://${url}`);
  });
  document.querySelectorAll('.examples button').forEach((b) =>
    b.addEventListener('click', () => {
      $('tester-url').value = b.dataset.url;
      analyze(b.dataset.url);
    })
  );

  // ---- allowlist ----
  function renderAllowlist() {
    $('allowlist').replaceChildren(
      ...(settings.allowlist.length
        ? settings.allowlist.map((d) =>
            h('span', { class: 'chip mono' }, [d, h('button', { title: `Remove ${d}`, 'aria-label': `Remove ${d}`, onclick: async () => {
              await send('untrust-site', { registrable: d });
              settings = await send('get-settings');
              renderAllowlist();
            } }, ['×'])])
          )
        : [h('span', { class: 'muted' }, ['No trusted sites yet.'])])
    );
  }
  $('trust-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const raw = $('trust-input').value.trim().toLowerCase();
    const domain = raw.replace(/^[a-z]+:\/\//, '').split(/[/?#:]/)[0].replace(/^www\./, '');
    if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(domain)) return;
    await send('trust-site', { registrable: domain });
    settings = await send('get-settings');
    $('trust-input').value = '';
    renderAllowlist();
  });
  renderAllowlist();

  // ---- history ----
  async function renderHistory() {
    const { history = [] } = await chrome.storage.local.get('history');
    $('history').replaceChildren(
      ...(history.length
        ? history.map((e) =>
            h('tr', {}, [
              h('td', {}, [new Date(e.at).toLocaleString()]),
              h('td', { class: 'mono', title: e.url }, [e.registrable]),
              h('td', { class: `num verdict-${e.verdict}` }, [`${e.score}`]),
              h('td', {}, [e.action]),
              h('td', {}, [e.reasons.join('; ')]),
            ])
          )
        : [h('tr', {}, [h('td', { colspan: '5', class: 'muted' }, ['Nothing detected yet.'])])])
    );
  }
  $('clear-history').addEventListener('click', async () => {
    await chrome.storage.local.set({ history: [] });
    renderHistory();
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.history) renderHistory();
  });
  renderHistory();
})();
