(async function () {
  'use strict';
  const { findingsList, send } = window.VeranoUI;
  const token = new URLSearchParams(location.search).get('t');
  const result = token ? await send('get-block', { token }) : null;

  const $ = (id) => document.getElementById(id);
  $('back').addEventListener('click', () => {
    // History still holds the phishing URL behind us, so open a fresh page instead of going back.
    location.replace('about:blank');
  });

  if (!result) {
    $('url').textContent = 'Details expired (the browser was restarted).';
    $('score').textContent = 'n/a';
    $('proceed').hidden = true;
    return;
  }

  $('url').textContent = result.unicodeHost !== result.host ? `${result.url}\n(displays as ${result.unicodeHost})` : result.url;
  $('score').textContent = `${result.score}/100`;
  $('findings').append(findingsList(result.findings));

  $('proceed').addEventListener('click', async () => {
    await send('bypass', { registrable: result.registrable });
    location.replace(result.url);
  });
})();
