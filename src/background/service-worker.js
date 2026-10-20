// Verano PhishGuard service worker.
//   1. Scores every top-level navigation by URL alone, before the page loads,
//      and swaps in the warning page when the verdict is "phishing".
//   2. Re-scores with the page snapshot the content script sends after load
//      (and again whenever a login form appears later).
//   3. Keeps per-tab results for the popup, sets the toolbar badge and logs detections.
importScripts(
  '/src/engine/punycode.js',
  '/src/engine/domain.js',
  '/src/engine/brands.js',
  '/src/engine/url-rules.js',
  '/src/engine/page-rules.js',
  '/src/engine/scorer.js'
);

const { evaluate } = self.Verano;

const DEFAULT_SETTINGS = {
  sensitivity: 'balanced', // relaxed | balanced | strict
  blockPhishing: true, // full-page warning for "phishing"
  showBanner: true, // in-page banner for "suspicious" / "phishing"
  guardSubmit: true, // confirm before sending a password/card on flagged pages
  allowlist: [], // registrable domains the user trusts
};
const HISTORY_LIMIT = 200;
const WARNING_PAGE = chrome.runtime.getURL('src/ui/warning.html');

async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return Object.assign({}, DEFAULT_SETTINGS, settings);
}

async function saveSettings(patch) {
  const settings = Object.assign(await getSettings(), patch);
  await chrome.storage.local.set({ settings });
  return settings;
}

const isScannable = (url) => /^https?:\/\//i.test(url || '');
const tabKey = (tabId) => `tab:${tabId}`;

async function getTabState(tabId) {
  const key = tabKey(tabId);
  return (await chrome.storage.session.get(key))[key] || null;
}

async function setTabState(tabId, result) {
  await chrome.storage.session.set({ [tabKey(tabId)]: result });
  await updateBadge(tabId, result);
}

async function updateBadge(tabId, result) {
  const look = {
    phishing: { text: '!', color: '#d93025' },
    suspicious: { text: '?', color: '#e37400' },
  }[result && result.verdict];
  try {
    await chrome.action.setBadgeText({ tabId, text: look ? look.text : '' });
    if (look) await chrome.action.setBadgeBackgroundColor({ tabId, color: look.color });
    await chrome.action.setTitle({
      tabId,
      title: result ? `Verano PhishGuard: ${result.verdict} (${result.score}/100)` : 'Verano PhishGuard',
    });
  } catch (e) {
    // The tab was closed before we got here.
  }
}

async function isBypassed(registrable) {
  const { bypass = {} } = await chrome.storage.session.get('bypass');
  return !!bypass[registrable];
}

async function logDetection(result, action) {
  if (result.verdict === 'safe') return;
  const { history = [] } = await chrome.storage.local.get('history');
  const last = history[0];
  // A page that is re-scanned should not flood the log.
  if (last && last.url === result.url && last.verdict === result.verdict && Date.now() - last.at < 60000) return;
  history.unshift({
    at: Date.now(),
    url: result.url,
    registrable: result.registrable,
    score: result.score,
    verdict: result.verdict,
    stage: result.stage,
    action,
    reasons: result.findings.slice(0, 3).map((f) => f.title),
  });
  await chrome.storage.local.set({ history: history.slice(0, HISTORY_LIMIT) });
}

async function block(tabId, result) {
  const token = crypto.randomUUID();
  await chrome.storage.session.set({ [`block:${token}`]: result });
  await logDetection(result, 'blocked');
  await chrome.tabs.update(tabId, { url: `${WARNING_PAGE}?t=${token}` });
}

// Returns true if the tab was sent to the warning page.
async function enforce(tabId, result, settings) {
  if (result.verdict === 'phishing' && settings.blockPhishing && !(await isBypassed(result.registrable))) {
    await block(tabId, result);
    return true;
  }
  return false;
}

// ---- navigation: URL-only check before the page loads ---------------------

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !isScannable(details.url)) return;
  const settings = await getSettings();
  const result = evaluate({ url: details.url, settings });
  await setTabState(details.tabId, result);
  await enforce(details.tabId, result, settings);
});

// Chrome clears per-tab badges on commit, so put ours back.
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const state = await getTabState(details.tabId);
  if (state && state.url === details.url) await updateBadge(details.tabId, state);
  else if (!isScannable(details.url)) await chrome.storage.session.remove(tabKey(details.tabId));
});

// Single-page apps change the URL without a navigation; ask the page to re-scan.
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0 || !isScannable(details.url)) return;
  chrome.tabs.sendMessage(details.tabId, { type: 'rescan' }).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(tabKey(tabId)));

// ---- messages from the content script and the extension pages -------------

const handlers = {
  async 'page-snapshot'(msg, sender) {
    const tabId = sender.tab && sender.tab.id;
    if (tabId == null) return null;
    const settings = await getSettings();
    const result = evaluate({ url: msg.snapshot.url, snapshot: msg.snapshot, settings });
    await setTabState(tabId, result);
    const blocked = await enforce(tabId, result, settings);
    if (!blocked) await logDetection(result, settings.showBanner ? 'warned' : 'logged');
    return {
      result,
      blocked,
      bypassed: await isBypassed(result.registrable),
      ui: { showBanner: settings.showBanner, guardSubmit: settings.guardSubmit },
    };
  },

  async 'get-tab-state'(msg) {
    return getTabState(msg.tabId);
  },

  async 'get-block'(msg) {
    const key = `block:${msg.token}`;
    return (await chrome.storage.session.get(key))[key] || null;
  },

  // "Proceed anyway" on the warning page: skip blocking for this site until the browser restarts.
  async bypass(msg) {
    const { bypass = {} } = await chrome.storage.session.get('bypass');
    bypass[msg.registrable] = true;
    await chrome.storage.session.set({ bypass });
    return true;
  },

  async 'trust-site'(msg) {
    const settings = await getSettings();
    if (!settings.allowlist.includes(msg.registrable)) {
      await saveSettings({ allowlist: settings.allowlist.concat(msg.registrable).sort() });
    }
    return true;
  },

  async 'untrust-site'(msg) {
    const settings = await getSettings();
    await saveSettings({ allowlist: settings.allowlist.filter((d) => d !== msg.registrable) });
    return true;
  },

  async 'get-settings'() {
    return getSettings();
  },

  async 'save-settings'(msg) {
    return saveSettings(msg.patch);
  },

  // URL tester on the options page.
  async 'analyze-url'(msg) {
    return evaluate({ url: msg.url, settings: await getSettings() });
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = msg && handlers[msg.type];
  if (!handler) return false;
  handler(msg, sender).then(sendResponse, (err) => {
    console.error('[verano]', msg.type, err);
    sendResponse(null);
  });
  return true; // keep the channel open for the async response
});

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set({ settings: await getSettings() });
});
