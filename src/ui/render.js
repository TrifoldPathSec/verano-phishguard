// Small DOM helpers shared by the popup, options and warning pages.
(function (root) {
  'use strict';

  function h(tag, attrs, children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else if (v !== undefined && v !== null) node.setAttribute(k, v);
    });
    (children || []).forEach((c) => c !== null && c !== undefined && node.append(c));
    return node;
  }

  function findingsList(findings) {
    return h('ul', { class: 'findings' }, findings.map((f) =>
      h('li', { 'data-sev': f.severity }, [
        h('div', { class: 'f-title' }, [h('span', {}, [f.title]), h('span', { class: 'f-weight' }, [`+${f.weight}`])]),
        h('div', { class: 'f-detail' }, [f.detail]),
      ])
    ));
  }

  const VERDICT_LABEL = { safe: 'Looks safe', suspicious: 'Suspicious', phishing: 'Phishing' };

  function send(type, payload) {
    return chrome.runtime.sendMessage(Object.assign({ type }, payload || {}));
  }

  root.VeranoUI = { h, findingsList, VERDICT_LABEL, send };
})(window);
