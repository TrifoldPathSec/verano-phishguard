// Combines URL and page findings into one 0-100 score and a verdict.
(function (root) {
  'use strict';
  const Verano = (root.Verano = root.Verano || {});

  const SENSITIVITY = {
    relaxed: { suspicious: 50, phishing: 80 },
    balanced: { suspicious: 40, phishing: 70 },
    strict: { suspicious: 30, phishing: 60 },
  };

  function isAllowlisted(host, allowlist) {
    return (allowlist || []).some((d) => host === d || host.endsWith('.' + d));
  }

  /**
   * evaluate({ url, snapshot?, settings? }) -> {
   *   url, host, unicodeHost, registrable, score, verdict, findings, trusted, brandsSeen
   * }
   * verdict is 'safe' | 'suspicious' | 'phishing'.
   */
  function evaluate({ url, snapshot, settings }) {
    const cfg = settings || {};
    const thresholds = SENSITIVITY[cfg.sensitivity] || SENSITIVITY.balanced;
    const urlResult = Verano.urlRules.analyzeUrl(url);
    const info = urlResult.info;
    const host = urlResult.parsed ? urlResult.parsed.host : '';
    const base = {
      url,
      host,
      unicodeHost: info ? info.unicodeHost : host,
      registrable: info ? info.registrable : host,
      thresholds,
      evaluatedAt: Date.now(),
      stage: snapshot ? 'page' : 'url',
    };

    const owner = info && !info.ip ? Verano.brands.brandOwning(host) : null;
    // A userinfo trick can sit in front of a real brand host, so don't trust those.
    if (owner && !urlResult.parsed.userinfo) {
      return Object.assign(base, { score: 0, verdict: 'safe', findings: [], brandsSeen: [], trusted: { reason: `Official ${owner.name} domain` } });
    }
    if (host && isAllowlisted(host, cfg.allowlist)) {
      return Object.assign(base, { score: 0, verdict: 'safe', findings: [], brandsSeen: [], trusted: { reason: 'On your trusted-sites list' } });
    }

    const pageResult = snapshot ? Verano.pageRules.analyzePage(snapshot, info) : { findings: [], brandsSeen: [] };
    const findings = urlResult.findings.concat(pageResult.findings).sort((a, b) => b.weight - a.weight);
    const score = Math.min(100, findings.reduce((sum, f) => sum + f.weight, 0));
    const verdict = score >= thresholds.phishing ? 'phishing' : score >= thresholds.suspicious ? 'suspicious' : 'safe';

    return Object.assign(base, { score, verdict, findings, brandsSeen: pageResult.brandsSeen, trusted: null });
  }

  Verano.evaluate = evaluate;
  Verano.SENSITIVITY = SENSITIVITY;
})(typeof globalThis !== 'undefined' ? globalThis : this);
